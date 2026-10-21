package realclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"time"
)

var ErrPCAPNG = errors.New("pcapng is not supported: capture with tcpdump -w, or convert with editcap -F pcap")

const (
	linkTypeNull      = 0
	linkTypeEthernet  = 1
	linkTypeRawAlt1   = 12
	linkTypeRawAlt2   = 14
	linkTypeRaw       = 101
	linkTypeLoop      = 108
	linkTypeLinuxSLL  = 113
	linkTypeLinuxSLL2 = 276

	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10

	// A gap that stays unfilled for this many segments is treated as capture
	// loss; the stream can no longer be split into TLS records reliably.
	maxPendingSegments = 4096
	maxPacketLength    = 1 << 18
)

// ReadPCAP reads a classic libpcap capture and returns one Trace per TCP
// connection with serverPort on one side, ordered by first packet. Direction
// is relative to the other side, the client. TCP payload is reassembled by
// sequence number, so retransmissions and reordering do not create records.
//
// Connections whose start was not captured, packets truncated by the snap
// length, sequence gaps left unfilled, and records cut off at the end of the
// capture mark the Trace as Malformed. On a
// truncated file, the connections read so far are returned with the error.
func ReadPCAP(reader io.Reader, serverPort uint16) ([]Trace, error) {
	var header [24]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	var nanoseconds bool
	switch magic := binary.LittleEndian.Uint32(header[:4]); magic {
	case 0xa1b2c3d4:
		order = binary.LittleEndian
	case 0xa1b23c4d:
		order, nanoseconds = binary.LittleEndian, true
	case 0xd4c3b2a1:
		order = binary.BigEndian
	case 0x4d3cb2a1:
		order, nanoseconds = binary.BigEndian, true
	case 0x0a0d0d0a:
		return nil, ErrPCAPNG
	default:
		return nil, fmt.Errorf("not a pcap file: magic %#x", magic)
	}
	linkType := order.Uint32(header[20:24]) & 0x0fffffff
	assembler := &tcpAssembler{
		serverPort: serverPort,
		open:       make(map[flowKey]*tcpConnection),
	}
	var packetHeader [16]byte
	var data []byte
	for {
		_, err := io.ReadFull(reader, packetHeader[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return assembler.traces(), err
		}
		seconds := int64(order.Uint32(packetHeader[0:4]))
		fraction := int64(order.Uint32(packetHeader[4:8]))
		capturedLength := order.Uint32(packetHeader[8:12])
		originalLength := order.Uint32(packetHeader[12:16])
		if capturedLength > maxPacketLength {
			return assembler.traces(), fmt.Errorf("invalid captured length %d", capturedLength)
		}
		if uint32(cap(data)) < capturedLength {
			data = make([]byte, capturedLength)
		}
		data = data[:capturedLength]
		if _, err = io.ReadFull(reader, data); err != nil {
			return assembler.traces(), err
		}
		if !nanoseconds {
			fraction *= int64(time.Microsecond)
		}
		assembler.packet(linkType, data, time.Unix(seconds, fraction), capturedLength < originalLength)
	}
	return assembler.traces(), nil
}

type flowKey struct {
	client netip.AddrPort
	server netip.AddrPort
}

type tcpConnection struct {
	recorder *traceRecorder
	upload   tcpStream
	download tcpStream
	synSeq   uint32
}

type tcpStream struct {
	started bool
	lost    bool
	next    uint32
	pending map[uint32]pendingSegment
}

type pendingSegment struct {
	payload []byte
	at      time.Time
}

type tcpPacket struct {
	source      netip.AddrPort
	destination netip.AddrPort
	seq         uint32
	flags       byte
	payload     []byte
}

type tcpAssembler struct {
	serverPort uint16
	open       map[flowKey]*tcpConnection
	finished   []*tcpConnection
}

func (a *tcpAssembler) packet(linkType uint32, data []byte, at time.Time, truncated bool) {
	network := networkLayer(linkType, data)
	if network == nil {
		return
	}
	packet, loaded := parseIP(network)
	if !loaded {
		return
	}
	var key flowKey
	var direction Direction
	switch a.serverPort {
	case packet.destination.Port():
		key, direction = flowKey{client: packet.source, server: packet.destination}, Upload
	case packet.source.Port():
		key, direction = flowKey{client: packet.destination, server: packet.source}, Download
	default:
		return
	}
	conn := a.open[key]
	isSYN := packet.flags&tcpFlagSYN != 0
	if isSYN && packet.flags&tcpFlagACK == 0 && direction == Upload && (conn == nil || conn.synSeq != packet.seq) {
		// A new connection on a reused four-tuple; a retransmitted SYN keeps its ISN.
		if conn != nil {
			a.finished = append(a.finished, conn)
		}
		conn = &tcpConnection{recorder: newTraceRecorder("", at), synSeq: packet.seq}
		a.open[key] = conn
	}
	if conn == nil {
		conn = &tcpConnection{recorder: newTraceRecorder("", at)}
		conn.recorder.markMalformed()
		a.open[key] = conn
	}
	if truncated {
		conn.recorder.markMalformed()
	}
	stream := &conn.download
	if direction == Upload {
		stream = &conn.upload
	}
	seq := packet.seq
	if isSYN {
		if !stream.started {
			stream.started = true
			stream.next = seq + 1
		}
		seq++
	}
	if len(packet.payload) > 0 {
		stream.deliver(seq, packet.payload, at, conn.recorder, direction)
	}
}

func (s *tcpStream) deliver(seq uint32, payload []byte, at time.Time, recorder *traceRecorder, direction Direction) {
	if s.lost {
		return
	}
	if !s.started {
		s.started = true
		s.next = seq
	}
	offset := int32(seq - s.next)
	if offset > 0 {
		if len(s.pending) >= maxPendingSegments {
			s.lost = true
			s.pending = nil
			recorder.markMalformed()
			return
		}
		if s.pending == nil {
			s.pending = make(map[uint32]pendingSegment)
		}
		if existing, loaded := s.pending[seq]; !loaded || len(existing.payload) < len(payload) {
			s.pending[seq] = pendingSegment{payload: append([]byte(nil), payload...), at: at}
		}
		return
	}
	if int(-offset) >= len(payload) {
		return
	}
	payload = payload[-offset:]
	recorder.observe(direction, payload, at)
	s.next += uint32(len(payload))
	for progressed := true; progressed && len(s.pending) > 0; {
		progressed = false
		for pendingSeq, segment := range s.pending {
			pendingOffset := int32(pendingSeq - s.next)
			if pendingOffset > 0 {
				continue
			}
			delete(s.pending, pendingSeq)
			progressed = true
			if int(-pendingOffset) < len(segment.payload) {
				remaining := segment.payload[-pendingOffset:]
				recorder.observe(direction, remaining, segment.at)
				s.next += uint32(len(remaining))
			}
		}
	}
}

func (a *tcpAssembler) traces() []Trace {
	connections := append([]*tcpConnection(nil), a.finished...)
	for _, conn := range a.open {
		connections = append(connections, conn)
	}
	traces := make([]Trace, len(connections))
	for index, conn := range connections {
		// The capture is over: an unfilled sequence gap or a record cut off
		// at the end leaves record lengths and byte counts unreliable.
		if len(conn.upload.pending) > 0 || len(conn.download.pending) > 0 {
			conn.recorder.markMalformed()
		}
		conn.recorder.finish()
		traces[index] = conn.recorder.snapshot()
	}
	sort.SliceStable(traces, func(i, j int) bool {
		return traces[i].Start.Before(traces[j].Start)
	})
	return traces
}

func networkLayer(linkType uint32, data []byte) []byte {
	switch linkType {
	case linkTypeEthernet:
		if len(data) < 14 {
			return nil
		}
		etherType := binary.BigEndian.Uint16(data[12:14])
		data = data[14:]
		for etherType == 0x8100 || etherType == 0x88a8 {
			if len(data) < 4 {
				return nil
			}
			etherType = binary.BigEndian.Uint16(data[2:4])
			data = data[4:]
		}
		if etherType != 0x0800 && etherType != 0x86dd {
			return nil
		}
		return data
	case linkTypeLinuxSLL:
		if len(data) < 16 {
			return nil
		}
		return data[16:]
	case linkTypeLinuxSLL2:
		if len(data) < 20 {
			return nil
		}
		return data[20:]
	case linkTypeNull, linkTypeLoop:
		if len(data) < 4 {
			return nil
		}
		return data[4:]
	case linkTypeRaw, linkTypeRawAlt1, linkTypeRawAlt2:
		return data
	}
	return nil
}

func parseIP(data []byte) (tcpPacket, bool) {
	if len(data) == 0 {
		return tcpPacket{}, false
	}
	switch data[0] >> 4 {
	case 4:
		if len(data) < 20 {
			return tcpPacket{}, false
		}
		headerLength := int(data[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(data[2:4]))
		if headerLength < 20 || len(data) < headerLength {
			return tcpPacket{}, false
		}
		// A zero total length appears with TCP segmentation offload.
		if totalLength >= headerLength && totalLength < len(data) {
			data = data[:totalLength]
		}
		if binary.BigEndian.Uint16(data[6:8])&0x3fff != 0 || data[9] != 6 {
			return tcpPacket{}, false
		}
		source := netip.AddrFrom4([4]byte(data[12:16]))
		destination := netip.AddrFrom4([4]byte(data[16:20]))
		return parseTCP(data[headerLength:], source, destination)
	case 6:
		if len(data) < 40 {
			return tcpPacket{}, false
		}
		payloadLength := int(binary.BigEndian.Uint16(data[4:6]))
		next := data[6]
		source := netip.AddrFrom16([16]byte(data[8:24]))
		destination := netip.AddrFrom16([16]byte(data[24:40]))
		data = data[40:]
		if payloadLength > 0 && payloadLength < len(data) {
			data = data[:payloadLength]
		}
		for {
			switch next {
			case 6:
				return parseTCP(data, source, destination)
			case 0, 43, 60:
				if len(data) < 8 {
					return tcpPacket{}, false
				}
				extensionLength := (int(data[1]) + 1) * 8
				if len(data) < extensionLength {
					return tcpPacket{}, false
				}
				next = data[0]
				data = data[extensionLength:]
			default:
				return tcpPacket{}, false
			}
		}
	}
	return tcpPacket{}, false
}

func parseTCP(data []byte, source, destination netip.Addr) (tcpPacket, bool) {
	if len(data) < 20 {
		return tcpPacket{}, false
	}
	dataOffset := int(data[12]>>4) * 4
	if dataOffset < 20 || len(data) < dataOffset {
		return tcpPacket{}, false
	}
	return tcpPacket{
		source:      netip.AddrPortFrom(source, binary.BigEndian.Uint16(data[0:2])),
		destination: netip.AddrPortFrom(destination, binary.BigEndian.Uint16(data[2:4])),
		seq:         binary.BigEndian.Uint32(data[4:8]),
		flags:       data[13],
		payload:     data[dataOffset:],
	}, true
}
