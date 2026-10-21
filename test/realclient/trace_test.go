package realclient

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func tlsRecord(recordType byte, length int) []byte {
	record := make([]byte, recordHeaderLen+length)
	record[0] = recordType
	record[1], record[2] = 3, 3
	binary.BigEndian.PutUint16(record[3:5], uint16(length))
	return record
}

func TestRecordParserAcrossReadBoundaries(t *testing.T) {
	t.Parallel()
	lengths := []int{0, 5, 300, 16384, 24}
	var stream []byte
	for _, length := range lengths {
		stream = append(stream, tlsRecord(RecordTypeApplicationData, length)...)
	}
	for _, chunk := range []int{1, 3, 5, 7, 4096, len(stream)} {
		parser := recordParser{direction: Download}
		var got []int
		for offset := 0; offset < len(stream); offset += chunk {
			parser.feed(stream[offset:min(offset+chunk, len(stream))], time.Duration(offset), func(record Record) {
				got = append(got, record.Length)
			})
		}
		if parser.failed || !reflect.DeepEqual(got, lengths) {
			t.Fatalf("chunk %d: got %v failed=%v, want %v", chunk, got, parser.failed, lengths)
		}
	}
}

func TestRecordParserTimesFirstByte(t *testing.T) {
	t.Parallel()
	parser := recordParser{direction: Upload}
	var times []time.Duration
	emit := func(record Record) { times = append(times, record.Time) }
	first := tlsRecord(RecordTypeHandshake, 10)
	second := tlsRecord(RecordTypeApplicationData, 2)
	parser.feed(first[:4], 1, emit)
	parser.feed(append(first[4:], second[:1]...), 2, emit)
	parser.feed(second[1:], 3, emit)
	if !reflect.DeepEqual(times, []time.Duration{1, 2}) {
		t.Fatalf("got %v", times)
	}
}

func TestRecordParserRejectsPlaintext(t *testing.T) {
	t.Parallel()
	recorder := newTraceRecorder("", time.Now())
	recorder.observe(Upload, []byte("GET / HTTP/1.1\r\nHost: example\r\n\r\n"), time.Now())
	trace := recorder.snapshot()
	if !trace.Malformed || len(trace.Records) != 0 || trace.TCPUp == 0 {
		t.Fatalf("unexpected trace %+v", trace)
	}
}

type pcapWriter struct {
	buffer bytes.Buffer
	base   time.Time
}

func newPCAPWriter() *pcapWriter {
	writer := &pcapWriter{base: time.Unix(1700000000, 0)}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65535)
	binary.LittleEndian.PutUint32(header[20:24], linkTypeEthernet)
	writer.buffer.Write(header)
	return writer
}

// packet writes an Ethernet/IPv4/TCP frame. captured < len(frame) truncates it.
func (w *pcapWriter) packet(at time.Duration, sourcePort, destinationPort uint16, seq uint32, flags byte, payload []byte, captured int) {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
	tcpHeader[12] = 5 << 4
	tcpHeader[13] = flags
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+20+len(payload)))
	ipHeader[9] = 6
	source, destination := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	if sourcePort == 443 {
		source, destination = destination, source
	}
	copy(ipHeader[12:16], source)
	copy(ipHeader[16:20], destination)
	frame := make([]byte, 14, 14+40+len(payload))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame = append(frame, ipHeader...)
	frame = append(frame, tcpHeader...)
	frame = append(frame, payload...)
	if captured <= 0 || captured > len(frame) {
		captured = len(frame)
	}
	timestamp := w.base.Add(at)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(timestamp.Unix()))
	binary.LittleEndian.PutUint32(header[4:8], uint32(timestamp.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(header[8:12], uint32(captured))
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(frame)))
	w.buffer.Write(header)
	w.buffer.Write(frame[:captured])
}

func TestReadPCAPReassemblesTLSRecords(t *testing.T) {
	t.Parallel()
	const (
		clientPort = 50000
		clientISN  = 1000
		serverISN  = 9000
	)
	writer := newPCAPWriter()
	ms := time.Millisecond
	writer.packet(0, clientPort, 443, clientISN, tcpFlagSYN, nil, 0)
	writer.packet(1*ms, 443, clientPort, serverISN, tcpFlagSYN|tcpFlagACK, nil, 0)
	upload := append(tlsRecord(RecordTypeHandshake, 200), tlsRecord(RecordTypeApplicationData, 40)...)
	// Out of order, then a retransmission overlapping already delivered data.
	writer.packet(3*ms, clientPort, 443, clientISN+1+100, tcpFlagACK, upload[100:], 0)
	writer.packet(4*ms, clientPort, 443, clientISN+1, tcpFlagACK, upload[:100], 0)
	writer.packet(5*ms, clientPort, 443, clientISN+1+50, tcpFlagACK, upload[50:150], 0)
	download := append(tlsRecord(RecordTypeHandshake, 1000), tlsRecord(RecordTypeApplicationData, 24)...)
	writer.packet(6*ms, 443, clientPort, serverISN+1, tcpFlagACK, download, 0)

	// A second connection whose server packet was truncated by the snap length.
	writer.packet(10*ms, clientPort+1, 443, 1, tcpFlagSYN, nil, 0)
	writer.packet(11*ms, clientPort+1, 443, 2, tcpFlagACK, tlsRecord(RecordTypeApplicationData, 100), 60)
	// A connection whose handshake was not captured.
	writer.packet(12*ms, clientPort+2, 443, 77, tcpFlagACK, tlsRecord(RecordTypeApplicationData, 8), 0)
	// Unrelated port.
	writer.packet(13*ms, clientPort, 80, 1, tcpFlagSYN, nil, 0)

	traces, err := ReadPCAP(bytes.NewReader(writer.buffer.Bytes()), 443)
	if err != nil {
		t.Fatal(err)
	}
	if len(traces) != 3 {
		t.Fatalf("got %d traces", len(traces))
	}
	first := traces[0]
	if first.Malformed || first.TCPUp != int64(len(upload)) || first.TCPDown != int64(len(download)) {
		t.Fatalf("unexpected first trace %+v", first)
	}
	want := []Record{
		{Direction: Upload, Type: RecordTypeHandshake, Length: 200, Time: 3 * ms},
		{Direction: Upload, Type: RecordTypeApplicationData, Length: 40, Time: 3 * ms},
		{Direction: Download, Type: RecordTypeHandshake, Length: 1000, Time: 6 * ms},
		{Direction: Download, Type: RecordTypeApplicationData, Length: 24, Time: 6 * ms},
	}
	// The first record starts in the segment captured at 4ms; the second in the
	// early segment at 3ms. Reassembly keeps capture times of each segment.
	want[0].Time = 4 * ms
	if !reflect.DeepEqual(first.Records, append([]Record{want[1], want[0]}, want[2:]...)) {
		t.Fatalf("records %+v", first.Records)
	}
	if !traces[1].Malformed || !traces[2].Malformed {
		t.Fatalf("truncated and partial connections must be malformed: %+v %+v", traces[1], traces[2])
	}
	summary := Summarize(traces, 16)
	if summary.Malformed != 2 || summary.Down.Short != 1 || summary.TotalUp != int64(len(upload)) {
		t.Fatalf("unexpected summary %+v", summary)
	}
}

func TestReadPCAPMarksIncompleteStreams(t *testing.T) {
	t.Parallel()
	ms := time.Millisecond
	writer := newPCAPWriter()
	record := tlsRecord(RecordTypeApplicationData, 100)
	// A sequence gap that is never filled: the second record is never delivered.
	writer.packet(0, 50000, 443, 1000, tcpFlagSYN, nil, 0)
	writer.packet(1*ms, 50000, 443, 1001, tcpFlagACK, record, 0)
	writer.packet(2*ms, 50000, 443, 1001+uint32(len(record))+10, tcpFlagACK, record, 0)
	// Half a TLS record at the end of the capture.
	writer.packet(3*ms, 50001, 443, 2000, tcpFlagSYN, nil, 0)
	writer.packet(4*ms, 50001, 443, 2001, tcpFlagACK, record[:50], 0)
	// A complete connection stays well formed.
	writer.packet(5*ms, 50002, 443, 3000, tcpFlagSYN, nil, 0)
	writer.packet(6*ms, 50002, 443, 3001, tcpFlagACK, record, 0)

	traces, err := ReadPCAP(bytes.NewReader(writer.buffer.Bytes()), 443)
	if err != nil {
		t.Fatal(err)
	}
	if len(traces) != 3 {
		t.Fatalf("got %d traces", len(traces))
	}
	if !traces[0].Malformed {
		t.Fatalf("sequence gap not marked malformed: %+v", traces[0])
	}
	if !traces[1].Malformed {
		t.Fatalf("partial record not marked malformed: %+v", traces[1])
	}
	if traces[2].Malformed || len(traces[2].Records) != 1 {
		t.Fatalf("complete connection misreported: %+v", traces[2])
	}
}

func TestReadPCAPRejectsPCAPNG(t *testing.T) {
	t.Parallel()
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header, 0x0a0d0d0a)
	if _, err := ReadPCAP(bytes.NewReader(header), 443); err != ErrPCAPNG {
		t.Fatalf("got %v", err)
	}
}

func TestRelayRecordsTLSConnection(t *testing.T) {
	t.Parallel()
	certificate, _ := newTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	relay, err := NewRelay(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	relay.SetLabel("echo")
	conn, err := tls.Dial("tcp", relay.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	message := bytes.Repeat([]byte{'x'}, 3000)
	if _, err = conn.Write(message); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, make([]byte, len(message))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	traces := relay.Traces()
	if len(traces) != 1 || traces[0].Label != "echo" || traces[0].Malformed {
		t.Fatalf("unexpected traces %+v", traces)
	}
	stats := traces[0].Stats()
	if stats.BytesUp != traces[0].TCPUp || stats.BytesDown != traces[0].TCPDown {
		t.Fatalf("record bytes %+v differ from TCP bytes up=%d down=%d", stats, traces[0].TCPUp, traces[0].TCPDown)
	}
	if len(traces[0].AppLengths(Upload, 0)) == 0 || len(traces[0].AppLengths(Download, 0)) == 0 {
		t.Fatal("missing application data records")
	}
	relay.DropAll()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("dropped connection still readable")
	}
	if netErr, isNetErr := err.(net.Error); isNetErr && netErr.Timeout() {
		t.Fatal("dropped connection was not closed")
	}
	conn.Close()
}

func TestSeparate(t *testing.T) {
	t.Parallel()
	makeTrace := func(lengths ...int) Trace {
		var trace Trace
		for _, length := range lengths {
			direction := Upload
			if length < 0 {
				direction, length = Download, -length
			}
			trace.Records = append(trace.Records, Record{Direction: direction, Type: RecordTypeApplicationData, Length: length})
		}
		return trace
	}
	a := []Trace{makeTrace(100, -24, -500), makeTrace(101, -24, -510), makeTrace(99, -24, -505)}
	b := []Trace{makeTrace(517, -4000, 80), makeTrace(517, -4010, 80), makeTrace(517, -3990, 81)}
	result := Separate(a, b, 4)
	if result.Accuracy != 1 || result.Recall != 1 || result.FalsePositive != 0 {
		t.Fatalf("unexpected %+v", result)
	}
	if mixed := Separate(append(a[:1:1], b[0]), append(b[1:2:2], a[1]), 4); mixed.Accuracy != 0 {
		t.Fatalf("mixed sets should not separate: %+v", mixed)
	}
	shape := NewShape(a, Download, 2)
	if shape.Short != 1 || shape.TopLength != 24 || shape.TopShare != 0.5 || shape.Distinct != 2 {
		t.Fatalf("unexpected shape %+v", shape)
	}
}
