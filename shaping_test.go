package anytls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type recordingConn struct {
	net.Conn
	writes [][]byte
	short  bool
}

func (c *recordingConn) Write(data []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(data))
	if c.short {
		return len(data) - 1, nil
	}
	return len(data), nil
}

func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

func wireFrame(command byte, streamID uint32, data []byte) []byte {
	frame := make([]byte, frameOverhead+len(data))
	putFrameHeader(frame, command, streamID, len(data))
	copy(frame[frameOverhead:], data)
	return frame
}

func decodeFrames(t *testing.T, data []byte) []controlFrame {
	t.Helper()
	var frames []controlFrame
	for len(data) > 0 {
		if len(data) < frameOverhead {
			t.Fatal("truncated frame header")
		}
		size := int(binary.BigEndian.Uint16(data[5:7]))
		if len(data) < frameOverhead+size {
			t.Fatal("truncated frame body")
		}
		frames = append(frames, controlFrame{command: data[0], streamID: binary.BigEndian.Uint32(data[1:5]), data: data[frameOverhead : frameOverhead+size]})
		data = data[frameOverhead+size:]
	}
	return frames
}

// Exercise splitting within frame headers/bodies and verify that WASTE is only
// inserted at a valid boundary, including small budgets and record-count cutoffs.
func TestDownlinkShapingPreservesFrames(t *testing.T) {
	t.Parallel()
	for _, size := range []int{7, 8, 64, 256, 1400, 16384} {
		for _, payloadSize := range []int{0, 1, 63, 257, maxFrameSize} {
			for _, budget := range []int{7, 13, 1024} {
				conn := &recordingConn{}
				shaper := &downlinkShaper{options: TrafficShapingOptions{MinRecordSize: size, MaxRecordSize: size}, remaining: 8, budget: budget}
				payload := bytes.Repeat([]byte{0x7b}, payloadSize)
				original := wireFrame(commandPSH, 1, payload)
				if err := shaper.write(conn, original); err != nil {
					t.Fatal(err)
				}
				wire := bytes.Join(conn.writes, nil)
				if len(wire)-len(original) > budget || shaper.budget < 0 || shaper.remaining < 0 {
					t.Fatal("shaping exceeded its budget")
				}
				frames := decodeFrames(t, wire)
				if frames[0].command != commandPSH || frames[0].streamID != 1 || !bytes.Equal(frames[0].data, payload) {
					t.Fatal("shaping changed application data")
				}
				for _, frame := range frames[1:] {
					if frame.command != commandWaste || frame.streamID != 0 {
						t.Fatal("unexpected added frame")
					}
				}
			}
		}
	}
}

func TestDownlinkShapingBudgetAndCutoff(t *testing.T) {
	t.Parallel()
	conn := &recordingConn{}
	shaper := &downlinkShaper{options: TrafficShapingOptions{MinRecordSize: 100, MaxRecordSize: 100}, remaining: 4, budget: 200}
	frame := wireFrame(commandSYNACK, 1, nil)
	for range 20 {
		if err := shaper.write(conn, frame); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(bytes.Join(conn.writes, nil)) - 20*len(frame); got != 186 {
		t.Fatalf("added %d bytes, want two complete 93-byte paddings", got)
	}
	if shaper.remaining != 0 || shaper.budget != 14 {
		t.Fatal("budget remainder was clamped into a distinctive short padding")
	}
	if !bytes.Equal(conn.writes[19], frame) {
		t.Fatal("traffic still shaped after cutoff")
	}
}

func TestShapingRearmsWithoutRefillingBudget(t *testing.T) {
	t.Parallel()
	options := &TrafficShapingOptions{MinRecordSize: 100, MaxRecordSize: 100, MinRecords: 1, MaxRecords: 1, MaxPaddingBytes: 1000}
	shaper := newDownlinkShaper(options)
	conn := &recordingConn{}
	data := wireFrame(commandPSH, 1, []byte("hello"))
	control := wireFrame(commandFIN, 1, nil)
	if err := shaper.write(conn, data); err != nil {
		t.Fatal(err)
	}
	if shaper.remaining != 0 {
		t.Fatal("data window did not end")
	}
	if err := shaper.writeControl(conn, control); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes[1]) != 100 || shaper.remaining != 0 {
		t.Fatal("control was not padded independently of data window")
	}
	budget := shaper.budget
	shaper.rearm()
	if shaper.budget != budget || shaper.remaining != 1 {
		t.Fatal("rearm changed the lifetime budget")
	}
	if err := shaper.write(conn, data); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes[2]) != 100 || shaper.remaining != 0 {
		t.Fatal("reused stream was not shaped")
	}
}

func TestLargeFinalWriteHasBoundedPaddedTail(t *testing.T) {
	t.Parallel()
	options := &TrafficShapingOptions{MinRecordSize: 512, MaxRecordSize: 512, MinRecords: 1, MaxRecords: 1, MaxPaddingBytes: 4096}
	shaper := newDownlinkShaper(options)
	conn := &recordingConn{}
	original := wireFrame(commandPSH, 1, bytes.Repeat([]byte{0xa5}, maxFrameSize))
	if err := shaper.write(conn, original); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 2 || len(conn.writes[1]) != 512 || shaper.remaining != 0 {
		t.Fatal("large response was not limited to bulk plus padded tail")
	}
	frames := decodeFrames(t, bytes.Join(conn.writes, nil))
	if len(frames) != 2 || frames[1].command != commandWaste || !bytes.Equal(frames[0].data, original[frameOverhead:]) {
		t.Fatal("padding lost data or was inserted inside a frame")
	}
}

func TestDownlinkShapingShortWrite(t *testing.T) {
	t.Parallel()
	options, _ := normalizeTrafficShaping(&TrafficShapingOptions{})
	if err := newDownlinkShaper(options).write(&recordingConn{short: true}, wireFrame(commandSYNACK, 1, nil)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v, want short write", err)
	}
}

type notifyingConn struct {
	net.Conn
	started chan struct{}
}

func (c *notifyingConn) Write(data []byte) (int, error) {
	close(c.started)
	return c.Conn.Write(data)
}

func TestShapedServerCloseUnblocksWriter(t *testing.T) {
	t.Parallel()
	server, peer := net.Pipe()
	defer peer.Close()
	service, err := NewService("password", ServiceOptions{TrafficShaping: &TrafficShapingOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	conn := &notifyingConn{Conn: server, started: make(chan struct{})}
	session := newServerSession(context.Background(), service, conn, M.Socksaddr{})
	defer session.Close()
	written := make(chan error, 1)
	go func() { written <- session.writeFrame(commandSYNACK, 1, nil) }()
	select {
	case <-conn.started:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not start")
	}
	closed := make(chan struct{})
	go func() {
		session.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind shaped write")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked write unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not unblock")
	}
}

func TestTrafficShapingValidation(t *testing.T) {
	t.Parallel()
	for _, options := range []TrafficShapingOptions{
		{MinRecordSize: -1},
		{MinRecordSize: 6},
		{MaxRecordSize: 16385},
		{MinRecordSize: 1000, MaxRecordSize: 500},
		{MinRecords: -1},
		{MinRecords: 20, MaxRecords: 10},
		{MaxRecords: 257},
		{MaxPaddingBytes: -1},
		{MaxPaddingBytes: 6},
		{MaxPaddingBytes: maxPaddingSize + 1},
	} {
		if _, err := NewService("password", ServiceOptions{TrafficShaping: &options}); err == nil {
			t.Fatalf("accepted invalid options: %+v", options)
		}
	}
}

func TestShapingPolicyAndDefaults(t *testing.T) {
	t.Parallel()
	legacy, err := NewService("password", ServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.trafficShaping != nil || !bytes.Equal(legacy.padding.Load().rawScheme, DefaultPaddingScheme) {
		t.Fatal("legacy defaults changed")
	}
	options := &TrafficShapingOptions{}
	service, err := NewService("password", ServiceOptions{TrafficShaping: options})
	if err != nil {
		t.Fatal(err)
	}
	options.MinRecords = -1 // Configuration is copied, not retained from the caller.
	factory := service.padding.Load()
	if factory.stop < 9 || factory.stop > 17 || bytes.Equal(factory.rawScheme, DefaultPaddingScheme) {
		t.Fatal("unexpected advertised policy")
	}
	for range 100 {
		padding := factory.GenerateHandshakePaddingSize()
		if padding < 64 || padding >= 512 {
			t.Fatalf("handshake padding outside advertised range: %d", padding)
		}
	}
	custom := []byte("stop=2\n0=80-80\n1=200-300")
	service, err = NewService("password", ServiceOptions{TrafficShaping: &TrafficShapingOptions{}, PaddingScheme: custom})
	if err != nil || !bytes.Equal(service.padding.Load().rawScheme, custom) {
		t.Fatal("explicit policy not preserved", err)
	}
}

func TestShapingCoalescesSettings(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"1", "2"} {
		service, err := NewService("password", ServiceOptions{TrafficShaping: &TrafficShapingOptions{MinRecordSize: 1400, MaxRecordSize: 1400}})
		if err != nil {
			t.Fatal(err)
		}
		conn := &recordingConn{}
		session := newServerSession(context.Background(), service, conn, M.Socksaddr{})
		request := settings{settingVersion: version, settingPaddingMD5: "different"}.Bytes()
		session.reader.Reset(bytes.NewReader(request))
		if err := session.handleSettings(len(request)); err != nil {
			t.Fatal(err)
		}
		if len(conn.writes) != 1 || len(conn.writes[0]) != 1400 {
			t.Fatal("settings not coalesced and padded")
		}
		frames := decodeFrames(t, conn.writes[0])
		if frames[0].command != commandUpdatePaddingScheme {
			t.Fatal("missing policy update")
		}
		if version == "2" && frames[1].command != commandServerSettings {
			t.Fatal("missing server settings")
		}
		if version == "1" && frames[1].command != commandWaste {
			t.Fatal("v2 command sent to v1 peer")
		}
		if frames[len(frames)-1].command != commandWaste {
			t.Fatal("missing padding")
		}
	}
}

type countingConn struct {
	net.Conn
	bytes  int64
	writes int64
}

func (c *countingConn) Write(data []byte) (int, error) {
	c.bytes += int64(len(data))
	c.writes++
	return len(data), nil
}

// Each iteration models a new session, including two small control replies and
// four data writes. This measures shaping CPU/allocations and wire overhead, not
// network throughput, TLS cost, or resistance to a traffic classifier.
func BenchmarkDownlinkShaping(b *testing.B) {
	for _, payloadSize := range []int{1024, 32768} {
		for _, enabled := range []bool{false, true} {
			b.Run(fmt.Sprintf("payload=%d/shaping=%t", payloadSize, enabled), func(b *testing.B) {
				options, err := normalizeTrafficShaping(&TrafficShapingOptions{})
				if err != nil {
					b.Fatal(err)
				}
				control := wireFrame(commandSYNACK, 1, nil)
				data := wireFrame(commandPSH, 1, make([]byte, payloadSize))
				frames := [][]byte{control, control, data, data, data, data}
				originalSize := 2*len(control) + 4*len(data)
				conn := &countingConn{}
				b.ReportAllocs()
				for b.Loop() {
					var shaper *downlinkShaper
					if enabled {
						shaper = newDownlinkShaper(options)
					}
					for index, frame := range frames {
						if shaper != nil {
							if index < 2 {
								err = shaper.writeControl(conn, frame)
							} else {
								err = shaper.write(conn, frame)
							}
						} else {
							err = writeFullRecord(conn, frame)
						}
						if err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportMetric(float64(conn.bytes)/float64(b.N)-float64(originalSize), "extra-B/session")
				b.ReportMetric(float64(conn.writes)/float64(b.N), "writes/session")
			})
		}
	}
}
