package anytls

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// TrafficShapingOptions enables bounded server-side traffic shaping using only
// existing AnyTLS v1/v2 frames. A nil option preserves the legacy wire behavior.
// Zero fields select defaults. Sizes describe writes to the supplied connection,
// not TCP packets or guaranteed TLS record sizes.
type TrafficShapingOptions struct {
	MinRecordSize   int // Default: 256 bytes, including AnyTLS frame headers.
	MaxRecordSize   int // Default: 1400 bytes; maximum: 16384.
	MinRecords      int // Default: 8 shaped data writes per stream-opening window.
	MaxRecords      int // Default: 16; sampled for each window; maximum: 256.
	MaxPaddingBytes int // Default: 16384 added bytes per session, including headers.
}

func normalizeTrafficShaping(options *TrafficShapingOptions) (*TrafficShapingOptions, error) {
	if options == nil {
		return nil, nil
	}
	value := *options
	if value.MinRecordSize == 0 {
		value.MinRecordSize = 256
	}
	if value.MaxRecordSize == 0 {
		value.MaxRecordSize = 1400
	}
	if value.MinRecords == 0 {
		value.MinRecords = 8
	}
	if value.MaxRecords == 0 {
		value.MaxRecords = 16
	}
	if value.MaxPaddingBytes == 0 {
		value.MaxPaddingBytes = 16384
	}
	if value.MinRecordSize < frameOverhead || value.MaxRecordSize < value.MinRecordSize || value.MaxRecordSize > 16384 {
		return nil, E.New("anytls: invalid traffic shaping record size range")
	}
	if value.MinRecords < 1 || value.MaxRecords < value.MinRecords || value.MaxRecords > 256 {
		return nil, E.New("anytls: invalid traffic shaping record count range")
	}
	if value.MaxPaddingBytes < frameOverhead || value.MaxPaddingBytes > maxPaddingSize {
		return nil, E.New("anytls: invalid traffic shaping padding budget")
	}
	return &value, nil
}

func randomBetween(minimum, maximum int) int {
	if minimum == maximum {
		return minimum
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum-minimum+1)))
	if err != nil {
		// crypto/rand failure is not safely recoverable on supported Go versions.
		panic(err)
	}
	return minimum + int(value.Int64())
}

// Generate once per service, rather than once per connection: repeatedly changing
// the advertised policy would make clients keep exchanging update frames. This is
// an alternative to the shared legacy template, not a model of browser traffic.
func (o *TrafficShapingOptions) clientPaddingScheme() []byte {
	var scheme strings.Builder
	count := randomBetween(o.MinRecords, o.MaxRecords)
	fmt.Fprintf(&scheme, "stop=%d\n0=64-512", count+1)
	for packet := 1; packet <= count; packet++ {
		// If data remains after the first target, cover a larger handshake-sized
		// remainder. The final small target deliberately has no preceding "c":
		// when the larger target consumes the remainder, it adds an independent
		// WASTE record instead of exposing an exact application-length tail.
		// This is bounded, not a guarantee for arbitrarily large client writes.
		fmt.Fprintf(&scheme, "\n%d=%d-%d,c,4096-8192,64-256", packet, o.MinRecordSize, o.MaxRecordSize)
	}
	return []byte(scheme.String())
}

type downlinkShaper struct {
	options   TrafficShapingOptions
	remaining int
	budget    int
}

func newDownlinkShaper(options *TrafficShapingOptions) *downlinkShaper {
	if options == nil {
		return nil
	}
	return &downlinkShaper{
		options:   *options,
		remaining: randomBetween(options.MinRecords, options.MaxRecords),
		budget:    options.MaxPaddingBytes,
	}
}

// rearm starts a data window for a newly accepted stream. The caller holds the
// session write lock. The lifetime padding budget is deliberately not replenished.
func (s *downlinkShaper) rearm() {
	s.remaining = randomBetween(s.options.MinRecords, s.options.MaxRecords)
}

// write is called under the session write lock. Input ends on a frame boundary.
// Splitting a frame across writes is legal; inserting WASTE inside one is not.
// No timer or queue is used: server-first streams, deadlines and Close remain
// independent of future application writes.
func (s *downlinkShaper) write(conn net.Conn, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if s.remaining == 0 {
		return writeFullRecord(conn, data)
	}
	s.remaining--
	return s.writeShaped(conn, data)
}

// Control replies remain eligible after the data window, but use the same
// lifetime byte budget. They do not consume the next stream's data window.
func (s *downlinkShaper) writeControl(conn net.Conn, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return s.writeShaped(conn, data)
}

func (s *downlinkShaper) writeShaped(conn net.Conn, data []byte) error {
	if s.budget < frameOverhead {
		return writeFullRecord(conn, data)
	}
	minimum := max(s.options.MinRecordSize, len(data)+frameOverhead)
	maximum := min(s.options.MaxRecordSize, len(data)+s.budget)
	if minimum <= maximum {
		// Sample from the feasible interval instead of clamping a larger sample
		// to the exact remaining budget, which creates a repeated endpoint.
		size := randomBetween(minimum, maximum)
		return s.writePadded(conn, data, size-len(data))
	}
	if len(data)+frameOverhead <= s.options.MaxRecordSize || s.options.MaxRecordSize <= frameOverhead {
		// A small write cannot reach the minimum target with this budget. Leave
		// the budget for a future feasible write, rather than emit a fixed tail.
		return writeFullRecord(conn, data)
	}
	// Keep a bounded suffix and pad it, leaving the bulk as a single write. This
	// avoids consuming the entire window in a burst of small fragments and keeps
	// the last fragment shaped even on the window's final logical write. Both
	// fragments together end at the original frame boundary before WASTE.
	size := randomBetween(max(s.options.MinRecordSize, frameOverhead+1), s.options.MaxRecordSize)
	extra := randomBetween(frameOverhead, min(s.budget, size-1))
	tailSize := size - extra
	if tailSize >= len(data) {
		// Near the upper record limit, constrain the sample to leave a nonempty
		// prefix. There is still no padding inserted inside an AnyTLS frame.
		extra = randomBetween(max(frameOverhead, size-len(data)+1), min(s.budget, size-1))
		tailSize = size - extra
	}
	if err := writeFullRecord(conn, data[:len(data)-tailSize]); err != nil {
		return err
	}
	return s.writePadded(conn, data[len(data)-tailSize:], extra)
}

func (s *downlinkShaper) writePadded(conn net.Conn, tail []byte, extra int) error {
	record := make([]byte, len(tail)+extra)
	copy(record, tail)
	putFrameHeader(record[len(tail):], commandWaste, 0, extra-frameOverhead)
	s.budget -= extra
	return writeFullRecord(conn, record)
}

func writeFullRecord(conn net.Conn, data []byte) error {
	n, err := conn.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
