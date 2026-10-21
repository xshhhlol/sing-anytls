// Package realclient observes AnyTLS connections at the TLS record layer, as a
// passive on-path observer would, and drives real client binaries in tests.
package realclient

import (
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

// Direction is relative to the proxy client.
type Direction int8

const (
	Upload   Direction = 1
	Download Direction = -1
)

func (d Direction) String() string {
	if d == Upload {
		return "up"
	}
	return "down"
}

const (
	RecordTypeChangeCipherSpec = 20
	RecordTypeAlert            = 21
	RecordTypeHandshake        = 22
	RecordTypeApplicationData  = 23

	recordHeaderLen = 5
)

// Record is one TLS record as seen on the wire. Length excludes the 5-byte
// record header. Time is when the record's first byte was observed, relative
// to the start of its connection.
type Record struct {
	Direction Direction     `json:"dir"`
	Type      byte          `json:"type"`
	Length    int           `json:"len"`
	Time      time.Duration `json:"t"`
}

// Trace holds the TLS records of one TCP connection. TCP byte counts include
// data that did not parse as TLS.
type Trace struct {
	Label     string    `json:"label,omitempty"`
	Start     time.Time `json:"start"`
	Records   []Record  `json:"records"`
	TCPUp     int64     `json:"tcp_up"`
	TCPDown   int64     `json:"tcp_down"`
	Malformed bool      `json:"malformed,omitempty"`
}

// recordParser splits one direction of a byte stream into TLS records without
// buffering record payloads.
type recordParser struct {
	direction Direction
	header    [recordHeaderLen]byte
	headerLen int
	remaining int
	current   Record
	failed    bool
}

func (p *recordParser) feed(data []byte, at time.Duration, emit func(Record)) {
	for len(data) > 0 && !p.failed {
		if p.remaining > 0 {
			n := min(p.remaining, len(data))
			p.remaining -= n
			data = data[n:]
			if p.remaining == 0 {
				emit(p.current)
			}
			continue
		}
		if p.headerLen == 0 {
			p.current.Time = at
		}
		n := copy(p.header[p.headerLen:], data)
		p.headerLen += n
		data = data[n:]
		if p.headerLen < recordHeaderLen {
			return
		}
		p.headerLen = 0
		recordType := p.header[0]
		if recordType < RecordTypeChangeCipherSpec || recordType > RecordTypeApplicationData || p.header[1] != 3 {
			p.failed = true
			return
		}
		p.current = Record{
			Direction: p.direction,
			Type:      recordType,
			Length:    int(binary.BigEndian.Uint16(p.header[3:])),
			Time:      p.current.Time,
		}
		p.remaining = p.current.Length
		if p.remaining == 0 {
			emit(p.current)
		}
	}
}

// incomplete reports whether the stream stopped inside a record header or payload.
func (p *recordParser) incomplete() bool {
	return p.headerLen > 0 || p.remaining > 0
}

// traceRecorder accumulates both directions of a connection. It is safe for
// concurrent use by one goroutine per direction.
type traceRecorder struct {
	access   sync.Mutex
	trace    Trace
	upload   recordParser
	download recordParser
}

func newTraceRecorder(label string, start time.Time) *traceRecorder {
	return &traceRecorder{
		trace:    Trace{Label: label, Start: start},
		upload:   recordParser{direction: Upload},
		download: recordParser{direction: Download},
	}
}

func (r *traceRecorder) observe(direction Direction, data []byte, at time.Time) {
	r.access.Lock()
	defer r.access.Unlock()
	parser := &r.download
	if direction == Upload {
		parser = &r.upload
		r.trace.TCPUp += int64(len(data))
	} else {
		r.trace.TCPDown += int64(len(data))
	}
	parser.feed(data, at.Sub(r.trace.Start), func(record Record) {
		r.trace.Records = append(r.trace.Records, record)
	})
	if parser.failed {
		r.trace.Malformed = true
	}
}

func (r *traceRecorder) markMalformed() {
	r.access.Lock()
	r.trace.Malformed = true
	r.access.Unlock()
}

// finish marks the trace malformed if either direction ended inside a record.
// Call it only after the stream has ended: a live connection is often mid-record.
func (r *traceRecorder) finish() {
	r.access.Lock()
	if r.upload.incomplete() || r.download.incomplete() {
		r.trace.Malformed = true
	}
	r.access.Unlock()
}

func (r *traceRecorder) snapshot() Trace {
	r.access.Lock()
	defer r.access.Unlock()
	trace := r.trace
	trace.Records = append([]Record(nil), r.trace.Records...)
	// Records are emitted when complete; order them by first observed byte.
	sort.SliceStable(trace.Records, func(i, j int) bool {
		return trace.Records[i].Time < trace.Records[j].Time
	})
	return trace
}

// Window returns the records observed in [from, to). A zero to means no end.
func (t Trace) Window(from, to time.Duration) Trace {
	window := t
	window.Records = nil
	for _, record := range t.Records {
		if record.Time >= from && (to == 0 || record.Time < to) {
			window.Records = append(window.Records, record)
		}
	}
	return window
}
