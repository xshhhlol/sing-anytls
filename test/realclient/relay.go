package realclient

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Relay is a recording TCP forwarder between a client and a server. Each
// accepted connection becomes one Trace.
type Relay struct {
	listener  net.Listener
	target    string
	access    sync.Mutex
	label     string
	recorders []*traceRecorder
	active    map[*relayConn]struct{}
}

type relayConn struct {
	client net.Conn
	server net.Conn
}

func NewRelay(target string) (*Relay, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	relay := &Relay{
		listener: listener,
		target:   target,
		active:   make(map[*relayConn]struct{}),
	}
	go relay.serve()
	return relay, nil
}

func (r *Relay) Addr() string {
	return r.listener.Addr().String()
}

// SetLabel labels connections accepted from now on.
func (r *Relay) SetLabel(label string) {
	r.access.Lock()
	r.label = label
	r.access.Unlock()
}

// Traces returns the connections accepted since the last Reset, in accept order.
func (r *Relay) Traces() []Trace {
	r.access.Lock()
	recorders := append([]*traceRecorder(nil), r.recorders...)
	r.access.Unlock()
	traces := make([]Trace, len(recorders))
	for index, recorder := range recorders {
		traces[index] = recorder.snapshot()
	}
	return traces
}

// Accepted returns the number of connections accepted since the last Reset.
func (r *Relay) Accepted() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.recorders)
}

// Reset forgets recorded connections. Open connections keep forwarding.
func (r *Relay) Reset() {
	r.access.Lock()
	r.recorders = nil
	r.access.Unlock()
}

// DropAll aborts every open connection with a TCP reset in both directions,
// as an abrupt network failure would.
func (r *Relay) DropAll() {
	r.access.Lock()
	active := make([]*relayConn, 0, len(r.active))
	for conn := range r.active {
		active = append(active, conn)
	}
	r.access.Unlock()
	for _, conn := range active {
		abort(conn.client)
		abort(conn.server)
	}
}

func (r *Relay) Close() error {
	err := r.listener.Close()
	r.DropAll()
	return err
}

func (r *Relay) serve() {
	for {
		client, err := r.listener.Accept()
		if err != nil {
			return
		}
		go r.handle(client)
	}
}

func (r *Relay) handle(client net.Conn) {
	start := time.Now()
	r.access.Lock()
	recorder := newTraceRecorder(r.label, start)
	r.recorders = append(r.recorders, recorder)
	r.access.Unlock()
	server, err := net.DialTimeout("tcp", r.target, 5*time.Second)
	if err != nil {
		recorder.markMalformed()
		abort(client)
		return
	}
	conn := &relayConn{client: client, server: server}
	r.access.Lock()
	r.active[conn] = struct{}{}
	r.access.Unlock()
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		relayCopy(server, client, recorder, Upload)
	}()
	go func() {
		defer wait.Done()
		relayCopy(client, server, recorder, Download)
	}()
	wait.Wait()
	client.Close()
	server.Close()
	r.access.Lock()
	delete(r.active, conn)
	r.access.Unlock()
}

func relayCopy(destination, source net.Conn, recorder *traceRecorder, direction Direction) {
	buffer := make([]byte, 64*1024)
	for {
		n, err := source.Read(buffer)
		if n > 0 {
			recorder.observe(direction, buffer[:n], time.Now())
			if _, writeErr := destination.Write(buffer[:n]); writeErr != nil {
				abort(source)
				abort(destination)
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if tcpConn, isTCP := destination.(*net.TCPConn); isTCP {
					tcpConn.CloseWrite()
					return
				}
			}
			abort(source)
			abort(destination)
			return
		}
	}
}

func abort(conn net.Conn) {
	if tcpConn, isTCP := conn.(*net.TCPConn); isTCP {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}
