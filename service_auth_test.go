package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type authFallbackFunc func(net.Conn)

func (f authFallbackFunc) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	f(conn)
}

func awaitAuthenticationResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("authentication did not finish")
		return nil
	}
}

func authenticationRequest(password string, padding []byte) []byte {
	digest := sha256.Sum256([]byte(password))
	request := append([]byte(nil), digest[:]...)
	request = binary.BigEndian.AppendUint16(request, uint16(len(padding)))
	return append(request, padding...)
}

func exchangeAuthenticationHeartbeat(t *testing.T, peer net.Conn) {
	t.Helper()
	if _, err := peer.Write(wireFrame(commandHeartRequest, 17, nil)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, frameOverhead)
	if _, err := io.ReadFull(peer, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, wireFrame(commandHeartResponse, 17, nil)) {
		t.Fatalf("unexpected heartbeat response: %x", response)
	}
}

func TestAuthenticationAcceptsFragmentedVerifierAndPadding(t *testing.T) {
	t.Parallel()
	service, err := NewService("password", ServiceOptions{HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	server, peer := net.Pipe()
	defer peer.Close()
	defer server.Close()
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), server, M.Socksaddr{}, nil) }()
	for _, value := range authenticationRequest("password", []byte("padding")) {
		if _, err := peer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	exchangeAuthenticationHeartbeat(t, peer)
	peer.Close()
	if err := awaitAuthenticationResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationDeadlineAndCancellationDoNotLeakIntoSession(t *testing.T) {
	t.Parallel()
	timeout := 40 * time.Millisecond
	service, err := NewService("password", ServiceOptions{HandshakeTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	server, peer := net.Pipe()
	defer peer.Close()
	defer server.Close()
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, server, M.Socksaddr{}, nil) }()
	if _, err := peer.Write(authenticationRequest("password", nil)); err != nil {
		t.Fatal(err)
	}
	exchangeAuthenticationHeartbeat(t, peer)
	cancel()
	<-time.After(2 * timeout)
	exchangeAuthenticationHeartbeat(t, peer)
	peer.Close()
	if err := awaitAuthenticationResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationTimeoutBoundsEmptyPartialAndPaddingReads(t *testing.T) {
	t.Parallel()
	request := authenticationRequest("password", nil)
	paddingRequest := bytes.Clone(request)
	binary.BigEndian.PutUint16(paddingRequest[passwordLen:], 1024)
	for name, payload := range map[string][]byte{
		"empty":          nil,
		"partial-digest": request[:5],
		"padding-length": request[:passwordLen+1],
		"padding-body":   append(paddingRequest, 1, 2, 3),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			service, err := NewService("password", ServiceOptions{HandshakeTimeout: 40 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			server, peer := net.Pipe()
			defer server.Close()
			defer peer.Close()
			result := make(chan error, 1)
			go func() { result <- service.NewConnection(context.Background(), server, M.Socksaddr{}, nil) }()
			if len(payload) > 0 {
				peer.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := peer.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := awaitAuthenticationResult(t, result); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("got %v, want deadline exceeded", err)
			}
		})
	}
}

func TestAuthenticationContextCancellation(t *testing.T) {
	t.Parallel()
	for _, payload := range [][]byte{nil, authenticationRequest("password", []byte("unread padding"))[:passwordLen+2]} {
		service, err := NewService("password", ServiceOptions{})
		if err != nil {
			t.Fatal(err)
		}
		server, peer := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- service.NewConnection(ctx, server, M.Socksaddr{}, nil) }()
		if len(payload) > 0 {
			peer.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := peer.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		cancel()
		if err := awaitAuthenticationResult(t, result); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context canceled", err)
		}
		peer.Close()
		server.Close()
	}
}

func TestAuthenticationFallbackReplaysBytesAndClearsDeadline(t *testing.T) {
	t.Parallel()
	for _, initial := range [][]byte{[]byte("GET /\r\n"), bytes.Repeat([]byte{0xab}, passwordLen+9)} {
		t.Run(strconv.Itoa(len(initial)), func(t *testing.T) {
			t.Parallel()
			started := make(chan struct{})
			received := make(chan []byte, 1)
			suffix := []byte("new bytes after fallback")
			service, err := NewService("password", ServiceOptions{
				HandshakeTimeout: 40 * time.Millisecond,
				FallbackHandler: authFallbackFunc(func(conn net.Conn) {
					defer conn.Close()
					payload := make([]byte, len(initial)+len(suffix))
					close(started)
					_, readErr := io.ReadFull(conn, payload)
					if readErr != nil {
						received <- nil
						return
					}
					received <- payload
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			server, peer := net.Pipe()
			defer server.Close()
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			result := make(chan error, 1)
			go func() { result <- service.NewConnection(context.Background(), server, M.Socksaddr{}, nil) }()
			if _, err := peer.Write(initial); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("fallback was not called")
			}
			if _, err := peer.Write(suffix); err != nil {
				t.Fatal(err)
			}
			if err := awaitAuthenticationResult(t, result); err != nil {
				t.Fatal(err)
			}
			if got := <-received; !bytes.Equal(got, append(bytes.Clone(initial), suffix...)) {
				t.Fatalf("fallback received %q", got)
			}
		})
	}
}

type authenticationEOFConn struct {
	net.Conn
	data     []byte
	deadline time.Time
}

func (c *authenticationEOFConn) Read(p []byte) (int, error) {
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, io.EOF
}

func (c *authenticationEOFConn) SetReadDeadline(deadline time.Time) error {
	c.deadline = deadline
	return nil
}

func (c *authenticationEOFConn) Close() error { return nil }

func TestAuthenticationFallbackPreservesDataReadWithEOF(t *testing.T) {
	t.Parallel()
	for _, initial := range [][]byte{[]byte("short request"), bytes.Repeat([]byte{0xab}, passwordLen)} {
		conn := &authenticationEOFConn{data: bytes.Clone(initial)}
		var got []byte
		service, err := NewService("password", ServiceOptions{FallbackHandler: authFallbackFunc(func(conn net.Conn) {
			defer conn.Close()
			got, _ = io.ReadAll(conn)
		})})
		if err != nil {
			t.Fatal(err)
		}
		if err := service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, initial) || !conn.deadline.IsZero() {
			t.Fatalf("fallback lost bytes or deadline leaked: got %q, deadline %v", got, conn.deadline)
		}
	}
}

func TestAuthenticationOptionsAndAtomicUserValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewService("password", ServiceOptions{HandshakeTimeout: -time.Second}); err == nil {
		t.Fatal("negative handshake timeout accepted")
	}
	service, err := NewMultiService[string](ServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if service.handshakeTimeout != 10*time.Second {
		t.Fatal("unexpected default handshake timeout")
	}
	if err := service.UpdateUsers([]string{"alice"}, []string{"password"}); err != nil {
		t.Fatal(err)
	}
	for _, passwords := range [][]string{nil, {"password", "other-password"}} {
		if err := service.UpdateUsers([]string{"bob"}, passwords); err == nil {
			t.Fatal("mismatched users and passwords accepted")
		}
		users := service.users.Load()
		if len(users) != 1 || users[sha256.Sum256([]byte("password"))] != "alice" {
			t.Fatal("invalid update changed the user map")
		}
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				service.UpdateUsers([]string{"alice"}, []string{"password"})
				_ = service.users.Load()[sha256.Sum256([]byte("password"))]
			}
		}()
	}
	workers.Wait()
}

func TestAuthenticationShortTextRequestFallsBackImmediately(t *testing.T) {
	t.Parallel()
	for _, payload := range []string{"hello\r\n", "GET / HTTP/1.0\r\n\r\n", "GET / HTTP/1.1\r\n"} {
		t.Run(strconv.Quote(payload), func(t *testing.T) {
			t.Parallel()
			got := make(chan []byte, 1)
			service, err := NewService("password", ServiceOptions{
				HandshakeTimeout: 10 * time.Second,
				FallbackHandler: authFallbackFunc(func(conn net.Conn) {
					defer conn.Close()
					data := make([]byte, len(payload))
					io.ReadFull(conn, data)
					got <- data
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			server, peer := net.Pipe()
			defer peer.Close()
			go service.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
			peer.SetDeadline(time.Now().Add(time.Second))
			if _, err := peer.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			select {
			case data := <-got:
				if string(data) != payload {
					t.Fatalf("fallback got %q", data)
				}
			case <-time.After(time.Second):
				t.Fatal("short text request waited for the handshake timeout")
			}
		})
	}
}

func TestAuthenticationShortNonTextWaits(t *testing.T) {
	t.Parallel()
	for _, payload := range [][]byte{[]byte("hi\n"), {0x5e, 0x88, 0x48, '\n'}, []byte("GET / HTTP/1.1")} {
		service, err := NewService("password", ServiceOptions{HandshakeTimeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		server, peer := net.Pipe()
		result := make(chan error, 1)
		go func() { result <- service.NewConnection(context.Background(), server, M.Socksaddr{}, nil) }()
		peer.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := peer.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := awaitAuthenticationResult(t, result); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%q: got %v, want deadline exceeded", payload, err)
		}
		peer.Close()
	}
}

func TestIsTextRequestLine(t *testing.T) {
	for data, want := range map[string]bool{
		"hello\r\n":           true,
		"GET / HTTP/1.0\r\n":  true,
		"abc\n":               true,
		"ab\r\n":              false,
		"\r\n":                false,
		"GET / HTTP/1.1":      false,
		"GE\x00 / HTTP/1.1\n": false,
		"\x16\x03\x01abc\n":   false,
	} {
		if got := isTextRequestLine([]byte(data)); got != want {
			t.Errorf("%q: got %v, want %v", data, got, want)
		}
	}
}
