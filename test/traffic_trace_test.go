package test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	upstream "github.com/anytls/sing-anytls"
	"github.com/stretchr/testify/require"
)

// Capture both the plaintext conn.Write boundaries and actual encrypted TLS
// records. This detects changes that disappear or create small tails in TLS.
type traceConn struct {
	net.Conn
	access sync.Mutex
	bytes  []byte
	writes []int
}

func (c *traceConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.access.Lock()
	c.bytes = append(c.bytes, data[:n]...)
	c.writes = append(c.writes, n)
	c.access.Unlock()
	return n, err
}

func (c *traceConn) reset() {
	c.access.Lock()
	c.bytes = nil
	c.writes = nil
	c.access.Unlock()
}

func (c *traceConn) snapshot() ([]byte, []int) {
	c.access.Lock()
	defer c.access.Unlock()
	return append([]byte(nil), c.bytes...), append([]int(nil), c.writes...)
}

type tracePair struct{ wire, plaintext *traceConn }

type traceTLSService struct {
	service connectionService
	config  *tls.Config
	started chan tracePair
}

func (s *traceTLSService) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	wire := &traceConn{Conn: conn}
	secured := tls.Server(wire, s.config)
	if err := secured.HandshakeContext(ctx); err != nil {
		conn.Close()
		return err
	}
	wire.reset()
	plaintext := &traceConn{Conn: secured}
	s.started <- tracePair{wire: wire, plaintext: plaintext}
	return s.service.NewConnection(ctx, plaintext, source, onClose)
}

type traceBurstHandler struct {
	payload []byte
	closed  chan struct{}
}

func (h traceBurstHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer func() {
		conn.Close()
		h.closed <- struct{}{}
	}()
	if N.ReportConnHandshakeSuccess(conn, conn) == nil {
		conn.Write(h.payload)
	}
}

func tlsRecordSizes(t *testing.T, wire []byte) []int {
	t.Helper()
	var sizes []int
	for len(wire) > 0 {
		require.GreaterOrEqual(t, len(wire), 5)
		size := int(binary.BigEndian.Uint16(wire[3:5]))
		require.GreaterOrEqual(t, len(wire), 5+size)
		if wire[0] == 23 {
			sizes = append(sizes, size)
		}
		wire = wire[5+size:]
	}
	return sizes
}

func TestTLSRecordTraceAcrossReusedStreams(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		name := "legacy"
		if enabled {
			name = "shaped"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			serverTLS, clientTLS := shapingTLSConfigs(t, tls.VersionTLS13)
			serverTLS.SessionTicketsDisabled = true
			serverTLS.DynamicRecordSizingDisabled = true
			payload := make([]byte, 32768)
			closed := make(chan struct{}, 2)
			options := anytls.ServiceOptions{
				Handler:       traceBurstHandler{payload: payload, closed: closed},
				PaddingScheme: anytls.DefaultPaddingScheme,
			}
			if enabled {
				// A one-write window must reopen for the second stream. Control
				// frames must remain padded even after application data uses it.
				options.TrafficShaping = &anytls.TrafficShapingOptions{MinRecords: 1, MaxRecords: 1}
			}
			service, err := anytls.NewService(testPassword, options)
			require.NoError(t, err)
			started := make(chan tracePair, 3)
			address := startService(t, &traceTLSService{service: service, config: serverTLS, started: started})
			client, err := upstream.NewClient(context.Background(), upstream.ClientConfig{
				Password: testPassword,
				DialOut: func(ctx context.Context) (net.Conn, error) {
					return (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", address.String())
				},
				Logger: testLogger("trace: "),
			})
			require.NoError(t, err)
			t.Cleanup(func() { client.Close() })
			var trace tracePair
			var previousWrites int
			for stream := range 2 {
				conn, dialErr := client.CreateProxy(context.Background(), M.ParseSocksaddr("example.com:443"))
				require.NoError(t, dialErr)
				require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
				got, readErr := io.ReadAll(conn)
				require.ErrorIs(t, readErr, net.ErrClosed)
				require.Equal(t, payload, got)
				conn.Close()
				select {
				case <-closed:
				case <-time.After(5 * time.Second):
					t.Fatal("server stream did not close")
				}
				if stream == 0 {
					trace = <-started
				} else {
					select {
					case <-started:
						t.Fatal("client did not reuse the original TLS session")
					default:
					}
				}
				wire, _ := trace.wire.snapshot()
				_, writes := trace.plaintext.snapshot()
				sizes := tlsRecordSizes(t, wire)
				require.NotEmpty(t, sizes)
				require.NotEmpty(t, writes)
				lastWrite := writes[len(writes)-1]
				// TLS 1.3 adds one content-type byte and a 16-byte AEAD tag.
				require.Equal(t, lastWrite+17, sizes[len(sizes)-1])
				if enabled {
					require.GreaterOrEqual(t, lastWrite, 256, "FIN was exposed after the data window")
					if stream == 1 {
						// SYNACK + two application writes + FIN. This proves the
						// second stream reopened the expired data window.
						require.Len(t, writes[previousWrites:], 4)
					}
				} else {
					require.Equal(t, 7, lastWrite)
				}
				t.Logf("stream=%d plaintext-writes=%v TLS-record-payloads=%v", stream+1, writes[previousWrites:], sizes)
				previousWrites = len(writes)
			}
		})
	}
}
