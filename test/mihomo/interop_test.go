package mihomo_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
)

const password = "mihomo-interop-test-only"

var greeting = []byte("server-first greeting\n")

func TestMihomoSessionAgainstShapedTLSService(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			serverTLS, clientTLS := tlsConfigs(t, version)
			service, err := anytls.NewService(password, anytls.ServiceOptions{
				TrafficShaping: &anytls.TrafficShapingOptions{},
				Handler:        echoHandler{},
			})
			must(t, err)
			server := startService(t, service, serverTLS)
			var policy atomic.Pointer[padding.PaddingFactory]
			if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &policy) {
				t.Fatal("Mihomo rejected its default padding policy")
			}
			initialMD5 := policy.Load().Md5
			var dials atomic.Int32
			client := session.NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
				dials.Add(1)
				dialer := tls.Dialer{Config: clientTLS}
				conn, dialErr := dialer.DialContext(ctx, "tcp", server)
				if dialErr != nil {
					return nil, dialErr
				}
				// This prologue is the wire format used by Mihomo's outer Client.
				// All session framing and policy handling below use Mihomo itself.
				digest := sha256.Sum256([]byte(password))
				var paddingLen int
				if sizes := policy.Load().GenerateRecordPayloadSizes(0); len(sizes) > 0 {
					paddingLen = sizes[0]
				}
				prologue := make([]byte, 34+paddingLen)
				copy(prologue, digest[:])
				binary.BigEndian.PutUint16(prologue[32:34], uint16(paddingLen))
				if _, dialErr = conn.Write(prologue); dialErr != nil {
					conn.Close()
					return nil, dialErr
				}
				return conn, nil
			}, &policy, "mihomo/interop-test", time.Minute, time.Minute, 0, false)
			t.Cleanup(func() { client.Close() })

			// Every reused stream starts with a server-first response, then a large
			// echo followed by small responses, exercising the shaping window.
			for streamIndex := range 3 {
				conn := openStream(t, client)
				readGreeting(t, conn)
				if policy.Load().Md5 == initialMD5 {
					t.Fatal("Mihomo did not install the server padding policy")
				}
				for _, size := range []int{1, 4096, 65536, 17} {
					payload := make([]byte, size)
					for index := range payload {
						payload[index] = byte(index*31 + streamIndex)
					}
					must(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
					_, err = conn.Write(payload)
					must(t, err)
					actual := make([]byte, len(payload))
					_, err = io.ReadFull(conn, actual)
					must(t, err)
					if !bytes.Equal(actual, payload) {
						t.Fatalf("echo changed for stream %d, payload %d", streamIndex, size)
					}
				}
				must(t, conn.Close())
			}
			if got := dials.Load(); got != 1 {
				t.Fatalf("three sequential streams used %d sessions, want one", got)
			}

			// Keeping one stream active forces a second TLS session, now using
			// the policy the real Mihomo reader installed from the first session.
			first := openStream(t, client)
			readGreeting(t, first)
			second := openStream(t, client)
			readGreeting(t, second)
			must(t, second.Close())
			must(t, first.Close())
			if got := dials.Load(); got != 2 {
				t.Fatalf("parallel streams used %d sessions, want two", got)
			}
		})
	}
}

func openStream(t *testing.T, client *session.Client) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.CreateStream(ctx)
	must(t, err)
	t.Cleanup(func() { conn.Close() })
	must(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	must(t, M.SocksaddrSerializer.WriteAddrPort(conn, M.ParseSocksaddr("example.com:443")))
	return conn
}

func readGreeting(t *testing.T, conn net.Conn) {
	t.Helper()
	actual := make([]byte, len(greeting))
	_, err := io.ReadFull(conn, actual)
	must(t, err)
	if !bytes.Equal(actual, greeting) {
		t.Fatalf("server-first greeting changed: %q", actual)
	}
}

type echoHandler struct{}

func (echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if err := N.ReportConnHandshakeSuccess(conn, conn); err != nil {
		return
	}
	if _, err := conn.Write(greeting); err != nil {
		return
	}
	_, err := io.Copy(conn, conn)
	if onClose != nil {
		onClose(err)
	}
}

func startService(t *testing.T, service *anytls.Service, config *tls.Config) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	must(t, err)
	var sessions sync.WaitGroup
	var access sync.Mutex
	connections := make(map[net.Conn]struct{})
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			access.Lock()
			connections[conn] = struct{}{}
			access.Unlock()
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				defer conn.Close()
				defer func() {
					access.Lock()
					delete(connections, conn)
					access.Unlock()
				}()
				_ = service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-accepted
		access.Lock()
		for conn := range connections {
			conn.Close()
		}
		access.Unlock()
		sessions.Wait()
	})
	return listener.Addr().String()
}

func tlsConfigs(t *testing.T, version uint16) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(t, err)
	certificate, err := x509.ParseCertificate(der)
	must(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	serverConfig := &tls.Config{
		MinVersion:   version,
		MaxVersion:   version,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	clientConfig := &tls.Config{
		MinVersion: version,
		MaxVersion: version,
		RootCAs:    pool,
		ServerName: "localhost",
	}
	return serverConfig, clientConfig
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
