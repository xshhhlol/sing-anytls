package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	upstream "github.com/anytls/sing-anytls"
	"github.com/stretchr/testify/require"
)

func TestUpstreamClientAgainstShapedService(t *testing.T) {
	t.Parallel()
	for _, scheme := range [][]byte{nil, customPaddingScheme} {
		service, err := anytls.NewService(testPassword, anytls.ServiceOptions{
			TrafficShaping: &anytls.TrafficShapingOptions{},
			PaddingScheme:  scheme,
			Handler:        proxyHandler{},
		})
		require.NoError(t, err)
		client := newUpstreamClient(t, startService(t, service))
		echoScenario(t, client.CreateProxy, startTCPEcho(t))
	}
}

func TestLocalClientAgainstShapedService(t *testing.T) {
	t.Parallel()
	service, err := anytls.NewMultiService[string](anytls.ServiceOptions{
		TrafficShaping: &anytls.TrafficShapingOptions{},
		Handler:        proxyHandler{},
	})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers([]string{"test"}, []string{testPassword}))
	client := newClient(t, startService(t, service))
	echoScenario(t, client.DialContext, startTCPEcho(t))
}

func TestShapedServiceServerFirstAndClose(t *testing.T) {
	t.Parallel()
	payload := []byte("server-first greeting")
	service, err := anytls.NewService(testPassword, anytls.ServiceOptions{
		TrafficShaping: &anytls.TrafficShapingOptions{},
		Handler:        burstHandler{payload: payload},
	})
	require.NoError(t, err)
	client := newUpstreamClient(t, startService(t, service))
	conn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	got, err := io.ReadAll(conn)
	// The reference client reports peer FIN as net.ErrClosed rather than EOF.
	require.ErrorIs(t, err, net.ErrClosed)
	require.Equal(t, payload, got)
}

func TestShapedServiceFallbackUnchanged(t *testing.T) {
	t.Parallel()
	service, err := anytls.NewService(testPassword, anytls.ServiceOptions{
		TrafficShaping:  &anytls.TrafficShapingOptions{},
		Handler:         proxyHandler{},
		FallbackHandler: echoHandler{},
	})
	require.NoError(t, err)
	conn, err := net.Dial("tcp", startService(t, service).String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	require.NoError(t, err)
	response := make([]byte, len("fallback"))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, "fallback", string(response))
}

func TestUpstreamClientAgainstShapedTLSService(t *testing.T) {
	t.Parallel()
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			t.Parallel()
			serverTLS, clientTLS := shapingTLSConfigs(t, version)
			service, err := anytls.NewService(testPassword, anytls.ServiceOptions{
				TrafficShaping: &anytls.TrafficShapingOptions{},
				Handler:        proxyHandler{},
			})
			require.NoError(t, err)
			server := startService(t, &tlsService{service: service, config: serverTLS})
			client, err := upstream.NewClient(context.Background(), upstream.ClientConfig{
				Password: testPassword,
				DialOut: func(ctx context.Context) (net.Conn, error) {
					dialer := tls.Dialer{Config: clientTLS}
					return dialer.DialContext(ctx, "tcp", server.String())
				},
				Logger: testLogger("tls-client: "),
			})
			require.NoError(t, err)
			t.Cleanup(func() { client.Close() })
			echoScenario(t, client.CreateProxy, startTCPEcho(t))
		})
	}
}

type tlsService struct {
	service connectionService
	config  *tls.Config
}

func (s *tlsService) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	secured := tls.Server(conn, s.config)
	if err := secured.HandshakeContext(ctx); err != nil {
		conn.Close()
		return err
	}
	return s.service.NewConnection(ctx, secured, source, onClose)
}

func shapingTLSConfigs(t *testing.T, version uint16) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
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
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
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
