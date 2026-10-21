package realclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	serverName       = "anytls.test"
	originName       = "origin.test"
	password         = "realclient-password"
	pageSize         = 3072
	bannerMessage    = "server-first-banner\n"
	handshakeTimeout = 3 * time.Second
)

// Binaries are looked up in REALCLIENT_BIN, by default ./bin, as written by
// build.sh. Missing binaries skip the tests that need them.
const (
	binarySingBox       = "sing-box"
	binarySingBoxLegacy = "sing-box-legacy"
	binaryMihomo        = "mihomo"
	binaryAnyTLSClient  = "anytls-client"
)

func binaryDir() string {
	if dir := os.Getenv("REALCLIENT_BIN"); dir != "" {
		return dir
	}
	dir, _ := filepath.Abs("bin")
	return dir
}

func findBinary(name string) string {
	path := filepath.Join(binaryDir(), name)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	return ""
}

// outputDir holds logs and reports. REALCLIENT_OUT keeps them after the test.
func outputDir(t testing.TB) string {
	if dir := os.Getenv("REALCLIENT_OUT"); dir != "" {
		dir, err := filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	return t.TempDir()
}

type certificates struct {
	pool          *x509.CertPool
	caPath        string
	serverCert    string
	serverKey     string
	serverLeaf    []byte
	origin        tls.Certificate
	originPoolTLS *tls.Config
}

func newTestCertificate(t testing.TB) (tls.Certificate, *x509.CertPool) {
	caCert, caKey := newCA(t)
	certificate, _ := issue(t, caCert, caKey, "localhost")
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return certificate, pool
}

func newCA(t testing.TB) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "realclient test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func issue(t testing.TB, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, name string) (tls.Certificate, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, der
}

func newCertificates(t testing.TB, dir string) *certificates {
	caCert, caKey := newCA(t)
	server, serverDER := issue(t, caCert, caKey, serverName)
	origin, _ := issue(t, caCert, caKey, originName)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	keyDER, err := x509.MarshalPKCS8PrivateKey(server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certs := &certificates{
		pool:          pool,
		caPath:        filepath.Join(dir, "ca.pem"),
		serverCert:    filepath.Join(dir, "server.pem"),
		serverKey:     filepath.Join(dir, "server.key"),
		serverLeaf:    serverDER,
		origin:        origin,
		originPoolTLS: &tls.Config{RootCAs: pool, ServerName: originName},
	}
	writeFile(t, certs.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	writeFile(t, certs.serverCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}))
	writeFile(t, certs.serverKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certs
}

func writeFile(t testing.TB, path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t testing.TB) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// origin serves the proxied destinations and the fallback website.
type origin struct {
	https  string
	http   string
	banner string
	udp    string
	page   []byte
}

func randomStream(seed uint64) io.Reader {
	var key [32]byte
	key[0], key[1] = byte(seed), byte(seed>>8)
	return mrand.NewChaCha8(key)
}

var (
	digestAccess sync.Mutex
	digestCache  = make(map[[2]uint64][32]byte)
)

func streamDigest(size int64, seed uint64) [32]byte {
	digestAccess.Lock()
	defer digestAccess.Unlock()
	key := [2]uint64{uint64(size), seed}
	if digest, loaded := digestCache[key]; loaded {
		return digest
	}
	hash := sha256.New()
	io.CopyN(hash, randomStream(seed), size)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	digestCache[key] = digest
	return digest
}

func startOrigin(t testing.TB, certs *certificates) *origin {
	page := []byte("<!doctype html><title>realclient</title><body>")
	for len(page) < pageSize-len("</body>") {
		page = append(page, "lorem ipsum dolor sit amet "...)
	}
	page = append(page[:pageSize-len("</body>")], "</body>"...)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(page)
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		seed, _ := strconv.ParseUint(r.URL.Query().Get("seed"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		io.CopyN(w, randomStream(seed), size)
	})
	result := &origin{page: page}

	httpsListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certs.origin}})
	if err != nil {
		t.Fatal(err)
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for _, listener := range []net.Listener{httpsListener, httpListener} {
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go server.Serve(listener)
		t.Cleanup(func() { server.Close() })
	}
	result.https = httpsListener.Addr().String()
	result.http = httpListener.Addr().String()

	bannerListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bannerListener.Close() })
	go func() {
		for {
			conn, acceptErr := bannerListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, writeErr := io.WriteString(conn, bannerMessage); writeErr == nil {
					io.Copy(conn, conn)
				}
			}()
		}
	}()
	result.banner = bannerListener.Addr().String()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpConn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, readErr := udpConn.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				return
			}
			udpConn.WriteToUDPAddrPort(buffer[:n], addr)
		}
	}()
	result.udp = udpConn.LocalAddr().String()
	return result
}

type process struct {
	name    string
	logPath string
	cmd     *exec.Cmd
	exited  chan struct{}
	once    sync.Once
}

func startProcess(t testing.TB, name, logPath, binary string, args ...string) *process {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = filepath.Dir(logPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	started := &process{name: name, logPath: logPath, cmd: cmd, exited: make(chan struct{})}
	go func() {
		cmd.Wait()
		logFile.Close()
		close(started.exited)
	}()
	t.Cleanup(started.stop)
	return started
}

func (p *process) stop() {
	p.once.Do(func() {
		p.cmd.Process.Kill()
		<-p.exited
	})
}

func (p *process) tail(lines int) string {
	data, _ := os.ReadFile(p.logPath)
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	return strings.Join(all[max(0, len(all)-lines):], "\n")
}

func (p *process) logContains(text string) bool {
	data, _ := os.ReadFile(p.logPath)
	return bytes.Contains(data, []byte(text))
}

// server is one sing-box process hosting AnyTLS inbounds, one per mode.
type server struct {
	name       string
	binary     string
	dir        string
	configPath string
	modes      []string
	inbounds   map[string]string
	process    *process
	t          testing.TB
}

// Modes of the patched server. "control" disables traffic shaping and is the
// paired comparison for "shaped"; extra profiles come from REALCLIENT_PROFILES
// as a JSON object of traffic_shaping objects, for parameter tuning.
func shapingModes(t testing.TB) (names []string, options map[string]map[string]any) {
	options = map[string]map[string]any{
		"control": nil,
		"shaped":  {"enabled": true},
	}
	names = []string{"control", "shaped"}
	if raw := os.Getenv("REALCLIENT_PROFILES"); raw != "" {
		var profiles map[string]map[string]any
		if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
			t.Fatal("REALCLIENT_PROFILES: ", err)
		}
		var extra []string
		for name, profile := range profiles {
			if _, exists := options[name]; exists || name == "legacy" {
				t.Fatalf("REALCLIENT_PROFILES: reserved profile name %q", name)
			}
			profile["enabled"] = true
			options[name] = profile
			extra = append(extra, name)
		}
		sort.Strings(extra)
		names = append(names, extra...)
	}
	return names, options
}

func startServer(t testing.TB, name, binary, dir string, certs *certificates, site *origin, legacy bool) *server {
	started := &server{
		name:       name,
		binary:     binary,
		dir:        dir,
		configPath: filepath.Join(dir, name+".json"),
		inbounds:   make(map[string]string),
		t:          t,
	}
	var modes []string
	shaping := map[string]map[string]any{}
	if legacy {
		modes = []string{"legacy"}
	} else {
		modes, shaping = shapingModes(t)
	}
	started.modes = modes
	_, fallbackPortText, _ := net.SplitHostPort(site.http)
	fallbackPort, _ := strconv.Atoi(fallbackPortText)
	var inbounds []map[string]any
	for _, mode := range modes {
		port := freePort(t)
		started.inbounds[mode] = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		inbound := map[string]any{
			"type":        "anytls",
			"tag":         mode,
			"listen":      "127.0.0.1",
			"listen_port": port,
			"users":       []map[string]string{{"name": "realclient", "password": password}},
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      serverName,
				"certificate_path": certs.serverCert,
				"key_path":         certs.serverKey,
			},
		}
		if !legacy {
			// The legacy inbound rejects these unknown fields.
			inbound["fallback"] = map[string]any{"server": "127.0.0.1", "server_port": fallbackPort}
			inbound["handshake_timeout"] = handshakeTimeout.String()
			if shaping[mode] != nil {
				inbound["traffic_shaping"] = shaping[mode]
			}
		}
		inbounds = append(inbounds, inbound)
	}
	writeJSON(t, started.configPath, map[string]any{
		"log":       map[string]any{"level": logLevel(), "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
	})
	started.start()
	return started
}

func logLevel() string {
	if level := os.Getenv("REALCLIENT_LOG"); level != "" {
		return level
	}
	return "warn"
}

func writeJSON(t testing.TB, path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, data)
}

func (s *server) start() {
	s.process = startProcess(s.t, s.name, filepath.Join(s.dir, s.name+".log"), s.binary, "run", "-c", s.configPath, "--disable-color")
	for mode, addr := range s.inbounds {
		if err := waitTCP(addr, 15*time.Second); err != nil {
			s.t.Fatalf("%s inbound %s not ready: %v\n%s", s.name, mode, err, s.process.tail(20))
		}
	}
}

func (s *server) restart() {
	s.process.stop()
	s.start()
}

type clientKind struct {
	name   string
	binary string
	start  func(t testing.TB, binary, dir string, socksPort int, serverAddr string, certs *certificates) *process
}

func clientKinds() []clientKind {
	return []clientKind{
		{name: "sing-box", binary: binarySingBox, start: startSingBoxClient},
		{name: "mihomo", binary: binaryMihomo, start: startMihomoClient},
		{name: "anytls-go", binary: binaryAnyTLSClient, start: startAnyTLSGoClient},
	}
}

// sing-box's AnyTLS outbound uses github.com/anytls/sing-anytls, as SFA, SFI,
// SFM and other sing-box based clients do. The server certificate is verified.
func startSingBoxClient(t testing.TB, binary, dir string, socksPort int, serverAddr string, certs *certificates) *process {
	host, portText, _ := net.SplitHostPort(serverAddr)
	port, _ := strconv.Atoi(portText)
	configPath := filepath.Join(dir, "client.json")
	writeJSON(t, configPath, map[string]any{
		"log":      map[string]any{"level": logLevel(), "timestamp": true},
		"inbounds": []map[string]any{{"type": "mixed", "tag": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
		"outbounds": []map[string]any{{
			"type":        "anytls",
			"tag":         "proxy",
			"server":      host,
			"server_port": port,
			"password":    password,
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      serverName,
				"certificate_path": certs.caPath,
			},
		}},
		"route": map[string]any{"final": "proxy"},
	})
	return startProcess(t, "sing-box client", filepath.Join(dir, "client.log"), binary, "run", "-c", configPath, "--disable-color")
}

// Mihomo pins the server certificate by its SHA-256 fingerprint.
func startMihomoClient(t testing.TB, binary, dir string, socksPort int, serverAddr string, certs *certificates) *process {
	host, port, _ := net.SplitHostPort(serverAddr)
	fingerprint := sha256.Sum256(certs.serverLeaf)
	config := fmt.Sprintf(`mixed-port: %d
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: %s
ipv6: false
geodata-mode: false
geo-auto-update: false
find-process-mode: off
profile:
  store-selected: false
  store-fake-ip: false
proxies:
  - name: anytls
    type: anytls
    server: %s
    port: %s
    password: %q
    sni: %s
    fingerprint: %x
    udp: true
rules:
  - MATCH,anytls
`, socksPort, mihomoLogLevel(), host, port, password, serverName, fingerprint)
	writeFile(t, filepath.Join(dir, "config.yaml"), []byte(config))
	return startProcess(t, "mihomo", filepath.Join(dir, "client.log"), binary, "-d", dir, "-f", filepath.Join(dir, "config.yaml"))
}

func mihomoLogLevel() string {
	switch level := logLevel(); level {
	case "warn":
		return "warning"
	default:
		return level
	}
}

// The anytls-go sample client skips certificate verification.
func startAnyTLSGoClient(t testing.TB, binary, dir string, socksPort int, serverAddr string, _ *certificates) *process {
	return startProcess(t, "anytls-go", filepath.Join(dir, "client.log"), binary,
		"-l", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)),
		"-s", serverAddr, "-p", password, "-sni", serverName)
}

// liveClient is a client process connected to one inbound through a Relay.
type liveClient struct {
	t       testing.TB
	kind    clientKind
	mode    string
	dir     string
	socks   string
	relay   *Relay
	process *process
	certs   *certificates
	site    *origin
	server  *server
}

func startClient(t testing.TB, kind clientKind, mode string, srv *server, certs *certificates, site *origin, dir string) *liveClient {
	relay, err := NewRelay(srv.inbounds[mode])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	client := &liveClient{
		t:      t,
		kind:   kind,
		mode:   mode,
		dir:    dir,
		relay:  relay,
		certs:  certs,
		site:   site,
		server: srv,
	}
	client.start()
	return client
}

func (c *liveClient) start() {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		c.t.Fatal(err)
	}
	socksPort := freePort(c.t)
	c.socks = net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	c.process = c.kind.start(c.t, findBinary(c.kind.binary), c.dir, socksPort, c.relay.Addr(), c.certs)
	if err := waitTCP(c.socks, 15*time.Second); err != nil {
		c.t.Fatalf("%s client not ready: %v\n%s", c.kind.name, err, c.process.tail(20))
	}
}

func (c *liveClient) stop() {
	c.process.stop()
}

func (c *liveClient) logs() string {
	return fmt.Sprintf("client log:\n%s\nserver log:\n%s", c.process.tail(15), c.server.process.tail(15))
}

func (c *liveClient) httpClient(keepAlive bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialSocks5(ctx, c.socks, addr)
			},
			TLSClientConfig:   c.certs.originPoolTLS.Clone(),
			DisableKeepAlives: !keepAlive,
		},
		Timeout: 30 * time.Second,
	}
}

type fetchResult struct {
	ttfb  time.Duration
	total time.Duration
}

// fetchPage opens a new proxied connection and fetches the page over HTTPS,
// so every call includes a nested TLS handshake on a new stream.
func (c *liveClient) fetchPage(ctx context.Context) (fetchResult, error) {
	return fetchPageWith(ctx, c.httpClient(false), c.site)
}

func fetchPageWith(ctx context.Context, client *http.Client, site *origin) (fetchResult, error) {
	start := time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+site.https+"/", nil)
	if err != nil {
		return fetchResult{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return fetchResult{}, err
	}
	defer response.Body.Close()
	ttfb := time.Since(start)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fetchResult{}, err
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, site.page) {
		return fetchResult{}, fmt.Errorf("unexpected page: status %d, %d bytes", response.StatusCode, len(body))
	}
	return fetchResult{ttfb: ttfb, total: time.Since(start)}, nil
}

// download fetches size deterministic bytes and verifies their digest.
// Reading stops after limit bytes when limit > 0.
func (c *liveClient) download(ctx context.Context, size int64, seed uint64, limit int64) (time.Duration, error) {
	start := time.Now()
	url := fmt.Sprintf("https://%s/download?bytes=%d&seed=%d", c.site.https, size, seed)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	response, err := c.httpClient(false).Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if limit > 0 {
		_, err = io.CopyN(io.Discard, response.Body, limit)
		return time.Since(start), err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, response.Body)
	if err != nil {
		return 0, err
	}
	if n != size || [32]byte(hash.Sum(nil)) != streamDigest(size, seed) {
		return 0, fmt.Errorf("download corrupted: %d of %d bytes", n, size)
	}
	return time.Since(start), nil
}

// retry runs fn until it succeeds or the deadline passes, returning attempts.
func retry(timeout time.Duration, fn func(context.Context) error) (int, error) {
	deadline := time.Now().Add(timeout)
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), max(time.Until(deadline), time.Second))
		err := fn(ctx)
		cancel()
		if err == nil || time.Now().After(deadline) {
			return attempt, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func dialSocks5(ctx context.Context, proxy, target string) (net.Conn, error) {
	conn, err := socks5Handshake(ctx, proxy, 1, target)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Handshake(ctx context.Context, proxy string, command byte, target string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if deadline, loaded := ctx.Deadline(); loaded {
		conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	reader := bufio.NewReader(conn)
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(reader, method[:]); err != nil {
		return fail(err)
	}
	if method != [2]byte{5, 0} {
		return fail(fmt.Errorf("socks5: unexpected method reply %v", method))
	}
	addrPort, err := netip.ParseAddrPort(target)
	if err != nil {
		return fail(err)
	}
	request := []byte{5, command, 0}
	request = appendSocksAddr(request, addrPort)
	if _, err = conn.Write(request); err != nil {
		return fail(err)
	}
	var reply [3]byte
	if _, err = io.ReadFull(reader, reply[:]); err != nil {
		return fail(err)
	}
	if reply[1] != 0 {
		return fail(fmt.Errorf("socks5: request failed with code %d", reply[1]))
	}
	bound, err := readSocksAddr(reader)
	if err != nil {
		return fail(err)
	}
	if reader.Buffered() > 0 {
		return fail(fmt.Errorf("socks5: unexpected data after reply"))
	}
	return &socksConn{Conn: conn, bound: bound}, nil
}

type socksConn struct {
	net.Conn
	bound netip.AddrPort
}

func (c *socksConn) CloseWrite() error {
	if tcpConn, isTCP := c.Conn.(*net.TCPConn); isTCP {
		return tcpConn.CloseWrite()
	}
	return c.Close()
}

func appendSocksAddr(buffer []byte, addrPort netip.AddrPort) []byte {
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		buffer = append(buffer, 1)
	} else {
		buffer = append(buffer, 4)
	}
	buffer = append(buffer, addr.AsSlice()...)
	return append(buffer, byte(addrPort.Port()>>8), byte(addrPort.Port()))
}

func readSocksAddr(reader io.Reader) (netip.AddrPort, error) {
	var addrType [1]byte
	if _, err := io.ReadFull(reader, addrType[:]); err != nil {
		return netip.AddrPort{}, err
	}
	var length int
	switch addrType[0] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		var nameLength [1]byte
		if _, err := io.ReadFull(reader, nameLength[:]); err != nil {
			return netip.AddrPort{}, err
		}
		if _, err := io.ReadFull(reader, make([]byte, int(nameLength[0])+2)); err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPort{}, nil
	default:
		return netip.AddrPort{}, fmt.Errorf("socks5: address type %d", addrType[0])
	}
	data := make([]byte, length+2)
	if _, err := io.ReadFull(reader, data); err != nil {
		return netip.AddrPort{}, err
	}
	addr, _ := netip.AddrFromSlice(data[:length])
	return netip.AddrPortFrom(addr, uint16(data[length])<<8|uint16(data[length+1])), nil
}

// socksUDP is a SOCKS5 UDP association.
type socksUDP struct {
	control net.Conn
	conn    *net.UDPConn
	relay   netip.AddrPort
}

func associateSocks5(ctx context.Context, proxy string) (*socksUDP, error) {
	control, err := socks5Handshake(ctx, proxy, 3, "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	control.SetDeadline(time.Time{})
	relay := control.(*socksConn).bound
	if !relay.Addr().IsValid() || relay.Addr().IsUnspecified() {
		proxyAddr, _ := netip.ParseAddrPort(proxy)
		relay = netip.AddrPortFrom(proxyAddr.Addr(), relay.Port())
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		control.Close()
		return nil, err
	}
	return &socksUDP{control: control, conn: conn, relay: relay}, nil
}

func (s *socksUDP) WriteTo(payload []byte, target netip.AddrPort) error {
	packet := appendSocksAddr([]byte{0, 0, 0}, target)
	_, err := s.conn.WriteToUDPAddrPort(append(packet, payload...), s.relay)
	return err
}

func (s *socksUDP) Read(buffer []byte) (int, error) {
	raw := make([]byte, 65535)
	n, err := s.conn.Read(raw)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("socks5: short UDP packet")
	}
	reader := bytes.NewReader(raw[3:n])
	if _, err = readSocksAddr(reader); err != nil {
		return 0, err
	}
	return reader.Read(buffer)
}

func (s *socksUDP) Close() {
	s.conn.Close()
	s.control.Close()
}
