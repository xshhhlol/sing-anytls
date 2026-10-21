package realclient

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var matrixScenarios = []string{
	"first", "reuse", "download", "server_first", "concurrent", "cancel", "udp", "drop_reconnect", "server_restart",
}

type matrix struct {
	access  sync.Mutex
	columns []string
	order   []string
	rows    map[string]map[string]string
}

func newMatrix(columns []string) *matrix {
	return &matrix{columns: columns, rows: make(map[string]map[string]string)}
}

func (m *matrix) set(row, column, value string) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.rows[row] == nil {
		m.rows[row] = make(map[string]string)
		m.order = append(m.order, row)
	}
	m.rows[row][column] = value
}

func (m *matrix) markdown() string {
	m.access.Lock()
	defer m.access.Unlock()
	var builder strings.Builder
	builder.WriteString("| |")
	for _, column := range m.columns {
		builder.WriteString(" " + column + " |")
	}
	builder.WriteString("\n|---|")
	builder.WriteString(strings.Repeat("---|", len(m.columns)))
	for _, row := range m.order {
		builder.WriteString("\n| " + row + " |")
		for _, column := range m.columns {
			value := m.rows[row][column]
			if value == "" {
				value = "-"
			}
			builder.WriteString(" " + value + " |")
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

type lab struct {
	dir     string
	certs   *certificates
	site    *origin
	servers []*server
}

func newLab(t *testing.T) *lab {
	if os.Getenv("REALCLIENT") == "" && os.Getenv("REALCLIENT_MEASURE") == "" {
		t.Skip("set REALCLIENT=1 to run real client binaries")
	}
	singBox := findBinary(binarySingBox)
	if singBox == "" {
		t.Skip("sing-box binary not found in ", binaryDir(), "; run build.sh or set REALCLIENT_BIN")
	}
	dir := outputDir(t)
	certs := newCertificates(t, dir)
	site := startOrigin(t, certs)
	result := &lab{dir: dir, certs: certs, site: site}
	if legacy := findBinary(binarySingBoxLegacy); legacy != "" {
		result.servers = append(result.servers, startServer(t, "legacy-server", legacy, dir, certs, site, true))
	} else {
		t.Log("legacy sing-box binary not found; skipping the legacy baseline")
	}
	result.servers = append(result.servers, startServer(t, "server", singBox, dir, certs, site, false))
	return result
}

func (l *lab) checkLogs(t *testing.T) {
	for _, srv := range l.servers {
		if srv.process.logContains("panic") {
			t.Errorf("%s log contains a panic:\n%s", srv.name, srv.process.tail(40))
		}
	}
}

// TestClientMatrix drives each real client through the same scenarios against
// the legacy server, the patched server without traffic shaping (control),
// and with traffic shaping (shaped).
//
//nolint:paralleltest // scenarios restart the shared server processes
func TestClientMatrix(t *testing.T) {
	l := newLab(t)
	results := newMatrix(matrixScenarios)
	for _, kind := range clientKinds() {
		if findBinary(kind.binary) == "" {
			t.Logf("skip %s: binary %s not found", kind.name, kind.binary)
			continue
		}
		for _, srv := range l.servers {
			for _, mode := range srv.modes {
				row := kind.name + " / " + mode
				t.Run(kind.name+"/"+mode, func(t *testing.T) {
					runScenarios(t, l, kind, mode, srv, func(column, value string) {
						results.set(row, column, value)
					})
				})
			}
		}
	}
	report := results.markdown()
	t.Log("\n" + report)
	writeFile(t, filepath.Join(l.dir, "matrix.md"), []byte(report))
	l.checkLogs(t)
}

func runScenarios(t *testing.T, l *lab, kind clientKind, mode string, srv *server, record func(column, value string)) {
	client := startClient(t, kind, mode, srv, l.certs, l.site, filepath.Join(l.dir, kind.name+"-"+mode))
	defer client.stop()
	step := func(name string, fn func(t *testing.T) string) {
		var note string
		passed := t.Run(name, func(t *testing.T) {
			note = fn(t)
		})
		if passed {
			record(name, "ok "+note)
		} else {
			record(name, "**FAIL**")
			t.Log(client.logs())
		}
	}
	timeout := func(duration time.Duration) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		t.Cleanup(cancel)
		return ctx
	}

	step("first", func(t *testing.T) string {
		result, err := client.fetchPage(timeout(20 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("ttfb %s", result.ttfb.Round(time.Millisecond))
	})

	step("reuse", func(t *testing.T) string {
		// Let the first stream close so its session returns to the idle pool.
		time.Sleep(300 * time.Millisecond)
		before := client.relay.Accepted()
		const requests = 5
		for range requests {
			if _, err := client.fetchPage(timeout(20 * time.Second)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
		}
		opened := client.relay.Accepted() - before
		if opened >= requests {
			t.Fatalf("no session reuse: %d new connections for %d requests", opened, requests)
		}
		return fmt.Sprintf("%d new conn/%d req", opened, requests)
	})

	step("download", func(t *testing.T) string {
		const size = 16 << 20
		elapsed, err := client.download(timeout(60*time.Second), size, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		// Small requests after a large response.
		for range 3 {
			if _, err = client.fetchPage(timeout(20 * time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		return fmt.Sprintf("%.0f Mbit/s", float64(size*8)/elapsed.Seconds()/1e6)
	})

	step("server_first", func(t *testing.T) string {
		conn, err := dialSocks5(timeout(10*time.Second), client.socks, l.site.banner)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		banner := make([]byte, len(bannerMessage))
		if _, err = io.ReadFull(conn, banner); err != nil || string(banner) != bannerMessage {
			t.Fatalf("banner %q: %v", banner, err)
		}
		if _, err = io.WriteString(conn, "ping\n"); err != nil {
			t.Fatal(err)
		}
		echo := make([]byte, 5)
		if _, err = io.ReadFull(conn, echo); err != nil || string(echo) != "ping\n" {
			t.Fatalf("echo %q: %v", echo, err)
		}
		return ""
	})

	step("concurrent", func(t *testing.T) string {
		ctx := timeout(60 * time.Second)
		var wait sync.WaitGroup
		errs := make(chan error, 20)
		for range 16 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := client.fetchPage(ctx)
				errs <- err
			}()
		}
		for seed := range uint64(4) {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := client.download(ctx, 2<<20, 10+seed, 0)
				errs <- err
			}()
		}
		wait.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		return "16 pages + 4×2 MiB"
	})

	step("cancel", func(t *testing.T) string {
		if _, err := client.download(timeout(30*time.Second), 64<<20, 2, 512<<10); err != nil {
			t.Fatal(err)
		}
		attempts, err := retry(10*time.Second, func(ctx context.Context) error {
			_, err := client.fetchPage(ctx)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%d attempt(s)", attempts)
	})

	step("udp", func(t *testing.T) string {
		association, err := associateSocks5(timeout(10*time.Second), client.socks)
		if err != nil {
			t.Fatal(err)
		}
		defer association.Close()
		target := netip.MustParseAddrPort(l.site.udp)
		sizes := []int{1, 16, 64, 200, 512, 1000, 1200, 1400}
		expected := make(map[string]bool)
		for index, size := range sizes {
			payload := []byte(fmt.Sprintf("%02d", index))
			for len(payload) < size {
				payload = append(payload, byte('a'+index))
			}
			expected[string(payload[:max(size, 2)])] = false
		}
		for payload := range expected {
			if err = association.WriteTo([]byte(payload), target); err != nil {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		association.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buffer := make([]byte, 65535)
		for received := 0; received < len(expected); {
			n, readErr := association.Read(buffer)
			if readErr != nil {
				t.Fatalf("received %d of %d datagrams: %v", received, len(expected), readErr)
			}
			seen, known := expected[string(buffer[:n])]
			if !known {
				t.Fatalf("unexpected datagram of %d bytes", n)
			}
			if !seen {
				expected[string(buffer[:n])] = true
				received++
			}
		}
		return fmt.Sprintf("%d datagrams", len(expected))
	})

	step("drop_reconnect", func(t *testing.T) string {
		client.relay.DropAll()
		attempts, err := retry(20*time.Second, func(ctx context.Context) error {
			_, err := client.fetchPage(ctx)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%d attempt(s)", attempts)
	})

	step("server_restart", func(t *testing.T) string {
		srv.restart()
		attempts, err := retry(20*time.Second, func(ctx context.Context) error {
			_, err := client.fetchPage(ctx)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%d attempt(s)", attempts)
	})
}

var fallbackProbes = []string{"website", "wrong_password", "short_eof", "short_timeout", "plain_tcp"}

// TestFallbackProbes connects to each inbound without an AnyTLS client, as an
// active prober would, and records what it gets back.
//
//nolint:paralleltest // probe latencies are compared with the handshake timeout
func TestFallbackProbes(t *testing.T) {
	l := newLab(t)
	results := newMatrix(fallbackProbes)
	for _, srv := range l.servers {
		for _, mode := range srv.modes {
			addr := srv.inbounds[mode]
			legacy := mode == "legacy"
			t.Run(mode, func(t *testing.T) {
				probe := func(name string, fn func(t *testing.T) string) {
					var note string
					if t.Run(name, func(t *testing.T) { note = fn(t) }) {
						results.set(mode, name, note)
					} else {
						results.set(mode, name, "**FAIL**")
					}
				}
				dial := func(t *testing.T) *tls.Conn {
					conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
						&tls.Config{RootCAs: l.certs.pool, ServerName: serverName})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { conn.Close() })
					conn.SetDeadline(time.Now().Add(handshakeTimeout + 10*time.Second))
					return conn
				}
				// expect returns the response status and latency, or that the
				// connection was closed without one where that is expected.
				expect := func(t *testing.T, conn net.Conn, start time.Time, status int, closedOK bool) string {
					response, err := http.ReadResponse(bufio.NewReader(conn), nil)
					elapsed := time.Since(start).Round(10 * time.Millisecond)
					if err != nil {
						if closedOK && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || isReset(err)) {
							return fmt.Sprintf("closed after %s", elapsed)
						}
						t.Fatalf("no HTTP response after %s: %v", elapsed, err)
					}
					body, _ := io.ReadAll(response.Body)
					response.Body.Close()
					if closedOK {
						t.Fatalf("unexpected response %d", response.StatusCode)
					}
					if response.StatusCode != status {
						t.Fatalf("status %d, want %d", response.StatusCode, status)
					}
					if status == http.StatusOK && string(body) != string(l.site.page) {
						t.Fatal("fallback page differs from the website")
					}
					return fmt.Sprintf("HTTP %d after %s", status, elapsed)
				}

				probe("website", func(t *testing.T) string {
					conn := dial(t)
					start := time.Now()
					io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n")
					return expect(t, conn, start, http.StatusOK, legacy)
				})
				probe("wrong_password", func(t *testing.T) string {
					conn := dial(t)
					request := make([]byte, 32, 64)
					rand.Read(request)
					request = append(request, 0, 0)
					request = append(request, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"...)
					start := time.Now()
					conn.Write(request)
					// The fallback website receives the consumed bytes too, so it
					// answers the corrupted request line with 400.
					return expect(t, conn, start, http.StatusBadRequest, legacy)
				})
				probe("short_eof", func(t *testing.T) string {
					conn := dial(t)
					start := time.Now()
					io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
					conn.CloseWrite()
					note := expect(t, conn, start, http.StatusOK, legacy)
					if elapsed := time.Since(start); !legacy && elapsed > handshakeTimeout/2 {
						t.Fatalf("short request with EOF waited %s", elapsed)
					}
					return note
				})
				probe("short_timeout", func(t *testing.T) string {
					conn := dial(t)
					start := time.Now()
					io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n")
					note := expect(t, conn, start, http.StatusOK, legacy)
					// Fewer than 32 bytes without EOF: the server cannot tell a
					// split authentication apart until the handshake timeout.
					if elapsed := time.Since(start); !legacy && (elapsed < handshakeTimeout-500*time.Millisecond || elapsed > handshakeTimeout+5*time.Second) {
						t.Fatalf("short request answered after %s, handshake timeout %s", elapsed, handshakeTimeout)
					}
					return note
				})
				probe("plain_tcp", func(t *testing.T) string {
					conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					start := time.Now()
					io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+serverName+"\r\n\r\n")
					reply, err := io.ReadAll(conn)
					elapsed := time.Since(start).Round(10 * time.Millisecond)
					if len(reply) > 0 {
						return fmt.Sprintf("%d bytes then closed after %s", len(reply), elapsed)
					}
					if err != nil && !isReset(err) {
						t.Fatalf("after %s: %v", elapsed, err)
					}
					return fmt.Sprintf("closed after %s", elapsed)
				})
			})
		}
	}
	report := results.markdown()
	t.Log("\n" + report)
	writeFile(t, filepath.Join(l.dir, "fallback.md"), []byte(report))
	l.checkLogs(t)
}

func isReset(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "broken pipe"))
}
