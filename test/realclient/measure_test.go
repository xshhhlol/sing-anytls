package realclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	measureRecords  = 16
	reuseRequests   = 5
	settleTime      = 300 * time.Millisecond
	bulkSize        = 32 << 20
	udpDatagrams    = 100
	udpDatagramSize = 100
)

type bulkMeasurement struct {
	Mbps     float64 `json:"mbps"`
	TLSUp    int64   `json:"tls_up"`
	TLSDown  int64   `json:"tls_down"`
	Overhead float64 `json:"overhead"`
}

type udpMeasurement struct {
	RTT     Quantiles `json:"rtt_ms"`
	TLSUp   int64     `json:"tls_up"`
	TLSDown int64     `json:"tls_down"`
}

type pairMeasurement struct {
	Client              string           `json:"client"`
	Mode                string           `json:"mode"`
	Failures            []string         `json:"failures,omitempty"`
	ColdTTFB            Quantiles        `json:"cold_ttfb_ms"`
	ReuseTTFB           Quantiles        `json:"reuse_ttfb_ms"`
	Cold                Summary          `json:"cold"`
	Reuse               Summary          `json:"reuse"`
	ReuseNewConnections int              `json:"reuse_new_connections"`
	Bulk                *bulkMeasurement `json:"bulk,omitempty"`
	UDP                 *udpMeasurement  `json:"udp,omitempty"`
	ColdTraces          []Trace          `json:"-"`
	ReuseTraces         []Trace          `json:"-"`
}

type separabilityRow struct {
	Client   string       `json:"client"`
	Positive string       `json:"positive"`
	Negative string       `json:"negative"`
	Result   Separability `json:"result"`
}

type measureReport struct {
	Samples      int                `json:"samples"`
	Records      int                `json:"records"`
	Profiles     string             `json:"profiles,omitempty"`
	Baseline     *pairMeasurement   `json:"https_baseline"`
	Pairs        []*pairMeasurement `json:"pairs"`
	Separability []separabilityRow  `json:"separability"`
}

// TestMeasure runs the same workload through every client against every
// server mode, and an HTTPS baseline, recording TLS records at a relay between
// client and server. It writes measure.md, measure.json and traces.json.
//
// REALCLIENT_MEASURE=1 enables it; REALCLIENT_SAMPLES sets the cold starts per
// client and mode (default 10). Loopback timing is not network timing.
//
//nolint:paralleltest // concurrent tests would distort the measurement
func TestMeasure(t *testing.T) {
	if os.Getenv("REALCLIENT_MEASURE") == "" {
		t.Skip("set REALCLIENT_MEASURE=1 to run the paired measurement")
	}
	samples := 10
	if value := os.Getenv("REALCLIENT_SAMPLES"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 2 {
			t.Fatal("REALCLIENT_SAMPLES must be an integer of at least 2")
		}
		samples = parsed
	}
	l := newLab(t)
	report := &measureReport{Samples: samples, Records: measureRecords, Profiles: os.Getenv("REALCLIENT_PROFILES")}
	report.Baseline = measureBaseline(t, l, samples)
	traces := map[string][]Trace{"https/cold": report.Baseline.ColdTraces}
	for _, kind := range clientKinds() {
		if findBinary(kind.binary) == "" {
			t.Logf("skip %s: binary %s not found", kind.name, kind.binary)
			continue
		}
		byMode := make(map[string]*pairMeasurement)
		var modes []string
		for _, srv := range l.servers {
			for _, mode := range srv.modes {
				t.Logf("measuring %s / %s", kind.name, mode)
				pair := measurePair(t, l, kind, mode, srv, samples)
				report.Pairs = append(report.Pairs, pair)
				byMode[mode] = pair
				modes = append(modes, mode)
				traces[kind.name+"/"+mode+"/cold"] = pair.ColdTraces
				traces[kind.name+"/"+mode+"/reuse"] = pair.ReuseTraces
			}
		}
		separate := func(positive, negative string, negativeTraces []Trace) {
			if byMode[positive] == nil || negativeTraces == nil {
				return
			}
			report.Separability = append(report.Separability, separabilityRow{
				Client:   kind.name,
				Positive: positive,
				Negative: negative,
				Result:   Separate(byMode[positive].ColdTraces, negativeTraces, measureRecords),
			})
		}
		for _, mode := range modes {
			separate(mode, "https", report.Baseline.ColdTraces)
		}
		if control := byMode["control"]; control != nil {
			for _, mode := range modes {
				if mode != "control" {
					separate(mode, "control", control.ColdTraces)
				}
			}
		}
	}
	markdown := report.markdown()
	t.Log("\n" + markdown)
	writeFile(t, filepath.Join(l.dir, "measure.md"), []byte(markdown))
	writeJSON(t, filepath.Join(l.dir, "measure.json"), report)
	writeJSON(t, filepath.Join(l.dir, "traces.json"), traces)
	t.Log("reports written to ", l.dir)
	l.checkLogs(t)
}

// windowTraces cuts every trace to records observed in [from, to) and merges
// them into one trace, for workloads that share or open connections.
func windowTraces(traces []Trace, from, to time.Time) Trace {
	merged := Trace{Start: from}
	for _, trace := range traces {
		window := trace.Window(from.Sub(trace.Start), to.Sub(trace.Start))
		offset := trace.Start.Sub(from)
		for _, record := range window.Records {
			record.Time += offset
			merged.Records = append(merged.Records, record)
		}
		merged.Malformed = merged.Malformed || trace.Malformed
	}
	return merged
}

func milliseconds(durations []time.Duration) Quantiles {
	values := make([]float64, len(durations))
	for index, duration := range durations {
		values[index] = float64(duration) / float64(time.Millisecond)
	}
	return NewQuantiles(values)
}

func measurePair(t *testing.T, l *lab, kind clientKind, mode string, srv *server, samples int) *pairMeasurement {
	pair := &pairMeasurement{Client: kind.name, Mode: mode}
	base := filepath.Join(l.dir, "measure", kind.name+"-"+mode)
	var coldTTFB, reuseTTFB []time.Duration
	fail := func(stage string, err error) {
		pair.Failures = append(pair.Failures, stage+": "+err.Error())
		t.Errorf("%s / %s %s: %v", kind.name, mode, stage, err)
	}
	for index := range samples {
		client := startClient(t, kind, mode, srv, l.certs, l.site, filepath.Join(base, strconv.Itoa(index)))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		result, err := client.fetchPage(ctx)
		if err != nil {
			fail("cold", err)
			cancel()
			client.stop()
			continue
		}
		coldTTFB = append(coldTTFB, result.ttfb)
		time.Sleep(settleTime)
		reuseStart := time.Now()
		traces := client.relay.Traces()
		first := traces[0]
		pair.ColdTraces = append(pair.ColdTraces, first.Window(0, reuseStart.Sub(first.Start)))
		for range reuseRequests {
			result, err = client.fetchPage(ctx)
			if err != nil {
				fail("reuse", err)
				break
			}
			reuseTTFB = append(reuseTTFB, result.ttfb)
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(settleTime)
		reuseEnd := time.Now()
		all := client.relay.Traces()
		pair.ReuseNewConnections += len(all) - len(traces)
		pair.ReuseTraces = append(pair.ReuseTraces, windowTraces(all, reuseStart, reuseEnd))
		cancel()
		client.stop()
		client.relay.Close()
	}
	pair.ColdTTFB = milliseconds(coldTTFB)
	pair.ReuseTTFB = milliseconds(reuseTTFB)
	pair.Cold = Summarize(pair.ColdTraces, measureRecords)
	pair.Reuse = Summarize(pair.ReuseTraces, measureRecords)

	client := startClient(t, kind, mode, srv, l.certs, l.site, filepath.Join(base, "bulk"))
	defer client.stop()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if _, err := client.fetchPage(ctx); err != nil {
		fail("bulk warm-up", err)
		return pair
	}
	time.Sleep(settleTime)
	bulkStart := time.Now()
	elapsed, err := client.download(ctx, bulkSize, 3, 0)
	if err != nil {
		fail("bulk", err)
		return pair
	}
	time.Sleep(settleTime)
	stats := windowTraces(client.relay.Traces(), bulkStart, time.Now()).Stats()
	pair.Bulk = &bulkMeasurement{
		Mbps:     float64(bulkSize*8) / elapsed.Seconds() / 1e6,
		TLSUp:    stats.BytesUp,
		TLSDown:  stats.BytesDown,
		Overhead: float64(stats.BytesDown-bulkSize) / bulkSize,
	}

	association, err := associateSocks5(ctx, client.socks)
	if err != nil {
		fail("udp", err)
		return pair
	}
	defer association.Close()
	target := netip.MustParseAddrPort(l.site.udp)
	udpStart := time.Now()
	var rtts []time.Duration
	buffer := make([]byte, 65535)
	for index := range udpDatagrams {
		payload := []byte(fmt.Sprintf("%04d", index))
		for len(payload) < udpDatagramSize {
			payload = append(payload, 'u')
		}
		sent := time.Now()
		if err = association.WriteTo(payload, target); err != nil {
			fail("udp", err)
			return pair
		}
		association.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			n, readErr := association.Read(buffer)
			if readErr != nil {
				fail("udp", readErr)
				return pair
			}
			if string(buffer[:n]) == string(payload) {
				break
			}
		}
		rtts = append(rtts, time.Since(sent))
	}
	time.Sleep(settleTime)
	stats = windowTraces(client.relay.Traces(), udpStart, time.Now()).Stats()
	pair.UDP = &udpMeasurement{RTT: milliseconds(rtts), TLSUp: stats.BytesUp, TLSDown: stats.BytesDown}
	return pair
}

// measureBaseline fetches the same page directly over HTTPS, one new
// connection per sample, through a relay to the origin.
func measureBaseline(t *testing.T, l *lab, samples int) *pairMeasurement {
	relay, err := NewRelay(l.site.https)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", relay.Addr())
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: dial, TLSClientConfig: l.certs.originPoolTLS.Clone(), DisableKeepAlives: true},
		Timeout:   60 * time.Second,
	}
	baseline := &pairMeasurement{Client: "go net/http", Mode: "https"}
	var ttfb []time.Duration
	for range samples {
		relay.Reset()
		result, fetchErr := fetchPageWith(context.Background(), client, l.site)
		if fetchErr != nil {
			t.Fatal(fetchErr)
		}
		ttfb = append(ttfb, result.ttfb)
		time.Sleep(settleTime)
		baseline.ColdTraces = append(baseline.ColdTraces, relay.Traces()...)
	}
	baseline.ColdTTFB = milliseconds(ttfb)
	baseline.Cold = Summarize(baseline.ColdTraces, measureRecords)

	relay.Reset()
	start := time.Now()
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/download?bytes=%d&seed=3", l.site.https, bulkSize), nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	written, err := io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if err != nil || written != bulkSize {
		t.Fatalf("baseline download: %d bytes: %v", written, err)
	}
	elapsed := time.Since(start)
	time.Sleep(settleTime)
	stats := windowTraces(relay.Traces(), start, time.Now()).Stats()
	baseline.Bulk = &bulkMeasurement{
		Mbps:     float64(bulkSize*8) / elapsed.Seconds() / 1e6,
		TLSUp:    stats.BytesUp,
		TLSDown:  stats.BytesDown,
		Overhead: float64(stats.BytesDown-bulkSize) / bulkSize,
	}
	return baseline
}

func (r *measureReport) markdown() string {
	var builder strings.Builder
	write := func(format string, args ...any) { fmt.Fprintf(&builder, format, args...) }
	control := make(map[string]*pairMeasurement)
	for _, pair := range r.Pairs {
		if pair.Mode == "control" {
			control[pair.Client] = pair
		}
	}
	delta := func(value, reference float64) string {
		if reference == 0 {
			return "-"
		}
		return fmt.Sprintf("%+.0f (%+.0f%%)", value-reference, (value-reference)/reference*100)
	}
	shape := func(s Shape) string {
		return fmt.Sprintf("%.1f | %.1f | %d (%.0f%%)", s.Short, s.Distinct, s.TopLength, s.TopShare*100)
	}

	write("Samples per client and mode: %d. Record shape covers the first %d application data records per direction; ", r.Samples, r.Records)
	write("short = at most %d bytes. TLS bytes include record headers. Loopback timing is not network timing.\n", ShortRecordLength)
	if r.Profiles != "" {
		write("\nProfiles: `%s`\n", r.Profiles)
	}

	write("\n### First connection: cold start, one HTTPS page\n\n")
	write("| client | mode | TTFB p50 ms | up B | down B | Δup vs control | Δdown vs control | short↓ | distinct↓ | top↓ len (share) | short↑ | distinct↑ | top↑ len (share) |\n")
	write("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	rows := append([]*pairMeasurement{r.Baseline}, r.Pairs...)
	for _, pair := range rows {
		reference := control[pair.Client]
		upDelta, downDelta := "-", "-"
		if reference != nil && pair != reference {
			upDelta = delta(pair.Cold.BytesUp.Mean, reference.Cold.BytesUp.Mean)
			downDelta = delta(pair.Cold.BytesDown.Mean, reference.Cold.BytesDown.Mean)
		}
		write("| %s | %s | %.1f | %.0f | %.0f | %s | %s | %s | %s |\n", pair.Client, pair.Mode, pair.ColdTTFB.P50,
			pair.Cold.BytesUp.Mean, pair.Cold.BytesDown.Mean, upDelta, downDelta, shape(pair.Cold.Down), shape(pair.Cold.Up))
	}

	write("\n### Reused session: %d more pages, each on a new stream\n\n", reuseRequests)
	write("| client | mode | new conns | TTFB p50 ms | up B/page | down B/page | Δdown vs control | short↓ | distinct↓ | top↓ len (share) | short↑ | distinct↑ | top↑ len (share) |\n")
	write("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, pair := range r.Pairs {
		reference := control[pair.Client]
		downDelta := "-"
		if reference != nil && pair != reference {
			downDelta = delta(pair.Reuse.BytesDown.Mean, reference.Reuse.BytesDown.Mean)
		}
		write("| %s | %s | %d | %.1f | %.0f | %.0f | %s | %s | %s |\n", pair.Client, pair.Mode, pair.ReuseNewConnections,
			pair.ReuseTTFB.P50, pair.Reuse.BytesUp.Mean/reuseRequests, pair.Reuse.BytesDown.Mean/reuseRequests,
			downDelta, shape(pair.Reuse.Down), shape(pair.Reuse.Up))
	}

	write("\n### Bulk download %d MiB and UDP (%d sequential %d-byte echoes)\n\n", bulkSize>>20, udpDatagrams, udpDatagramSize)
	write("| client | mode | Mbit/s | down overhead | up B | UDP RTT p50 ms | UDP RTT p90 ms | UDP up B | UDP down B |\n")
	write("|---|---|---|---|---|---|---|---|---|\n")
	for _, pair := range rows {
		if pair.Bulk == nil {
			write("| %s | %s | failed | | | | | | |\n", pair.Client, pair.Mode)
			continue
		}
		udp := "| - | - | - | - |"
		if pair.UDP != nil {
			udp = fmt.Sprintf("| %.2f | %.2f | %d | %d |", pair.UDP.RTT.P50, pair.UDP.RTT.P90, pair.UDP.TLSUp, pair.UDP.TLSDown)
		}
		write("| %s | %s | %.0f | %.2f%% | %d %s\n", pair.Client, pair.Mode, pair.Bulk.Mbps, pair.Bulk.Overhead*100, pair.Bulk.TLSUp, udp)
	}

	write("\n### Lab separability of first connections (leave-one-out 1-NN on the first %d signed record lengths)\n\n", r.Records)
	write("| client | positive | negative | accuracy | recall | false positive |\n|---|---|---|---|---|---|\n")
	for _, row := range r.Separability {
		write("| %s | %s | %s | %.2f | %.2f | %.2f |\n", row.Client, row.Positive, row.Negative,
			row.Result.Accuracy, row.Result.Recall, row.Result.FalsePositive)
	}

	write("\n### Example: first downlink application data records of the first sample\n\n")
	for _, pair := range rows {
		if len(pair.ColdTraces) > 0 {
			write("- %s / %s: `%v`\n", pair.Client, pair.Mode, pair.ColdTraces[0].AppLengths(Download, 12))
		}
	}
	for _, pair := range r.Pairs {
		if len(pair.Failures) > 0 {
			data, _ := json.Marshal(pair.Failures)
			write("\nFailures %s / %s: %s\n", pair.Client, pair.Mode, data)
		}
	}
	return builder.String()
}
