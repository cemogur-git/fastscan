package scan_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cemogur-git/fastscan/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTCPServer opens a loopback TCP listener and returns its port number.
// The server accepts every connection and closes it immediately. The returned
// cancel function shuts the listener down.
func startTCPServer(t *testing.T) (port uint16, cancel func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return // listener was closed
			}
			conn.Close()
		}
	}()

	addr := l.Addr().(*net.TCPAddr)
	return uint16(addr.Port), func() { l.Close() }
}

// freePort allocates a listener on :0, records the OS-assigned port, and
// immediately closes the listener. The returned port is transiently unused.
// There is an inherent TOCTOU race, but it is acceptable in controlled tests.
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return port
}

// testCfg returns a ScanConfig tuned for fast test execution.
func testCfg() scan.ScanConfig {
	cfg := scan.NewScanConfig()
	cfg.Timeout = 200 * time.Millisecond
	cfg.Concurrency = 50
	cfg.RateLimit = 0 // no rate limit so tests finish quickly
	return cfg
}

// TestConnectScanner_OpenPort verifies that a listening port is reported as Open.
func TestConnectScanner_OpenPort(t *testing.T) {
	port, cancel := startTCPServer(t)
	defer cancel()

	s := scan.NewConnectScanner(testCfg())
	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{port})
	require.NoError(t, err)

	var results []scan.Result
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, scan.StateOpen, results[0].State)
	assert.Equal(t, "127.0.0.1", results[0].IP)
	assert.Equal(t, port, results[0].Port)
	assert.Positive(t, results[0].Latency)
}

// TestConnectScanner_ClosedPort verifies that a port with no listener is
// reported as Closed (connection refused → RST).
func TestConnectScanner_ClosedPort(t *testing.T) {
	port := freePort(t)

	s := scan.NewConnectScanner(testCfg())
	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, []uint16{port})
	require.NoError(t, err)

	var results []scan.Result
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, scan.StateClosed, results[0].State)
}

// TestConnectScanner_Filtered verifies that a non-responding probe is reported
// as Filtered. Instead of manipulating iptables, a mock dialFunc that returns
// a timeout error simulates a packet-drop firewall.
func TestConnectScanner_Filtered(t *testing.T) {
	timeoutDial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, fmt.Errorf("i/o timeout: connection timed out")
	}

	s := scan.NewConnectScanner(testCfg(), scan.WithDialFunc(timeoutDial))
	ch, err := s.Scan(context.Background(), []string{"192.0.2.1"}, []uint16{80})
	require.NoError(t, err)

	var results []scan.Result
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, scan.StateFiltered, results[0].State)
}

// TestConnectScanner_ContextCancel verifies that cancelling ctx stops the scan
// and the results channel closes promptly, with no goroutine leaks.
func TestConnectScanner_ContextCancel(t *testing.T) {
	var mu sync.Mutex
	active := 0

	// blockingDial blocks until ctx is cancelled, simulating a very slow network.
	blockingDial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		active++
		mu.Unlock()

		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()

		<-ctx.Done()
		return nil, ctx.Err()
	}

	cfg := scan.NewScanConfig()
	cfg.Concurrency = 10
	cfg.RateLimit = 0
	s := scan.NewConnectScanner(cfg, scan.WithDialFunc(blockingDial))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ports := make([]uint16, 100)
	for i := range ports {
		ports[i] = uint16(20000 + i)
	}

	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, ports)
	require.NoError(t, err)

	// Let a few goroutines start before cancelling.
	time.Sleep(20 * time.Millisecond)
	cancel()

	// The results channel must close within a reasonable deadline.
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("results channel did not close after context cancellation — possible goroutine leak")
	}

	// All blocking goroutines should have exited by now.
	mu.Lock()
	remaining := active
	mu.Unlock()
	assert.Zero(t, remaining, "goroutine leak: %d dial goroutines still active", remaining)
}

// TestConnectScanner_Concurrency verifies that 100 open ports are each scanned
// exactly once and all results carry StateOpen.
func TestConnectScanner_Concurrency(t *testing.T) {
	const portCount = 100

	ports := make([]uint16, portCount)
	for i := 0; i < portCount; i++ {
		p, cancel := startTCPServer(t)
		defer cancel()
		ports[i] = p
	}

	cfg := testCfg()
	cfg.Concurrency = portCount
	s := scan.NewConnectScanner(cfg)

	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, ports)
	require.NoError(t, err)

	var results []scan.Result
	for r := range ch {
		results = append(results, r)
	}

	assert.Len(t, results, portCount, "expected one result per port")
	for _, r := range results {
		assert.Equal(t, scan.StateOpen, r.State, "port %d should be open", r.Port)
	}
}

// TestState_String verifies the human-readable representation of each State value.
func TestState_String(t *testing.T) {
	cases := []struct {
		state scan.State
		want  string
	}{
		{scan.StateOpen, "open"},
		{scan.StateClosed, "closed"},
		{scan.StateFiltered, "filtered"},
		{scan.State(99), "unknown"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.String())
	}
}

// TestNewScanConfig verifies that constructor values match the exported constants.
func TestNewScanConfig(t *testing.T) {
	cfg := scan.NewScanConfig()
	assert.Equal(t, scan.DefaultConcurrency, cfg.Concurrency)
	assert.Equal(t, scan.DefaultTimeout, cfg.Timeout)
	assert.Equal(t, scan.DefaultRateLimit, cfg.RateLimit)
	assert.Equal(t, scan.DefaultRetryCount, cfg.RetryCount)
}

// ---------------------------------------------------------------------------
// Aggregator tests
// ---------------------------------------------------------------------------

// TestAggregator_Empty verifies that collecting from a closed empty channel
// yields zero results and a summary that reports 0 open ports.
func TestAggregator_Empty(t *testing.T) {
	a := scan.NewAggregator()
	ch := make(chan scan.Result)
	close(ch)
	a.Collect(ch)

	assert.Empty(t, a.Results())
	assert.Contains(t, a.Summary(), "open: 0")
}

// TestAggregator_ConcurrentWrite verifies that 100 results written to the
// channel from concurrent goroutines are all collected without data races.
// Run with -race to exercise the mutex protection.
func TestAggregator_ConcurrentWrite(t *testing.T) {
	const n = 100

	a := scan.NewAggregator()
	ch := make(chan scan.Result, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ch <- scan.Result{
				IP:    "127.0.0.1",
				Port:  uint16(10000 + i),
				State: scan.StateOpen,
			}
		}(i)
	}
	// Close channel only after all senders have finished.
	go func() {
		wg.Wait()
		close(ch)
	}()

	a.Collect(ch)
	assert.Len(t, a.Results(), n)
}

// TestAggregator_FilterByState verifies that FilterByState returns only the
// results that match the requested state, leaving the other groups untouched.
func TestAggregator_FilterByState(t *testing.T) {
	a := scan.NewAggregator()

	ch := make(chan scan.Result, 5)
	ch <- scan.Result{State: scan.StateOpen}
	ch <- scan.Result{State: scan.StateClosed}
	ch <- scan.Result{State: scan.StateOpen}
	ch <- scan.Result{State: scan.StateFiltered}
	ch <- scan.Result{State: scan.StateOpen}
	close(ch)
	a.Collect(ch)

	open := a.FilterByState(scan.StateOpen)
	assert.Len(t, open, 3, "expected three open results")

	closed := a.FilterByState(scan.StateClosed)
	assert.Len(t, closed, 1, "expected one closed result")

	filtered := a.FilterByState(scan.StateFiltered)
	assert.Len(t, filtered, 1, "expected one filtered result")
}

// TestAggregator_Summary verifies that the summary string includes the open
// count, total count, and a non-zero elapsed time after collection.
func TestAggregator_Summary(t *testing.T) {
	a := scan.NewAggregator()

	ch := make(chan scan.Result, 3)
	ch <- scan.Result{State: scan.StateOpen}
	ch <- scan.Result{State: scan.StateOpen}
	ch <- scan.Result{State: scan.StateClosed}
	close(ch)
	a.Collect(ch)

	summary := a.Summary()
	assert.Contains(t, summary, "open: 2", "summary should report 2 open ports")
	assert.Contains(t, summary, "/ 3", "summary should report 3 total results")
}

// ---------------------------------------------------------------------------
// Banner tests
// ---------------------------------------------------------------------------

// startBannerServer listens on a random loopback port and writes banner to
// every accepted connection before closing it. Returns the port and a cancel
// function that shuts the listener down.
func startBannerServer(t *testing.T, banner string) (port uint16, cancel func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte(banner))
			}()
		}
	}()

	return uint16(l.Addr().(*net.TCPAddr).Port), func() { l.Close() }
}

// startSilentServer listens on a random loopback port, accepts connections,
// but never sends any data — used to exercise timeout behaviour in GrabBanner.
func startSilentServer(t *testing.T) (port uint16, cancel func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Block until the connection is closed by the client or listener.
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)
			}()
		}
	}()

	return uint16(l.Addr().(*net.TCPAddr).Port), func() { l.Close() }
}

// TestGrabBanner_WithBanner verifies that GrabBanner returns the server's
// greeting with non-printable bytes stripped.
func TestGrabBanner_WithBanner(t *testing.T) {
	const greeting = "SSH-2.0-OpenSSH_9.3\r\n"
	port, cancel := startBannerServer(t, greeting)
	defer cancel()

	got := scan.GrabBanner(context.Background(), "127.0.0.1", port, time.Second)
	assert.Contains(t, got, "SSH-2.0-OpenSSH", "banner should contain the SSH version string")
}

// TestGrabBanner_ControlCharsStripped verifies that null bytes and control
// characters are removed from the returned banner.
func TestGrabBanner_ControlCharsStripped(t *testing.T) {
	// Banner with embedded null bytes and a BEL control character.
	port, cancel := startBannerServer(t, "hello\x00world\x07\r\n")
	defer cancel()

	got := scan.GrabBanner(context.Background(), "127.0.0.1", port, time.Second)
	assert.Equal(t, "helloworld", got)
}

// TestGrabBanner_Timeout verifies that GrabBanner returns an empty string when
// the server accepts the connection but never sends data within the timeout.
func TestGrabBanner_Timeout(t *testing.T) {
	port, cancel := startSilentServer(t)
	defer cancel()

	got := scan.GrabBanner(context.Background(), "127.0.0.1", port, 50*time.Millisecond)
	assert.Empty(t, got, "should return empty string when server sends no data before deadline")
}

// TestGrabBanner_NoServer verifies that GrabBanner returns an empty string
// when the target port is not listening (connection refused).
func TestGrabBanner_NoServer(t *testing.T) {
	port := freePort(t)
	got := scan.GrabBanner(context.Background(), "127.0.0.1", port, 200*time.Millisecond)
	assert.Empty(t, got)
}

// TestServiceHint_BannerPriority verifies that banner-based detection takes
// precedence over the port-number map.
func TestServiceHint_BannerPriority(t *testing.T) {
	// Port 80 is HTTP by port map, but the banner says SSH — banner wins.
	got := scan.ServiceHint(80, "SSH-2.0-OpenSSH_9.3")
	assert.Equal(t, "SSH", got)
}

// TestServiceHint_KnownPorts verifies the port-number fallback for common
// services, including every entry required by the spec (≥ 20 services).
func TestServiceHint_KnownPorts(t *testing.T) {
	cases := []struct {
		port    uint16
		banner  string
		want    string
	}{
		{21, "", "FTP"},
		{22, "", "SSH"},
		{22, "SSH-2.0-OpenSSH_9.3", "SSH"},
		{23, "", "Telnet"},
		{25, "", "SMTP"},
		{53, "", "DNS"},
		{80, "", "HTTP"},
		{110, "", "POP3"},
		{143, "", "IMAP"},
		{389, "", "LDAP"},
		{443, "", "HTTPS"},
		{445, "", "SMB"},
		{1433, "", "MSSQL"},
		{1521, "", "Oracle"},
		{2181, "", "ZooKeeper"},
		{3306, "", "MySQL"},
		{3389, "", "RDP"},
		{5432, "", "PostgreSQL"},
		{5900, "", "VNC"},
		{6379, "", "Redis"},
		{8080, "", "HTTP-Proxy"},
		{8443, "", "HTTPS-Alt"},
		{9092, "", "Kafka"},
		{9200, "", "Elasticsearch"},
		{11211, "", "Memcached"},
		{27017, "", "MongoDB"},
		{9999, "", ""},  // unknown port with no banner → empty
	}
	for _, tc := range cases {
		got := scan.ServiceHint(tc.port, tc.banner)
		assert.Equal(t, tc.want, got, "port=%d banner=%q", tc.port, tc.banner)
	}
}

// ---------------------------------------------------------------------------
// Export tests
// ---------------------------------------------------------------------------

// sampleResults returns a small deterministic slice used by export tests.
func sampleResults() []scan.Result {
	return []scan.Result{
		{IP: "127.0.0.1", Port: 80, State: scan.StateOpen, Service: "HTTP", Latency: 10 * time.Millisecond},
		{IP: "127.0.0.1", Port: 443, State: scan.StateClosed, Service: "HTTPS", Latency: 5 * time.Millisecond},
		{IP: "10.0.0.1", Port: 22, State: scan.StateOpen, Service: "SSH", Banner: "SSH-2.0-OpenSSH_9.3", Latency: 20 * time.Millisecond},
	}
}

// TestExportJSON_ValidParse verifies that ExportJSON produces valid JSON that
// can be unmarshalled and contains the expected number of records.
func TestExportJSON_ValidParse(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, scan.ExportJSON(sampleResults(), &buf))

	var records []map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &records), "output must be valid JSON")
	assert.Len(t, records, 3)

	// Spot-check field names and value types.
	first := records[0]
	assert.Equal(t, "127.0.0.1", first["ip"])
	assert.Equal(t, "open", first["state"], "state should be serialised as a string")
	_, hasLatency := first["latency_ms"]
	assert.True(t, hasLatency, "latency_ms field must be present")
}

// TestExportJSON_Empty verifies that ExportJSON produces a valid empty JSON
// array when given no results.
func TestExportJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, scan.ExportJSON(nil, &buf))

	var records []map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &records))
	assert.Empty(t, records)
}

// TestExportCSV_RowCount verifies that ExportCSV writes exactly one header row
// plus one data row per result.
func TestExportCSV_RowCount(t *testing.T) {
	results := sampleResults()
	var buf bytes.Buffer
	require.NoError(t, scan.ExportCSV(results, &buf))

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// header + 3 data rows = 4 lines
	assert.Len(t, lines, 4, "expected 1 header + %d data rows", len(results))
}

// TestExportCSV_Header verifies that the first row of the CSV output matches
// the documented column order.
func TestExportCSV_Header(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, scan.ExportCSV(sampleResults(), &buf))

	r := csv.NewReader(&buf)
	header, err := r.Read()
	require.NoError(t, err)
	assert.Equal(t, []string{"IP", "Port", "State", "Service", "Banner", "Latency"}, header)
}

// TestExportCSV_Values verifies that data rows contain the correct field values
// for a Result with all fields populated.
func TestExportCSV_Values(t *testing.T) {
	results := []scan.Result{
		{IP: "192.168.1.1", Port: 22, State: scan.StateOpen, Service: "SSH",
			Banner: "SSH-2.0", Latency: 1500 * time.Microsecond},
	}

	var buf bytes.Buffer
	require.NoError(t, scan.ExportCSV(results, &buf))

	r := csv.NewReader(&buf)
	rows, err := r.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2) // header + 1 data row

	data := rows[1]
	assert.Equal(t, "192.168.1.1", data[0])
	assert.Equal(t, "22", data[1])
	assert.Equal(t, "open", data[2])
	assert.Equal(t, "SSH", data[3])
	assert.Equal(t, "SSH-2.0", data[4])
}
