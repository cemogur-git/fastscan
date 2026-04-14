package scan_test

import (
	"context"
	"fmt"
	"net"
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
