// Package tests contains integration tests for fastscan.
// These tests exercise multiple packages together but never open real
// outbound network connections — they use loopback or mock sockets only.
package tests

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cemogur-git/fastscan/pkg/network"
	"github.com/cemogur-git/fastscan/pkg/scan"
	"github.com/cemogur-git/fastscan/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TCP flag bit values that mirror the unexported constants in pkg/network.
const (
	tcpFlagSYN = byte(0x02)
	tcpFlagACK = byte(0x10)
	tcpFlagRST = byte(0x04)
	tcpSynAck  = tcpFlagSYN | tcpFlagACK // 0x12 — port is open
)

// mockSender implements network.PacketSender without raw sockets.
// The responses map associates destination ports with the TCP flags byte the
// mock should echo back. Ports absent from the map block until the probe
// context expires, simulating a filtered (no-response) port.
type mockSender struct {
	mu        sync.Mutex
	responses map[uint16]byte // dstPort → TCP flags
}

// SendRecv implements PacketSender.
//
// It extracts the destination port from the outgoing SYN packet at bytes
// 22-23 (IP header 20 bytes + TCP dst-port offset 2) and returns a synthetic
// 40-byte IP/TCP packet whose flags byte reflects the configured response.
// A cancelled context returns immediately — this is the path taken by
// SYNScanner.sendOnly when dispatching RST packets after a SYN-ACK.
func (m *mockSender) SendRecv(ctx context.Context, pkt []byte, _ uint16) ([]byte, error) {
	// SYNScanner.sendOnly cancels the context before calling SendRecv so that
	// the RST transmission does not block. Return immediately in that case.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if len(pkt) < 24 {
		return nil, fmt.Errorf("mock: packet too short (%d bytes)", len(pkt))
	}

	// TCP destination port in an outbound SYN packet:
	// IP header (20 bytes) + TCP dst-port field (offset 2) = byte 22.
	dstPort := binary.BigEndian.Uint16(pkt[22:24])

	m.mu.Lock()
	flags, ok := m.responses[dstPort]
	m.mu.Unlock()

	if !ok {
		// Simulate a non-responsive (filtered) host: block until the probe
		// context is cancelled by the per-probe timeout in SYNScanner.probe.
		<-ctx.Done()
		return nil, ctx.Err()
	}

	// Construct a minimal 40-byte IPv4/TCP packet that parseTCPResponse can
	// decode: IPv4 version+IHL=0x45 at byte 0, TCP flags at byte 33
	// ([IHL=20] + [TCP flags offset=13]).
	raw := make([]byte, 40)
	raw[0] = 0x45  // IPv4, IHL = 5 × 4 = 20 bytes
	raw[33] = flags // TCP flags at IP header (20) + TCP flags offset (13)
	return raw, nil
}

// Close implements PacketSender.
func (m *mockSender) Close() error { return nil }

// Compile-time assertion: mockSender must satisfy the PacketSender interface.
var _ network.PacketSender = (*mockSender)(nil)

// findFreePorts temporarily binds n TCP listeners on 127.0.0.1 to obtain
// OS-assigned free port numbers, then closes all listeners before returning.
// Callers that need the ports to remain unbound (AllClosed test) should call
// this; callers that need the ports to stay open should open their own
// listeners directly.
func findFreePorts(t *testing.T, n int) []uint16 {
	t.Helper()

	listeners := make([]net.Listener, n)
	ports := make([]uint16, n)

	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err, "findFreePorts: bind attempt %d", i)
		listeners[i] = l
		ports[i] = uint16(l.Addr().(*net.TCPAddr).Port)
	}

	for _, l := range listeners {
		l.Close()
	}
	return ports
}

// TestConnectScan_Loopback opens 5 TCP listeners on loopback, runs
// ConnectScanner against those exact ports, and asserts that every port is
// detected as StateOpen.
func TestConnectScan_Loopback(t *testing.T) {
	const portCount = 5

	listeners := make([]net.Listener, portCount)
	openPorts := make([]uint16, portCount)

	for i := 0; i < portCount; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err, "listener %d", i)
		listeners[i] = l
		openPorts[i] = uint16(l.Addr().(*net.TCPAddr).Port)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	cfg := scan.NewScanConfig()
	cfg.Concurrency = 50
	cfg.RateLimit = 0 // loopback does not need rate limiting
	cfg.Timeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner := scan.NewConnectScanner(cfg)
	ch, err := scanner.Scan(ctx, []string{"127.0.0.1"}, openPorts)
	require.NoError(t, err)

	agg := scan.NewAggregator()
	agg.Collect(ch)

	results := agg.Results()
	require.Len(t, results, portCount, "expected one result per scanned port")

	for _, r := range results {
		assert.Equal(t, scan.StateOpen, r.State,
			"loopback port %d should be open", r.Port)
	}
}

// TestConnectScan_AllClosed scans ports that were briefly opened then closed
// so that no listener exists at scan time. All results must be Closed or
// Filtered — none may be Open.
func TestConnectScan_AllClosed(t *testing.T) {
	closedPorts := findFreePorts(t, 3)

	cfg := scan.NewScanConfig()
	cfg.Concurrency = 50
	cfg.RateLimit = 0
	cfg.Timeout = 500 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner := scan.NewConnectScanner(cfg)
	ch, err := scanner.Scan(ctx, []string{"127.0.0.1"}, closedPorts)
	require.NoError(t, err)

	agg := scan.NewAggregator()
	agg.Collect(ch)

	results := agg.Results()
	require.Len(t, results, len(closedPorts))

	for _, r := range results {
		assert.NotEqual(t, scan.StateOpen, r.State,
			"port %d has no listener and must not appear open", r.Port)
	}
}

// TestSYNScanner_MockNetwork verifies SYNScanner result classification using
// a mock PacketSender that returns SYN-ACK for ports 80 and 443 and RST for
// port 22. No raw sockets or elevated privileges are required.
func TestSYNScanner_MockNetwork(t *testing.T) {
	mock := &mockSender{
		responses: map[uint16]byte{
			80:  tcpSynAck,  // → StateOpen
			443: tcpSynAck,  // → StateOpen
			22:  tcpFlagRST, // → StateClosed
		},
	}

	cfg := scan.NewScanConfig()
	cfg.Concurrency = 10
	cfg.RateLimit = 0
	cfg.Timeout = 2 * time.Second

	syn := network.NewSYNScanner(mock, cfg, net.ParseIP("127.0.0.1"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ch, err := syn.Scan(ctx, []string{"127.0.0.1"}, []uint16{22, 80, 443})
	require.NoError(t, err)

	agg := scan.NewAggregator()
	agg.Collect(ch)

	results := agg.Results()
	require.Len(t, results, 3, "expected one result per probed port")

	byPort := make(map[uint16]scan.State, len(results))
	for _, r := range results {
		byPort[r.Port] = r.State
	}

	assert.Equal(t, scan.StateOpen, byPort[80], "port 80: SYN-ACK → open")
	assert.Equal(t, scan.StateOpen, byPort[443], "port 443: SYN-ACK → open")
	assert.Equal(t, scan.StateClosed, byPort[22], "port 22: RST → closed")
}

// TestExportPipeline creates 5 results with mixed states, writes them via
// ExportJSON and ExportCSV, then validates the output structure.
func TestExportPipeline(t *testing.T) {
	results := []scan.Result{
		{IP: "10.0.0.1", Port: 80, State: scan.StateOpen, Service: "http"},
		{IP: "10.0.0.1", Port: 443, State: scan.StateOpen, Service: "https"},
		{IP: "10.0.0.1", Port: 22, State: scan.StateClosed},
		{IP: "10.0.0.1", Port: 8080, State: scan.StateFiltered},
		{IP: "10.0.0.2", Port: 80, State: scan.StateOpen},
	}

	t.Run("JSON_round_trip", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, scan.ExportJSON(results, &buf))

		type jsonRow struct {
			IP    string `json:"ip"`
			Port  uint16 `json:"port"`
			State string `json:"state"`
		}
		var decoded []jsonRow
		require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded),
			"JSON output must be valid")
		require.Len(t, decoded, len(results), "row count must match input")

		for i, orig := range results {
			assert.Equal(t, orig.IP, decoded[i].IP, "row %d: IP", i)
			assert.Equal(t, orig.Port, decoded[i].Port, "row %d: Port", i)
			assert.Equal(t, orig.State.String(), decoded[i].State, "row %d: State", i)
		}
	})

	t.Run("CSV_row_count", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, scan.ExportCSV(results, &buf))

		records, err := csv.NewReader(&buf).ReadAll()
		require.NoError(t, err, "CSV output must be parseable")
		// ExportCSV writes one header row followed by one row per result.
		assert.Len(t, records, len(results)+1,
			"expected 1 header + %d data rows", len(results))
	})
}

// TestParseTargets_Integration verifies that CIDR and range expressions
// expand to the correct number of IP addresses.
func TestParseTargets_Integration(t *testing.T) {
	t.Run("CIDR_slash24", func(t *testing.T) {
		ips, err := utils.ParseTargets("10.0.0.0/24")
		require.NoError(t, err)
		// /24 yields 254 host addresses: .1 through .254 (network and
		// broadcast excluded per parseCIDRTargets semantics).
		assert.Len(t, ips, 254, "/24 should yield 254 host addresses")
		assert.Equal(t, "10.0.0.1", ips[0], "first host must be .1")
		assert.Equal(t, "10.0.0.254", ips[len(ips)-1], "last host must be .254")
	})

	t.Run("range_last_octet", func(t *testing.T) {
		ips, err := utils.ParseTargets("192.168.1.10-20")
		require.NoError(t, err)
		// Inclusive range 10..20 → 11 addresses.
		assert.Len(t, ips, 11, "last-octet range 10-20 is 11 addresses")
		assert.Equal(t, "192.168.1.10", ips[0])
		assert.Equal(t, "192.168.1.20", ips[len(ips)-1])
	})
}

// TestFullPipeline exercises the complete scan workflow end-to-end:
// ParseTargets → ParsePorts → ConnectScanner → Aggregator → ExportJSON.
func TestFullPipeline(t *testing.T) {
	const portCount = 3

	listeners := make([]net.Listener, portCount)
	openPorts := make([]uint16, portCount)

	for i := 0; i < portCount; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err, "listener %d", i)
		listeners[i] = l
		openPorts[i] = uint16(l.Addr().(*net.TCPAddr).Port)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	// Step 1 — ParseTargets: single loopback address.
	targets, err := utils.ParseTargets("127.0.0.1")
	require.NoError(t, err)
	require.Len(t, targets, 1)

	// Step 2 — ParsePorts: build comma-separated expression from listener ports.
	portExprs := make([]string, portCount)
	for i, p := range openPorts {
		portExprs[i] = fmt.Sprintf("%d", p)
	}
	ports, err := utils.ParsePorts(strings.Join(portExprs, ","))
	require.NoError(t, err)
	require.Len(t, ports, portCount)

	// Step 3 — ConnectScanner.
	cfg := scan.NewScanConfig()
	cfg.Concurrency = 50
	cfg.RateLimit = 0
	cfg.Timeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner := scan.NewConnectScanner(cfg)
	ch, err := scanner.Scan(ctx, targets, ports)
	require.NoError(t, err)

	// Step 4 — Aggregator.
	agg := scan.NewAggregator()
	agg.Collect(ch)

	openResults := agg.FilterByState(scan.StateOpen)
	assert.Len(t, openResults, portCount,
		"all %d listening ports must appear as open", portCount)

	// Step 5 — ExportJSON and parse back.
	var buf bytes.Buffer
	require.NoError(t, scan.ExportJSON(agg.Results(), &buf))

	var exported []map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &exported))
	assert.Len(t, exported, portCount)

	// Aggregator.Summary must produce a non-empty string.
	assert.NotEmpty(t, agg.Summary())
}
