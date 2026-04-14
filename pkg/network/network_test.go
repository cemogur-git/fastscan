package network_test

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/cemogur-git/fastscan/pkg/network"
	"github.com/cemogur-git/fastscan/pkg/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── buildSynPacket ────────────────────────────────────────────────────────────

func TestBuildSynPacket_Size(t *testing.T) {
	pkt := network.BuildSynPacketExported(
		net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), 40000, 80,
	)
	assert.Len(t, pkt, 40, "packet must be exactly 40 bytes (20 IP + 20 TCP)")
}

func TestBuildSynPacket_SYNFlagOnly(t *testing.T) {
	pkt := network.BuildSynPacketExported(
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 50000, 443,
	)
	// TCP flags are at byte 33 (IP header 20 + TCP offset 13).
	flags := pkt[33]
	assert.Equal(t, byte(0x02), flags, "only SYN flag must be set")
}

func TestBuildSynPacket_IPChecksum(t *testing.T) {
	pkt := network.BuildSynPacketExported(
		net.ParseIP("172.16.0.1"), net.ParseIP("172.16.0.2"), 45000, 22,
	)
	// Verifying the checksum: one's complement sum over 20 bytes must equal 0xffff.
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	assert.Equal(t, uint32(0xffff), sum, "IP header checksum verification must yield 0xffff")
}

func TestBuildSynPacket_TCPChecksum(t *testing.T) {
	src := net.ParseIP("192.168.0.10")
	dst := net.ParseIP("192.168.0.20")
	pkt := network.BuildSynPacketExported(src, dst, 50001, 8080)

	// Build the same pseudo-header the function uses and verify the checksum.
	tcpSeg := pkt[20:]
	pseudo := make([]byte, 12+20)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 0
	pseudo[9] = 6 // IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	copy(pseudo[12:], tcpSeg)

	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	assert.Equal(t, uint32(0xffff), sum, "TCP checksum verification must yield 0xffff")
}

// ── parseTCPResponse ──────────────────────────────────────────────────────────

// makeTCPResponse builds a minimal raw IP+TCP reply for test use.
func makeTCPResponse(srcPort uint16, flags byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[9] = 6
	// TCP source port at offset 20
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	// TCP flags at offset 33
	pkt[33] = flags
	return pkt
}

func TestParseTCPResponse_SYNACKPort(t *testing.T) {
	raw := makeTCPResponse(8080, 0x12) // SYN-ACK
	flags, srcPort, err := network.ParseTCPResponseExported(raw)
	require.NoError(t, err)
	assert.Equal(t, byte(0x12), flags)
	assert.Equal(t, uint16(8080), srcPort)
}

func TestParseTCPResponse_RST(t *testing.T) {
	raw := makeTCPResponse(443, 0x04) // RST
	flags, srcPort, err := network.ParseTCPResponseExported(raw)
	require.NoError(t, err)
	assert.Equal(t, byte(0x04), flags)
	assert.Equal(t, uint16(443), srcPort)
}

func TestParseTCPResponse_TooShort(t *testing.T) {
	_, _, err := network.ParseTCPResponseExported([]byte{0x45, 0x00})
	require.Error(t, err, "truncated packet must return an error")
}

func TestParseTCPResponse_TruncatedTCP(t *testing.T) {
	pkt := make([]byte, 25) // IP header OK, TCP header truncated
	pkt[0] = 0x45
	_, _, err := network.ParseTCPResponseExported(pkt)
	require.Error(t, err)
}

// ── SYNScanner (mock-based) ───────────────────────────────────────────────────

// mockSender is a PacketSender that returns a pre-built response without
// touching the network. Safe for concurrent use via value semantics.
type mockSender struct {
	response []byte
	sendErr  error
}

func (m *mockSender) SendRecv(_ context.Context, _ []byte, _ uint16) ([]byte, error) {
	if m.sendErr != nil {
		return nil, m.sendErr
	}
	out := make([]byte, len(m.response))
	copy(out, m.response)
	return out, nil
}

func (m *mockSender) Close() error { return nil }

func TestSYNScanner_OpenPort(t *testing.T) {
	// Mock returns a SYN-ACK from port 80 so the scanner reports StateOpen.
	resp := makeTCPResponse(80, 0x12)
	ms := &mockSender{response: resp}

	cfg := scan.NewScanConfig()
	cfg.Concurrency = 10
	s := network.NewSYNScanner(ms, cfg, net.ParseIP("127.0.0.1"))

	ctx := context.Background()
	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, []uint16{80})
	require.NoError(t, err)

	var results []scan.Result
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, scan.StateOpen, results[0].State)
	assert.Equal(t, uint16(80), results[0].Port)
}

func TestSYNScanner_ClosedPort(t *testing.T) {
	resp := makeTCPResponse(22, 0x04) // RST
	ms := &mockSender{response: resp}

	cfg := scan.NewScanConfig()
	s := network.NewSYNScanner(ms, cfg, net.ParseIP("127.0.0.1"))

	ctx := context.Background()
	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, []uint16{22})
	require.NoError(t, err)

	var results []scan.Result
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, scan.StateClosed, results[0].State)
}

func TestSYNScanner_FilteredOnSendError(t *testing.T) {
	ms := &mockSender{sendErr: assert.AnError}

	cfg := scan.NewScanConfig()
	s := network.NewSYNScanner(ms, cfg, net.ParseIP("127.0.0.1"))

	ctx := context.Background()
	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, []uint16{443})
	require.NoError(t, err)

	var results []scan.Result
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, scan.StateFiltered, results[0].State)
}

func TestSYNScanner_EmptyTargets(t *testing.T) {
	ms := &mockSender{}
	cfg := scan.NewScanConfig()
	s := network.NewSYNScanner(ms, cfg, nil)

	_, err := s.Scan(context.Background(), []string{}, []uint16{80})
	require.Error(t, err)
}

func TestSYNScanner_ContextCancellation(t *testing.T) {
	// Sender blocks until ctx is cancelled.
	blocking := &blockingSender{}
	cfg := scan.NewScanConfig()
	cfg.Concurrency = 2
	s := network.NewSYNScanner(blocking, cfg, net.ParseIP("127.0.0.1"))

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, []uint16{80, 443, 8080})
	require.NoError(t, err)

	cancel() // abort immediately

	// Drain the channel; it must close without deadlock.
	for range ch {
	}
}

// blockingSender blocks SendRecv until ctx is done, simulating a slow network.
type blockingSender struct{}

func (b *blockingSender) SendRecv(ctx context.Context, _ []byte, _ uint16) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *blockingSender) Close() error { return nil }
