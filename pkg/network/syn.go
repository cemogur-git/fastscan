package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/cemogur-git/fastscan/pkg/scan"
	"golang.org/x/sync/semaphore"
)

// ephemeralBase is the starting source port used for SYN probes.
// Linux ephemeral range is 32768–60999; we use the low end so it is
// predictable in tests while staying out of well-known port territory.
const ephemeralBase = 32768

// SYNScanner performs TCP SYN (half-open) scanning via raw packets.
// It never completes the three-way handshake, making it faster and
// less visible in application logs than a full connect scan.
//
// CAP_NET_RAW is required; use scan.ConnectScanner when privileges are
// unavailable.
type SYNScanner struct {
	sender PacketSender
	cfg    scan.ScanConfig
	// localIP is the source address written into outbound SYN packets.
	// Resolved from the local default route when not set explicitly.
	localIP net.IP
}

// NewSYNScanner constructs a SYNScanner that uses sender for packet delivery.
// cfg carries concurrency, rate-limit, and timeout settings.
// localIP is the source IPv4 address embedded in outbound packets; pass nil
// to use 127.0.0.1 (useful only for loopback tests — production callers
// should supply the real outbound interface address).
func NewSYNScanner(sender PacketSender, cfg scan.ScanConfig, localIP net.IP) *SYNScanner {
	if localIP == nil {
		localIP = net.IPv4(127, 0, 0, 1)
	}
	return &SYNScanner{sender: sender, cfg: cfg, localIP: localIP}
}

// Scan implements scan.Scanner using raw SYN packets.
//
// For each (target, port) pair a SYN is sent; the response is parsed for
// SYN-ACK (open) or RST (closed). A RST is sent after a SYN-ACK to
// cleanly abort the half-open connection before the kernel sends one.
// A bounded semaphore caps in-flight goroutines at cfg.Concurrency.
//
// CAP_NET_RAW is required.
func (s *SYNScanner) Scan(ctx context.Context, targets []string, ports []uint16) (<-chan scan.Result, error) {
	if s.sender == nil {
		return nil, fmt.Errorf("SYNScanner.Scan: PacketSender is nil")
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("SYNScanner.Scan: target list is empty")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("SYNScanner.Scan: port list is empty")
	}

	results := make(chan scan.Result, s.cfg.Concurrency)
	sem := semaphore.NewWeighted(int64(s.cfg.Concurrency))

	go func() {
		defer close(results)

		var wg sync.WaitGroup
		portIdx := 0 // monotonically incremented to derive unique source ports

	loop:
		for _, target := range targets {
			for _, port := range ports {
				if err := sem.Acquire(ctx, 1); err != nil {
					break loop
				}

				// Each probe uses a distinct ephemeral source port so the
				// receive filter in SendRecv can match replies unambiguously.
				srcPort := uint16(ephemeralBase + (portIdx % 10000)) //nolint:gosec
				portIdx++

				wg.Add(1)
				go func(ip string, dstPort, sp uint16) {
					defer wg.Done()
					defer sem.Release(1)

					r := s.probe(ctx, ip, dstPort, sp)
					select {
					case results <- r:
					case <-ctx.Done():
					}
				}(target, port, srcPort)
			}
		}

		wg.Wait()
	}()

	return results, nil
}

// probe sends a single SYN to (ip, dstPort) from srcPort and interprets
// the response. It returns StateFiltered on timeout or context cancellation.
func (s *SYNScanner) probe(ctx context.Context, ip string, dstPort, srcPort uint16) scan.Result {
	dst := net.ParseIP(ip)
	if dst == nil {
		return scan.Result{IP: ip, Port: dstPort, State: scan.StateFiltered}
	}

	probeCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	pkt := buildSynPacket(s.localIP, dst, srcPort, dstPort)

	raw, err := s.sender.SendRecv(probeCtx, pkt, srcPort)
	if err != nil {
		// Timeout or context cancellation → filtered.
		return scan.Result{IP: ip, Port: dstPort, State: scan.StateFiltered}
	}

	flags, _, parseErr := parseTCPResponse(raw)
	if parseErr != nil {
		return scan.Result{IP: ip, Port: dstPort, State: scan.StateFiltered}
	}

	switch {
	case flags&synAckFlags == synAckFlags:
		// Port is open: send RST to abort the half-open connection cleanly,
		// preventing the remote from accumulating half-open state.
		rst := buildRSTPacket(s.localIP, dst, srcPort, dstPort)
		_ = s.sendOnly(ctx, rst) // best-effort; ignore RST send errors
		return scan.Result{IP: ip, Port: dstPort, State: scan.StateOpen}

	case flags&rstFlag != 0:
		return scan.Result{IP: ip, Port: dstPort, State: scan.StateClosed}

	default:
		return scan.Result{IP: ip, Port: dstPort, State: scan.StateFiltered}
	}
}

// sendOnly transmits pkt without waiting for a reply. Used to send RST packets
// after a SYN-ACK is received so the remote kernel does not accumulate
// half-open connections.
func (s *SYNScanner) sendOnly(ctx context.Context, pkt []byte) error {
	// We fabricate a dummy srcPort of 0 — SendRecv will never match a reply
	// because we immediately discard this context and move on.
	noReplyCtx, cancel := context.WithCancel(ctx)
	cancel() // cancel immediately so SendRecv returns without blocking
	_, err := s.sender.SendRecv(noReplyCtx, pkt, 0)
	return err
}

// buildRSTPacket constructs a 40-byte IPv4/TCP RST packet to abort a
// half-open connection after receiving a SYN-ACK.
func buildRSTPacket(src, dst net.IP, srcPort, dstPort uint16) []byte {
	pkt := buildSynPacket(src, dst, srcPort, dstPort)
	// Overwrite the flags byte (IP header 20 bytes + TCP flags at offset 13).
	pkt[ipHeaderLen+13] = flagRST

	// Recompute TCP checksum — flags changed.
	tcp := pkt[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcp[16:18], 0) // zero out old checksum
	chk := tcpChecksum(src.To4(), dst.To4(), tcp)
	binary.BigEndian.PutUint16(tcp[16:18], chk)

	return pkt
}
