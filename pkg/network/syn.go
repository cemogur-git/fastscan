package network

import (
	"context"
	"fmt"

	"github.com/cemogur-git/fastscan/pkg/scan"
)

// SYNScanner performs TCP SYN (half-open) scanning via raw packets.
// Because it never completes the three-way handshake, it is faster and
// less visible in application logs than a full connect scan.
//
// CAP_NET_RAW is required; use scan.ConnectScanner when privileges are
// unavailable.
type SYNScanner struct {
	sender PacketSender
}

// NewSYNScanner constructs a SYNScanner that uses sender for packet delivery.
func NewSYNScanner(sender PacketSender) *SYNScanner {
	return &SYNScanner{sender: sender}
}

// Scan implements scan.Scanner using raw SYN packets.
// Responses are captured by listening on the raw socket for SYN-ACK / RST.
// targets must be valid IPv4 address strings; ports is the list of ports to probe.
//
// CAP_NET_RAW is required.
func (s *SYNScanner) Scan(ctx context.Context, targets []string, ports []uint16) (<-chan scan.Result, error) {
	if s.sender == nil {
		return nil, fmt.Errorf("SYNScanner.Scan: PacketSender is nil")
	}
	return nil, fmt.Errorf("SYNScanner.Scan: not implemented")
}
