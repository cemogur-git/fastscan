// Package utils provides shared helper utilities for fastscan:
// target parsing (IP / CIDR / range), port expression parsing, and structured logging.
package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// maxTargets caps the number of addresses a single ParseTargets call may expand
// to. This prevents accidental /0 or /1 expansions from allocating gigabytes
// of memory.
const maxTargets = 1 << 20 // 1,048,576

// ParseTargets parses a target expression and returns the list of IP address
// strings it represents. Three formats are accepted:
//
//   - Single IP:    "192.168.1.1"
//   - CIDR block:   "192.168.1.0/24"  (network and broadcast excluded for prefix < /31)
//   - Octet range:  "192.168.1.1-20"  (last-octet range, inclusive)
//
// An error is returned for invalid input or if the expanded set would exceed
// maxTargets addresses (guards against /0 exhausting memory).
func ParseTargets(input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("ParseTargets: input is empty")
	}

	switch {
	case strings.Contains(input, "/"):
		return parseCIDRTargets(input)
	case strings.Contains(input, "-"):
		return parseRangeTargets(input)
	default:
		return parseSingleTarget(input)
	}
}

// parseSingleTarget validates and returns a single IP address string.
func parseSingleTarget(input string) ([]string, error) {
	ip := net.ParseIP(strings.TrimSpace(input))
	if ip == nil {
		return nil, fmt.Errorf("ParseTargets: %q is not a valid IP address", input)
	}
	// Normalize to dotted-decimal IPv4 when possible.
	if v4 := ip.To4(); v4 != nil {
		return []string{v4.String()}, nil
	}
	return []string{ip.String()}, nil
}

// parseCIDRTargets enumerates all host addresses within a CIDR block.
//
// Handling by prefix length:
//   - /32 → the single host address
//   - /31 → both addresses (RFC 3021 point-to-point; no network/broadcast)
//   - ≤/30 → all addresses between network+1 and broadcast-1 (inclusive)
func parseCIDRTargets(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("ParseTargets: invalid CIDR %q: %w", cidr, err)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("ParseTargets: IPv6 CIDR not yet supported: %q", cidr)
	}

	// /32: exactly one host.
	if ones == 32 {
		return []string{ipNet.IP.To4().String()}, nil
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("ParseTargets: could not convert network address to IPv4: %q", cidr)
	}

	networkAddr := ip4ToUint32(ip4)
	broadcastAddr := networkAddr | ^maskToUint32(ipNet.Mask)

	var first, last uint32
	if ones >= 31 {
		// /31: RFC 3021 — both addresses are usable hosts.
		first, last = networkAddr, broadcastAddr
	} else {
		first, last = networkAddr+1, broadcastAddr-1
	}

	// Guard: last can underflow to 0xFFFFFFFF if the subnet is /32 handled
	// above, but be safe anyway.
	if first > last {
		return nil, fmt.Errorf("ParseTargets: CIDR %q contains no host addresses", cidr)
	}

	count := int64(last) - int64(first) + 1
	if count > maxTargets {
		return nil, fmt.Errorf("ParseTargets: CIDR %q would expand to %d addresses (limit %d); use a smaller prefix", cidr, count, maxTargets)
	}

	ips := make([]string, 0, count)
	for i := first; i <= last; i++ {
		ips = append(ips, uint32ToIP4(i).String())
	}
	return ips, nil
}

// parseRangeTargets expands a last-octet range expression such as
// "192.168.1.1-20" into the IPs 192.168.1.1 through 192.168.1.20.
// The end value must be >= the start octet and <= 255.
func parseRangeTargets(input string) ([]string, error) {
	// Use the last "-" so that the start address can contain hyphens-as-octets
	// if ever extended, and to keep the split unambiguous.
	dashIdx := strings.LastIndex(input, "-")
	startStr := strings.TrimSpace(input[:dashIdx])
	endStr := strings.TrimSpace(input[dashIdx+1:])

	startIP := net.ParseIP(startStr)
	if startIP == nil {
		return nil, fmt.Errorf("ParseTargets: invalid start IP %q in range %q", startStr, input)
	}
	startIP4 := startIP.To4()
	if startIP4 == nil {
		return nil, fmt.Errorf("ParseTargets: IPv6 ranges not yet supported: %q", input)
	}

	endOctet, err := strconv.ParseUint(endStr, 10, 9) // 9 bits catches >255
	if err != nil || endOctet > 255 {
		return nil, fmt.Errorf("ParseTargets: invalid end octet %q in range %q (must be 0–255)", endStr, input)
	}

	startOctet := uint64(startIP4[3])
	if endOctet < startOctet {
		return nil, fmt.Errorf("ParseTargets: range end %d is less than start %d in %q", endOctet, startOctet, input)
	}

	count := int(endOctet - startOctet + 1)
	ips := make([]string, 0, count)
	for i := startOctet; i <= endOctet; i++ {
		ip := net.IP{startIP4[0], startIP4[1], startIP4[2], byte(i)}
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// ip4ToUint32 converts a 4-byte IPv4 address to a uint32 (big-endian).
func ip4ToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP4 converts a uint32 back to a 4-byte net.IP (big-endian).
func uint32ToIP4(n uint32) net.IP {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// maskToUint32 converts a 4-byte net.IPMask to a uint32 (big-endian).
func maskToUint32(mask net.IPMask) uint32 {
	return uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
}
