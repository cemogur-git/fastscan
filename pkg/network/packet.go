package network

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
)

// TCP flag bit masks (RFC 793 §3.1).
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
	flagURG = 0x20

	synAckFlags = flagSYN | flagACK // 0x12 — port is open
	rstFlag     = flagRST           // 0x04 — port is closed

	tcpWindow    = 65535
	ipTTL        = 64
	ipProtoTCP   = 6
	ipVersion    = 0x45 // version=4, IHL=5 (20 bytes, no options)
	tcpDataOff   = 0x50 // data offset = 5 (20 bytes), reserved = 0
)

// buildSynPacket constructs a raw 40-byte IPv4/TCP SYN packet.
//
// The returned slice is [20-byte IP header | 20-byte TCP header].
// Both IP and TCP checksums are computed per RFC 791 / RFC 793.
// src and dst must be 4-byte IPv4 addresses (net.IP.To4()).
func buildSynPacket(src, dst net.IP, srcPort, dstPort uint16) []byte {
	src4 := src.To4()
	dst4 := dst.To4()

	pkt := make([]byte, ipHeaderLen+tcpHeaderLen)

	// ── IP header ──────────────────────────────────────────────
	pkt[0] = ipVersion                                       // version + IHL
	pkt[1] = 0                                               // DSCP / ECN
	binary.BigEndian.PutUint16(pkt[2:4], ipHeaderLen+tcpHeaderLen) // total length
	binary.BigEndian.PutUint16(pkt[4:6], 0)                  // identification
	binary.BigEndian.PutUint16(pkt[6:8], 0)                  // flags + fragment offset
	pkt[8] = ipTTL                                           // TTL
	pkt[9] = ipProtoTCP                                      // protocol
	// checksum bytes [10:12] stay zero until we compute below
	copy(pkt[12:16], src4) // source IP
	copy(pkt[16:20], dst4) // destination IP

	ipChecksum := checksumRFC1071(pkt[0:ipHeaderLen])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum)

	// ── TCP header ─────────────────────────────────────────────
	tcp := pkt[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)  // source port
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)  // destination port
	// Random Initial Sequence Number — avoids predictable sequences.
	isn := rand.Uint32() //nolint:gosec // ISN randomness does not need crypto quality
	binary.BigEndian.PutUint32(tcp[4:8], isn)      // sequence number
	binary.BigEndian.PutUint32(tcp[8:12], 0)       // acknowledgement number
	tcp[12] = tcpDataOff                            // data offset + reserved
	tcp[13] = flagSYN                               // flags: SYN only
	binary.BigEndian.PutUint16(tcp[14:16], tcpWindow) // window size
	// checksum bytes [16:18] computed via pseudo-header below
	binary.BigEndian.PutUint16(tcp[18:20], 0)      // urgent pointer

	tcpChecksum := tcpChecksum(src4, dst4, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum)

	return pkt
}

// tcpChecksum computes the TCP checksum using the RFC 793 pseudo-header.
// The pseudo-header covers: source IP, destination IP, zero byte, protocol,
// TCP segment length, and the full TCP segment itself.
func tcpChecksum(src, dst []byte, tcpSeg []byte) uint16 {
	tcpLen := len(tcpSeg)
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0           // reserved
	pseudo[9] = ipProtoTCP  // protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen)) //nolint:gosec
	copy(pseudo[12:], tcpSeg)
	return checksumRFC1071(pseudo)
}

// parseTCPResponse parses a raw IP packet (as returned by the receive socket)
// and extracts the TCP flags and TCP source port.
//
// Returns an error for truncated or malformed packets.
// Callers typically check:
//
//	flags == synAckFlags (0x12) → port open
//	flags == rstFlag     (0x04) → port closed
func parseTCPResponse(raw []byte) (flags byte, srcPort uint16, err error) {
	if len(raw) < ipHeaderLen {
		return 0, 0, fmt.Errorf("parseTCPResponse: packet too short for IP header (%d bytes)", len(raw))
	}

	ihl := int(raw[0]&0x0f) * 4
	if ihl < ipHeaderLen || len(raw) < ihl+tcpHeaderLen {
		return 0, 0, fmt.Errorf("parseTCPResponse: packet too short for TCP header (ihl=%d, len=%d)", ihl, len(raw))
	}

	tcp := raw[ihl:]
	srcPort = binary.BigEndian.Uint16(tcp[0:2])
	flags = tcp[13]
	return flags, srcPort, nil
}
