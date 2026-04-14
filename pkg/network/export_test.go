// export_test.go exposes internal functions for white-box testing.
// This file is compiled only when running tests (the _test.go suffix).
package network

import "net"

// BuildSynPacketExported calls the internal buildSynPacket for use in tests.
func BuildSynPacketExported(src, dst net.IP, srcPort, dstPort uint16) []byte {
	return buildSynPacket(src, dst, srcPort, dstPort)
}

// ParseTCPResponseExported calls the internal parseTCPResponse for use in tests.
func ParseTCPResponseExported(raw []byte) (flags byte, srcPort uint16, err error) {
	return parseTCPResponse(raw)
}
