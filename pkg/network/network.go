// Package network handles raw socket operations and low-level packet
// construction for fastscan. All exported functions in this package may
// require the CAP_NET_RAW Linux capability; this is documented per-function.
//
// Raw socket code must not appear anywhere outside this package.
package network

import (
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketSender abstracts the transmission of raw network packets.
// All implementations must be safe for concurrent use.
type PacketSender interface {
	// Send transmits packet to dst. The caller retains ownership of packet
	// after Send returns; implementations must not modify or retain it.
	Send(ctx context.Context, dst net.IP, packet []byte) error
	// Close releases any underlying OS resources (sockets, handles).
	Close() error
}

// RawSocket is a PacketSender backed by an AF_PACKET socket on Linux.
//
// CAP_NET_RAW is required to open this socket.
type RawSocket struct {
	iface  string
	handle gopacket.PacketDataSource // will be *pcap.Handle in implementation
}

// NewRawSocket opens a raw packet socket on the named network interface.
//
// CAP_NET_RAW is required on Linux.
func NewRawSocket(iface string) (*RawSocket, error) {
	return nil, fmt.Errorf("NewRawSocket: not implemented")
}

// Send implements PacketSender.
//
// CAP_NET_RAW is required.
func (r *RawSocket) Send(ctx context.Context, dst net.IP, packet []byte) error {
	return fmt.Errorf("RawSocket.Send: not implemented")
}

// Close implements PacketSender.
func (r *RawSocket) Close() error {
	return fmt.Errorf("RawSocket.Close: not implemented")
}

// buildEthernetFrame wraps payload in an Ethernet + IP + TCP frame.
// Kept internal; callers use SYNScanner.
func buildEthernetFrame(dst net.IP, payload []byte) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Placeholder: serialize an empty TCP layer to confirm gopacket linkage.
	tcp := &layers.TCP{}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return nil, fmt.Errorf("buildEthernetFrame: %w", err)
	}

	return buf.Bytes(), fmt.Errorf("buildEthernetFrame: not implemented")
}
