// Package network handles raw socket operations and low-level packet
// construction for fastscan. All exported symbols that open or transmit
// raw sockets require the CAP_NET_RAW Linux capability; this is noted
// per-function. Raw socket code must never appear outside this package.
package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// PacketSender abstracts low-level packet transmission and reception.
// Implementations must be safe for concurrent use.
type PacketSender interface {
	// SendRecv sends pkt on the wire and waits for an IP reply whose TCP
	// source port equals srcPort. The raw IP response bytes are returned.
	// Callers own both slices; implementations must not retain them.
	SendRecv(ctx context.Context, pkt []byte, srcPort uint16) ([]byte, error)

	// Close releases underlying OS resources (sockets, handles).
	Close() error
}

// RawSocket is a PacketSender backed by a raw IP socket (IPPROTO_RAW) on
// Linux. A companion SOCK_RAW/IPPROTO_TCP socket is opened for reception so
// that only TCP segments addressed to the ephemeral source port are returned.
//
// CAP_NET_RAW is required to open either socket.
type RawSocket struct {
	iface   string
	sendFd  int // IPPROTO_RAW for sending hand-crafted IP packets
	recvFd  int // IPPROTO_TCP raw socket for capturing inbound TCP segments
}

// NewRawSocket opens a pair of raw sockets bound to iface for SYN scanning.
//
// CAP_NET_RAW is required on Linux. Returns an error if the capability is
// absent or if the interface does not exist.
func NewRawSocket(iface string) (*RawSocket, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, fmt.Errorf("NewRawSocket: unknown interface %q: %w", iface, err)
	}

	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("NewRawSocket: open send socket: %w", err)
	}

	// IP_HDRINCL tells the kernel that we supply our own IP header.
	hdrincl := 1
	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, hdrincl); err != nil {
		_ = syscall.Close(sendFd)
		return nil, fmt.Errorf("NewRawSocket: IP_HDRINCL: %w", err)
	}

	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		_ = syscall.Close(sendFd)
		return nil, fmt.Errorf("NewRawSocket: open recv socket: %w", err)
	}

	return &RawSocket{iface: iface, sendFd: sendFd, recvFd: recvFd}, nil
}

// SendRecv implements PacketSender.
//
// CAP_NET_RAW is required.
func (r *RawSocket) SendRecv(ctx context.Context, pkt []byte, srcPort uint16) ([]byte, error) {
	if len(pkt) < ipHeaderLen {
		return nil, fmt.Errorf("RawSocket.SendRecv: packet too short")
	}

	// Parse destination IP from our pre-built packet header (bytes 16-20).
	dstIP := net.IP(pkt[16:20])
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], dstIP.To4())

	if err := syscall.Sendto(r.sendFd, pkt, 0, sa); err != nil {
		return nil, fmt.Errorf("RawSocket.SendRecv: sendto: %w", err)
	}

	// Receive loop: discard packets that don't match srcPort as dstPort.
	buf := make([]byte, recvBufSize)
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		n, _, err := syscall.Recvfrom(r.recvFd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("RawSocket.SendRecv: recvfrom: %w", err)
		}

		raw := buf[:n]
		if len(raw) < ipHeaderLen+tcpHeaderLen {
			continue
		}
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) < ihl+tcpHeaderLen {
			continue
		}

		// TCP destination port sits at offset 2 inside the TCP header.
		dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
		if dstPort != srcPort {
			continue
		}

		out := make([]byte, n)
		copy(out, raw)
		return out, nil
	}
}

// Close implements PacketSender.
func (r *RawSocket) Close() error {
	e1 := syscall.Close(r.sendFd)
	e2 := syscall.Close(r.recvFd)
	if e1 != nil {
		return fmt.Errorf("RawSocket.Close: %w", e1)
	}
	if e2 != nil {
		return fmt.Errorf("RawSocket.Close: %w", e2)
	}
	return nil
}

// checksumRFC1071 computes the Internet checksum (RFC 1071) over data.
// The slice length must be even; callers must pad if necessary.
func checksumRFC1071(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum) //nolint:gosec // intentional bit-flip for checksum
}

// nativeEndian detects the host byte order once at init time via unsafe.
// Used only for setsockopt calls where the kernel expects native-endian ints.
var nativeEndian = func() binary.ByteOrder {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	if buf[0] == 0xAB {
		return binary.BigEndian
	}
	return binary.LittleEndian
}()

// Size constants — avoids magic numbers throughout the package.
const (
	ipHeaderLen  = 20
	tcpHeaderLen = 20
	recvBufSize  = 4096
)
