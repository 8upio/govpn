// Package netstacktest provides supported test helpers for embedders
// driving a netstack.Stack from their own tests: builders for valid,
// checksummed IPv4/UDP/ICMP-echo/fragment frames that netstack's own
// parseIPv4/parseUDP accept, plus FakeSession, an in-memory
// io.ReadWriteCloser that structurally satisfies netstack.Session.
//
// It depends on the standard library and netstack/internal/frame only — it
// does NOT import netstack itself. netstack's own in-package _test.go files
// import netstacktest (see netstack/netstacktest_frames_test.go), so an
// import of netstack here would be a cycle. The shared frame-construction
// logic therefore lives in netstack/internal/frame, which both netstack and
// netstacktest import, so there is exactly one implementation rather than
// two that could drift apart.
//
// This package deliberately has no "testing" import: it is usable from
// ordinary main programs and fuzzers, not just from *testing.T-driven
// tests.
//
// Every builder here takes netip.Addr, not net.IP: every existing call site
// in netstack's own test suite already holds a netip.Addr, and a net.IP
// signature would have made the migration onto this package a hand-edit
// instead of a mechanical rename. MustAddr is exported precisely so a
// caller holding a net.IP (for example, the address returned by
// ovpn.Session.AssignedIP()) can convert it in one call.
package netstacktest

import (
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/8upio/govpn/netstack/internal/frame"
)

// MustAddr converts ip (must have a usable IPv4 form) to a netip.Addr,
// panicking otherwise. Intended for test setup code and other contexts
// where a non-IPv4 argument is a programmer error, not a runtime condition
// to recover from.
func MustAddr(ip net.IP) netip.Addr {
	ip4 := ip.To4()
	if ip4 == nil {
		panic("netstacktest.MustAddr: not an IPv4 address")
	}
	return netip.AddrFrom4([4]byte(ip4))
}

// BuildIPv4 builds a complete, checksummed IPv4 packet from src to dst
// carrying protocol proto and payload — the same frame netstack's own
// parseIPv4 accepts.
func BuildIPv4(src, dst netip.Addr, proto uint8, payload []byte) []byte {
	return frame.BuildIPv4(nil, src, dst, proto, payload)
}

// BuildUDP builds a complete, checksummed IPv4+UDP datagram from src to dst
// with the given ports and payload — the same frame netstack's own
// parseIPv4/parseUDP accept.
func BuildUDP(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	segment := frame.BuildUDP(nil, src, dst, srcPort, dstPort, payload)
	return frame.BuildIPv4(nil, src, dst, frame.ProtocolUDP, segment)
}

// BuildICMPEchoRequest builds a complete, checksummed IPv4+ICMP echo
// request packet from src to dst, with the given identifier, sequence
// number, and payload — so a caller's test reads as intent (source,
// destination, identifier, sequence, payload), not as hand-assembled byte
// arithmetic.
func BuildICMPEchoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, frame.MinICMPHeaderLen+len(payload))
	icmp[0] = frame.ICMPTypeEchoRequest
	icmp[1] = 0 // code
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], frame.InternetChecksum(icmp))

	return frame.BuildIPv4(nil, src, dst, frame.ProtocolICMP, icmp)
}

// BuildFragment builds one IPv4 fragment carrying payload: a normal packet
// from BuildIPv4, with the Identification field set to id, the
// flags/fragment-offset word set from offsetBytes and mf, and the header
// checksum recomputed over the patched header. offsetBytes is in BYTES, not
// the on-wire 8-byte units — it is divided by 8 here, so no caller ever has
// to do that arithmetic itself.
func BuildFragment(src, dst netip.Addr, proto uint8, id uint16, offsetBytes int, mf bool, payload []byte) []byte {
	pkt := frame.BuildIPv4(nil, src, dst, proto, payload)

	binary.BigEndian.PutUint16(pkt[4:6], id)

	flagsFragOffset := uint16(offsetBytes / 8)
	if mf {
		flagsFragOffset |= frame.FlagMoreFragments
	}
	binary.BigEndian.PutUint16(pkt[6:8], flagsFragOffset)

	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], frame.InternetChecksum(pkt[:frame.MinIPv4HeaderLen]))
	return pkt
}
