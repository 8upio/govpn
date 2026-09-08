// Package frame is the single implementation of IPv4/UDP frame construction
// and the RFC 1071 Internet checksum family, shared by netstack's own
// production code (netstack/ipv4.go, netstack/udp.go, netstack/icmp.go) and
// netstack/netstacktest (an exported package for embedders driving a
// netstack.Stack from their own tests). Without this package the two would
// each carry their own copy of the same wire-format logic, free to drift
// apart silently; keeping it here instead means there is exactly one
// implementation to get right and to verify against the OpenVPN/RFC
// reference material.
//
// This package is internal/ because only code under netstack/... may depend
// on it — it is not part of this module's public API surface on its own,
// only through the higher-level packages that build on it.
package frame

import (
	"encoding/binary"
	"net/netip"
)

const (
	// MinIPv4HeaderLen is the shortest legal IPv4 header: IHL=5, no
	// options (RFC 791 §3.1).
	MinIPv4HeaderLen = 20

	// DefaultTTL is the TTL this stack sets on every packet it builds.
	// This is this project's own choice (no RFC mandates a specific
	// value); 64 matches common Linux/BSD defaults.
	DefaultTTL = 64

	// IPv4 protocol numbers this stack recognizes (RFC 791 §3.1's
	// Protocol field; assignments from the IANA protocol-numbers
	// registry).
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17

	// FlagMoreFragments is the MF bit of the 3-bit Flags field, packed
	// into the same 16-bit big-endian word as the 13-bit Fragment Offset
	// (RFC 791 §3.1).
	FlagMoreFragments = 0x2000

	// UDPHeaderLen is the fixed 8-byte UDP header: source port,
	// destination port, length, checksum (RFC 768).
	UDPHeaderLen = 8

	// ICMPTypeEchoRequest is RFC 792's ICMP type value for echo request.
	ICMPTypeEchoRequest = 8

	// MinICMPHeaderLen is the fixed ICMP echo header size (type, code,
	// checksum, identifier, sequence number — RFC 792).
	MinICMPHeaderLen = 8
)

// BuildIPv4 appends a 20-byte, options-free IPv4 header (IHL 5, DSCP/ECN 0,
// identification 0, flags/fragment-offset 0, TTL DefaultTTL) followed by
// payload to dst, and returns the result. Emitting identification 0 with a
// zero flags/fragment-offset word is correct here because RFC 6864 §4 only
// requires the Identification field to be unique per (source, destination,
// protocol) within one reassembly window, and an unfragmented datagram is
// never reassembled: an identification is assigned only when the stack's own
// fragmentIPv4 actually fragments, and only to the fragments it emits.
func BuildIPv4(dst []byte, src, dstAddr netip.Addr, protocol uint8, payload []byte) []byte {
	totalLen := MinIPv4HeaderLen + len(payload)

	start := len(dst)
	dst = append(dst, make([]byte, MinIPv4HeaderLen)...)
	hdr := dst[start : start+MinIPv4HeaderLen]

	hdr[0] = 0x45 // version 4, IHL 5 (20 bytes, no options)
	hdr[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:6], 0) // identification
	binary.BigEndian.PutUint16(hdr[6:8], 0) // flags/fragment offset
	hdr[8] = DefaultTTL
	hdr[9] = protocol
	hdr[10], hdr[11] = 0, 0 // checksum, computed below with this zeroed

	srcB := src.As4()
	dstB := dstAddr.As4()
	copy(hdr[12:16], srcB[:])
	copy(hdr[16:20], dstB[:])

	binary.BigEndian.PutUint16(hdr[10:12], InternetChecksum(hdr))

	dst = append(dst, payload...)
	return dst
}

// BuildUDP appends an 8-byte UDP header (source port, destination port,
// length, checksum) followed by payload to dst, and returns the result. The
// checksum is computed with TransportChecksum over the pseudo-header (src,
// dstAddr, ProtocolUDP) plus the UDP header (checksum field zeroed) plus
// payload. RFC 768's special rule is applied explicitly: a computed checksum
// of 0x0000 is transmitted as 0xFFFF, because an on-wire 0x0000 means
// "sender computed no checksum" and must not be confused with an actual zero
// result.
func BuildUDP(dst []byte, src, dstAddr netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	start := len(dst)
	totalLen := UDPHeaderLen + len(payload)

	dst = append(dst, make([]byte, UDPHeaderLen)...)
	hdr := dst[start : start+UDPHeaderLen]
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(totalLen))
	hdr[6], hdr[7] = 0, 0 // checksum, computed below with this zeroed

	dst = append(dst, payload...)

	segment := dst[start:]
	checksum := TransportChecksum(src, dstAddr, ProtocolUDP, segment)
	if checksum == 0 {
		// RFC 768: "If the computed checksum is zero, it is transmitted
		// as all ones" — an on-wire 0x0000 means "no checksum computed"
		// and must never be produced by a sender that did compute one.
		checksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(dst[start+6:start+8], checksum)

	return dst
}

// InternetChecksum computes the RFC 1071 Internet checksum over b: the
// one's complement of the one's-complement sum of b's 16-bit big-endian
// words, with a trailing odd byte treated as the high byte of a final
// zero-padded word. Callers must zero the checksum field within b before
// calling. This is byte-for-byte the function already live-verified against
// a real OpenVPN 2.6.14 client in test/interop/server/main.go's harness ICMP
// responder (main.go:565-578) — RFC 1071 itself: "Adjacent octets to be
// checksummed are paired to form 16-bit integers, and the 1's complement sum
// of these 16-bit integers is formed."
func InternetChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// PseudoHeaderSum computes the RFC 768 / RFC 9293 §3.1 12-byte IPv4
// pseudo-header partial sum (src 4B, dst 4B, zero 1B, protocol 1B, length
// 2B) — the un-folded, un-complemented running sum, so TransportChecksum
// below can add the payload's own words before folding and complementing
// once at the end.
func PseudoHeaderSum(src, dst netip.Addr, protocol uint8, length uint16) uint32 {
	srcB := src.As4()
	dstB := dst.As4()

	var sum uint32
	sum += uint32(srcB[0])<<8 | uint32(srcB[1])
	sum += uint32(srcB[2])<<8 | uint32(srcB[3])
	sum += uint32(dstB[0])<<8 | uint32(dstB[1])
	sum += uint32(dstB[2])<<8 | uint32(dstB[3])
	sum += uint32(protocol)
	sum += uint32(length)
	return sum
}

// TransportChecksum folds PseudoHeaderSum's partial sum together with
// payload's own 16-bit words and returns the completed, complemented
// checksum — the value a UDP or TCP header's checksum field should carry.
// payload here means the full transport segment (header with its own
// checksum field zeroed, plus data), per RFC 768/9293.
func TransportChecksum(src, dst netip.Addr, protocol uint8, payload []byte) uint16 {
	sum := PseudoHeaderSum(src, dst, protocol, uint16(len(payload)))

	n := len(payload)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if n%2 == 1 {
		sum += uint32(payload[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
