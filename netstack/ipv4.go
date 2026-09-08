// ipv4.go implements RFC 791 §3.1's IPv4 header parse/build and the RFC
// 1071 Internet checksum, plus the RFC 768/9293 IPv4 pseudo-header sum
// shared by UDP and TCP checksums. Every field read explicitly checks the
// remaining buffer length first and returns a typed sentinel error rather
// than ever indexing out of range — this file must never panic on
// arbitrary/adversarial input, mirroring internal/wire's own
// "explicit length check before every field read" discipline
// (internal/wire/wire.go:149-152).
//
//   - IPv4 header format, IHL, fragmentation flags: RFC 791 §3.1
//     (rfc-editor.org/rfc/rfc791)
//   - Internet checksum algorithm: RFC 1071 (rfc-editor.org/rfc/rfc1071)
//   - UDP/TCP IPv4 pseudo-header layout: RFC 768 (rfc-editor.org/rfc/rfc768),
//     RFC 9293 §3.1 (obsoletes RFC 793; uses the identical pseudo-header
//     shape with protocol=6 instead of UDP's 17)
package netstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	// minIPv4HeaderLen is the shortest legal IPv4 header: IHL=5, no
	// options (RFC 791 §3.1).
	minIPv4HeaderLen = 20

	// maxIPv4HeaderLen is the longest legal IPv4 header: IHL=15 (RFC 791
	// §3.1, the 4-bit IHL field's maximum value, ×4 bytes/word).
	maxIPv4HeaderLen = 60

	// defaultTTL is the TTL this stack sets on every packet it builds.
	// This is this project's own choice (no RFC mandates a specific
	// value); 64 matches common Linux/BSD defaults.
	defaultTTL = 64

	// IPv4 protocol numbers this stack recognizes (RFC 791 §3.1's
	// Protocol field; assignments from the IANA protocol-numbers
	// registry).
	protocolICMP = 1
	protocolTCP  = 6
	protocolUDP  = 17

	// flagMoreFragments is the MF bit of the 3-bit Flags field, packed
	// into the same 16-bit big-endian word as the 13-bit Fragment Offset
	// (RFC 791 §3.1).
	flagMoreFragments = 0x2000

	// fragOffsetMask isolates the 13-bit Fragment Offset from the
	// combined Flags+Fragment-Offset word (RFC 791 §3.1).
	fragOffsetMask = 0x1FFF

	// flagDontFragment is the DF bit of the same 3-bit Flags field,
	// sharing the 16-bit word with MF and the 13-bit Fragment Offset
	// (RFC 791 §3.1). This stack never sets it on a packet it builds:
	// writePacket fragments anything larger than the configured MTU
	// itself rather than asking a peer to shrink, and it generates no
	// ICMP fragmentation-needed error either.
	flagDontFragment = 0x4000

	// maxIPv4Datagram is the largest datagram RFC 791 §3.1's 16-bit
	// Total Length field can express, and therefore the largest
	// reassembled datagram this stack can ever produce.
	maxIPv4Datagram = 65535
)

// Sentinel parse errors, in the style of internal/wire's own ErrTooShort
// etc. (internal/wire/wire.go:77-81).
var (
	errTooShort       = errors.New("netstack: buffer too short for an IPv4 header")
	errNotIPv4        = errors.New("netstack: version nibble is not 4")
	errBadIHL         = errors.New("netstack: IHL is out of range for this buffer")
	errBadTotalLength = errors.New("netstack: total length field is out of range for this buffer")
	errBadFragment    = errors.New("netstack: IPv4 fragment geometry is invalid")
)

// ipv4Header is a parsed IPv4 header: the fields deliver and writePacket
// need, nothing more. IP options (if any, IHL > 5) are never parsed —
// payloadOff already points past them (see parseIPv4's doc comment).
type ipv4Header struct {
	ihl        int
	totalLen   int
	protocol   uint8
	src        netip.Addr
	dst        netip.Addr
	payloadOff int

	// id is RFC 791 §3.1's 16-bit Identification field: together with
	// (src, dst, protocol) it names the datagram a fragment belongs to.
	id uint16

	// moreFragments is the MF bit: more fragments of this datagram
	// follow (RFC 791 §3.1).
	moreFragments bool

	// fragOffset is this fragment's offset within its datagram in
	// BYTES — the on-wire 13-bit field value multiplied by 8, since RFC
	// 791 §3.1 counts the offset in 8-byte units. Scaling here, once,
	// means no call site ever has to remember to do it.
	fragOffset int
}

// isFragment reports whether h describes a fragment of a larger datagram:
// either more fragments follow it, or it is not the first one (RFC 791
// §3.1 — a complete datagram carries MF clear AND a zero offset).
func (h ipv4Header) isFragment() bool { return h.moreFragments || h.fragOffset != 0 }

// parseIPv4 parses pkt's IPv4 header. Validation proceeds in this exact
// order, each step strictly before the next dereference it depends on, so
// no field is ever read past a length this function has not already
// checked against len(pkt):
//
//  1. len(pkt) >= minIPv4HeaderLen
//  2. the version nibble == 4
//  3. ihl := (IHL nibble)*4, with minIPv4HeaderLen <= ihl <= len(pkt)
//  4. totalLen := the 16-bit Total Length field, with ihl <= totalLen <=
//     len(pkt)
//  5. the fragment fields — Identification, MF and the byte-scaled
//     Fragment Offset — are read and, if and only if the packet IS a
//     fragment, its geometry is validated: a non-empty payload, a
//     payload length that is a multiple of 8 whenever MF is set (RFC 791
//     §3.2 requires every non-final fragment's data length to be an
//     8-byte multiple, since the offset field counts in 8-byte units),
//     and fragOffset+payloadLen no greater than maxIPv4Datagram.
//     Anything else is errBadFragment. Because writePacket re-parses
//     every packet it is about to send, this same check also guarantees
//     this stack can never EMIT a geometrically invalid fragment.
//
// IP options are skipped past, not rejected (RESEARCH.md Anti-Patterns,
// Assumption A3): payloadOff is set to ihl, correctly computed, so an
// IHL > 5 packet's options are simply never interpreted.
//
// This function deliberately does not verify the inbound IPv4 header
// checksum: every packet reaching here already passed AES-256-GCM
// authentication below the Session boundary (internal/datachan.Wrapper.
// Open), so a corrupted header is not a threat this layer adds value
// against.
func parseIPv4(pkt []byte) (ipv4Header, error) {
	if len(pkt) < minIPv4HeaderLen {
		return ipv4Header{}, errTooShort
	}

	version := pkt[0] >> 4
	if version != 4 {
		return ipv4Header{}, errNotIPv4
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < minIPv4HeaderLen || ihl > len(pkt) {
		return ipv4Header{}, errBadIHL
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		return ipv4Header{}, errBadTotalLength
	}

	id := binary.BigEndian.Uint16(pkt[4:6])
	flagsFragOffset := binary.BigEndian.Uint16(pkt[6:8])
	moreFragments := flagsFragOffset&flagMoreFragments != 0
	fragOffset := int(flagsFragOffset&fragOffsetMask) * 8

	if moreFragments || fragOffset != 0 {
		payloadLen := totalLen - ihl
		if payloadLen == 0 {
			return ipv4Header{}, errBadFragment
		}
		if moreFragments && payloadLen%8 != 0 {
			return ipv4Header{}, errBadFragment
		}
		if fragOffset+payloadLen > maxIPv4Datagram {
			return ipv4Header{}, errBadFragment
		}
	}

	protocol := pkt[9]
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))

	return ipv4Header{
		ihl:           ihl,
		totalLen:      totalLen,
		protocol:      protocol,
		src:           src,
		dst:           dst,
		payloadOff:    ihl,
		id:            id,
		moreFragments: moreFragments,
		fragOffset:    fragOffset,
	}, nil
}

// buildIPv4 appends a 20-byte, options-free IPv4 header (IHL 5, DSCP/ECN
// 0, identification 0, flags/fragment-offset 0, TTL defaultTTL) followed by
// payload to dst, and returns the result. Emitting identification 0 with a
// zero flags/fragment-offset word is correct here because RFC 6864 §4 only
// requires the Identification field to be unique per (source, destination,
// protocol) within one reassembly window, and an unfragmented datagram is
// never reassembled: an identification is assigned only when writePacket
// actually fragments (see fragmentIPv4), and only to the fragments it emits.
func buildIPv4(dst []byte, src, dstAddr netip.Addr, protocol uint8, payload []byte) []byte {
	totalLen := minIPv4HeaderLen + len(payload)

	start := len(dst)
	dst = append(dst, make([]byte, minIPv4HeaderLen)...)
	hdr := dst[start : start+minIPv4HeaderLen]

	hdr[0] = 0x45 // version 4, IHL 5 (20 bytes, no options)
	hdr[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:6], 0) // identification
	binary.BigEndian.PutUint16(hdr[6:8], 0) // flags/fragment offset
	hdr[8] = defaultTTL
	hdr[9] = protocol
	hdr[10], hdr[11] = 0, 0 // checksum, computed below with this zeroed

	srcB := src.As4()
	dstB := dstAddr.As4()
	copy(hdr[12:16], srcB[:])
	copy(hdr[16:20], dstB[:])

	binary.BigEndian.PutUint16(hdr[10:12], internetChecksum(hdr))

	dst = append(dst, payload...)
	return dst
}

// fragmentIPv4 splits an already-parsed, already-valid datagram into
// RFC 791 §3.2 fragments no larger than mtu, all carrying identification
// id, and returns them in ascending-offset order. Each fragment is a
// freshly allocated slice: callers hand these straight to Session.Write,
// so none of them may alias pkt or each other.
//
// The input's own header checksum is irrelevant here — every fragment's
// header is rewritten (Total Length, Identification, flags/offset) and
// gets a freshly computed checksum of its own.
//
// The full hdr.ihl header bytes are copied rather than a hardcoded 20, so
// IP options (which this stack never generates, but may one day) ride along
// on every fragment instead of being silently truncated away.
func fragmentIPv4(hdr ipv4Header, pkt []byte, mtu int, id uint16) [][]byte {
	// The largest payload chunk that still fits the MTU, rounded DOWN to
	// a multiple of 8 so every non-final fragment's data length is
	// 8-aligned as RFC 791 §3.2 requires (the Fragment Offset field
	// counts in 8-byte units, so a non-final fragment of any other length
	// could not be addressed at all).
	maxData := (mtu - hdr.ihl) &^ 7
	if maxData <= 0 {
		// Unreachable given minMTU (576) and maxIPv4HeaderLen (60): the
		// worst case is 576-60 = 516, floored to 512. Defensive only —
		// returning nil rather than looping forever or panicking.
		return nil
	}

	payload := pkt[hdr.payloadOff:hdr.totalLen]

	var frags [][]byte
	for off := 0; off < len(payload); off += maxData {
		end := off + maxData
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]

		frag := make([]byte, hdr.ihl+len(chunk))
		copy(frag, pkt[:hdr.ihl])
		copy(frag[hdr.ihl:], chunk)

		binary.BigEndian.PutUint16(frag[2:4], uint16(hdr.ihl+len(chunk)))
		binary.BigEndian.PutUint16(frag[4:6], id)

		flagsFragOffset := uint16(off / 8)
		if end < len(payload) {
			flagsFragOffset |= flagMoreFragments
		}
		binary.BigEndian.PutUint16(frag[6:8], flagsFragOffset)

		frag[10], frag[11] = 0, 0
		binary.BigEndian.PutUint16(frag[10:12], internetChecksum(frag[:hdr.ihl]))

		frags = append(frags, frag)
	}
	return frags
}

// internetChecksum computes the RFC 1071 Internet checksum over b: the
// one's complement of the one's-complement sum of b's 16-bit big-endian
// words, with a trailing odd byte treated as the high byte of a final
// zero-padded word. Callers must zero the checksum field within b before
// calling. This is byte-for-byte the function already live-verified
// against a real OpenVPN 2.6.14 client in test/interop/server/main.go's
// harness ICMP responder (main.go:565-578) — RFC 1071 itself: "Adjacent
// octets to be checksummed are paired to form 16-bit integers, and the 1's
// complement sum of these 16-bit integers is formed."
func internetChecksum(b []byte) uint16 {
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

// pseudoHeaderSum computes the RFC 768 / RFC 9293 §3.1 12-byte IPv4
// pseudo-header partial sum (src 4B, dst 4B, zero 1B, protocol 1B, length
// 2B) — the un-folded, un-complemented running sum, so transportChecksum
// below can add the payload's own words before folding and complementing
// once at the end. This function and transportChecksum have no ICMP call
// site: they exist here, in wave 1, so plan 03-02 (UDP) and plan 03-03
// (TCP) can both consume them in wave 2 without either plan creating the
// same function in the other's file.
func pseudoHeaderSum(src, dst netip.Addr, protocol uint8, length uint16) uint32 {
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

// transportChecksum folds pseudoHeaderSum's partial sum together with
// payload's own 16-bit words and returns the completed, complemented
// checksum — the value a UDP or TCP header's checksum field should carry.
// payload here means the full transport segment (header with its own
// checksum field zeroed, plus data), per RFC 768/9293.
func transportChecksum(src, dst netip.Addr, protocol uint8, payload []byte) uint16 {
	sum := pseudoHeaderSum(src, dst, protocol, uint16(len(payload)))

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
