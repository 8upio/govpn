// tcp_segment.go implements RFC 9293 (obsoletes RFC 793) §3.1's TCP header
// parse/build, and the MSS option (§3.2, kind=2, len=4). Every field read
// explicitly checks the remaining buffer length first and returns a typed
// sentinel error rather than ever indexing out of range — this file must
// never panic on arbitrary/adversarial input, mirroring internal/wire's own
// "explicit length check before every field read" discipline
// (internal/wire/wire.go:149-152) and netstack/ipv4.go's identical
// discipline for the IPv4 header.
//
// This file deliberately does not verify the inbound TCP checksum: every
// packet reaching here already passed AES-256-GCM authentication below the
// Session boundary, the same reasoning ipv4.go and icmp.go already record
// for their own headers (D-04's fail-closed check is the actual security
// boundary, not this checksum). It IS computed correctly on send — a real
// client's kernel does verify it.
package netstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	// TCP flag bits (RFC 9293 §3.1's Control Bits field, low byte order as
	// this project lays out its own tcpSegment.flags field).
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10

	// tcpHeaderMinLen is the shortest legal TCP header: no options (RFC
	// 9293 §3.1).
	tcpHeaderMinLen = 20

	// tcpHeaderMaxLen is the longest legal TCP header: the 4-bit Data
	// Offset field's maximum value (15) × 4 bytes/word (RFC 9293 §3.1).
	tcpHeaderMaxLen = 60

	// mssOptionKind / mssOptionLen: RFC 9293 §3.2's Maximum Segment Size
	// option — kind 2, a fixed total length of 4 bytes (kind + length +
	// 2-byte value).
	mssOptionKind = 2
	mssOptionLen  = 4

	// optionKindEnd / optionKindNop: RFC 9293 §3.1's End of Option List
	// (kind 0, no length byte, terminates the options region) and No
	// Operation (kind 1, no length byte, padding between options) option
	// kinds — the only two single-byte (no length field) TCP options.
	optionKindEnd = 0
	optionKindNop = 1

	// defaultMSSWhenAbsent is RFC 9293's own default: "If this option is
	// not used, any segment size is allowed" is refined in practice, and
	// this project follows the long-standing Internet convention (and
	// RESEARCH.md's own TestTCPMSSOption behavior spec) of 536 bytes — the
	// default MSS for a non-local-network TCP peer per RFC 1122 §4.2.2.6,
	// used when a SYN carries no MSS option at all.
	defaultMSSWhenAbsent = 536
)

// Sentinel parse errors, in the style of ipv4.go's own errTooShort etc.
var (
	errTCPTooShort      = errors.New("netstack: buffer too short for a TCP header")
	errTCPBadDataOffset = errors.New("netstack: TCP data offset is out of range for this buffer")
	errTCPBadOption     = errors.New("netstack: truncated or zero-length TCP option")
)

// tcpSegment is a parsed (or about-to-be-built) TCP segment: the fields the
// state machine, retransmit timer, and RST generator all need, nothing
// more. hasMSS/mss represent the MSS option as an ok-flag pair rather than
// a pointer, since Go zero-values a bool to false — "absent" is meaningful
// here (RFC 9293's own "no MSS option present" default, TestTCPMSSOption)
// and a nil-pointer check would be no clearer.
type tcpSegment struct {
	srcPort uint16
	dstPort uint16
	seq     uint32
	ack     uint32
	flags   uint8
	window  uint16
	hasMSS  bool
	mss     uint16
	payload []byte
}

// segLen returns SEG.LEN as RFC 9293 §3.10.7 defines it: the number of
// sequence numbers the segment occupies — its payload length, plus one each
// for SYN and FIN, which each consume exactly one sequence number of their
// own. Used by RST generation (§3.5.2) and by sequence bookkeeping.
func (s tcpSegment) segLen() uint32 {
	n := uint32(len(s.payload))
	if s.flags&flagSYN != 0 {
		n++
	}
	if s.flags&flagFIN != 0 {
		n++
	}
	return n
}

// parseTCP parses payload's TCP header (and, if present, its MSS option),
// in this exact validation order, each step strictly before the next
// dereference it depends on:
//
//  1. len(payload) >= tcpHeaderMinLen
//  2. dataOffset := (Data Offset nibble)*4, with tcpHeaderMinLen <=
//     dataOffset <= len(payload)
//  3. walk the options region (payload[tcpHeaderMinLen:dataOffset]),
//     honoring End-of-Options and NOP, bounds-checking each option's own
//     length byte before advancing past it — a truncated or zero-length
//     option is errTCPBadOption, never an infinite loop or an
//     out-of-range index. Unknown option kinds are skipped by their
//     length, not rejected (only MSS, kind 2, is interpreted).
//
// payload beyond dataOffset is the segment's own payload.
func parseTCP(payload []byte) (tcpSegment, error) {
	if len(payload) < tcpHeaderMinLen {
		return tcpSegment{}, errTCPTooShort
	}

	dataOffset := int(payload[12]>>4) * 4
	if dataOffset < tcpHeaderMinLen || dataOffset > len(payload) {
		return tcpSegment{}, errTCPBadDataOffset
	}

	seg := tcpSegment{
		srcPort: binary.BigEndian.Uint16(payload[0:2]),
		dstPort: binary.BigEndian.Uint16(payload[2:4]),
		seq:     binary.BigEndian.Uint32(payload[4:8]),
		ack:     binary.BigEndian.Uint32(payload[8:12]),
		flags:   payload[13],
		window:  binary.BigEndian.Uint16(payload[14:16]),
	}

	opts := payload[tcpHeaderMinLen:dataOffset]
	for len(opts) > 0 {
		kind := opts[0]
		if kind == optionKindEnd {
			break
		}
		if kind == optionKindNop {
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 {
			return tcpSegment{}, errTCPBadOption
		}
		optLen := int(opts[1])
		if optLen < 2 || optLen > len(opts) {
			return tcpSegment{}, errTCPBadOption
		}
		if kind == mssOptionKind {
			if optLen != mssOptionLen {
				return tcpSegment{}, errTCPBadOption
			}
			seg.mss = binary.BigEndian.Uint16(opts[2:4])
			seg.hasMSS = true
		}
		opts = opts[optLen:]
	}

	seg.payload = payload[dataOffset:]
	return seg, nil
}

// buildTCP appends seg's TCP header (with an MSS option if seg.hasMSS —
// used only for a SYN-ACK, D-06's "MSS only" prohibition) and payload to
// dst, and returns the result. The checksum is computed last, over the
// pseudo-header plus the just-written header and payload, via
// transportChecksum (ipv4.go), with protocol 6 (RFC 9293 §3.1: "the same
// checksum algorithm as UDP", RFC 768, applied over the identical IPv4
// pseudo-header shape).
func buildTCP(dst []byte, seg tcpSegment, src, dstAddr netip.Addr) []byte {
	headerLen := tcpHeaderMinLen
	if seg.hasMSS {
		headerLen += mssOptionLen
	}

	start := len(dst)
	dst = append(dst, make([]byte, headerLen)...)
	hdr := dst[start : start+headerLen]

	binary.BigEndian.PutUint16(hdr[0:2], seg.srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], seg.dstPort)
	binary.BigEndian.PutUint32(hdr[4:8], seg.seq)
	binary.BigEndian.PutUint32(hdr[8:12], seg.ack)
	hdr[12] = byte(headerLen/4) << 4
	hdr[13] = seg.flags
	binary.BigEndian.PutUint16(hdr[14:16], seg.window)
	hdr[16], hdr[17] = 0, 0 // checksum, computed below with this zeroed
	hdr[18], hdr[19] = 0, 0 // urgent pointer, unused (D-06: no urgent data)

	if seg.hasMSS {
		hdr[20] = mssOptionKind
		hdr[21] = mssOptionLen
		binary.BigEndian.PutUint16(hdr[22:24], seg.mss)
	}

	dst = append(dst, seg.payload...)

	full := dst[start:]
	cs := transportChecksum(src, dstAddr, protocolTCP, full)
	binary.BigEndian.PutUint16(dst[start+16:start+18], cs)

	return dst
}
