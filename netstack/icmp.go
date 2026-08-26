// icmp.go implements the ICMP echo responder (NET-03, RFC 792): the server
// tunnel IP answers echo requests addressed to it, and drops every other
// ICMP type and every other destination silently, generating no ICMP error
// of its own (D-11; ICMP error generation is a Deferred Idea).
//
// This is adapted from test/interop/server/main.go's icmpEchoReply
// (main.go:430-472), live-verified against a real OpenVPN 2.6.14 client's
// ping — the logic is already correct and proven; this version differs in
// exactly three ways (D-11): (1) it is reached only after deliver has
// already confirmed the packet's destination is the server tunnel IP, so
// this responder does not re-check; (2) every ICMP type other than echo
// request is dropped with no reply and no generated ICMP error; (3) the
// reply is emitted through writePacket, so D-04's outbound source-IP
// fail-closed check applies to it exactly like any other outbound packet.
package netstack

import "encoding/binary"

const (
	// icmpTypeEchoRequest / icmpTypeEchoReply are RFC 792's ICMP type
	// values for echo request and echo reply.
	icmpTypeEchoRequest = 8
	icmpTypeEchoReply   = 0

	// minICMPHeaderLen is the fixed ICMP echo header size (type, code,
	// checksum, identifier, sequence number — RFC 792).
	minICMPHeaderLen = 8
)

// handleICMP answers icmpMsg, the ICMP message carried by an IPv4 packet
// deliver has already confirmed is addressed to the server tunnel IP, if
// and only if icmpMsg is a well-formed echo request. Every other ICMP
// type — including a malformed/too-short message — is dropped silently
// with no reply and no generated ICMP error (D-11).
func (s *Stack) handleICMP(a *attachment, hdr ipv4Header, icmpMsg []byte) {
	if len(icmpMsg) < minICMPHeaderLen {
		s.stats.malformedDropped.Add(1)
		return
	}
	if icmpMsg[0] != icmpTypeEchoRequest {
		return
	}
	s.stats.icmpEchoRequests.Add(1)

	// Swap type to echo reply, code unchanged; identifier, sequence
	// number, and payload are echoed back unchanged (RFC 792). Recompute
	// the ICMP checksum over the whole message with its checksum field
	// zeroed first.
	out := append([]byte(nil), icmpMsg...)
	out[0] = icmpTypeEchoReply
	out[2], out[3] = 0, 0
	binary.BigEndian.PutUint16(out[2:4], internetChecksum(out))

	reply := buildIPv4(nil, s.serverIP, hdr.src, protocolICMP, out)
	if err := s.writePacket(a, reply); err != nil {
		return
	}
	s.stats.icmpEchoReplies.Add(1)
}
