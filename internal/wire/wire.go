// Package wire implements the OpenVPN control-channel packet wire format:
// the opcode/key-id/session-id header, and the plaintext body layout (ack
// array, optional remote session ID, own reliability packet ID, payload)
// that lives inside a tls-crypt-wrapped (or, in a later phase, tls-auth)
// control packet.
//
// Byte layout and constants below are traceable to the pinned OpenVPN
// reference checkout (/Users/svenloth/dev/openvpn-reference, branch
// release/2.6, commit c9b790f5b9e8ebca5da38c22f479c31bb8d33686):
//
//   - opcode/key-id packing and the legal opcode range:
//     src/openvpn/ssl_pkt.h:38-39,42-65 (P_OPCODE_SHIFT, P_KEY_ID_MASK,
//     P_FIRST_OPCODE, P_LAST_OPCODE)
//   - control-packet plaintext layout (ack array, remote session id, own
//     packet id): src/openvpn/reliable.c reliable_ack_write/reliable_ack_parse
//     (~lines 172-310), and src/openvpn/ssl.c:2946-2968 (the reliability
//     layer's own packet ID is already embedded in the outgoing buffer
//     before write_control_auth prepends the ack array in front of it)
//   - P_ACK_V1 carries no own packet id: src/openvpn/ssl.c:4009
//     ("if (op != P_ACK_V1 && reliable_can_get(...))")
//   - session ID size: src/openvpn/session_id.h:45 (SID_SIZE)
package wire

import (
	"encoding/binary"
	"errors"
)

// Opcode identifies the kind of a control-channel packet. The legal range is
// P_FIRST_OPCODE..P_LAST_OPCODE (ssl_pkt.h:64-65); opcodes 1 and 2 (Key
// Method 1 hard resets) are defined in the reference but permanently
// unreachable for a key-method-2 client, and are rejected rather than
// special-cased.
type Opcode uint8

const (
	OpControlSoftResetV1       Opcode = 3  // P_CONTROL_SOFT_RESET_V1
	OpControlV1                Opcode = 4  // P_CONTROL_V1
	OpAckV1                    Opcode = 5  // P_ACK_V1
	OpDataV1                   Opcode = 6  // P_DATA_V1
	OpControlHardResetClientV2 Opcode = 7  // P_CONTROL_HARD_RESET_CLIENT_V2
	OpControlHardResetServerV2 Opcode = 8  // P_CONTROL_HARD_RESET_SERVER_V2
	OpDataV2                   Opcode = 9  // P_DATA_V2
	OpControlHardResetClientV3 Opcode = 10 // P_CONTROL_HARD_RESET_CLIENT_V3
	OpControlWKCV1             Opcode = 11 // P_CONTROL_WKC_V1
)

const (
	// opcodeShift / keyIDMask: ssl_pkt.h:38-39 (P_OPCODE_SHIFT, P_KEY_ID_MASK).
	opcodeShift = 3
	keyIDMask   = 0x07

	// FirstOpcode / LastOpcode: ssl_pkt.h:64-65 (P_FIRST_OPCODE, P_LAST_OPCODE).
	FirstOpcode = 3
	LastOpcode  = 11

	// SessionIDSize: session_id.h:45 (SID_SIZE = sizeof(session_id.id), 8 bytes).
	SessionIDSize = 8

	// MaxAcks: reliable.h:44 (RELIABLE_ACK_SIZE) — the maximum number of
	// packet IDs that can be piggybacked in one ack record.
	MaxAcks = 8

	// packetIDSize is the reliability-layer packet ID's on-wire size: 4
	// bytes, big-endian, short form (packet_id.c packet_id_write with
	// long_form=false). This is a DIFFERENT field from tls-crypt's own
	// 8-byte long-form packet ID (internal/tlscrypt owns that one) — see
	// the package doc's Pitfall-1 cross-reference.
	packetIDSize = 4
)

// Sentinel parse errors. Every wire-parse function below explicitly checks
// remaining buffer length before each field read and returns one of these
// instead of ever letting a slice index panic on truncated or adversarial
// UDP input (mirrors the cheap-rejection discipline of
// tls_pre_decrypt_lite, ssl_pkt.c:305-423).
var (
	ErrTooShort    = errors.New("wire: buffer too short")
	ErrTooManyAcks = errors.New("wire: ack count exceeds RELIABLE_ACK_SIZE")
	ErrBadOpcode   = errors.New("wire: opcode outside P_FIRST_OPCODE..P_LAST_OPCODE")
)

// SessionID is an 8-byte OpenVPN control-channel session identifier
// (SID_SIZE, session_id.h:38-45).
type SessionID [SessionIDSize]byte

// PacketID is the 4-byte, big-endian control-channel reliability-layer
// packet ID. It is intentionally a distinct type from tls-crypt's own
// packet ID (see internal/tlscrypt) — the two are computed by different
// subsystems, incremented independently, and must never be assigned to or
// compared against each other.
type PacketID uint32

// Header is the cleartext opcode/key-id/session-id prefix of a control
// packet: the portion tls-crypt authenticates but never encrypts, minus
// tls-crypt's own packet-id field (which internal/tlscrypt owns and
// prepends/strips on the wire independently of this package).
type Header struct {
	Opcode    Opcode
	KeyID     uint8
	SessionID SessionID
}

// ParseHeaderByte decodes the leading header byte (opcode<<3 | keyID),
// ssl_pkt.h:38-39.
func ParseHeaderByte(b byte) (opcode Opcode, keyID uint8) {
	return Opcode(b >> opcodeShift), b & keyIDMask
}

// AppendHeaderByte appends the packed opcode/key-id header byte to dst.
func AppendHeaderByte(dst []byte, opcode Opcode, keyID uint8) []byte {
	return append(dst, byte(opcode)<<opcodeShift|keyID&keyIDMask)
}

// ValidOpcode reports whether op falls within the legal wire range
// P_FIRST_OPCODE..P_LAST_OPCODE (ssl_pkt.h:61-65).
func ValidOpcode(op Opcode) bool {
	return op >= FirstOpcode && op <= LastOpcode
}

// ControlPacket is a parsed control-channel plaintext: the header fields it
// was parsed under, the ack array, the optional remote session ID (present
// iff len(Acks) > 0), this packet's own reliability packet ID (absent for
// OpAckV1), and the trailing payload bytes.
type ControlPacket struct {
	Opcode          Opcode
	KeyID           uint8
	SessionID       SessionID
	Acks            []PacketID
	RemoteSessionID SessionID
	PacketID        PacketID
	Payload         []byte
}

// ParseControlPacket parses the tls-crypt (or tls-auth) plaintext body of a
// control packet:
//
//	[ack_count(1 byte)]
//	[ack_count x 4-byte big-endian reliability packet IDs]
//	[remote session ID (8 bytes), present only if ack_count > 0]
//	[this packet's own reliability packet ID (4 bytes), OMITTED for OpAckV1]
//	[payload]
//
// hdr supplies the opcode/key-id/session-id already parsed from the
// packet's authenticated cleartext header (see Header) — the plaintext body
// format itself mirrors reliable_ack_parse (reliable.c:172-205) followed by
// the reliability layer's own packet_id_read (packet_id.c:298-321), gated
// by the "own packet id absent for P_ACK_V1" rule (ssl.c:4009).
//
// Every field read explicitly checks the remaining buffer length first and
// returns a typed sentinel error rather than ever indexing out of range —
// this function must never panic on arbitrary/adversarial input.
func ParseControlPacket(plaintext []byte, hdr Header) (ControlPacket, error) {
	if !ValidOpcode(hdr.Opcode) {
		return ControlPacket{}, ErrBadOpcode
	}

	buf := plaintext
	if len(buf) < 1 {
		return ControlPacket{}, ErrTooShort
	}
	ackCount := int(buf[0])
	buf = buf[1:]
	if ackCount > MaxAcks {
		return ControlPacket{}, ErrTooManyAcks
	}

	acks := make([]PacketID, 0, ackCount)
	for i := 0; i < ackCount; i++ {
		if len(buf) < packetIDSize {
			return ControlPacket{}, ErrTooShort
		}
		acks = append(acks, PacketID(binary.BigEndian.Uint32(buf[:packetIDSize])))
		buf = buf[packetIDSize:]
	}

	var remoteSID SessionID
	if ackCount > 0 {
		if len(buf) < SessionIDSize {
			return ControlPacket{}, ErrTooShort
		}
		copy(remoteSID[:], buf[:SessionIDSize])
		buf = buf[SessionIDSize:]
	}

	var pid PacketID
	if hdr.Opcode != OpAckV1 {
		if len(buf) < packetIDSize {
			return ControlPacket{}, ErrTooShort
		}
		pid = PacketID(binary.BigEndian.Uint32(buf[:packetIDSize]))
		buf = buf[packetIDSize:]
	}

	payload := make([]byte, len(buf))
	copy(payload, buf)

	return ControlPacket{
		Opcode:          hdr.Opcode,
		KeyID:           hdr.KeyID,
		SessionID:       hdr.SessionID,
		Acks:            acks,
		RemoteSessionID: remoteSID,
		PacketID:        pid,
		Payload:         payload,
	}, nil
}

// AppendPlaintext serializes p's plaintext body (ack array, optional remote
// session ID, optional own packet ID, payload) and appends it to dst. It is
// the exact inverse of ParseControlPacket: parse then serialize reproduces
// the original bytes, with ACK packet-IDs emitted in the order they were
// parsed.
func (p ControlPacket) AppendPlaintext(dst []byte) []byte {
	dst = append(dst, byte(len(p.Acks)))
	for _, id := range p.Acks {
		dst = binary.BigEndian.AppendUint32(dst, uint32(id))
	}
	if len(p.Acks) > 0 {
		dst = append(dst, p.RemoteSessionID[:]...)
	}
	if p.Opcode != OpAckV1 {
		dst = binary.BigEndian.AppendUint32(dst, uint32(p.PacketID))
	}
	dst = append(dst, p.Payload...)
	return dst
}
