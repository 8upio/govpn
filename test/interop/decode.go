// Package interop's decode.go builds on pcap.go's raw UDP-payload extraction
// to tls-crypt-unwrap and control-packet-parse every captured datagram on
// the tunnel port, in capture order. This is the shared building block
// behind capture_test.go's byte-exactness/tamper-detection checks,
// interop_test.go's fragmentation assertion, and golden_export.go's vector
// selection (01-04-PLAN.md Task 1/2) — one decode path, three consumers,
// rather than three drifting re-implementations of the same tls-crypt
// unwrap + control-packet parse sequence.
//
// 02-04-PLAN.md Task 2 extends this decode path with a P_DATA_V2
// AES-256-GCM open, so control and data packets share one decoder
// (dataChannelKeyMaterial below) rather than data packets always being
// skipped.
package interop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/8upio/govpn/internal/datachan"
	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// tunnelPort must match the UDP port test/interop/docker-compose.yml's
// server service listens on and cmd/gentestpki's generated client.conf
// targets.
const tunnelPort = 1194

// dataChannelKeyID is always 0 in v1 (no renegotiation, SESS-04) — the
// harness's own view of the same fixed TLS key slot
// internal/datachan.NewWrapper's callers already use.
const dataChannelKeyID = 0

// decodedPacket is one captured, successfully decoded datagram: either
// tls-crypt-unwrapped and control-packet-parsed (control opcodes), or, when
// dataChannelKeyMaterial was supplied to decodeCapture, AES-256-GCM-opened
// (P_DATA_V1/P_DATA_V2). IsDataPacket distinguishes the two — Header/Control
// are the control-channel-only fields (zero-valued for a data packet), and
// PeerID/DataPacketID/Plaintext are the data-channel-only fields
// (zero-valued for a control packet, or for any data packet decoded without
// key material — every pre-existing caller).
type decodedPacket struct {
	Direction Direction
	Raw       []byte // the exact captured wire bytes (tls-crypt wrapped, or, for a data packet, the P_DATA_V2 wire bytes)
	Header    wire.Header
	Control   wire.ControlPacket

	IsDataPacket bool
	IsPing       bool // true when Open returned datachan.ErrPingAbsorbed — the AEAD tag still verified, only the plaintext itself is withheld (mirrors Session.Read's own behavior)
	PeerID       uint32
	DataPacketID uint32
	Plaintext    []byte // only populated when IsDataPacket && !IsPing && dataChannelKeyMaterial was supplied
}

// dataChannelKeyMaterial supplies the per-session AES-256-GCM key material
// decodeCapture needs to also OPEN (not skip) P_DATA_V2 payloads —
// 02-04-PLAN.md Task 2's extension for golden-vector export/verification.
// Passing nil to decodeCapture (every pre-existing caller) preserves the
// function's original behavior of skipping data-channel payloads entirely.
//
// Two Wrapper key sets are needed, not one, because a single session's
// P_DATA_V2 traffic runs in two directions under the mirror-opposite
// key-direction convention (RESEARCH Pitfall 1): ServerPerspective (the
// server's own view — decrypt=keys[0]) opens client-to-server traffic;
// ClientPerspective (the exact mirror of ServerPerspective — decrypt=keys[1])
// opens server-to-client traffic. ClientPerspective is never independently
// derived; mirrorDataKeys below always builds it from ServerPerspective, the
// same "swap the four fields" relationship keyderiv.Key2.ServerSlots' own
// doc comment establishes between the two roles.
type dataChannelKeyMaterial struct {
	peerID            uint32
	serverPerspective keyderiv.DataKeys
}

// mirrorDataKeys returns keys' mirror-opposite role: encrypt and decrypt
// swapped. Given the server's own ServerSlots() output (encrypt=keys[1],
// decrypt=keys[0]), the mirror is exactly the client's own perspective
// (encrypt=keys[0], decrypt=keys[1]) — RESEARCH Pattern 4/Pitfall 1's
// mirror-opposite convention, expressed as a field swap rather than
// re-derived from Key2 (internal/keyderiv exposes no client-perspective
// accessor; this project's only two roles differ by exactly this swap).
func mirrorDataKeys(keys keyderiv.DataKeys) keyderiv.DataKeys {
	return keyderiv.DataKeys{
		EncryptCipher:     keys.DecryptCipher,
		EncryptImplicitIV: keys.DecryptImplicitIV,
		DecryptCipher:     keys.EncryptCipher,
		DecryptImplicitIV: keys.EncryptImplicitIV,
	}
}

// decodeCapture reads capturePath, tls-crypt-unwraps every control-channel
// UDP payload on port under key (building a fresh tlscrypt.Wrapper per
// payload — see capture_test.go's doc comment for why a fresh anti-replay
// window per payload is deliberate, not an oversight), and parses each
// into a decodedPacket. dataKeys is optional (nil for every pre-existing
// caller): when nil, P_DATA_V1/P_DATA_V2 payloads are skipped rather than
// decoded, exactly as before — that traffic is never tls-crypt wrapped
// (only the control channel is — RESEARCH Pitfall 3) and carries a
// different, shorter header shape with no 8-byte session ID at the
// control-channel offset. When dataKeys is supplied, P_DATA_V2 payloads are
// instead opened via internal/datachan.Wrapper (building the direction-
// appropriate Wrapper — server-perspective for client-to-server,
// client-perspective/mirrored for server-to-client, per Pitfall 1) and
// decoded into IsDataPacket/PeerID/DataPacketID/Plaintext. A control-channel
// payload that fails to authenticate or parse is still a hard error: exactly
// the case where a control packet went out unwrapped or corrupted, which
// must never be silently skipped (mirrors capture_test.go's own
// discipline). A data-channel payload that fails to authenticate when
// dataKeys IS supplied is also a hard error, for the same reason — a
// capture selected for golden-vector export must decode cleanly, or the
// export itself is unreliable.
func decodeCapture(capturePath string, key []byte, port uint16, dataKeys *dataChannelKeyMaterial) ([]decodedPacket, error) {
	f, err := os.Open(capturePath)
	if err != nil {
		return nil, fmt.Errorf("decode capture: open %s: %w", capturePath, err)
	}
	defer f.Close()

	payloads, err := ReadUDPPayloads(f, port)
	if err != nil {
		return nil, fmt.Errorf("decode capture: parse pcap: %w", err)
	}

	out := make([]decodedPacket, 0, len(payloads))
	for i, p := range payloads {
		// Opcode class must be determined BEFORE any tls-crypt-specific
		// length check: P_DATA_V1/P_DATA_V2 payloads are legitimately
		// shorter than tlscrypt.OffCT (the data channel has its own,
		// much shorter, 4-byte header + tag layout — RESEARCH Pattern 5),
		// and 02-04-PLAN.md Task 1 extended the live ping round-trip to
		// every scenario, so short data-channel packets now legitimately
		// appear in every capture, not only clean-small's. Checking the
		// tls-crypt minimum length first (as an earlier version of this
		// function did) rejected every such packet as "too short" before
		// ever reaching the data-channel skip below.
		if len(p.Payload) < 1 {
			return nil, fmt.Errorf("decode capture: payload %d (%s): empty payload", i, p.Direction)
		}
		opcode, _ := wire.ParseHeaderByte(p.Payload[0])
		if !wire.ValidOpcode(opcode) {
			return nil, fmt.Errorf("decode capture: payload %d (%s): header opcode %d outside the legal range", i, p.Direction, opcode)
		}
		if opcode == wire.OpDataV1 || opcode == wire.OpDataV2 {
			if dataKeys == nil || opcode != wire.OpDataV2 {
				// No key material supplied (every pre-existing caller), or
				// P_DATA_V1 (out of scope — RESEARCH State of the Art:
				// real 2.6 clients always negotiate V2): skip, exactly as
				// before.
				continue
			}

			// P_DATA_V2 header (RESEARCH Pattern 5):
			//   [opcode+keyid(1B)][peer-id(3B)][packet-id(4B)][tag(16B)][ciphertext]
			// 8 bytes are needed just to read peer-id/packet-id, before any
			// AEAD work.
			if len(p.Payload) < 8 {
				return nil, fmt.Errorf("decode capture: payload %d (%s): P_DATA_V2 payload shorter than its own 8-byte header+packet-id", i, p.Direction)
			}
			peerID := uint32(p.Payload[1])<<16 | uint32(p.Payload[2])<<8 | uint32(p.Payload[3])
			dataPacketID := binary.BigEndian.Uint32(p.Payload[4:8])

			var dw *datachan.Wrapper
			switch p.Direction {
			case DirClientToServer:
				// The server's own view opens client-to-server traffic
				// directly: its decrypt slot is the client's own encrypt
				// slot (Pitfall 1's mirror-opposite convention).
				dw, err = datachan.NewWrapper(dataKeys.serverPerspective, dataKeys.peerID, dataChannelKeyID)
			case DirServerToClient:
				// The mirrored (client-perspective) role's decrypt slot is
				// the server's own encrypt slot.
				dw, err = datachan.NewWrapper(mirrorDataKeys(dataKeys.serverPerspective), dataKeys.peerID, dataChannelKeyID)
			}
			if err != nil {
				return nil, fmt.Errorf("decode capture: payload %d (%s): build data-channel wrapper: %w", i, p.Direction, err)
			}

			plaintext, openErr := dw.Open(nil, p.Payload)
			isPing := errors.Is(openErr, datachan.ErrPingAbsorbed)
			if openErr != nil && !isPing {
				return nil, fmt.Errorf("decode capture: payload %d (%s): data-channel authentication failed: %w", i, p.Direction, openErr)
			}

			raw := append([]byte(nil), p.Payload...)
			out = append(out, decodedPacket{
				Direction:    p.Direction,
				Raw:          raw,
				IsDataPacket: true,
				IsPing:       isPing,
				PeerID:       peerID,
				DataPacketID: dataPacketID,
				Plaintext:    plaintext,
			})
			continue
		}

		if len(p.Payload) < tlscrypt.OffCT {
			return nil, fmt.Errorf("decode capture: payload %d (%s): length %d shorter than the tls-crypt prefix", i, p.Direction, len(p.Payload))
		}

		var w *tlscrypt.Wrapper
		switch p.Direction {
		case DirClientToServer:
			w, err = tlscrypt.NewWrapper(key, true)
		case DirServerToClient:
			w, err = tlscrypt.NewWrapper(key, false)
		}
		if err != nil {
			return nil, fmt.Errorf("decode capture: payload %d (%s): build wrapper: %w", i, p.Direction, err)
		}

		header, plaintext, err := w.Unwrap(nil, p.Payload)
		if err != nil {
			return nil, fmt.Errorf("decode capture: payload %d (%s): tls-crypt authentication failed: %w", i, p.Direction, err)
		}

		hdrOpcode, hdrKeyID := wire.ParseHeaderByte(header[0])
		var sid wire.SessionID
		copy(sid[:], header[1:1+wire.SessionIDSize])
		hdr := wire.Header{Opcode: hdrOpcode, KeyID: hdrKeyID, SessionID: sid}

		cp, err := wire.ParseControlPacket(plaintext, hdr)
		if err != nil {
			return nil, fmt.Errorf("decode capture: payload %d (%s): decrypted but did not parse as a well-formed control packet: %w", i, p.Direction, err)
		}

		raw := append([]byte(nil), p.Payload...)
		out = append(out, decodedPacket{Direction: p.Direction, Raw: raw, Header: hdr, Control: cp})
	}

	return out, nil
}
