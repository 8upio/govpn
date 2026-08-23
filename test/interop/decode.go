// Package interop's decode.go builds on pcap.go's raw UDP-payload extraction
// to tls-crypt-unwrap and control-packet-parse every captured datagram on
// the tunnel port, in capture order. This is the shared building block
// behind capture_test.go's byte-exactness/tamper-detection checks,
// interop_test.go's fragmentation assertion, and golden_export.go's vector
// selection (01-04-PLAN.md Task 1/2) — one decode path, three consumers,
// rather than three drifting re-implementations of the same tls-crypt
// unwrap + control-packet parse sequence.
package interop

import (
	"fmt"
	"os"

	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// tunnelPort must match the UDP port test/interop/docker-compose.yml's
// server service listens on and cmd/gentestpki's generated client.conf
// targets.
const tunnelPort = 1194

// decodedPacket is one captured, successfully tls-crypt-unwrapped and
// control-packet-parsed datagram.
type decodedPacket struct {
	Direction Direction
	Raw       []byte // the exact captured wire bytes (tls-crypt wrapped)
	Header    wire.Header
	Control   wire.ControlPacket
}

// decodeCapture reads capturePath, tls-crypt-unwraps every UDP payload on
// port under key (building a fresh tlscrypt.Wrapper per payload — see
// capture_test.go's doc comment for why a fresh anti-replay window per
// payload is deliberate, not an oversight), and parses each into a
// decodedPacket. A payload that fails to authenticate or parse is a hard
// error: exactly the case where a control packet went out unwrapped or
// corrupted, which must never be silently skipped (mirrors
// capture_test.go's own discipline).
func decodeCapture(capturePath string, key []byte, port uint16) ([]decodedPacket, error) {
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
		if len(p.Payload) < tlscrypt.OffCT {
			return nil, fmt.Errorf("decode capture: payload %d (%s): length %d shorter than the tls-crypt prefix", i, p.Direction, len(p.Payload))
		}

		opcode, _ := wire.ParseHeaderByte(p.Payload[0])
		if !wire.ValidOpcode(opcode) {
			return nil, fmt.Errorf("decode capture: payload %d (%s): header opcode %d outside the legal range", i, p.Direction, opcode)
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
