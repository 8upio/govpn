//go:build interop

package interop

import (
	"os"
	"testing"

	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// TestCaptureIsFullyTLSCryptWrapped is Phase 1 plan 01-02's Task 2
// verification: an independent packet capture taken on the wire during a
// real client run, parsed with a stdlib-only reader (no gopacket), proves
// that every control-channel datagram on the tunnel port authenticates and
// decrypts under the harness tls-crypt key in its correct direction —
// Phase 1 success criterion 3. It runs against the "clean-small" scenario's
// preserved capture and tls-crypt key (01-04-PLAN.md Task 1 restructured
// the single-run harness into a scenario table driven from TestMain;
// clean-small is the fastest scenario and the direct successor of this
// test's original single-run fixture).
func TestCaptureIsFullyTLSCryptWrapped(t *testing.T) {
	res, ok := scenarioResults["clean-small"]
	if !ok {
		t.Fatal("no result recorded for scenario \"clean-small\" (TestMain setup failure?)")
	}
	if res.composeErr != nil {
		t.Fatalf("clean-small scenario did not pass, capture may be incomplete: %v", res.composeErr)
	}

	f, err := os.Open(res.capturePath)
	if err != nil {
		t.Fatalf("open capture %s: %v", res.capturePath, err)
	}
	defer f.Close()

	payloads, err := ReadUDPPayloads(f, tunnelPort)
	if err != nil {
		t.Fatalf("parse capture: %v", err)
	}

	key, err := readTLSCryptKey(res.keyPath)
	if err != nil {
		t.Fatalf("read tls-crypt key %s: %v", res.keyPath, err)
	}

	// A fresh Wrapper per payload, not one long-lived Wrapper per direction.
	// Mirroring the client/server key-direction convention
	// (internal/tlscrypt.NewWrapper doc): a captured client-to-server
	// payload was encrypted with the CLIENT's encrypt slot (keys[1]), which
	// is the SERVER-direction wrapper's decrypt slot, and vice versa.
	//
	// Constructing a fresh Wrapper per payload deliberately gives each
	// payload its own virgin anti-replay window. As of plan 01-03 the
	// server's own reliability layer ACKs control traffic all the way
	// through a completed TLS handshake, so legitimate retransmissions of
	// the SAME already-tls-crypt-wrapped buffer are now the exception
	// rather than the rule (they can still happen transiently — e.g. the
	// client's very first hard reset racing the server's reply). A single
	// persistent Wrapper would correctly (by tls-crypt's own design) reject
	// a genuine retransmission's second copy as a replay — that is exactly
	// what a real, protocol-complete server's tls-crypt layer would also do
	// once it had ACKed the first copy — but this test is not checking
	// anti-replay enforcement (internal/tlscrypt/tlscrypt_test.go already
	// covers that byte-exactly); it is checking that every captured
	// datagram, including any retransmission, authenticates and decrypts
	// correctly under the harness key in its correct direction.
	var clientToServer int
	for i, p := range payloads {
		if len(p.Payload) < tlscrypt.OffCT {
			t.Fatalf("payload %d (%s): length %d is shorter than the 49-byte tls-crypt prefix", i, p.Direction, len(p.Payload))
		}

		opcode, _ := wire.ParseHeaderByte(p.Payload[0])
		if !wire.ValidOpcode(opcode) {
			t.Fatalf("payload %d (%s): header opcode %d outside the legal P_FIRST_OPCODE..P_LAST_OPCODE range", i, p.Direction, opcode)
		}

		var w *tlscrypt.Wrapper
		switch p.Direction {
		case DirClientToServer:
			w, err = tlscrypt.NewWrapper(key, true)
			clientToServer++
		case DirServerToClient:
			w, err = tlscrypt.NewWrapper(key, false)
		}
		if err != nil {
			t.Fatalf("payload %d (%s): build wrapper: %v", i, p.Direction, err)
		}

		header, plaintext, err := w.Unwrap(nil, p.Payload)
		if err != nil {
			// A single payload that fails to authenticate is exactly the
			// case where a control packet went out unwrapped — fail the
			// whole test, don't skip and keep going.
			t.Fatalf("payload %d (%s) failed tls-crypt authentication: %v — a control packet went out unwrapped or corrupted", i, p.Direction, err)
		}

		hdrOpcode, hdrKeyID := wire.ParseHeaderByte(header[0])
		var sid wire.SessionID
		copy(sid[:], header[1:1+wire.SessionIDSize])
		hdr := wire.Header{Opcode: hdrOpcode, KeyID: hdrKeyID, SessionID: sid}

		if _, err := wire.ParseControlPacket(plaintext, hdr); err != nil {
			t.Fatalf("payload %d (%s) decrypted but its plaintext did not parse as a well-formed control packet: %v", i, p.Direction, err)
		}
	}

	// Not a hardcoded total packet count (loss/retransmission make counts
	// vary between runs) — only a floor that rules out an empty or
	// truncated capture: the reset plus at least one subsequent control
	// packet.
	if clientToServer < 2 {
		t.Fatalf("only %d client-to-server control payloads observed (want at least 2: the reset and one control packet) — capture is empty or truncated", clientToServer)
	}

	// Regression coverage proving the assertion above has teeth: corrupting
	// one byte inside a payload's authentication tag (offset 20 falls
	// within tls_crypt.h's TLS_CRYPT_OFF_TAG..OFF_CT range, bytes 17-48)
	// must make tls-crypt authentication fail, not silently succeed.
	t.Run("tamper detection proves the assertion has teeth", func(t *testing.T) {
		var target UDPPayload
		found := false
		for _, p := range payloads {
			if p.Direction == DirClientToServer && len(p.Payload) > 20 {
				target = p
				found = true
				break
			}
		}
		if !found {
			t.Fatal("no client-to-server payload long enough to tamper with")
		}

		tampered := append([]byte(nil), target.Payload...)
		tampered[20] ^= 0xFF

		w, err := tlscrypt.NewWrapper(key, true)
		if err != nil {
			t.Fatalf("build wrapper: %v", err)
		}
		if _, _, err := w.Unwrap(nil, tampered); err == nil {
			t.Fatal("expected tls-crypt authentication to fail on a tampered payload, but Unwrap succeeded — the main assertion above would silently accept corrupted traffic")
		}
	})
}
