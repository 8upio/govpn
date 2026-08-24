package datachan

import (
	"bytes"
	"errors"
	"testing"

	"github.com/8upio/govpn/internal/wire"
)

// TestPingMagicBytesExact asserts the package's magic constant equals the
// 16 bytes from ping.c:42-45, against a literal, and that its length is
// exactly 16.
func TestPingMagicBytesExact(t *testing.T) {
	want := [16]byte{
		0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
		0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
	}
	if PingSize != 16 {
		t.Fatalf("PingSize = %d, want 16", PingSize)
	}
	if pingMagic != want {
		t.Errorf("pingMagic = %x, want %x", pingMagic, want)
	}
}

// TestPingIsAbsorbedNotDelivered asserts a sealed ping packet fed through
// Open yields ErrPingAbsorbed and no plaintext, while a 16-byte payload
// differing in one byte is delivered normally as an IP packet.
func TestPingIsAbsorbedNotDelivered(t *testing.T) {
	w, err := NewWrapper(testDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	sealed, err := w.SealPing(nil)
	if err != nil {
		t.Fatalf("SealPing: %v", err)
	}
	plaintext, err := w.Open(nil, sealed)
	if !errors.Is(err, ErrPingAbsorbed) {
		t.Errorf("Open(ping) err = %v, want ErrPingAbsorbed", err)
	}
	if plaintext != nil {
		t.Errorf("Open(ping) plaintext = %x, want nil", plaintext)
	}

	real := append([]byte(nil), pingMagic[:]...)
	real[0] ^= 0x01 // one bit different from the magic — must be delivered
	sealedReal, err := w.Seal(nil, real)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := w.Open(nil, sealedReal)
	if err != nil {
		t.Fatalf("Open(non-ping 16-byte payload) = %v, want success", err)
	}
	if !bytes.Equal(got, real) {
		t.Errorf("Open(non-ping) = %x, want %x", got, real)
	}
}

// TestPingIsEncryptedLikeAnyPacket asserts an emitted server ping is a
// well-formed P_DATA_V2 packet that the peer wrapper decrypts to exactly
// the magic bytes — not a special opcode, not sent in the clear.
func TestPingIsEncryptedLikeAnyPacket(t *testing.T) {
	serverKeys := testDataKeys(t) // symmetric: encrypt slot == decrypt slot
	w, err := NewWrapper(serverKeys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	sealed, err := w.SealPing(nil)
	if err != nil {
		t.Fatalf("SealPing: %v", err)
	}

	// A well-formed P_DATA_V2 packet: correct opcode nibble, correct
	// length (no shortcut opcode/framing for a ping).
	if got := sealed[0] >> 3; wire.Opcode(got) != wire.OpDataV2 {
		t.Errorf("sealed ping opcode = %d, want OpDataV2", got)
	}
	wantLen := headerSize + TagSize + PingSize
	if len(sealed) != wantLen {
		t.Fatalf("len(sealed ping) = %d, want %d", len(sealed), wantLen)
	}

	// The wire ciphertext must NOT equal the plaintext magic — proving the
	// ping is genuinely encrypted, not sent in the clear.
	ciphertext := sealed[offCiphertext:]
	if bytes.Equal(ciphertext, pingMagic[:]) {
		t.Error("ciphertext bytes equal the plaintext magic — the ping was not actually encrypted")
	}

	// A separate Wrapper built from the SAME (symmetric, self-decrypting)
	// keys decrypts it back to exactly the magic bytes — the peer's own
	// receive path, proving the round trip end to end.
	peer, err := NewWrapper(serverKeys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper (peer): %v", err)
	}
	if _, err := peer.Open(nil, sealed); !errors.Is(err, ErrPingAbsorbed) {
		t.Errorf("peer Open(ping) = %v, want ErrPingAbsorbed (the decrypted plaintext must equal the magic)", err)
	}
}

// TestServerEmitsPingOnSchedule and TestPingTimerStopsOnClose exercise the
// per-session keepalive timer, which lives in package ovpn (ovpn.go/
// session.go), not here — see ovpn_test.go's TestSessionPingTimer* for
// those, driven with an injected clock exactly like internal/reliable's
// own Clock pattern.
