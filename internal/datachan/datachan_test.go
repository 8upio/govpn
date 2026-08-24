package datachan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/wire"
)

// testDataKeys builds a deterministic, symmetric keyderiv.DataKeys: the
// encrypt and decrypt slots are identical, so a single Wrapper built from
// it can Seal and Open its own traffic — sufficient for this file's
// wire-layout/tamper tests, which are about byte-exact framing, not
// cross-direction key-derivation correctness (already proven by
// internal/keyderiv's own tests against the reference's byte ranges).
func testDataKeys(t testing.TB) keyderiv.DataKeys {
	t.Helper()
	var keys keyderiv.DataKeys
	for i := range keys.EncryptCipher {
		keys.EncryptCipher[i] = byte(0x10 + i)
	}
	for i := range keys.EncryptImplicitIV {
		keys.EncryptImplicitIV[i] = byte(0x20 + i)
	}
	keys.DecryptCipher = keys.EncryptCipher
	keys.DecryptImplicitIV = keys.EncryptImplicitIV
	return keys
}

// TestSealLayout asserts the full P_DATA_V2 wire layout: opcode+keyid byte,
// 24-bit big-endian peer-id, 32-bit big-endian packet-id, exact length, and
// — independently — that bytes 8..23 equal the tag a separate, directly
// constructed cipher.AEAD.Seal call produces for the same inputs, proving
// the tag occupies the slot immediately after the header and before the
// ciphertext (RESEARCH Pattern 5).
func TestSealLayout(t *testing.T) {
	keys := testDataKeys(t)
	const peerID = 0x102030
	const keyID = 3

	w, err := NewWrapper(keys, peerID, keyID)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	plaintext := bytes.Repeat([]byte{0xAB}, 100)
	sealed, err := w.Seal(nil, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wantFirstByte := byte(wire.OpDataV2)<<3 | keyID
	if sealed[0] != wantFirstByte {
		t.Errorf("first byte = 0x%02x, want 0x%02x", sealed[0], wantFirstByte)
	}

	gotPeerID := uint32(sealed[1])<<16 | uint32(sealed[2])<<8 | uint32(sealed[3])
	if gotPeerID != peerID {
		t.Errorf("peer-id = 0x%06x, want 0x%06x", gotPeerID, peerID)
	}

	gotPacketID := binary.BigEndian.Uint32(sealed[4:8])
	if gotPacketID != 1 {
		t.Errorf("packet-id = %d, want 1", gotPacketID)
	}

	wantLen := 8 + TagSize + len(plaintext)
	if len(sealed) != wantLen {
		t.Fatalf("len(sealed) = %d, want %d", len(sealed), wantLen)
	}

	block, err := aes.NewCipher(keys.EncryptCipher[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	var nonce [NonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], gotPacketID)
	copy(nonce[4:12], keys.EncryptImplicitIV[:])
	header := sealed[:8]
	directSealed := aead.Seal(nil, nonce[:], plaintext, header)
	directTag := directSealed[len(directSealed)-TagSize:]

	if !bytes.Equal(sealed[8:24], directTag) {
		t.Errorf("bytes 8..23 (wire tag) = %x, want %x (an independently-computed aead.Seal tag) — the tag must occupy the slot immediately after the header, before the ciphertext", sealed[8:24], directTag)
	}
}

// TestSealAADIsHeaderOnly asserts the AAD covers exactly the first 8 header
// bytes: mutating any of them, or the tag's first byte (offset 8), breaks
// authentication.
func TestSealAADIsHeaderOnly(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 5, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sealed, err := w.Seal(nil, []byte("hello world"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for i := 0; i < headerSize; i++ {
		tampered := append([]byte(nil), sealed...)
		tampered[i] ^= 0xFF
		if _, err := w.Open(nil, tampered); err == nil {
			t.Errorf("mutating header byte %d did not cause Open to fail", i)
		}
	}

	tampered := append([]byte(nil), sealed...)
	tampered[offTag] ^= 0xFF // first byte of the tag, offset 8
	if _, err := w.Open(nil, tampered); err == nil {
		t.Error("mutating byte 8 (start of tag) did not cause Open to fail")
	}
}

// TestNonceIsConcatenationNotXor asserts the 12-byte nonce is the literal
// concatenation packetID(4) || implicitIV(8), not a bitwise XOR of two
// disjoint ranges (Pitfall 2 / CLAUDE.md's own loose shorthand phrasing).
// It decrypts Seal's own output using a directly-constructed cipher.AEAD
// and the LITERAL expected nonce bytes — an XOR implementation would
// produce a different actual nonce and this decrypt would fail.
func TestNonceIsConcatenationNotXor(t *testing.T) {
	keys := testDataKeys(t)
	for i := range keys.EncryptImplicitIV {
		keys.EncryptImplicitIV[i] = 0xFF
	}
	keys.DecryptImplicitIV = keys.EncryptImplicitIV

	w, err := NewWrapper(keys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	plaintext := []byte("nonce test")
	sealed, err := w.Seal(nil, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wantNonce := []byte{
		0x00, 0x00, 0x00, 0x01, // packet ID 1, big-endian
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // implicit IV
	}

	block, err := aes.NewCipher(keys.EncryptCipher[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	header := sealed[:headerSize]
	tag := sealed[offTag:offCiphertext]
	ciphertext := sealed[offCiphertext:]
	reordered := append(append([]byte{}, ciphertext...), tag...)

	plain, err := aead.Open(nil, wantNonce, reordered, header)
	if err != nil {
		t.Fatalf("decrypting with the literal concatenated nonce failed (an XOR implementation would fail here): %v", err)
	}
	if !bytes.Equal(plain, plaintext) {
		t.Errorf("decrypted plaintext = %q, want %q", plain, plaintext)
	}
}

// TestOpenRejectsShortPacket asserts every prefix length from 0 to 23
// (offCiphertext-1) returns ErrShort without ever indexing out of range.
func TestOpenRejectsShortPacket(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	full, err := w.Seal(nil, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for n := 0; n < offCiphertext; n++ {
		prefix := full[:n]
		if _, err := w.Open(nil, prefix); !errors.Is(err, ErrShort) {
			t.Errorf("Open with a %d-byte prefix = %v, want ErrShort", n, err)
		}
	}
}

// TestOpenRejectsWrongPeerID asserts that a packet whose peer-id bytes have
// been tampered with fails authentication: the peer-id is part of the AAD,
// so a forged peer-id from the wrong source cannot produce plaintext
// (T-02-12 — peer-id is a routing hint, never a trust signal on its own).
func TestOpenRejectsWrongPeerID(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 0x000001, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sealed, err := w.Seal(nil, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := append([]byte(nil), sealed...)
	tampered[offPeerID] ^= 0xFF
	if _, err := w.Open(nil, tampered); !errors.Is(err, ErrAuth) {
		t.Errorf("Open with a tampered peer-id = %v, want ErrAuth", err)
	}
}

// TestOpenRejectsTamperedTag asserts a flipped bit in either the tag
// (bytes 8..23) or the ciphertext returns ErrAuth and no plaintext.
func TestOpenRejectsTamperedTag(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sealed, err := w.Seal(nil, []byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tag := append([]byte(nil), sealed...)
	tag[offTag] ^= 0xFF
	plaintext, err := w.Open(nil, tag)
	if !errors.Is(err, ErrAuth) {
		t.Errorf("Open with a tampered tag byte = %v, want ErrAuth", err)
	}
	if plaintext != nil {
		t.Errorf("Open with a tampered tag returned non-nil plaintext: %x", plaintext)
	}

	cipherTamper := append([]byte(nil), sealed...)
	cipherTamper[len(cipherTamper)-1] ^= 0xFF
	if _, err := w.Open(nil, cipherTamper); !errors.Is(err, ErrAuth) {
		t.Errorf("Open with a tampered ciphertext byte = %v, want ErrAuth", err)
	}
}

// TestPacketIDStartsAtOne asserts the first sealed packet carries packet ID
// 1, not 0 (packet_id_send_update, packet_id.c:323-344).
func TestPacketIDStartsAtOne(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sealed, err := w.Seal(nil, []byte("x"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got := binary.BigEndian.Uint32(sealed[offPacketID:offTag]); got != 1 {
		t.Errorf("first packet ID = %d, want 1", got)
	}
}

// TestOpenAbsorbsPingWithoutDeliveringPlaintext proves the tracer's own
// minimal ping guard (Task 1's action text) works before Task 3 completes
// it: a sealed ping magic packet yields ErrPingAbsorbed and no plaintext,
// while an ordinary same-length payload is delivered normally.
func TestOpenAbsorbsPingWithoutDeliveringPlaintext(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 1, 0)
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

	real := append([]byte(nil), pingMagicTask1[:]...)
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
