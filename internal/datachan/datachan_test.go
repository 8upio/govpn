package datachan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/tlscrypt"
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

// TestAuthFailureDoesNotTouchWindow is the state-assertion proof (not a
// comment) that Open's ordering — AEAD success strictly gates
// replay.accept — actually holds: a tampered packet at packet ID 7 fails
// with ErrAuth, and the SAME, untampered packet ID 7 is still accepted
// afterward, proving the failed attempt never advanced or marked the
// window (T-02-15).
func TestAuthFailureDoesNotTouchWindow(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	w.sendSeq = 6 // so the next Seal assigns packet ID 7

	sealed, err := w.Seal(nil, []byte("packet seven"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got := binary.BigEndian.Uint32(sealed[offPacketID:offTag]); got != 7 {
		t.Fatalf("test setup bug: sealed packet ID = %d, want 7", got)
	}

	tampered := append([]byte(nil), sealed...)
	tampered[offTag] ^= 0xFF
	if _, err := w.Open(nil, tampered); !errors.Is(err, ErrAuth) {
		t.Fatalf("Open(tampered packet ID 7) = %v, want ErrAuth", err)
	}

	plaintext, err := w.Open(nil, sealed)
	if err != nil {
		t.Fatalf("Open(untampered packet ID 7, after the rejected tamper attempt) = %v, want success — the failed attempt must not have marked the window", err)
	}
	if string(plaintext) != "packet seven" {
		t.Errorf("plaintext = %q, want %q", plaintext, "packet seven")
	}
}

// TestDataChannelWindowIndependentOfTLSCrypt mirrors
// internal/reliable's own TestReliabilityAndTLSCryptWindowsAreIndependent:
// a datachan.Wrapper and a tlscrypt.Wrapper driven with overlapping
// sequence numbers do not interfere — neither rejects a packet because the
// other saw that number (02-RESEARCH.md Pitfall 5).
func TestDataChannelWindowIndependentOfTLSCrypt(t *testing.T) {
	dataWrapper, err := NewWrapper(testDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	tlsCryptKey := make([]byte, 256)
	if _, err := rand.Read(tlsCryptKey); err != nil {
		t.Fatalf("generate tls-crypt key: %v", err)
	}
	sender, err := tlscrypt.NewWrapper(tlsCryptKey, true)
	if err != nil {
		t.Fatalf("tlscrypt sender: %v", err)
	}
	receiver, err := tlscrypt.NewWrapper(tlsCryptKey, false)
	if err != nil {
		t.Fatalf("tlscrypt receiver: %v", err)
	}
	header := make([]byte, 0, 9)
	header = append(header, 0x20)
	header = append(header, make([]byte, 8)...)

	for i := 1; i <= 2; i++ {
		tlsWire, err := sender.Wrap(nil, header, []byte("tls-crypt packet"))
		if err != nil {
			t.Fatalf("tlscrypt Wrap %d: %v", i, err)
		}
		if _, _, err := receiver.Unwrap(nil, tlsWire); err != nil {
			t.Fatalf("tlscrypt Unwrap %d (would fail if the data-channel window shared state with tls-crypt's): %v", i, err)
		}

		sealed, err := dataWrapper.Seal(nil, []byte("data channel packet"))
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		if _, err := dataWrapper.Open(nil, sealed); err != nil {
			t.Fatalf("Open %d (would fail if the data-channel window shared state with tls-crypt's): %v", i, err)
		}
	}
}

// TestTamperHasTeeth mirrors internal/tlscrypt/golden_test.go's own
// TestGoldenVectorTamperHasTeeth pattern: flipping one bit in the tag
// region of a valid packet makes Open fail, and the observed failure is
// logged (t.Logf), so a reader can see the assertion actually fired rather
// than trusting that it would have.
func TestTamperHasTeeth(t *testing.T) {
	keys := testDataKeys(t)
	w, err := NewWrapper(keys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sealed, err := w.Seal(nil, []byte("tamper has teeth"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := w.Open(nil, sealed); err != nil {
		t.Fatalf("untampered packet failed to open: %v", err)
	}

	tampered := append([]byte(nil), sealed...)
	tampered[offTag] ^= 0xFF

	w2, err := NewWrapper(keys, 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	if _, err := w2.Open(nil, tampered); err == nil {
		t.Fatal("expected Open to fail on a tampered tag byte, but it succeeded — the byte-exactness assertions elsewhere in this file would silently accept corrupted traffic")
	} else {
		t.Logf("observed expected failure on a tampered tag byte: %v", err)
	}
}

// TestConcurrentSealNeverDuplicatesPacketID asserts 500 goroutines calling
// Seal under -race produce 500 distinct packet IDs — GCM's entire
// nonce-uniqueness guarantee rests on this counter.
func TestConcurrentSealNeverDuplicatesPacketID(t *testing.T) {
	w, err := NewWrapper(testDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	const n = 500
	ids := make([]uint32, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sealed, err := w.Seal(nil, []byte("x"))
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = binary.BigEndian.Uint32(sealed[offPacketID:offTag])
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Seal (goroutine %d): %v", i, err)
		}
	}

	seen := make(map[uint32]bool, n)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate packet ID %d observed across %d concurrent Seal calls", id, n)
		}
		seen[id] = true
	}
	if len(seen) != n {
		t.Fatalf("observed %d distinct packet IDs, want %d", len(seen), n)
	}
}

// TestPacketIDFailsClosedAtMax asserts a Wrapper whose counter is already
// at 0xFFFFFFFF returns ErrPacketIDExhausted on the next Seal rather than
// wrapping to 0 and reusing a GCM nonce.
func TestPacketIDFailsClosedAtMax(t *testing.T) {
	w, err := NewWrapper(testDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	w.sendSeq = 0xFFFFFFFF

	if _, err := w.Seal(nil, []byte("one too many")); !errors.Is(err, ErrPacketIDExhausted) {
		t.Fatalf("Seal at counter ceiling = %v, want ErrPacketIDExhausted", err)
	}
}

// TestOpenReplayRejectionDoesNotLeakPlaintextIntoDst is WR-02's regression
// test. Unlike an ErrAuth failure (where Go's own GCM implementation zeroes
// the output region it wrote before returning), a replay rejection happens
// *after* AEAD.Open has already succeeded and written real decrypted
// plaintext — so if that decryption target were the caller's own dst
// buffer, a dst with spare backing capacity would be left holding
// successfully decrypted, attacker-controlled plaintext even though Open's
// return value discards it. Open must decrypt into a buffer that is never
// dst until after the replay check has also passed.
func TestOpenReplayRejectionDoesNotLeakPlaintextIntoDst(t *testing.T) {
	w, err := NewWrapper(testDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	plaintext := []byte("secret payload that must never leak into dst")
	sealed, err := w.Seal(nil, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// First Open succeeds and marks the replay window.
	if _, err := w.Open(nil, sealed); err != nil {
		t.Fatalf("first Open = %v, want success", err)
	}

	// Second Open with the identical bytes authenticates fine (same tag,
	// same key) but must be rejected as a replay.
	backing := make([]byte, 0, 64)
	for i := 0; i < cap(backing); i++ {
		backing = append(backing, 0xEE)
	}
	sentinel := append([]byte(nil), backing...)
	dst := backing[:0] // len 0, cap 64 — spare capacity aliasing backing's array.

	got, err := w.Open(dst, sealed)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("second Open (replay) = %v, want ErrReplay", err)
	}
	if got != nil {
		t.Errorf("second Open (replay) returned %q, want nil", got)
	}
	if !bytes.Equal(backing[:cap(backing)], sentinel) {
		t.Errorf("dst's backing array was written to on a replay rejection: got %x, want unchanged sentinel %x — decrypted attacker-controlled plaintext leaked into dst's spare capacity", backing[:cap(backing)], sentinel)
	}
}
