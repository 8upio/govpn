package keyderiv

import (
	"bytes"
	"testing"
)

// TestKeyDirectionServerIsInverse asserts keyDirection's server/client
// mapping matches the reference's KEY_DIRECTION_INVERSE/NORMAL selection
// (ssl.c:1519-1530).
func TestKeyDirectionServerIsInverse(t *testing.T) {
	encIdx, decIdx := keyDirection(true)
	if encIdx != 1 || decIdx != 0 {
		t.Fatalf("keyDirection(true) = (%d, %d), want (1, 0)", encIdx, decIdx)
	}

	encIdx, decIdx = keyDirection(false)
	if encIdx != 0 || decIdx != 1 {
		t.Fatalf("keyDirection(false) = (%d, %d), want (0, 1)", encIdx, decIdx)
	}
}

// TestKeyDirectionIsOppositeOfTLSCrypt is an explicit assertion, per
// RESEARCH.md Pitfall 1, that keyDirection(true)'s encrypt index is NOT 0 —
// i.e. NOT the value internal/tlscrypt.NewWrapper uses for the same
// server boolean (tlscrypt.go:180-184: server encrypt=keys[0]). The
// data-channel convention is the mirror opposite of tls-crypt's; copying
// tlscrypt's slot-assignment pattern here would silently break interop
// with a real client while still passing any test that only checks two
// instances of this package's own types agree with each other.
func TestKeyDirectionIsOppositeOfTLSCrypt(t *testing.T) {
	encIdx, _ := keyDirection(true)
	const tlsCryptServerEncryptIdx = 0 // internal/tlscrypt.NewWrapper's server encrypt=keys[0]
	if encIdx == tlsCryptServerEncryptIdx {
		t.Fatalf("keyDirection(true) encrypt index = %d, which matches internal/tlscrypt's server encrypt index (%d) — the data-channel convention must be the mirror opposite (RESEARCH.md Pitfall 1)", encIdx, tlsCryptServerEncryptIdx)
	}
}

// TestServerSlotsMatchReferenceByteRanges builds a Key2 from 256 bytes
// where byte i has value byte(i) and asserts ServerSlots() returns slices
// equal to literal expected ranges stated independently in this test body
// (never against another call of the same function) — so a flipped
// keyDirection makes this test fail, per RESEARCH.md Pitfall 1's "Warning
// signs" paragraph.
func TestServerSlotsMatchReferenceByteRanges(t *testing.T) {
	raw := make([]byte, 256)
	for i := range raw {
		raw[i] = byte(i)
	}
	k, err := NewKey2(raw)
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}

	slots := k.ServerSlots()

	wantEncCipher := raw[128:160]
	wantEncIV := raw[192:200]
	wantDecCipher := raw[0:32]
	wantDecIV := raw[64:72]

	if !bytes.Equal(slots.EncryptCipher[:], wantEncCipher) {
		t.Fatalf("EncryptCipher = %x, want %x (key2[128:160])", slots.EncryptCipher[:], wantEncCipher)
	}
	if !bytes.Equal(slots.EncryptImplicitIV[:], wantEncIV) {
		t.Fatalf("EncryptImplicitIV = %x, want %x (key2[192:200])", slots.EncryptImplicitIV[:], wantEncIV)
	}
	if !bytes.Equal(slots.DecryptCipher[:], wantDecCipher) {
		t.Fatalf("DecryptCipher = %x, want %x (key2[0:32])", slots.DecryptCipher[:], wantDecCipher)
	}
	if !bytes.Equal(slots.DecryptImplicitIV[:], wantDecIV) {
		t.Fatalf("DecryptImplicitIV = %x, want %x (key2[64:72])", slots.DecryptImplicitIV[:], wantDecIV)
	}
}

// TestSlotSizes asserts encrypt/decrypt cipher keys are exactly 32 bytes
// (AES-256) and implicit IVs are exactly 8 bytes — a 12-byte GCM nonce
// minus the 4-byte explicit packet ID leaves exactly the implicit-IV
// width.
func TestSlotSizes(t *testing.T) {
	raw := make([]byte, 256)
	k, err := NewKey2(raw)
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}
	slots := k.ServerSlots()

	if len(slots.EncryptCipher) != 32 {
		t.Fatalf("len(EncryptCipher) = %d, want 32", len(slots.EncryptCipher))
	}
	if len(slots.DecryptCipher) != 32 {
		t.Fatalf("len(DecryptCipher) = %d, want 32", len(slots.DecryptCipher))
	}
	if len(slots.EncryptImplicitIV) != 8 {
		t.Fatalf("len(EncryptImplicitIV) = %d, want 8", len(slots.EncryptImplicitIV))
	}
	if len(slots.DecryptImplicitIV) != 8 {
		t.Fatalf("len(DecryptImplicitIV) = %d, want 8", len(slots.DecryptImplicitIV))
	}

	const gcmNonceSize = 12
	const explicitPacketIDSize = 4
	wantImplicitIVSize := gcmNonceSize - explicitPacketIDSize
	if len(slots.EncryptImplicitIV) != wantImplicitIVSize {
		t.Fatalf("implicit IV size %d does not equal GCM nonce size (%d) minus explicit packet-ID size (%d) = %d", len(slots.EncryptImplicitIV), gcmNonceSize, explicitPacketIDSize, wantImplicitIVSize)
	}
}

// TestKey2RejectsWrongLength asserts constructing a Key2 from anything
// other than 256 bytes returns an error.
func TestKey2RejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 255, 257, 512} {
		if _, err := NewKey2(make([]byte, n)); err == nil {
			t.Fatalf("NewKey2(%d bytes) returned nil error, want an error", n)
		}
	}
}
