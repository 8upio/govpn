// Golden-vector tests for DATA-01/DATA-02, verified against real OpenVPN
// 2.6.14 client data-channel traffic: unlike datachan_test.go's
// self-generated round-trip vectors, every vector here is a raw P_DATA_V2
// datagram a real, unmodified client actually produced, captured via the
// Docker interop harness and committed to testdata/golden (02-04-PLAN.md
// Task 2). No build tag: this runs in the fast tier, no Docker needed —
// the corpus is regenerated deliberately via `make golden`, not on every
// run. Mirrors internal/tlscrypt/golden_test.go's own structure and helper
// shapes (loadGoldenManifest/readVector), extended with the data-channel-
// only fields (peer_id, data_packet_id, key_file, sender_slot)
// manifest.json's schema gained this phase.
package datachan

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/8upio/govpn/internal/keyderiv"
)

const goldenDir = "../../testdata/golden"

// goldenManifestEntry mirrors test/interop/golden_export.go's own struct of
// the same name exactly — an independent local copy, matching this
// project's established per-package convention (internal/wire/golden_test.go
// and internal/tlscrypt/golden_test.go each already define their own).
// Cipher (05-05-PLAN.md Task 1) is a data-channel-only field: an absent
// value means AES-256-GCM (every entry committed before Phase 5's cipher
// negotiation meant that implicitly), so a manifest checked out at an
// older revision — or any control-channel entry, which never sets it —
// stays readable unchanged.
type goldenManifestEntry struct {
	File      string `json:"file"`
	Direction string `json:"direction"`
	Opcode    int    `json:"opcode"`
	PacketID  uint32 `json:"packet_id"`

	PeerID       *uint32 `json:"peer_id,omitempty"`
	DataPacketID *uint32 `json:"data_packet_id,omitempty"`
	KeyFile      string  `json:"key_file,omitempty"`
	SenderSlot   *int    `json:"sender_slot,omitempty"`
	Cipher       string  `json:"cipher,omitempty"`
}

// manifestCipher returns entry's cipher name, defaulting to "AES-256-GCM"
// when absent — goldenManifestEntry.Cipher's own documented meaning for
// every vector committed before cipher negotiation existed.
func manifestCipher(entry goldenManifestEntry) string {
	if entry.Cipher == "" {
		return "AES-256-GCM"
	}
	return entry.Cipher
}

func loadGoldenManifest(t *testing.T) []goldenManifestEntry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json (run `make golden` to (re)generate testdata/golden): %v", err)
	}
	var manifest []goldenManifestEntry
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest.json: %v", err)
	}
	if len(manifest) == 0 {
		t.Fatal("manifest.json is empty")
	}
	return manifest
}

// dataChannelEntries filters manifest to the data-channel vectors
// (KeyFile != "" — control-channel entries never set it).
func dataChannelEntries(manifest []goldenManifestEntry) []goldenManifestEntry {
	var out []goldenManifestEntry
	for _, e := range manifest {
		if e.KeyFile != "" {
			out = append(out, e)
		}
	}
	return out
}

func readVector(t *testing.T, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir, file))
	if err != nil {
		t.Fatalf("read vector %s: %v", file, err)
	}
	return raw
}

// dataChannelKeyFile mirrors test/interop/server/main.go's own
// dataChannelKeyExport JSON shape exactly (hex-encoded byte fields).
// Cipher/CipherKeyLen (05-05-PLAN.md Task 1) are optional: a key file
// written before 05-04-PLAN.md landed has neither, and loadGoldenDataKeys
// below defaults CipherKeyLen to 32 in that case — the only cipher v1.0
// ever produced. EncryptCipher/DecryptCipher stay 32-byte-wide (64 hex
// chars) for every cipher, including AES-128-GCM: they carry the full
// key-expansion slot, not the trimmed AEAD key (RESEARCH.md Pitfall 5) —
// hexDecodeFixed's exact-length check against the fixed [32]byte
// destination is unchanged and still runs for every key file.
type dataChannelKeyFile struct {
	EncryptCipher     string `json:"encrypt_cipher"`
	EncryptImplicitIV string `json:"encrypt_implicit_iv"`
	DecryptCipher     string `json:"decrypt_cipher"`
	DecryptImplicitIV string `json:"decrypt_implicit_iv"`
	Cipher            string `json:"cipher,omitempty"`
	CipherKeyLen      int    `json:"cipher_key_len,omitempty"`
}

func loadGoldenDataKeys(t *testing.T, keyFile string) keyderiv.DataKeys {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, keyFile))
	if err != nil {
		t.Fatalf("read data-channel key file %s: %v", keyFile, err)
	}
	var f dataChannelKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", keyFile, err)
	}
	var keys keyderiv.DataKeys
	hexDecodeFixed(t, f.EncryptCipher, keys.EncryptCipher[:])
	hexDecodeFixed(t, f.EncryptImplicitIV, keys.EncryptImplicitIV[:])
	hexDecodeFixed(t, f.DecryptCipher, keys.DecryptCipher[:])
	hexDecodeFixed(t, f.DecryptImplicitIV, keys.DecryptImplicitIV[:])
	// CipherKeyLen (05-05-PLAN.md Task 1): a key file predating cipher
	// negotiation (no cipher/cipher_key_len field) means AES-256-GCM,
	// matching every vector this corpus held before Phase 5 — default to
	// 32 rather than reading the zero value straight through.
	keys.CipherKeyLen = f.CipherKeyLen
	if keys.CipherKeyLen == 0 {
		keys.CipherKeyLen = 32
	}
	return keys
}

func hexDecodeFixed(t *testing.T, s string, dst []byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	if len(b) != len(dst) {
		t.Fatalf("hex field %q: expected %d bytes, got %d", s, len(dst), len(b))
	}
	copy(dst, b)
}

// mirrorDataKeys returns keys' mirror-opposite role — encrypt and decrypt
// swapped. This is the same "swap the four fields" relationship
// test/interop/decode.go's own mirrorDataKeys establishes: given the
// server's own ServerSlots() output (encrypt=keys[1], decrypt=keys[0]),
// the mirror is exactly the client's own perspective (encrypt=keys[0],
// decrypt=keys[1]) — RESEARCH Pattern 4/Pitfall 1's mirror-opposite
// convention.
func mirrorDataKeys(keys keyderiv.DataKeys) keyderiv.DataKeys {
	return keyderiv.DataKeys{
		EncryptCipher:     keys.DecryptCipher,
		EncryptImplicitIV: keys.DecryptImplicitIV,
		DecryptCipher:     keys.EncryptCipher,
		DecryptImplicitIV: keys.EncryptImplicitIV,
		CipherKeyLen:      keys.CipherKeyLen,
	}
}

// wrapperForVector builds the Wrapper needed either to OPEN (the
// receiver's own natural role) or to RESEAL (the ORIGINAL SENDER's role —
// the opposite of the role used to open, mirroring
// internal/tlscrypt.golden_test.go's own documented inversion,
// 01-04-SUMMARY.md Deviation 3) a vector captured in the given direction:
//
//   - OPEN a client-to-server vector: serverSlots directly (its decrypt
//     slot IS the client's own encrypt slot).
//   - OPEN a server-to-client vector: mirrorDataKeys(serverSlots) (its
//     decrypt slot IS the server's own encrypt slot).
//   - RESEAL a client-to-server vector: mirrorDataKeys(serverSlots) (its
//     encrypt slot must match the client's own encrypt slot).
//   - RESEAL a server-to-client vector: serverSlots directly (its encrypt
//     slot must match the server's own encrypt slot).
//
// cipher (05-05-PLAN.md Task 1) is the vector's own manifest-named cipher
// (manifestCipher(entry)) — used only in the failure message below, so a
// mismatched key length fails with "which cipher the entry claimed" rather
// than a bare "open failed" that costs an hour to trace back to the
// manifest.
func wrapperForVector(t *testing.T, serverSlots keyderiv.DataKeys, peerID uint32, direction string, forOpen bool, cipher string) *Wrapper {
	t.Helper()
	clientToServer := direction == "client->server"
	useServerSlotsDirectly := clientToServer == forOpen
	keys := serverSlots
	if !useServerSlotsDirectly {
		keys = mirrorDataKeys(serverSlots)
	}
	// keyID is always 0 in v1 (no renegotiation, SESS-04) — matching every
	// live-traffic caller's own fixed value.
	w, err := NewWrapper(keys, peerID, 0)
	if err != nil {
		t.Fatalf("build wrapper (cipher=%s direction=%s forOpen=%v): %v", cipher, direction, forOpen, err)
	}
	return w
}

// TestGoldenDataChannelOpen is 02-04-PLAN.md Task 2's DATA-01 verification
// against real client bytes: every committed P_DATA_V2 vector opens with
// the key material committed alongside it, yielding a plaintext that
// parses as an IPv4 packet (checked structurally — version nibble, minimum
// header length) or is the 16-byte ping keepalive (observed via
// ErrPingAbsorbed, which only Open returns after its own AEAD tag check
// AND its own plaintext-equals-ping-magic check have both already
// succeeded — datachan.go's own documented ordering).
func TestGoldenDataChannelOpen(t *testing.T) {
	manifest := loadGoldenManifest(t)
	entries := dataChannelEntries(manifest)
	if len(entries) == 0 {
		t.Fatal("no data-channel vectors in manifest.json")
	}

	for _, entry := range entries {
		entry := entry
		t.Run(entry.File, func(t *testing.T) {
			if entry.PeerID == nil {
				t.Fatalf("manifest entry %s has no peer_id", entry.File)
			}
			raw := readVector(t, entry.File)
			serverSlots := loadGoldenDataKeys(t, entry.KeyFile)
			w := wrapperForVector(t, serverSlots, *entry.PeerID, entry.Direction, true, manifestCipher(entry))

			plaintext, err := w.Open(nil, raw)
			if err != nil {
				if errors.Is(err, ErrPingAbsorbed) {
					return // AEAD verified AND the plaintext was the ping magic — see doc comment above.
				}
				t.Fatalf("Open failed to authenticate a committed golden vector: %v", err)
			}
			if len(plaintext) < 20 || plaintext[0]>>4 != 4 {
				t.Fatalf("opened plaintext does not parse as an IPv4 packet (got %d bytes, version nibble %d): %x", len(plaintext), plaintext[0]>>4, plaintext)
			}
		})
	}
}

// TestGoldenDataChannelReseal is DATA-01's byte-exactness proof: for every
// committed vector, open it (recovering its plaintext — the ping vector's
// plaintext is pingMagic itself, since this test file is in package
// datachan and can reference it directly, unlike an external decoder that
// only observes ErrPingAbsorbed), then re-seal that plaintext using
// SealWithPacketID with the vector's own recorded data_packet_id and the
// ORIGINAL SENDER's own role (the opposite Wrapper role from the one used
// to open — 01-04-SUMMARY.md Deviation 3's data-channel analogue), and
// assert the result is byte-for-byte identical to the committed original.
func TestGoldenDataChannelReseal(t *testing.T) {
	manifest := loadGoldenManifest(t)
	entries := dataChannelEntries(manifest)
	if len(entries) == 0 {
		t.Fatal("no data-channel vectors in manifest.json")
	}

	for _, entry := range entries {
		entry := entry
		t.Run(entry.File, func(t *testing.T) {
			if entry.PeerID == nil || entry.DataPacketID == nil {
				t.Fatalf("manifest entry %s missing peer_id/data_packet_id", entry.File)
			}
			raw := readVector(t, entry.File)
			serverSlots := loadGoldenDataKeys(t, entry.KeyFile)

			openW := wrapperForVector(t, serverSlots, *entry.PeerID, entry.Direction, true, manifestCipher(entry))
			plaintext, err := openW.Open(nil, raw)
			if err != nil {
				if !errors.Is(err, ErrPingAbsorbed) {
					t.Fatalf("Open failed to authenticate a committed golden vector: %v", err)
				}
				plaintext = append([]byte(nil), pingMagic[:]...)
			}

			resealW := wrapperForVector(t, serverSlots, *entry.PeerID, entry.Direction, false, manifestCipher(entry))
			resealed := resealW.SealWithPacketID(nil, *entry.DataPacketID, plaintext)

			if string(resealed) != string(raw) {
				t.Fatalf("re-sealed datagram does not match the committed original:\n got: %x\nwant: %x", resealed, raw)
			}
		})
	}
}

// TestGoldenDataChannelTamperHasTeeth proves the byte-exactness assertion
// above actually detects corruption: flipping one byte inside a committed
// vector's tag region (bytes 8 through 23 — offTag through offCiphertext,
// RESEARCH Pattern 5's wire layout) must make Open fail, not silently
// succeed. Mirrors internal/tlscrypt/golden_test.go's own
// TestGoldenVectorTamperHasTeeth pattern.
func TestGoldenDataChannelTamperHasTeeth(t *testing.T) {
	manifest := loadGoldenManifest(t)
	entries := dataChannelEntries(manifest)
	if len(entries) == 0 {
		t.Fatal("no data-channel vectors in manifest.json")
	}
	entry := entries[0]
	if entry.PeerID == nil {
		t.Fatalf("manifest entry %s has no peer_id", entry.File)
	}

	raw := readVector(t, entry.File)
	if len(raw) <= offTag {
		t.Fatalf("vector %s too short to tamper with its tag region: %d bytes", entry.File, len(raw))
	}
	serverSlots := loadGoldenDataKeys(t, entry.KeyFile)

	w := wrapperForVector(t, serverSlots, *entry.PeerID, entry.Direction, true, manifestCipher(entry))
	if _, err := w.Open(nil, raw); err != nil && !errors.Is(err, ErrPingAbsorbed) {
		t.Fatalf("untampered golden vector %s failed to open: %v", entry.File, err)
	}

	tampered := append([]byte(nil), raw...)
	tampered[offTag] ^= 0xFF // flip the first byte of the tag region

	w2 := wrapperForVector(t, serverSlots, *entry.PeerID, entry.Direction, true, manifestCipher(entry))
	if _, err := w2.Open(nil, tampered); err == nil {
		t.Fatalf("expected AEAD authentication to fail on a tampered golden vector (%s), but Open succeeded — the byte-exactness assertion above would silently accept corrupted traffic", entry.File)
	} else {
		t.Logf("observed expected failure on tampered vector %s: %v", entry.File, err)
	}
}

// TestGoldenKeyDirectionWouldCatchAnInversion is the assertion round-trip
// self-consistency cannot make (RESEARCH.md Pitfall 1's own "Warning
// signs" paragraph): opening a committed client-to-server vector — bytes a
// real client's own encryption actually produced — with the two key slots
// swapped (the exact mistake a copy-paste of internal/tlscrypt's own
// server/client convention would introduce) must fail. A test built only
// from this project's own encrypt/decrypt would pass even with the wrong
// convention, as long as both sides are wrong consistently; a real
// client's own bytes cannot be fooled that way.
func TestGoldenKeyDirectionWouldCatchAnInversion(t *testing.T) {
	manifest := loadGoldenManifest(t)
	var entry *goldenManifestEntry
	for i := range manifest {
		if manifest[i].KeyFile != "" && manifest[i].Direction == "client->server" {
			entry = &manifest[i]
			break
		}
	}
	if entry == nil {
		t.Fatal("no client-to-server data-channel vector in manifest.json")
	}
	if entry.PeerID == nil {
		t.Fatalf("manifest entry %s has no peer_id", entry.File)
	}

	raw := readVector(t, entry.File)
	serverSlots := loadGoldenDataKeys(t, entry.KeyFile)

	correctW := wrapperForVector(t, serverSlots, *entry.PeerID, entry.Direction, true, manifestCipher(*entry))
	if _, err := correctW.Open(nil, raw); err != nil && !errors.Is(err, ErrPingAbsorbed) {
		t.Fatalf("sanity check: correct-role Open failed on a committed client-to-server vector: %v", err)
	}

	invertedW, err := NewWrapper(mirrorDataKeys(serverSlots), *entry.PeerID, 0)
	if err != nil {
		t.Fatalf("build inverted wrapper: %v", err)
	}
	if _, err := invertedW.Open(nil, raw); err == nil {
		t.Fatal("expected an inverted key-direction Wrapper to fail opening a real client's own P_DATA_V2 packet, but it succeeded — this is the one assertion RESEARCH.md Pitfall 1 says round-trip self-consistency cannot catch")
	} else {
		t.Logf("observed expected failure with inverted key direction: %v", err)
	}
}

// TestGoldenManifestCoversEveryFile asserts manifest.json and the .bin
// files under testdata/golden name exactly the same set — an orphan in
// either direction fails, so a future regeneration or hand-edit can never
// silently drift the two apart.
func TestGoldenManifestCoversEveryFile(t *testing.T) {
	manifest := loadGoldenManifest(t)
	known := make(map[string]bool, len(manifest))
	for _, e := range manifest {
		known[e.File] = true
	}

	dirEntries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read %s: %v", goldenDir, err)
	}

	seen := make(map[string]bool)
	for _, de := range dirEntries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".bin" {
			continue
		}
		seen[de.Name()] = true
		if !known[de.Name()] {
			t.Errorf("orphan vector file %s has no manifest.json entry", de.Name())
		}
	}
	for file := range known {
		if !seen[file] {
			t.Errorf("manifest.json entry %q names a file that does not exist under %s", file, goldenDir)
		}
	}
}
