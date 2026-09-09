// Golden-vector test for WIRE-03 against live evidence: unlike
// keyexpansion_test.go's own vectors (seeded from the reference's own
// committed PRF test vector, tests/unit_tests/openvpn/test_crypto.c), this
// file verifies DeriveKeys against the raw Key Method 2 seed material a
// real OpenVPN 2.6.14 client's own session actually exchanged, captured via
// the Docker interop harness and committed alongside the data-channel
// golden corpus (02-04-PLAN.md Task 2). No build tag: fast tier, no Docker
// needed — the corpus is regenerated deliberately via `make golden`.
package keyderiv

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const goldenDir = "../../testdata/golden"

// keyMethod2ExportFile mirrors test/interop/server/main.go's own
// keyMethod2Export JSON shape exactly (hex-encoded byte fields).
type keyMethod2ExportFile struct {
	ClientPreMaster string `json:"client_pre_master"`
	ClientRandom1   string `json:"client_random1"`
	ClientRandom2   string `json:"client_random2"`
	ServerRandom1   string `json:"server_random1"`
	ServerRandom2   string `json:"server_random2"`
	ClientSessionID string `json:"client_session_id"`
	ServerSessionID string `json:"server_session_id"`
}

// dataChannelKeyExportFile mirrors test/interop/server/main.go's own
// dataChannelKeyExport JSON shape exactly.
type dataChannelKeyExportFile struct {
	EncryptCipher     string `json:"encrypt_cipher"`
	EncryptImplicitIV string `json:"encrypt_implicit_iv"`
	DecryptCipher     string `json:"decrypt_cipher"`
	DecryptImplicitIV string `json:"decrypt_implicit_iv"`
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

// TestGoldenKeyExpansionFromCapture is 02-04-PLAN.md Task 2's WIRE-03
// verification against live evidence: DeriveKeys, run against the raw Key
// Method 2 seed material a real client's own session actually exchanged
// (testdata/golden/data-channel-km2.json), reproduces the same derived key
// material committed as testdata/golden/data-channel.key, byte-for-byte —
// proving DeriveKeys against a real client's own captured randoms and
// session IDs, not only against the reference's own PRF test vector
// (keyexpansion_test.go's existing coverage).
func TestGoldenKeyExpansionFromCapture(t *testing.T) {
	km2Path := filepath.Join(goldenDir, "data-channel-km2.json")
	km2Data, err := os.ReadFile(km2Path)
	if err != nil {
		t.Fatalf("read %s (run `make golden` to (re)generate testdata/golden): %v", km2Path, err)
	}
	var km keyMethod2ExportFile
	if err := json.Unmarshal(km2Data, &km); err != nil {
		t.Fatalf("parse %s: %v", km2Path, err)
	}

	var src KeySource2
	hexDecodeFixed(t, km.ClientPreMaster, src.Client.PreMaster[:])
	hexDecodeFixed(t, km.ClientRandom1, src.Client.Random1[:])
	hexDecodeFixed(t, km.ClientRandom2, src.Client.Random2[:])
	hexDecodeFixed(t, km.ServerRandom1, src.Server.Random1[:])
	hexDecodeFixed(t, km.ServerRandom2, src.Server.Random2[:])

	var clientSID, serverSID [8]byte
	hexDecodeFixed(t, km.ClientSessionID, clientSID[:])
	hexDecodeFixed(t, km.ServerSessionID, serverSID[:])

	key2, err := DeriveKeys(&src, &clientSID, &serverSID)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	got := key2.ServerSlots(32)

	keyPath := filepath.Join(goldenDir, "data-channel.key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read %s: %v", keyPath, err)
	}
	var wantFile dataChannelKeyExportFile
	if err := json.Unmarshal(keyData, &wantFile); err != nil {
		t.Fatalf("parse %s: %v", keyPath, err)
	}
	var want DataKeys
	hexDecodeFixed(t, wantFile.EncryptCipher, want.EncryptCipher[:])
	hexDecodeFixed(t, wantFile.EncryptImplicitIV, want.EncryptImplicitIV[:])
	hexDecodeFixed(t, wantFile.DecryptCipher, want.DecryptCipher[:])
	hexDecodeFixed(t, wantFile.DecryptImplicitIV, want.DecryptImplicitIV[:])
	// This golden vector predates cipher negotiation and is AES-256-GCM
	// only (the only cipher v1.0 ever produced) — CipherKeyLen isn't part
	// of the committed JSON shape, so it's set to match got's own
	// ServerSlots(32) call above rather than compared as a zero value.
	want.CipherKeyLen = 32

	if got != want {
		t.Fatalf("DeriveKeys from the captured Key Method 2 material does not match the committed derived key material:\n got:  %+v\n want: %+v", got, want)
	}
	t.Logf("DeriveKeys reproduced the real client's own committed data-channel key material byte-for-byte")
}
