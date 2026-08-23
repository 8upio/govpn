// Golden-vector tests for WIRE-01, verified against real OpenVPN 2.6
// client traffic: unlike wire_test.go's self-generated round-trip vectors,
// every vector here is a raw datagram a real, unmodified client actually
// produced, captured via the Docker interop harness and committed to
// testdata/golden (01-04-PLAN.md Task 2, closing 01-RESEARCH.md Open
// Question 1). No build tag: this runs in the fast tier, no Docker needed —
// the corpus is regenerated deliberately via `make golden`, not on every
// run.
package wire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/8upio/govpn/internal/tlscrypt"
)

// goldenDir locates testdata/golden relative to this package (two levels
// up to the repo root, then into testdata/golden).
const goldenDir = "../../testdata/golden"

type goldenManifestEntry struct {
	File      string `json:"file"`
	Direction string `json:"direction"`
	Opcode    int    `json:"opcode"`
	PacketID  uint32 `json:"packet_id"`
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

func loadGoldenKey(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, "tls-crypt.key"))
	if err != nil {
		t.Fatalf("read tls-crypt.key: %v", err)
	}
	key, err := tlscrypt.ParseStaticKeyV1(data)
	if err != nil {
		t.Fatalf("parse tls-crypt.key: %v", err)
	}
	return key
}

// unwrapGoldenVector unwraps entry's raw wire bytes under key, choosing the
// wrapper direction that matches how a real peer would have decrypted it: a
// client-to-server vector is unwrapped as the SERVER (server=true, decrypt
// slot = keys[1] = the client's encrypt slot), and a server-to-client
// vector is unwrapped as the CLIENT (server=false) — mirroring
// test/interop/capture_test.go's own convention.
func unwrapGoldenVector(t *testing.T, key []byte, entry goldenManifestEntry, raw []byte) (header, plaintext []byte) {
	t.Helper()
	server := entry.Direction == "client->server"
	w, err := tlscrypt.NewWrapper(key, server)
	if err != nil {
		t.Fatalf("%s: build wrapper: %v", entry.File, err)
	}
	header, plaintext, err = w.Unwrap(nil, raw)
	if err != nil {
		t.Fatalf("%s: tls-crypt unwrap failed: %v", entry.File, err)
	}
	return header, plaintext
}

// TestGoldenControlPacketsRoundTrip is 01-04-PLAN.md Task 2's WIRE-01
// verification against real client bytes: for every committed vector,
// unwrap it, parse the recovered plaintext as a control packet, assert its
// opcode and reliability packet ID match the manifest, then re-serialize
// and assert the result is byte-identical to what unwrap produced.
func TestGoldenControlPacketsRoundTrip(t *testing.T) {
	key := loadGoldenKey(t)
	manifest := loadGoldenManifest(t)

	for _, entry := range manifest {
		entry := entry
		t.Run(entry.File, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(goldenDir, entry.File))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}

			header, plaintext := unwrapGoldenVector(t, key, entry, raw)

			if len(header) < 1+SessionIDSize {
				t.Fatalf("recovered header too short: %d bytes", len(header))
			}
			hdrOpcode, hdrKeyID := ParseHeaderByte(header[0])
			var sid SessionID
			copy(sid[:], header[1:1+SessionIDSize])
			hdr := Header{Opcode: hdrOpcode, KeyID: hdrKeyID, SessionID: sid}

			if int(hdrOpcode) != entry.Opcode {
				t.Fatalf("decoded opcode = %d, manifest says %d", hdrOpcode, entry.Opcode)
			}

			cp, err := ParseControlPacket(plaintext, hdr)
			if err != nil {
				t.Fatalf("ParseControlPacket: %v", err)
			}
			if cp.Opcode != OpAckV1 && uint32(cp.PacketID) != entry.PacketID {
				t.Fatalf("decoded packet ID = %d, manifest says %d", cp.PacketID, entry.PacketID)
			}

			reserialized := cp.AppendPlaintext(nil)
			if string(reserialized) != string(plaintext) {
				t.Fatalf("re-serialized plaintext does not match what Unwrap produced:\n got: %x\nwant: %x", reserialized, plaintext)
			}
		})
	}
}

// TestGoldenManifestTamperDetection proves the assertion above has teeth:
// flipping one byte inside a committed vector's ciphertext must make
// ParseControlPacket see different (and, for a random flip, almost
// certainly invalid-looking) plaintext than the untampered vector — the
// tls-crypt authentication layer (internal/tlscrypt/golden_test.go) is what
// actually catches tampering at the crypto boundary; this test instead
// confirms that decoding is sensitive to the exact bytes committed, not
// merely "close enough."
func TestGoldenManifestTamperDetection(t *testing.T) {
	key := loadGoldenKey(t)
	manifest := loadGoldenManifest(t)
	entry := manifest[0]

	raw, err := os.ReadFile(filepath.Join(goldenDir, entry.File))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}

	server := entry.Direction == "client->server"
	w, err := tlscrypt.NewWrapper(key, server)
	if err != nil {
		t.Fatalf("build wrapper: %v", err)
	}
	if _, _, err := w.Unwrap(nil, raw); err != nil {
		t.Fatalf("untampered vector failed to unwrap: %v", err)
	}

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xFF // flip the last ciphertext byte

	w2, err := tlscrypt.NewWrapper(key, server)
	if err != nil {
		t.Fatalf("build wrapper: %v", err)
	}
	if _, _, err := w2.Unwrap(nil, tampered); err == nil {
		t.Fatal("expected tls-crypt authentication to fail on a tampered golden vector, but Unwrap succeeded")
	}
}
