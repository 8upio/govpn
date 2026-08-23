// Golden-vector tests for WIRE-04, verified against real OpenVPN 2.6 client
// traffic: unlike tlscrypt_test.go's self-generated round-trip vectors,
// every vector here is a raw datagram a real, unmodified client actually
// produced, captured via the Docker interop harness and committed to
// testdata/golden (01-04-PLAN.md Task 2, closing 01-RESEARCH.md Open
// Question 1). No build tag: this runs in the fast tier, no Docker needed —
// the corpus is regenerated deliberately via `make golden`, not on every
// run.
package tlscrypt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
	key, err := ParseStaticKeyV1(data)
	if err != nil {
		t.Fatalf("parse tls-crypt.key: %v", err)
	}
	return key
}

// TestGoldenTLSCryptRewrap is 01-04-PLAN.md Task 2's WIRE-04 verification
// against real client bytes: for every committed vector, unwrap it (proving
// the auth tag verifies), then re-wrap the recovered plaintext using the
// SAME tls-crypt packet ID recovered from the vector itself
// (WrapWithPacketID — Wrap's own auto-generated seq+time.Now() packet ID
// can never reproduce a historical capture) and assert the resulting
// datagram is byte-for-byte identical to the committed original. That
// final equality is the byte-exactness proof WIRE-01/WIRE-04 ask for,
// against bytes a real OpenVPN 2.6 client actually produced.
func TestGoldenTLSCryptRewrap(t *testing.T) {
	key := loadGoldenKey(t)
	manifest := loadGoldenManifest(t)

	for _, entry := range manifest {
		entry := entry
		t.Run(entry.File, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(goldenDir, entry.File))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			if len(raw) < OffCT {
				t.Fatalf("vector shorter than the tls-crypt prefix: %d bytes", len(raw))
			}

			// A client-to-server vector was encrypted with the CLIENT's
			// slot (keys[1]) and must be UNWRAPPED as the server
			// (server=true, decrypt=keys[1]) — mirroring
			// test/interop/capture_test.go's convention.
			unwrapAsServer := entry.Direction == "client->server"
			w, err := NewWrapper(key, unwrapAsServer)
			if err != nil {
				t.Fatalf("build wrapper: %v", err)
			}

			header, plaintext, err := w.Unwrap(nil, raw)
			if err != nil {
				t.Fatalf("Unwrap failed to authenticate a committed golden vector: %v", err)
			}

			var pid [PIDSize]byte
			copy(pid[:], raw[OffPID:OffPID+PIDSize])

			// Wrap/WrapWithPacketID always encrypt with w.encrypt, so
			// reproducing this vector's exact bytes requires a Wrapper
			// built in the ORIGINAL SENDER's role — the opposite of the
			// role used to unwrap it above. A client-to-server vector was
			// sent by the client, so the re-wrap Wrapper must be built
			// with server=false (encrypt=keys[1], the client's own slot),
			// not server=true (which would encrypt with the SERVER's
			// slot — the wrong key entirely, and the actual cause of this
			// test's first failing run: reusing unwrapAsServer here
			// produced a tag that authenticates under neither peer's real
			// traffic).
			rewrapAsServer := !unwrapAsServer
			rewrapper, err := NewWrapper(key, rewrapAsServer)
			if err != nil {
				t.Fatalf("build re-wrap wrapper: %v", err)
			}
			rewrapped, err := rewrapper.WrapWithPacketID(nil, header, pid, plaintext)
			if err != nil {
				t.Fatalf("WrapWithPacketID: %v", err)
			}

			if string(rewrapped) != string(raw) {
				t.Fatalf("re-wrapped datagram does not match the committed original:\n got: %x\nwant: %x", rewrapped, raw)
			}
		})
	}
}

// TestGoldenVectorTamperHasTeeth proves the byte-exactness assertion above
// actually detects corruption: flipping one byte inside a committed
// vector's authentication tag must make Unwrap fail, not silently succeed
// (mirrors test/interop/capture_test.go's own "tamper detection proves the
// assertion has teeth" subtest, applied here to the committed fast-tier
// corpus itself — the observed failure below is the recorded proof
// 01-04-PLAN.md Task 2's acceptance criteria asks for).
func TestGoldenVectorTamperHasTeeth(t *testing.T) {
	key := loadGoldenKey(t)
	manifest := loadGoldenManifest(t)
	entry := manifest[0]

	raw, err := os.ReadFile(filepath.Join(goldenDir, entry.File))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	if len(raw) <= OffTag {
		t.Fatalf("vector too short to tamper with its tag: %d bytes", len(raw))
	}

	server := entry.Direction == "client->server"
	w, err := NewWrapper(key, server)
	if err != nil {
		t.Fatalf("build wrapper: %v", err)
	}
	if _, _, err := w.Unwrap(nil, raw); err != nil {
		t.Fatalf("untampered golden vector %s failed to unwrap: %v", entry.File, err)
	}

	tampered := append([]byte(nil), raw...)
	tampered[OffTag] ^= 0xFF // flip the first byte of the auth tag

	w2, err := NewWrapper(key, server)
	if err != nil {
		t.Fatalf("build wrapper: %v", err)
	}
	if _, _, err := w2.Unwrap(nil, tampered); err == nil {
		t.Fatalf("expected tls-crypt authentication to fail on a tampered golden vector (%s), but Unwrap succeeded — the byte-exactness assertion above would silently accept corrupted traffic", entry.File)
	} else {
		t.Logf("observed expected failure on tampered vector %s: %v", entry.File, err)
	}
}
