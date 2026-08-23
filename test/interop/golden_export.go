//go:build interop

// golden_export.go writes a small, representative corpus of real OpenVPN
// 2.6 client control-channel datagrams — captured and decoded by decode.go
// — into testdata/golden, so internal/wire/golden_test.go and
// internal/tlscrypt/golden_test.go can assert byte-exact parse/serialize
// and unwrap/re-wrap against a real client's own bytes in the fast tier,
// with no Docker dependency (01-04-PLAN.md Task 2, closing RESEARCH Open
// Question 1).
//
// ExportGolden is driven from a flag on the interop test
// (-update-golden, see interop_test.go), never as a side effect of an
// ordinary run — regenerating the corpus is a deliberate act.
package interop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/wire"
)

// goldenManifestEntry is one vector's provenance: which file holds its raw
// wire bytes, which direction it was captured in, and the opcode/packet ID
// its plaintext was decoded to — the fast-tier golden tests assert their
// own independently-decoded values against these recorded ones.
type goldenManifestEntry struct {
	File      string `json:"file"`
	Direction string `json:"direction"`
	Opcode    int    `json:"opcode"`
	PacketID  uint32 `json:"packet_id"`
}

// ExportGolden decodes capturePath under the tls-crypt key at keyPath,
// selects a small representative set of vectors — at minimum one client
// hard reset, one server hard reset, one ACK-only packet, one
// maximum-size certificate-flight fragment, and one final small control
// packet — and writes each vector's raw wire bytes plus a manifest and a
// copy of the tls-crypt key into outDir.
func ExportGolden(capturePath, keyPath, outDir string) error {
	key, err := readTLSCryptKey(keyPath)
	if err != nil {
		return fmt.Errorf("export golden: read tls-crypt key: %w", err)
	}
	packets, err := decodeCapture(capturePath, key, tunnelPort)
	if err != nil {
		return fmt.Errorf("export golden: decode capture: %w", err)
	}

	selected, err := selectGoldenVectors(packets)
	if err != nil {
		return fmt.Errorf("export golden: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("export golden: create %s: %w", outDir, err)
	}

	manifest := make([]goldenManifestEntry, 0, len(selected))
	for i, sel := range selected {
		file := fmt.Sprintf("%03d-%s-%s.bin", i+1, directionSlug(sel.packet.Direction), sel.label)
		if err := os.WriteFile(filepath.Join(outDir, file), sel.packet.Raw, 0o644); err != nil {
			return fmt.Errorf("export golden: write %s: %w", file, err)
		}
		manifest = append(manifest, goldenManifestEntry{
			File:      file,
			Direction: sel.packet.Direction.String(),
			Opcode:    int(sel.packet.Control.Opcode),
			PacketID:  uint32(sel.packet.Control.PacketID),
		})
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("export golden: marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), append(manifestJSON, '\n'), 0o644); err != nil {
		return fmt.Errorf("export golden: write manifest.json: %w", err)
	}

	if err := copyFile(keyPath, filepath.Join(outDir, "tls-crypt.key")); err != nil {
		return fmt.Errorf("export golden: copy tls-crypt key: %w", err)
	}

	return nil
}

func directionSlug(d Direction) string {
	if d == DirClientToServer {
		return "client-to-server"
	}
	return "server-to-client"
}

// goldenSelection pairs a chosen decodedPacket with a short, descriptive
// label used in its filename.
type goldenSelection struct {
	packet decodedPacket
	label  string
}

// selectGoldenVectors picks the representative set 01-04-PLAN.md Task 2
// requires: the client's own hard reset, the server's hard reset, an
// ACK-only packet, a maximum-size fragment from the certificate flight,
// and a final small control packet — in that capture order, deduplicated
// (the same decodedPacket is never selected twice even if it would satisfy
// two criteria).
func selectGoldenVectors(packets []decodedPacket) ([]goldenSelection, error) {
	var out []goldenSelection
	used := make(map[int]bool)

	pick := func(label string, match func(decodedPacket) bool) bool {
		for i, p := range packets {
			if used[i] || !match(p) {
				continue
			}
			used[i] = true
			out = append(out, goldenSelection{packet: p, label: label})
			return true
		}
		return false
	}

	if !pick("client-hard-reset", func(p decodedPacket) bool {
		return p.Direction == DirClientToServer && p.Control.Opcode == wire.OpControlHardResetClientV2
	}) {
		return nil, fmt.Errorf("no client hard reset (OpControlHardResetClientV2) found in capture")
	}

	if !pick("server-hard-reset", func(p decodedPacket) bool {
		return p.Direction == DirServerToClient && p.Control.Opcode == wire.OpControlHardResetServerV2
	}) {
		return nil, fmt.Errorf("no server hard reset (OpControlHardResetServerV2) found in capture")
	}

	if !pick("ack-only", func(p decodedPacket) bool {
		return p.Control.Opcode == wire.OpAckV1
	}) {
		return nil, fmt.Errorf("no ack-only (OpAckV1) packet found in capture")
	}

	if !pick("max-fragment", func(p decodedPacket) bool {
		return p.Direction == DirServerToClient && p.Control.Opcode == wire.OpControlV1 && len(p.Control.Payload) == ctrlconn.MaxPayload
	}) {
		return nil, fmt.Errorf("no maximum-size (%d-byte) server-to-client fragment found in capture — was this exported from a large-certificate scenario?", ctrlconn.MaxPayload)
	}

	// The final small control packet: the LAST control packet in the whole
	// capture whose payload is present but strictly smaller than a full
	// fragment — walk from the end so this is genuinely the tail of the
	// handshake, not an early small packet.
	foundFinal := false
	for i := len(packets) - 1; i >= 0; i-- {
		if used[i] {
			continue
		}
		p := packets[i]
		if p.Control.Opcode == wire.OpControlV1 && len(p.Control.Payload) > 0 && len(p.Control.Payload) < ctrlconn.MaxPayload {
			used[i] = true
			out = append(out, goldenSelection{packet: p, label: "final-small"})
			foundFinal = true
			break
		}
	}
	if !foundFinal {
		return nil, fmt.Errorf("no final small control packet found in capture")
	}

	return out, nil
}
