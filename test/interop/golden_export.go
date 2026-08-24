//go:build interop

// golden_export.go writes a small, representative corpus of real OpenVPN
// 2.6 client control-channel datagrams — captured and decoded by decode.go
// — into testdata/golden, so internal/wire/golden_test.go and
// internal/tlscrypt/golden_test.go can assert byte-exact parse/serialize
// and unwrap/re-wrap against a real client's own bytes in the fast tier,
// with no Docker dependency (01-04-PLAN.md Task 2, closing RESEARCH Open
// Question 1).
//
// 02-04-PLAN.md Task 2 extends this to a small representative data-channel
// corpus (a client-to-server ICMP echo request, a server-to-client echo
// reply, and a ping-magic packet) plus the derived key material and raw Key
// Method 2 seed material needed to open/re-seal/re-derive them in the fast
// tier — extending manifest.json's schema rather than introducing a second
// manifest format (01-04-SUMMARY.md's own established pattern).
//
// ExportGolden is driven from a flag on the interop test
// (-update-golden, see interop_test.go), never as a side effect of an
// ordinary run — regenerating the corpus is a deliberate act.
package interop

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/wire"
)

// goldenManifestEntry is one vector's provenance. File/Direction/Opcode/
// PacketID are Phase 1's original control-channel schema, unchanged.
// PeerID/DataPacketID/KeyFile/SenderSlot (02-04-PLAN.md Task 2) are
// data-channel-only fields, always nil/omitted for a control-channel entry
// — pointers, not bare values, so a legitimate zero (peer-id 0, sender
// slot 0) is never confused with "field absent" the way an omitempty bare
// uint32 would.
type goldenManifestEntry struct {
	File      string `json:"file"`
	Direction string `json:"direction"`
	Opcode    int    `json:"opcode"`
	PacketID  uint32 `json:"packet_id"`

	PeerID       *uint32 `json:"peer_id,omitempty"`
	DataPacketID *uint32 `json:"data_packet_id,omitempty"`
	KeyFile      string  `json:"key_file,omitempty"`
	SenderSlot   *int    `json:"sender_slot,omitempty"`
}

// dataChannelKeyExportFile / keyMethod2ExportFile mirror
// test/interop/server/main.go's own dataChannelKeyExport/keyMethod2Export
// JSON shapes exactly (hex-encoded byte fields) — this is a deliberate,
// independent local copy rather than a shared type, matching this
// project's own established convention of each consumer defining its own
// small manifest/export-reading struct (internal/wire/golden_test.go and
// internal/tlscrypt/golden_test.go each already do this for manifest.json
// itself).
type dataChannelKeyExportFile struct {
	EncryptCipher     string `json:"encrypt_cipher"`
	EncryptImplicitIV string `json:"encrypt_implicit_iv"`
	DecryptCipher     string `json:"decrypt_cipher"`
	DecryptImplicitIV string `json:"decrypt_implicit_iv"`
}

func readDataChannelKeyExport(path string) (keyderiv.DataKeys, error) {
	var out keyderiv.DataKeys
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	var f dataChannelKeyExportFile
	if err := json.Unmarshal(data, &f); err != nil {
		return out, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := hexDecodeFixed(f.EncryptCipher, out.EncryptCipher[:]); err != nil {
		return out, fmt.Errorf("%s: encrypt_cipher: %w", path, err)
	}
	if err := hexDecodeFixed(f.EncryptImplicitIV, out.EncryptImplicitIV[:]); err != nil {
		return out, fmt.Errorf("%s: encrypt_implicit_iv: %w", path, err)
	}
	if err := hexDecodeFixed(f.DecryptCipher, out.DecryptCipher[:]); err != nil {
		return out, fmt.Errorf("%s: decrypt_cipher: %w", path, err)
	}
	if err := hexDecodeFixed(f.DecryptImplicitIV, out.DecryptImplicitIV[:]); err != nil {
		return out, fmt.Errorf("%s: decrypt_implicit_iv: %w", path, err)
	}
	return out, nil
}

func hexDecodeFixed(s string, dst []byte) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(dst) {
		return fmt.Errorf("expected %d bytes, got %d", len(dst), len(b))
	}
	copy(dst, b)
	return nil
}

// ExportGolden decodes capturePath under the tls-crypt key at keyPath,
// selects a small representative set of control-channel vectors (at
// minimum one client hard reset, one server hard reset, one ACK-only
// packet, one maximum-size certificate-flight fragment, and one final
// small control packet) plus a small representative set of data-channel
// vectors (at minimum one client-to-server ICMP echo request, one
// server-to-client echo reply, and one ping-magic packet), and writes each
// vector's raw wire bytes plus a manifest, a copy of the tls-crypt key, and
// a copy of the data-channel key/Key-Method-2 material into outDir.
// dataKeysPath/keyMethod2Path are the scenario's own preserved copies of
// the harness server's /tmp exports (test/interop/server/main.go,
// retrieved via `docker cp` in interop_test.go's runScenario) — required
// for the data-channel portion; empty means "skip data-channel export",
// which keeps ExportGolden usable even for a scenario that failed to
// produce these files, at the cost of only refreshing the control-channel
// corpus.
func ExportGolden(capturePath, keyPath, dataKeysPath, keyMethod2Path, outDir string) error {
	key, err := readTLSCryptKey(keyPath)
	if err != nil {
		return fmt.Errorf("export golden: read tls-crypt key: %w", err)
	}

	var dataKeys *dataChannelKeyMaterial
	var serverSlots keyderiv.DataKeys
	if dataKeysPath != "" {
		serverSlots, err = readDataChannelKeyExport(dataKeysPath)
		if err != nil {
			return fmt.Errorf("export golden: read data-channel key export: %w", err)
		}
		// This harness never allocates more than one session per run, so
		// the peer-id this session was assigned is always 0 — matching
		// ippool.go's own allocation policy (sequential first-free,
		// starting at 0). Recorded here for datachan.NewWrapper's own API
		// shape (it's used only for Seal's own header, never checked by
		// Open), and independently confirmed per-vector when decodeCapture
		// parses each P_DATA_V2 payload's own peer-id field below.
		dataKeys = &dataChannelKeyMaterial{peerID: 0, serverPerspective: serverSlots}
	}

	packets, err := decodeCapture(capturePath, key, tunnelPort, dataKeys)
	if err != nil {
		return fmt.Errorf("export golden: decode capture: %w", err)
	}

	selected, err := selectGoldenVectors(packets, dataKeys != nil)
	if err != nil {
		return fmt.Errorf("export golden: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("export golden: create %s: %w", outDir, err)
	}

	const dataChannelKeyFile = "data-channel.key"

	manifest := make([]goldenManifestEntry, 0, len(selected))
	for i, sel := range selected {
		file := fmt.Sprintf("%03d-%s-%s.bin", i+1, directionSlug(sel.packet.Direction), sel.label)
		if err := os.WriteFile(filepath.Join(outDir, file), sel.packet.Raw, 0o644); err != nil {
			return fmt.Errorf("export golden: write %s: %w", file, err)
		}

		entry := goldenManifestEntry{
			File:      file,
			Direction: sel.packet.Direction.String(),
			Opcode:    int(sel.packet.Control.Opcode),
			PacketID:  uint32(sel.packet.Control.PacketID),
		}
		if sel.packet.IsDataPacket {
			peerID := sel.packet.PeerID
			dataPacketID := sel.packet.DataPacketID
			// sender_slot: RESEARCH Pattern 4/Pitfall 1's mirror-opposite
			// convention as DATA rather than inference — a client-to-server
			// vector was encrypted with the client's own encrypt slot
			// (keys[0]); a server-to-client vector was encrypted with the
			// server's own encrypt slot (keys[1]).
			senderSlot := 1
			if sel.packet.Direction == DirClientToServer {
				senderSlot = 0
			}
			entry.Opcode = int(wire.OpDataV2)
			entry.PacketID = 0 // not a control-channel reliability packet ID; DataPacketID below is the data channel's own
			entry.PeerID = &peerID
			entry.DataPacketID = &dataPacketID
			entry.KeyFile = dataChannelKeyFile
			entry.SenderSlot = &senderSlot
		}
		manifest = append(manifest, entry)
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

	if dataKeys != nil {
		if err := copyFile(dataKeysPath, filepath.Join(outDir, dataChannelKeyFile)); err != nil {
			return fmt.Errorf("export golden: copy data-channel key export: %w", err)
		}
		if keyMethod2Path != "" {
			if err := copyFile(keyMethod2Path, filepath.Join(outDir, "data-channel-km2.json")); err != nil {
				return fmt.Errorf("export golden: copy Key Method 2 export: %w", err)
			}
		}
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

// selectGoldenVectors picks the representative control-channel set
// 01-04-PLAN.md Task 2 established (the client's own hard reset, the
// server's hard reset, an ACK-only packet, a maximum-size fragment from
// the certificate flight, and a final small control packet), then — when
// includeDataChannel is true — extends the same slice with 02-04-PLAN.md
// Task 2's representative data-channel set (a client-to-server ICMP echo
// request, a server-to-client echo reply, and a ping-magic packet), all in
// capture order, deduplicated (the same decodedPacket is never selected
// twice even if it would satisfy two criteria).
func selectGoldenVectors(packets []decodedPacket, includeDataChannel bool) ([]goldenSelection, error) {
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

	if !includeDataChannel {
		return out, nil
	}

	if !pick("icmp-echo-request", func(p decodedPacket) bool {
		return p.IsDataPacket && !p.IsPing && p.Direction == DirClientToServer && isICMPEchoRequest(p.Plaintext)
	}) {
		return nil, fmt.Errorf("no client-to-server P_DATA_V2 ICMP echo request found in capture — was the ping round-trip assertion exercised on this scenario?")
	}

	if !pick("icmp-echo-reply", func(p decodedPacket) bool {
		return p.IsDataPacket && !p.IsPing && p.Direction == DirServerToClient && isICMPEchoReply(p.Plaintext)
	}) {
		return nil, fmt.Errorf("no server-to-client P_DATA_V2 ICMP echo reply found in capture")
	}

	if !pick("ping-keepalive", func(p decodedPacket) bool {
		return p.IsDataPacket && p.IsPing
	}) {
		return nil, fmt.Errorf("no ping-keepalive P_DATA_V2 packet found in capture")
	}

	return out, nil
}

// isICMPEchoRequest/isICMPEchoReply do the minimal IPv4/ICMP type sniffing
// needed to select representative golden vectors — deliberately not a
// full parser (this is test-tooling classification, not a production IP
// stack), and deliberately not shared code with
// test/interop/server/main.go's own icmpEchoReply (that file is package
// main, a different, non-importable package; a few lines of duplicated
// classification logic here is cheaper and clearer than introducing a
// shared package for it).
func isICMPEchoRequest(pkt []byte) bool { return isICMPType(pkt, 8) }
func isICMPEchoReply(pkt []byte) bool   { return isICMPType(pkt, 0) }

func isICMPType(pkt []byte, wantType byte) bool {
	const (
		minIPv4HeaderLen = 20
		minICMPHeaderLen = 8
		protocolICMP     = 1
	)
	if len(pkt) < minIPv4HeaderLen {
		return false
	}
	version := pkt[0] >> 4
	ihl := int(pkt[0]&0x0F) * 4
	if version != 4 || ihl < minIPv4HeaderLen || len(pkt) < ihl+minICMPHeaderLen {
		return false
	}
	if pkt[9] != protocolICMP {
		return false
	}
	return pkt[ihl] == wantType
}
