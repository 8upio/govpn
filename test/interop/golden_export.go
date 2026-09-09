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
// 05-05-PLAN.md Task 1 extends ExportGolden to accept more than one source
// scenario and write exactly one merged manifest: the pre-existing
// clean-large source still contributes the control-channel corpus plus its
// own (AES-256-GCM) data-channel vectors, and a second source (cipher-128)
// contributes ONLY AES-128-GCM data-channel vectors under their own key
// file, since key expansion itself is cipher-independent and control-
// channel vectors need capturing only once. Every data-channel manifest
// entry now names the cipher its vectors were captured under
// (goldenManifestEntry.Cipher); an absent value still means AES-256-GCM, so
// the pre-Phase-5 corpus stays readable unchanged.
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
	"strings"

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
// uint32 would. Cipher (05-05-PLAN.md Task 1) is a data-channel-only field
// too: an absent value means AES-256-GCM, exactly what every entry meant
// implicitly before this phase, so a corpus regenerated at an older
// revision (or a pre-Phase-5 checkout of this file) stays readable.
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

	// Cipher/CipherKeyLen (05-05-PLAN.md Task 1) mirror
	// test/interop/server/main.go's dataChannelKeyExport.Cipher/
	// .CipherKeyLen (05-04-PLAN.md Task 1) exactly — the negotiated cipher
	// name and its AEAD key length in bytes (16 or 32). Both are optional:
	// a key-export file written before 05-04 landed has neither, and
	// readDataChannelKeyExport below defaults CipherKeyLen to 32 in that
	// case, matching every vector this corpus held before cipher
	// negotiation existed. EncryptCipher/DecryptCipher themselves always
	// stay 32 bytes (64 hex chars) wide regardless of Cipher/CipherKeyLen
	// — they carry the full key-expansion slot, not the trimmed AEAD key
	// (RESEARCH.md Pitfall 5); truncating the hex width for AES-128-GCM
	// would break hexDecodeFixed's exact-length check for no benefit.
	Cipher       string `json:"cipher,omitempty"`
	CipherKeyLen int    `json:"cipher_key_len,omitempty"`
}

// readDataChannelKeyExport reads path (a dataChannelKeyExportFile) into a
// keyderiv.DataKeys plus the cipher name it was captured under. An absent
// (pre-05-04) cipher_key_len defaults to 32 — the only cipher v1.0 ever
// produced — matching internal/datachan/golden_test.go's own
// loadGoldenDataKeys default.
func readDataChannelKeyExport(path string) (keyderiv.DataKeys, string, error) {
	var out keyderiv.DataKeys
	data, err := os.ReadFile(path)
	if err != nil {
		return out, "", err
	}
	var f dataChannelKeyExportFile
	if err := json.Unmarshal(data, &f); err != nil {
		return out, "", fmt.Errorf("parse %s: %w", path, err)
	}
	if err := hexDecodeFixed(f.EncryptCipher, out.EncryptCipher[:]); err != nil {
		return out, "", fmt.Errorf("%s: encrypt_cipher: %w", path, err)
	}
	if err := hexDecodeFixed(f.EncryptImplicitIV, out.EncryptImplicitIV[:]); err != nil {
		return out, "", fmt.Errorf("%s: encrypt_implicit_iv: %w", path, err)
	}
	if err := hexDecodeFixed(f.DecryptCipher, out.DecryptCipher[:]); err != nil {
		return out, "", fmt.Errorf("%s: decrypt_cipher: %w", path, err)
	}
	if err := hexDecodeFixed(f.DecryptImplicitIV, out.DecryptImplicitIV[:]); err != nil {
		return out, "", fmt.Errorf("%s: decrypt_implicit_iv: %w", path, err)
	}
	out.CipherKeyLen = f.CipherKeyLen
	if out.CipherKeyLen == 0 {
		out.CipherKeyLen = 32
	}
	return out, f.Cipher, nil
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

// goldenSource is one interop scenario's own captured data — capture,
// tls-crypt key, and (when non-empty) data-channel key/Key-Method-2
// material — that ExportGolden should extract vectors from and fold into
// one merged manifest (05-05-PLAN.md Task 1). Name is used only in error
// messages, to say which source a decode/export failure came from.
//
// IncludeControlChannel should be true for exactly one source (the one
// whose capture also anchors tls-crypt.key): control-channel vectors are
// cipher-independent, so capturing them from a second source would only
// duplicate work and risk a second, possibly-divergent tls-crypt key ever
// being committed.
//
// DataKeysPath == "" skips data-channel export for this source entirely
// (matching the pre-05-05 "empty means skip" convention) — Cipher and
// KeyFileName are meaningless in that case. KeyMethod2Path == "" skips
// writing data-channel-km2.json for this source: only the first source
// needs one, since key expansion is cipher-independent and
// internal/keyderiv's own golden test already proves it byte-exact from
// that one capture.
type goldenSource struct {
	name                  string
	capturePath           string
	keyPath               string
	dataKeysPath          string
	keyMethod2Path        string
	cipher                string
	keyFileName           string
	includeControlChannel bool
}

// ExportGolden decodes every source's capture under its own tls-crypt key,
// selects a small representative set of vectors from each — control-channel
// vectors (at minimum one client hard reset, one server hard reset, one
// ACK-only packet, one maximum-size certificate-flight fragment, and one
// final small control packet) from the source(s) with IncludeControlChannel
// set, and data-channel vectors (at minimum one client-to-server ICMP echo
// request, one server-to-client echo reply, and one ping-magic packet) from
// every source with a non-empty DataKeysPath — and writes the combined
// vector set plus ONE merged manifest.json into outDir. Output file names
// are numbered continuously across sources (the second source's vectors
// continue after the first's, never restarting), and each source's
// data-channel key material is copied to its own KeyFileName so two
// sources' key sets never collide or overwrite each other (05-05-PLAN.md
// Task 1).
func ExportGolden(sources []goldenSource, outDir string) error {
	if len(sources) == 0 {
		return fmt.Errorf("export golden: no sources given")
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("export golden: create %s: %w", outDir, err)
	}

	var manifest []goldenManifestEntry
	fileIndex := 0

	for _, src := range sources {
		key, err := readTLSCryptKey(src.keyPath)
		if err != nil {
			return fmt.Errorf("export golden: %s: read tls-crypt key: %w", src.name, err)
		}

		var dataKeys *dataChannelKeyMaterial
		var serverSlots keyderiv.DataKeys
		cipherName := src.cipher
		if src.dataKeysPath != "" {
			var fileCipher string
			serverSlots, fileCipher, err = readDataChannelKeyExport(src.dataKeysPath)
			if err != nil {
				return fmt.Errorf("export golden: %s: read data-channel key export: %w", src.name, err)
			}
			if fileCipher != "" {
				if src.cipher != "" && !strings.EqualFold(src.cipher, fileCipher) {
					return fmt.Errorf("export golden: %s: source declared cipher %q but the exported key file names %q", src.name, src.cipher, fileCipher)
				}
				cipherName = fileCipher
			}
			// This harness never allocates more than one session per run,
			// so the peer-id this session was assigned is always 0 —
			// matching ippool.go's own allocation policy (sequential
			// first-free, starting at 0). Recorded here for
			// datachan.NewWrapper's own API shape (it's used only for
			// Seal's own header, never checked by Open), and independently
			// confirmed per-vector when decodeCapture parses each
			// P_DATA_V2 payload's own peer-id field below.
			dataKeys = &dataChannelKeyMaterial{peerID: 0, serverPerspective: serverSlots}
		}

		packets, err := decodeCapture(src.capturePath, key, tunnelPort, dataKeys)
		if err != nil {
			return fmt.Errorf("export golden: %s: decode capture: %w", src.name, err)
		}

		selected, err := selectGoldenVectors(packets, src.includeControlChannel, dataKeys != nil)
		if err != nil {
			return fmt.Errorf("export golden: %s: %w", src.name, err)
		}

		for _, sel := range selected {
			fileIndex++
			file := fmt.Sprintf("%03d-%s-%s.bin", fileIndex, directionSlug(sel.packet.Direction), sel.label)
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
				entry.KeyFile = src.keyFileName
				entry.SenderSlot = &senderSlot
				// Every entry a fresh regeneration writes names its cipher
				// explicitly, including AES-256-GCM ones — the absent-
				// means-AES-256-GCM rule (goldenManifestEntry's own doc
				// comment) exists only so a manifest committed BEFORE this
				// field existed stays readable, not so a freshly written
				// entry should omit it.
				if cipherName == "" {
					cipherName = "AES-256-GCM"
				}
				entry.Cipher = cipherName
			}
			manifest = append(manifest, entry)
		}

		if src.includeControlChannel {
			if err := copyFile(src.keyPath, filepath.Join(outDir, "tls-crypt.key")); err != nil {
				return fmt.Errorf("export golden: %s: copy tls-crypt key: %w", src.name, err)
			}
		}

		if dataKeys != nil {
			if err := copyFile(src.dataKeysPath, filepath.Join(outDir, src.keyFileName)); err != nil {
				return fmt.Errorf("export golden: %s: copy data-channel key export: %w", src.name, err)
			}
			if src.keyMethod2Path != "" {
				if err := copyFile(src.keyMethod2Path, filepath.Join(outDir, "data-channel-km2.json")); err != nil {
					return fmt.Errorf("export golden: %s: copy Key Method 2 export: %w", src.name, err)
				}
			}
		}
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("export golden: marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), append(manifestJSON, '\n'), 0o644); err != nil {
		return fmt.Errorf("export golden: write manifest.json: %w", err)
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
// the certificate flight, and a final small control packet) — only when
// includeControlChannel is true — then, when includeDataChannel is true,
// extends the same slice with 02-04-PLAN.md Task 2's representative
// data-channel set (a client-to-server ICMP echo request, a server-to-client
// echo reply, and a ping-magic packet), all in capture order, deduplicated
// (the same decodedPacket is never selected twice even if it would satisfy
// two criteria). 05-05-PLAN.md Task 1 splits the two flags apart so a
// second source (e.g. cipher-128) can contribute ONLY its data-channel
// vectors without also re-selecting a redundant control-channel set.
func selectGoldenVectors(packets []decodedPacket, includeControlChannel, includeDataChannel bool) ([]goldenSelection, error) {
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

	if includeControlChannel {
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
