# Phase 2: Tunnel Up - Pattern Map

**Mapped:** 2026-08-24
**Files analyzed:** 9 (new/modified)
**Analogs found:** 9 / 9

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|----------------|
| `internal/keyderiv/prf.go` (new) | utility (crypto primitive) | transform | `internal/tlscrypt/tlscrypt.go` (wrap/unwrap crypto core) | role-match |
| `internal/keyderiv/keymethod2.go` (new) | model/codec (KM2 message read/write) | request-response (framed exchange) | `internal/wire/wire.go` (`ParseControlPacket` field-by-field bounds-checked parse) | exact (parse discipline) |
| `internal/keyderiv/keyexpansion.go` (new) | utility (key-slot slicing + direction assignment) | transform | `internal/tlscrypt/tlscrypt.go` (`keySlot`, `NewWrapper` slot assignment) | exact (structurally identical, inverted semantics) |
| `internal/datachan/datachan.go` (new) | service (per-session AEAD wrapper) | streaming (data channel) | `internal/tlscrypt/tlscrypt.go` (`Wrapper`, `Wrap`/`Unwrap`, `replayWindow`) | exact |
| `internal/datachan/replay.go` (new, or same file) | utility (sliding window) | event-driven | `internal/tlscrypt/tlscrypt.go` (`replayWindow` type + `accept`) | exact — copy verbatim, own instance |
| `ovpn.go` (modified: `handleDatagram`, `runHandshake` continuation, IP pool, peer-id routing) | controller (dispatch/session orchestration) | event-driven + request-response | `ovpn.go` itself (existing `handleDatagram`, `runHandshake`, `Server` struct) | exact (extend in place) |
| `session.go` (modified: real `Read`/`Write`, `AssignedIP`) | model/controller (session state + IO) | streaming | `session.go` itself (existing `Session`, `Close`, `stopCh` pattern) | exact (extend in place) |
| `internal/pushreply` or inline in `ovpn.go` (new: PUSH_REQUEST/PUSH_REPLY string exchange) | controller (plain-string protocol step) | request-response | `internal/wire/wire.go` sentinel-error parse style; `ovpn.go`'s `runHandshake` sequencing | role-match |
| `test/interop/decode.go` + `capture_test.go` (extended: KM2/PUSH/data-channel decode+assert) | test (integration decode/assert) | batch (pcap post-processing) | `test/interop/decode.go` / `capture_test.go` (existing tls-crypt unwrap + assertion pattern) | exact |
| `internal/keyderiv/prf_test.go`, `internal/datachan/*_test.go` (new) | test (unit, golden-vector + tamper) | batch | `internal/tlscrypt/golden_test.go`, `internal/tlscrypt/tlscrypt_test.go` | exact |

## Pattern Assignments

### `internal/keyderiv/prf.go` + `keyexpansion.go` (utility, transform)

**Analog:** `internal/tlscrypt/tlscrypt.go`

**Package-doc citation-header pattern** (lines 1-20 of tlscrypt.go):
```go
// Package X implements ... — NOT a standard AEAD call. cipher.NewGCM/...
//
// Byte layout and constants are traceable to the pinned OpenVPN reference
// checkout (/Users/svenloth/dev/openvpn-reference, branch release/2.6,
// commit c9b790f5b9e8ebca5da38c22f479c31bb8d33686):
//
//   - <topic>: src/openvpn/<file>.c:<lines> (<C symbol names>)
package tlscrypt
```
Copy this header shape exactly for `internal/keyderiv`, citing `ssl.c:1476-1517` (openvpn_PRF seed assembly), `crypto_openssl.c:1467-1626` (ssl_tls1_PRF/tls1_P_hash), `ssl.c:1579-1630` (generate_key_expansion_openvpn_prf) per RESEARCH.md Patterns 2-3.

**keySlot / 64-byte-slot-prefix pattern** (tlscrypt.go lines 75-82):
```go
type keySlot struct {
	cipher [cipherKeySize]byte
	hmac   [hmacKeySize]byte
}
```
`internal/keyderiv`'s key-expansion output (256 bytes → `key2.keys[2]`, each 128 bytes = 64+64, only first 32 of each consumed) is the exact same "prefix-of-a-64-byte-field" shape as `tlscrypt.keyfile.go`'s doc comment table (lines 30-36) already documents for the 256-byte Static-key-V1 body. Reuse the same struct shape and doc-comment table format.

**CRITICAL — do NOT copy this slot-assignment snippet** (tlscrypt.go lines 179-185):
```go
if server {
    w.encrypt, w.decrypt = keys[0], keys[1]
} else {
    w.encrypt, w.decrypt = keys[1], keys[0]
}
```
Per RESEARCH.md Pattern 4/Pitfall 1, the data-channel convention is the **mirror opposite**: `server: encrypt=keys[1], decrypt=keys[0]`. Write `internal/keyderiv`'s equivalent (`keyDirection(server bool) (encryptIdx, decryptIdx int)`) as an explicitly separate, separately-unit-tested function with a doc comment quoting the inverted table, and a unit test asserting the reversed expectation vs. `tlscrypt`'s own test.

**PRF reference test vector** — seed `internal/keyderiv`'s first unit test directly from RESEARCH.md Pattern 2's `tests/unit_tests/openvpn/test_crypto.c:140-166` vector (secret/seed/expected-32-byte-output all quoted verbatim in RESEARCH.md).

---

### `internal/keyderiv/keymethod2.go` (model/codec, request-response)

**Analog:** `internal/wire/wire.go` (bounds-checked field parser) + RESEARCH.md Pattern 1/Code-Example "KM2 field-by-field read"

**Bounds-check-before-read discipline** (wire.go doc comment, lines 71-75):
```go
// Sentinel parse errors. Every wire-parse function below explicitly checks
// remaining buffer length before each field read and returns one of these
// instead of ever letting a slice index panic on truncated or adversarial
// UDP input (mirrors the cheap-rejection discipline of
// tls_pre_decrypt_lite, ssl_pkt.c:305-423).
var (
	ErrTooShort    = errors.New("wire: buffer too short")
	...
)
```
Apply identically to KM2 field reads (48B pre_master, 32B random1, 32B random2, 2-byte-length-prefixed options/username/password/peer_info) — never trust a length field without a remaining-buffer check first (RESEARCH.md Security Domain V5).

**Exact-length-read framing** (RESEARCH.md Code Examples, illustrative, not yet in codebase):
```go
func readString(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, nil // write_empty_string's counterpart
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
```
Use `io.ReadFull` against `sess.conn`/`tlsConn` (a `bufio.Reader`-backed helper scoped to `runHandshake`'s continuation, per RESEARCH.md Open Question 1) — do not modify `ctrlconn.Conn`.

---

### `internal/datachan/datachan.go` (service, streaming)

**Analog:** `internal/tlscrypt/tlscrypt.go` in full — this is the single strongest analog in the codebase; mirror its shape almost exactly except where RESEARCH.md explicitly flags divergence.

**Imports** (tlscrypt.go lines 22-31):
```go
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)
```
`internal/datachan` swaps `crypto/sha256`+CTR for `crypto/cipher.NewGCM` (AEAD), and drops `time` — the data-channel packet ID is short-form only, no frozen timestamp (RESEARCH.md Pitfall 5).

**Sentinel-error pattern** (tlscrypt.go lines 68-73):
```go
var (
	ErrShort  = errors.New("tlscrypt: packet shorter than the tls-crypt prefix")
	ErrAuth   = errors.New("tlscrypt: authentication failed")
	ErrReplay = errors.New("tlscrypt: packet ID replay")
)
```
Copy directly for `internal/datachan` (`ErrShort`/`ErrAuth`/`ErrReplay`, same three failure modes).

**Wrapper struct shape + monotonic-sequence-under-mutex** (tlscrypt.go lines 135-162, 197-238):
```go
type Wrapper struct {
	encrypt keySlot
	decrypt keySlot

	mu      sync.Mutex
	sendSeq uint32
	...
	replay replayWindow
}
```
Copy this shape; `internal/datachan.Wrapper` needs `aead cipher.AEAD`, `encryptImplicitIV`/`decryptImplicitIV [8]byte` instead of `keySlot.hmac`, and a plain `sendSeq uint32` counter guarded by the same `sync.Mutex` discipline — but **no `sendTime`/`sendRolloverAt`/rollover-gate fields**: short-form packet IDs (RESEARCH.md Pitfall 5) never roll over in this project's scope (fails closed at `0xFFFFFFFF`, per RESEARCH.md Pattern 5's own note — no wraparound logic needed, unlike tls-crypt's long-form field).

**AAD assembly + tag placement — must diverge from tlscrypt's CTR/SIV construction.** Use RESEARCH.md Pattern 5's `sealDataV2`/`openDataV2` code skeleton (quoted there in full) as the primary template instead of tlscrypt's `wrapWithPID`/`Unwrap`, because tlscrypt is CTR+HMAC (tag-is-the-IV), while datachan is real AEAD with an explicit tag-before-ciphertext wire reorder — the two are structurally similar (AAD-then-authenticated-payload) but the actual Seal/Open calls differ. Key excerpt (RESEARCH.md Pattern 5 / Pitfall 2):
```go
sealed := aead.Seal(nil, nonce, plaintext, aad) // ciphertext ‖ tag (Go convention)
tag, ciphertext := sealed[len(sealed)-16:], sealed[:len(sealed)-16]
wire = append(append(append([]byte{}, header...), tag...), ciphertext...)
// decrypt:
tag, ciphertext := wire[8:24], wire[24:]
sealed := append(append([]byte{}, ciphertext...), tag...)
plaintext, err := aead.Open(nil, nonce, sealed, aad)
```

**Tag-verify-before-replay-check ordering** (tlscrypt.go lines 320-328, quoted in RESEARCH.md Security Domain V6):
```go
if !hmac.Equal(wireTag, computed) {
	return nil, nil, ErrAuth
}

seq := binary.BigEndian.Uint32(packet[OffPID : OffPID+4])
if !w.replay.accept(seq) {
	return nil, nil, ErrReplay
}
```
For AEAD this collapses to: `aead.Open` returning an error IS the tag-verify step — replay-window `accept()` must only run after `Open` succeeds, never before (mirrors the same ordering, just via a different primitive).

---

### `internal/datachan` replay window (utility, event-driven)

**Analog:** `internal/tlscrypt/tlscrypt.go` lines 84-127 (`replayWindow` type + `accept` method) — **copy verbatim**, as its own fresh instance per `Wrapper`, never shared with `tlscrypt`'s window (RESEARCH.md Pitfall 5):
```go
type replayWindow struct {
	mu      sync.Mutex
	init    bool
	highest uint32
	seen    uint64
}

func (r *replayWindow) accept(seq uint32) bool {
	// ... identical sliding-window bit-shift logic, replayWindowSize = 64
}
```
`replayWindowSize = 64` matches `DEFAULT_SEQ_BACKTRACK` (RESEARCH.md DATA-02) exactly — no change needed to the constant.

---

### `ovpn.go` modifications (controller, event-driven + request-response)

**Analog:** `ovpn.go` itself — extend, don't replace.

**Opcode-class branch needed BEFORE existing fixed-offset parse** (current bug site, lines 219-226):
```go
opcode, keyID := wire.ParseHeaderByte(packet[0])
if !wire.ValidOpcode(opcode) {
	return
}
var sid wire.SessionID
copy(sid[:], packet[1:1+wire.SessionIDSize])
```
Per RESEARCH.md Pitfall 3, insert a branch here: if `opcode == wire.OpDataV1 || opcode == wire.OpDataV2`, route via a new peer-id-keyed table (`map[uint32]*Session`, `Server`-scoped, mutex-guarded like `s.sessions`) instead of parsing `packet[1:9]` as a `SessionID`. Mirror the existing `sessionKey{addr, sid}` map's locking pattern (`s.mu.Lock()` / `s.mu.Unlock()`, lines 228-230, 421-427 `removeSession`) for the new table's add/remove.

**Continuation point after Handshake()** (lines 368-386, `runHandshake`):
```go
state := tlsConn.ConnectionState()
sess.connState = state
if len(state.PeerCertificates) > 0 {
	sess.PeerCN = state.PeerCertificates[0].Subject.CommonName
}
if s.cfg.OnSession != nil {
	s.callOnSession(sess)
}
```
Insert the KM2 read/write + PUSH_REQUEST/PUSH_REPLY exchange **between** `sess.PeerCN = ...` and the `OnSession` call — `s.callOnSession(sess)` moves to fire only after tunnel-up completes (CONTEXT.md's locked `OnSession` timing decision). Keep the existing panic-recovery wrapper (`callOnSession`, lines 398-407) unchanged.

**IP pool allocator** — new `Server`-scoped type, mutex-guarded like `Server.sessions`/`Server.mu` (lines 116-120): no existing analog for pool arithmetic itself (RESEARCH.md flags this MEDIUM confidence, project's own design), but the concurrency-safety shape (a `sync.Mutex`-guarded map/slice owned by `Server`, released in a `removeSession`-shaped teardown hook) should mirror `Server.sessions` exactly.

---

### `session.go` modifications (model/controller, streaming)

**Analog:** `session.go` itself.

**Current placeholders to replace** (lines 100-112):
```go
func (s *Session) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (s *Session) Write(p []byte) (int, error) {
	return 0, errors.New("ovpn: data channel not implemented until phase 2")
}
```
Replace with real datagram-semantics IO backed by `internal/datachan.Wrapper` and a bounded inbound IP-packet queue (mirror `sess.inbound chan wire.ControlPacket`, lines 63-68, sized like `inboundQueueSize = 32`, lines 87-93) — CONTEXT.md's locked "one full IP packet per Read/Write, short-buffer Read errors, never truncates" semantics.

**Field-doc-comment convention** — every `Session` field has a multi-line doc comment explaining reference provenance and concurrency contract (lines 28-97); add `assignedIP net.IP`, `dataWrapper *internal/datachan.Wrapper`, `ipInbound chan []byte` following the same documentation density (see e.g. `wrapper *tlscrypt.Wrapper` doc, lines 52-57).

**Teardown pattern** (lines 129-140, `Close`) — reuse `stopOnce.Do`/`stopCh` unchanged; add IP-pool release (freed-on-close, CONTEXT.md decision) and peer-id-table removal inside the same `stopOnce.Do` block, alongside the existing `s.srv.removeSession(s)` call.

---

### PUSH_REQUEST/PUSH_REPLY exchange (controller, request-response)

**Analog:** RESEARCH.md Pattern 6 (verbatim strings, byte-exact) + `ovpn.go`'s existing sequencing style in `runHandshake`.

Exact strings to construct/match, per RESEARCH.md:
```
client sends: "PUSH_REQUEST\0"           (13 bytes, literal)
server sends: "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id 0,cipher AES-256-GCM,ping 10,ping-restart 60\0"
```
Use `tls_send_payload`-equivalent framing: NUL-terminated, no length prefix (different framing than KM2's TLV fields — do not reuse `readString`'s 2-byte-length-prefix logic here).

---

### `test/interop` extensions (test, batch)

**Analog:** `test/interop/decode.go` + `test/interop/capture_test.go` (existing tls-crypt unwrap-then-assert pattern).

Extend `decode.go` with a data-channel AES-256-GCM unwrap function analogous to its existing tls-crypt unwrap call (mirrors how `capture_test.go` already unwraps tls-crypt using harness-derived keys); extend `golden_export.go`/`manifest.json` provenance conventions (`internal/tlscrypt/golden_test.go` lines 1-40: `goldenManifestEntry` struct, `loadGoldenManifest`/`loadGoldenKey` helpers) for any new KM2/data-channel golden vectors.

## Shared Patterns

### Package-doc citation header
**Source:** `internal/tlscrypt/tlscrypt.go` lines 1-20, `internal/wire/wire.go` lines 1-20
**Apply to:** `internal/keyderiv`, `internal/datachan` (both new packages) — cite pinned reference checkout path/commit, then a bulleted list of `<topic>: src/openvpn/<file>.c:<lines> (<C symbol>)`.

### Sentinel parse/crypto errors, never panic on adversarial input
**Source:** `internal/wire/wire.go` lines 71-80, `internal/tlscrypt/tlscrypt.go` lines 68-73
**Apply to:** `internal/keyderiv` (KM2 field parsing), `internal/datachan` (P_DATA_V2 header parsing) — bounds-check every length-prefixed/fixed-size field before indexing; return typed sentinel errors.

### Mutex-guarded monotonic sequence counter for AEAD/HMAC nonces
**Source:** `internal/tlscrypt/tlscrypt.go` lines 139-140, 202-231 (`sendSeq` under `w.mu`)
**Apply to:** `internal/datachan.Wrapper`'s packet-ID counter — same `sync.Mutex` discipline, critical for GCM nonce-uniqueness (RESEARCH.md Security Domain: nonce reuse = catastrophic).

### Auth-check strictly before replay-window mutation
**Source:** `internal/tlscrypt/tlscrypt.go` lines 320-328
**Apply to:** `internal/datachan`'s decrypt path — `aead.Open` success gates `replay.accept()`, never the reverse.

### Per-session state, never server-global
**Source:** `session.go` `wrapper *tlscrypt.Wrapper` field (per-session, doc comment lines 52-57); `ovpn.go` `Server.sessions` map pattern
**Apply to:** each `Session` gets its own `internal/datachan.Wrapper` instance (own keys, own replay window) even though key material derives from a shared exchange — never a server-wide data-channel wrapper.

### Goroutine-per-session teardown via stopCh/stopOnce
**Source:** `session.go` lines 86-98, 129-140
**Apply to:** any new per-session goroutine/queue this phase adds (IP-packet inbound queue, keepalive timer) — select on the existing `stopCh`, never introduce a second teardown signal.

## No Analog Found

None — every file/change this phase requires has at least a role-match or exact analog already in the Phase 1 codebase (`internal/tlscrypt`, `internal/wire`, `ovpn.go`, `session.go`, `test/interop`).

## Metadata

**Analog search scope:** `internal/`, `ovpn.go`, `session.go`, `test/interop/` (entire repo — small enough for exhaustive read, no glob/grep pruning needed)
**Files scanned:** `internal/wire/wire.go`, `internal/tlscrypt/tlscrypt.go`, `internal/tlscrypt/keyfile.go`, `internal/tlscrypt/golden_test.go`, `ovpn.go`, `session.go`, plus 02-CONTEXT.md and 02-RESEARCH.md's own extensive verbatim-quoted excerpts (RESEARCH.md itself doubles as a pattern source for wire-format/crypto excerpts not yet in any Go file)
**Pattern extraction date:** 2026-08-24
