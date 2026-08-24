---
phase: 02-tunnel-up
verified: 2026-08-25T00:20:00Z
status: passed
score: 10/10 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 2: Tunnel Up Verification Report

**Phase Goal:** The client brings its tunnel interface up with a pushed IP and cipher, and encrypted IP packets round-trip between the client and the embedder's `Session`
**Verified:** 2026-08-25T00:20:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Client logs "Initialization Sequence Completed" after PUSH_REPLY with tunnel IP from `Config.Network` (topology subnet, server = first host IP, 1 IP/client), explicit `cipher AES-256-GCM`, and keepalive parameters | ✓ VERIFIED | Live `make interop`-equivalent run (this session, independent of prior claims): client log line `PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id 0,cipher AES-256-GCM,ping 10,ping-restart 60'` followed by `net_addr_v4_add: 10.8.0.2/24 dev tun0` and `Initialization Sequence Completed` on all 3 scenarios |
| 2 | `OnSession` hands the embedder a `Session` exposing the assigned tunnel IP; a client ping arrives on `Read` as a raw IP packet, and the reply written to `Write` reaches the client — encrypted round-trip both directions | ✓ VERIFIED | `test/interop/server/main.go`'s harness ICMP responder reads/writes exclusively through `Session.Read`/`Write` (`session.go:314-360`); live run confirms `ping_rx=10 ping_tx=10` (clean scenarios) / `ping_rx=9 ping_tx=9` (lossy) on the server PASS line and matching client-side ping statistics |
| 3 | TLS 1.0 PRF and Key Method 2 expansion (per-direction slots + implicit-IV) pass golden-vector tests derived from `ssl.c`/`crypto.c` before any live data-channel traffic runs | ✓ VERIFIED | `go test -race -run TestPRFReferenceVector ./internal/keyderiv/` passes against the reference's own committed 32-byte vector; `TestServerSlotsMatchReferenceByteRanges` asserts against literal byte ranges 128:160/192:200/0:32/64:72, independently of round-trip self-consistency |
| 4 | Replayed/out-of-window data packets are dropped; keepalive/ping magic packets are answered inside the library and never surface to the Session consumer | ✓ VERIFIED | `internal/datachan/datachan.go:284-291` consults the replay window strictly after `aead.Open` succeeds (`TestAuthFailureDoesNotTouchWindow`); `IsPing`/`ErrPingAbsorbed` path (`datachan.go:293-295`) confirmed by `TestPingNeverReachesSessionRead` |
| 5 | Harness runs a lossy scenario (5–10% packet loss and reordering) in which handshake AND ping round-trip both succeed | ✓ VERIFIED | Live run this session: `lossy-large` PASS, client-egress loss 7.0% (within [5,10]), server decorator drop 7.0%, ping 9/10 replies received, tunnel-up assertion passed |

### Plan-Level Must-Have Truths

All plan-declared `must_haves.truths` across 02-01–02-04 were checked directly against source, not merely re-read from SUMMARY claims:

| # | Truth (paraphrased) | Status | Evidence |
|---|------|--------|----------|
| 6 | P_DATA_V2 wire layout: `[opcode\|keyID][peer-id 3B][packet-id 4B][tag 16B][ciphertext]`, tag before ciphertext (reverse of Go's `Seal`) | ✓ VERIFIED | `datachan.go:39-58` offsets + `sealWithSeq`/`Open` explicit reorder (lines 197-215, 260-268), `TestSealLayout`/`TestGoldenDataChannelReseal` pass |
| 7 | Nonce = `packetID(4) ‖ implicitIV(8)` concatenation, never XOR; AAD = 8 header bytes | ✓ VERIFIED | `datachan.go:203-205, 246-248` build nonce via `binary.BigEndian.PutUint32` + `copy`, no XOR operator present; `TestNonceIsConcatenationNotXor` asserts against a literal |
| 8 | Data-channel key direction is the mirror opposite of tls-crypt's | ✓ VERIFIED | `keyexpansion.go:65-70`: `keyDirection(true)` returns `(1,0)`; `TestKeyDirectionIsOppositeOfTLSCrypt` + `TestGoldenKeyDirectionWouldCatchAnInversion` (opens a real captured vector, fails when slots swapped) |
| 9 | 64-wide sliding replay window, independent of tls-crypt's/reliability's own sequence spaces | ✓ VERIFIED | `internal/datachan/replay.go` (separate instance, `replayWindowSize=64`); `TestDataChannelWindowIndependentOfTLSCrypt` passes |
| 10 | Tunnel-IP pool: server = first host IP, sequential first-free, network/broadcast reserved, released-on-close reuse, duplicate CN gets distinct IPs, never double-assigns under concurrency | ✓ VERIFIED | `ippool.go` implements exactly this; `TestPoolConcurrentAllocationNeverDuplicates` (200 goroutines, `-race`) and `TestDuplicateCNGetsDistinctIPs` pass |

**Score:** 10/10 truths verified (0 present-but-behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/keyderiv/{prf,keyexpansion,keymethod2}.go` + tests | PRF, key expansion, KM2 codec | ✓ VERIFIED | Present, substantive, wired into `ovpn.go`'s `performKeyMethod2Exchange`; golden test reproduces real client's key material |
| `push.go`, `ippool.go` + tests | PUSH_REQUEST/PUSH_REPLY, IP pool | ✓ VERIFIED | Present, substantive, wired into `runHandshake`/`performPushExchange` |
| `internal/datachan/{datachan,replay,ping}.go` + tests | AEAD wrapper, replay window, ping absorption | ✓ VERIFIED | Present, substantive, wired into `handleDatagram`/`Session.Read`/`Write` |
| `gates_test.go` | AST-based standing prohibition gates | ✓ VERIFIED | 5 tests present, all pass, wired into `make gates`/`make test` and CI (`.github/workflows/ci.yml`) |
| `testdata/golden/006-008.bin` + `manifest.json`/`README.md` | Real-client data-channel golden corpus | ✓ VERIFIED | 3 vectors + key material committed; `TestGoldenManifestCoversEveryFile` passes; provenance block present in README |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `runHandshake` | `internal/keyderiv.DeriveKeys` | `performKeyMethod2Exchange` | ✓ WIRED | Confirmed by code read + live client reaching PUSH_REQUEST |
| `Session.dataKeys.ServerSlots()` | `internal/datachan.NewWrapper` | `performPushExchange` | ✓ WIRED | `ovpn.go` constructs wrapper from `sess.dataKeys.ServerSlots()` before publish |
| `handleDatagram` opcode branch | `Server.dataSessions` | peer-id routing | ✓ WIRED | Branch precedes the 8-byte session-ID parse (grep confirms `OpDataV2` referenced ahead of `packet[1:1+wire.SessionIDSize]`) |
| `Session.Close` | `ipPool.release` / `dataSessions` delete | `stopOnce.Do` | ✓ WIRED | WR-04/WR-05 fixes verified: delete-before-release ordering, atomic publish-or-abort under nested `sess.mu`→`srv.mu` |

### Data-Flow Trace (Level 4)

Pushed IP: `buildPushReply` receives `clientIP` from `ipPool.allocate()` (a real, mutex-guarded allocation, not a static value) — confirmed FLOWING by the live interop run showing distinct/incrementing behavior is not needed here (single client per scenario) but the pool's own concurrency tests (200 goroutines, zero duplicates) prove the allocator is real, not a stub returning a fixed IP.

Decrypted IP packets: `Session.Read` sources from `ipInbound`, populated by `handleDataPacket` off `dataWrapper.Open`'s real AEAD decrypt — confirmed FLOWING by the harness ICMP responder actually parsing and replying to real ICMP echo requests captured from a live client (`ping_rx=`/`ping_tx=` non-zero, byte-identical to golden-vector-derived plaintexts in `TestGoldenDataChannelOpen`).

### Behavioral Spot-Checks / Live Verification

This verification independently re-ran (not just re-read) the following, all in this session:

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Fast tier | `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` | All packages `ok`, no race reports | ✓ PASS |
| PRF reference vector | `go test -race -run TestPRFReferenceVector -v ./internal/keyderiv/` | PASS | ✓ PASS |
| Prohibition gates | `make gates` (`go test -race -run TestPhase2 -v ./`) | All 5 gate tests PASS | ✓ PASS |
| Golden vectors (all packages) | `go test -race -run TestGolden -v ./internal/datachan/ ./internal/keyderiv/ ./internal/wire/ ./internal/tlscrypt/` | All PASS, including tamper-has-teeth and key-direction-inversion-has-teeth, logged failures observed | ✓ PASS |
| WR-05 regression + WR-03/WR-04 regressions | `go test -race -count=10 -run 'TestPerformPushExchangeReleasesAllocationWhenSessionAlreadyClosing\|TestPerformPushExchangeFieldWritesRaceSafeAgainstClose\|TestCloseRemovesRoutingEntryBeforeReleasingPeerID' -v ./` | 10/10 iterations PASS, no flakes | ✓ PASS |
| Live 3-scenario Docker interop | `go run ./cmd/gentestpki -out test/interop/pki -profile large && go test -tags interop -count=1 -timeout 900s -run TestInteropScenarios -v ./test/interop/` | `clean-small`/`clean-large`: `Initialization Sequence Completed`, `10/10` ping replies, `km2=ok push_request=seen assigned_ip=10.8.0.2 peer_id=0`. `lossy-large`: same tunnel-up + `9/10` ping replies at ~7-10% observed/injected loss. All 3 PASS, none SKIP | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| WIRE-02 | 02-01 | TLS 1.0 PRF verified against reference vector | ✓ SATISFIED | `TestPRFReferenceVector` byte-exact |
| WIRE-03 | 02-01, 02-04 | KM2 key expansion, slot/implicit-IV mapping, verified against reference AND live capture | ✓ SATISFIED | `TestServerSlotsMatchReferenceByteRanges` + `TestGoldenKeyExpansionFromCapture` |
| CTRL-04 | 02-01 | KM2 exchange completes with real client | ✓ SATISFIED | Live interop `km2=ok push_request=seen` |
| CTRL-05 | 02-02 | PUSH_REQUEST/PUSH_REPLY works, tunnel comes up | ✓ SATISFIED | Live interop `Initialization Sequence Completed` + pushed address |
| DATA-01 | 02-03, 02-04 | P_DATA_V2 AES-256-GCM encrypt/decrypt, correct nonce/AAD | ✓ SATISFIED | `TestSealLayout`, `TestNonceIsConcatenationNotXor`, golden vectors |
| DATA-02 | 02-03, 02-04 | Replay protection | ✓ SATISFIED | `TestReplay*`, `TestAuthFailureDoesNotTouchWindow`, golden manifest completeness |
| DATA-03 | 02-03 | Ping absorbed, never surfaced | ✓ SATISFIED | `TestPingNeverReachesSessionRead`, `ErrPingAbsorbed` path |
| SESS-02 | 02-02 (partial), 02-03 (complete) | Session is real `io.ReadWriteCloser` with assigned IP | ✓ SATISFIED | `Session.Read`/`Write` real; `TestSessionReadWriteDatagramSemantics` |
| SESS-03 | 02-02 | Tunnel IPs from configurable `*net.IPNet` | ✓ SATISFIED | `ippool.go`, tested at `/30`, `/24`, `/16` |
| VRFY-03 | 02-04 | Lossy scenario proves tunnel-up + ping, not just handshake | ✓ SATISFIED | Live `lossy-large` PASS this session |

**No orphaned requirements.** All 10 declared requirement IDs (WIRE-02, WIRE-03, CTRL-04, CTRL-05, DATA-01, DATA-02, DATA-03, SESS-02, SESS-03, VRFY-03) appear in REQUIREMENTS.md mapped to Phase 2 and are each claimed by at least one plan's `requirements-completed` frontmatter.

**Note (informational, not a gap):** REQUIREMENTS.md's checkbox column still shows CTRL-05, DATA-03, SESS-02, and SESS-03 as unchecked (`[ ]`) and the Traceability table lists them "Pending" — this is stale bookkeeping relative to the actual codebase state confirmed above, not a functional gap. REQUIREMENTS.md is typically synchronized at ship/milestone-completion time rather than at phase-verify time; recommend updating it as part of closing this phase.

### Anti-Patterns Found

None. Scanned all files created/modified in this phase's four plans (`internal/keyderiv/*.go`, `internal/datachan/*.go`, `ovpn.go`, `session.go`, `push.go`, `ippool.go`, `gates_test.go`, `test/interop/**`) for `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER`/"not yet implemented" — zero matches.

### Human Verification Required

None. The one item that could plausibly warrant human judgment — WR-05's concurrency/lock-ordering argument (state-transition + cleanup invariant: "the IP/peer-id allocation is never double-released or permanently stranded under any `Close()`/`performPushExchange` interleaving") — already has both (a) a deterministic behavioral regression test (`TestPerformPushExchangeReleasesAllocationWhenSessionAlreadyClosing`) that forces the race window and asserts the release happens exactly once, re-run 10x under `-race` in this verification with no flakes, and (b) a documented exhaustive interleaving trace in `02-REVIEW.md` (iteration 3, "clean" status) covering both possible race orderings and confirming no lock-ordering cycle exists. This satisfies the behavior-dependent-truth bar (Step 3) without requiring a fresh human read.

### Gaps Summary

No gaps. All ROADMAP Phase 2 success criteria and all plan-declared must-haves are verified against the actual codebase and a live, independently-executed 3-scenario Docker interop run (not merely re-read from SUMMARY.md). The fast tier (`go build`, `go vet`, `go test -race ./...`, `make gates`) and the full interop suite (including the lossy scenario) both pass cleanly in this session. The prior code-review cycle (CR-01, WR-01 through WR-05) is closed with a "clean" final review status, independently spot-checked here via repeated `-race` runs of the WR-05 regression test.

---

_Verified: 2026-08-25T00:20:00Z_
_Verifier: Claude (gsd-verifier)_
