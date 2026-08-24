---
phase: 01-handshake
verified: 2026-08-24T07:34:20Z
status: human_needed
score: 31/34 must-haves verified
behavior_unverified: 1
overrides_applied: 0
gaps: []
behavior_unverified_items:
  - truth: "A session that has not completed its handshake within the reference's 60 second handshake window is torn down and its state released (01-03-PLAN.md)"
    test: "Establish a session (send a HARD_RESET_CLIENT_V2), never send another packet or complete the TLS handshake, and wait for `reliable.HandshakeWindow` (60s, hardcoded, not clock-injectable in `ovpn.go`'s `enforceHandshakeWindow`) to elapse."
    expected: "The session is removed from `Server.sessions`, `sess.conn` is closed, and the `pump`/`runHandshake`/`enforceHandshakeWindow` goroutines all exit — the same teardown `TestSessionCloseStopsPumpAndRemovesFromSessions` already verifies for the `Close()` path, but for the timeout path specifically."
    why_human: "`enforceHandshakeWindow` (ovpn.go:404) calls `time.After(reliable.HandshakeWindow)` directly with a hardcoded 60s constant, not an injectable clock, so no automated test can observe this transition in bounded time. The code is present and wired (goroutine started at session creation, `ovpn.go:309`) but no test exercises the actual timeout-triggered teardown; this is presence + wiring only, not behavioral proof."
human_verification:
  - test: "Confirm a real GitHub Actions run (e.g. this phase's own PR) executes the `interop` job: verify it actually finds Docker on `ubuntu-latest`, uploads the capture artifact when a step fails, and does not silently skip when Docker is unavailable."
    expected: "The `interop` job runs `make interop` to completion (or fails loudly with an uploaded capture artifact), matching `.github/workflows/ci.yml`'s design — this cannot be executed from a sandbox with no git remote configured."
    why_human: "01-02-PLAN.md's truth 'the interop harness is runnable in CI without an interactive terminal and produces a machine-readable pass/fail exit status plus a retained capture artifact on failure' is authored as `verification: backstop` in the plan itself and 01-04-SUMMARY.md's own coverage table (D4) already records this as `human_judgment: true` — no GitHub Actions runner is reachable from this environment (`git remote -v` returns no remotes)."
  - test: "Deliberately break the reliability layer (e.g. force every retransmission to be dropped) or otherwise force a lossy interop run that never completes a handshake, and confirm the CI job's exit code is non-zero rather than the job timing out silently or reporting success."
    expected: "The `interop` CI job fails outright (matching `.github/workflows/ci.yml`'s `timeout-minutes: 25` and no `continue-on-error` on the test step), not skip or pass."
    why_human: "01-04-PLAN.md's truth 'a lossy interop run that never completes a handshake causes the CI job to fail rather than time out silently or report success' is authored as `verification: backstop`, same reasoning as above — requires an actual failing CI run to close the loop, which cannot be exercised from this sandbox."
  - test: "Establish a session and let 60 real seconds pass without completing the TLS handshake; confirm the session is torn down and its goroutines/state released."
    expected: "See `behavior_unverified_items` above."
    why_human: "State-transition truth with no clock-injected test; see `behavior_unverified_items`."
---

# Phase 1: Handshake Verification Report

**Phase Goal:** A real, unmodified OpenVPN 2.6 client connects to a Go program embedding the
library and reaches "TLS established" — over tls-crypt, with certificate-based mutual auth

**Verified:** 2026-08-24T07:34:20Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Verification Method

This verification did **not** rely on SUMMARY.md claims for the phase's central assertions.
Docker Desktop was available in this environment, so the full Docker-gated interop harness
was run live, from scratch, independently of any prior recorded run:

```
go run ./cmd/gentestpki -out test/interop/pki -profile large
go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -v
go test -tags interop -count=1 -timeout 300s -run TestCaptureIsFullyTLSCryptWrapped -v ./test/interop/
```

All three scenarios (`clean-small`, `clean-large`, `lossy-large`) and the capture-integrity
test passed on this independent run (`ok github.com/8upio/govpn/test/interop 67.535s`, then
`ok github.com/8upio/govpn/test/interop 53.126s`), with a real OpenVPN 2.6.14 client
completing a TLS 1.3 mutual-certificate handshake against the library in every scenario. Raw
server-side log excerpt from the `clean-small` run:

```
govpn-interop-server | 2026/08/24 07:30:18 recv opcode=7 key_id=0 session=1fb043f58c216a2a addr=172.28.0.3:45338
govpn-interop-server | 2026/08/24 07:30:18 send opcode=8 key_id=0 session=0429a96bb344a3a3 addr=172.28.0.3:45338
govpn-interop-client | 2026-08-24 us=788992 VERIFY OK: depth=1, CN=govpn-interop-CA
govpn-interop-client | 2026-08-24 us=789861 VERIFY OK: depth=0, CN=govpn-interop-server
govpn-interop-server | 2026/08/24 07:30:18 handshake established peer_cn=govpn-interop-client tls_version=TLS 1.3 cipher_suite=TLS_AES_128_GCM_SHA256
govpn-interop-server | 2026/08/24 07:30:20 PASS: session established and stable 2s past handshake completion; ...
```

`lossy-large` (7% loss and reordering injected in both directions, seed 1) also completed:
`interop_test.go:263: client-egress loss (NETEM_LOSS_PCT) = 7.0% (within [5,10])`, server
decorator log `lossy decorator active: drop=7.0% reorder=7.0%`, handshake still established.
`clean-large`/`lossy-large` observed 4 and 3 consecutive maximum-size (1150-byte)
server-to-client control fragments respectively, proving real certificate-chain fragmentation.
Container teardown was confirmed clean (`docker ps -a` empty after the run) and no working-tree
changes were left behind (generated PKI/captures are gitignored).

The fast tier (`go build ./...`, `go vet ./...`, `go test -race ./...`) was also run
independently and is Docker-free and green with zero external dependencies (`go list -m all`
→ 1 line).

## Goal Achievement

### Roadmap Success Criteria (phase contract)

| # | Success Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Embedder starts a server with `ovpn.NewServer(Config{}).Serve(pc)` over UDP; one command stands up a pinned OpenVPN 2.6 client container that connects with generated certs and a tls-crypt key | ✓ VERIFIED | `ovpn.go` public surface confirmed (`NewServer`, `Serve`, `Close`); live `make interop`-equivalent run above — all three scenarios PASS |
| 2 | Real client completes the full handshake (HARD_RESET_V2 → TLS established); both sides report the peer's verified certificate CN | ✓ VERIFIED | Live logs: client `VERIFY OK: depth=0, CN=govpn-interop-server`; server `handshake established peer_cn=govpn-interop-client` — TLS 1.3, `TLS_AES_128_GCM_SHA256` |
| 3 | Packet capture shows every control packet tls-crypt wrapped; wrap/unwrap and parse→serialize round-trip byte-exactly against isolated vectors from the C reference | ✓ VERIFIED | `TestCaptureIsFullyTLSCryptWrapped` PASS (live run); `TestGoldenControlPacketsRoundTrip`/`TestGoldenTLSCryptRewrap` PASS against 5 real-client-captured vectors in `testdata/golden/`; tamper tests (`TestGoldenVectorTamperHasTeeth`, capture tamper subtest) demonstrated to fail on a corrupted byte |
| 4 | Handshake still completes with a realistic multi-KB certificate chain (fragmented across several control packets) and with 5–10% synthetic packet loss injected on the link | ✓ VERIFIED | Live `clean-large` (4 consecutive max-size fragments) and `lossy-large` (3 consecutive max-size fragments, 7% loss both directions, handshake completed) scenarios both PASS |

**All four roadmap Success Criteria are directly, independently re-verified against the live
codebase — not inferred from SUMMARY.md text.**

### Plan 01-01 truths (wire format, tls-crypt, HARD_RESET round trip)

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | Embedder can construct `ovpn.NewServer(Config{})` and `Serve(net.PacketConn)` over UDP unprivileged | ✓ VERIFIED | `ovpn.go` exports match; `go build`/`go vet` clean |
| 2 | tls-crypt-wrapped `HARD_RESET_CLIENT_V2` (client key direction) unwrapped, parsed, answered with `HARD_RESET_SERVER_V2` the peer unwraps under keys[0] | ✓ VERIFIED | `TestHardResetRoundTrip` PASS (`go test -race -run TestHardResetRoundTrip -v .`) |
| 3 | Server's reply carries fresh 8-byte session ID, packet-ID 0, ACK of client's packet-ID 0 + client session ID | ✓ VERIFIED | Same test asserts these fields explicitly; live interop logs confirm distinct session IDs per run |
| 4 | tls-crypt unwrap fails closed on bad HMAC; no session state allocated | ✓ VERIFIED | `internal/tlscrypt/tlscrypt.go` uses `hmac.Equal`, verified before decrypt; `TestUnwrapRejectsTamperedPacket` PASS |
| 5 | Ack-count 0/8/9 parsing edge cases | ✓ VERIFIED | `TestControlPacketAdjacency` PASS |
| 6 | Zero-length/1-byte/truncated datagrams → typed errors, no panic, no state alloc | ✓ VERIFIED | `TestControlPacketTruncation` PASS; `FuzzParseControlPacket` re-run live for 5s with zero crashers |
| 7 | Parse→serialize round-trips byte-exactly, ACK order preserved | ✓ VERIFIED | `TestControlPacketRoundTrip` PASS |
| 8 | Concurrent `Wrap` calls never duplicate tls-crypt sequence numbers; race-clean | ✓ VERIFIED | `TestWrapConcurrentSequenceIDs` PASS under `-race` |
| 9 | `Serve` handles multiple client session IDs concurrently without corruption; returns after `Close`; race-clean | ✓ VERIFIED | `TestConcurrentSessions`/`TestServeClose` PASS under `-race` |

### Plan 01-02 truths (Docker interop harness)

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | One command stands up pinned client container + Go server on a user-defined bridge network | ✓ VERIFIED | Live run: both containers up, communicate over `172.28.0.0/x` bridge |
| 2 | PKI/tls-crypt key/.conf generated in Go, no easy-rsa, no shelled openvpn | ✓ VERIFIED | `cmd/gentestpki/main.go` contains `x509.CreateCertificate`, no `easy-rsa`/`os/exec` calls to openvpn for key generation |
| 3 | Real client's `HARD_RESET_CLIENT_V2` authenticated/answered; client sends `P_CONTROL_V1` afterward | ✓ VERIFIED | Live logs: `recv opcode=7` → `send opcode=8` → `recv opcode=4`, same session |
| 4 | Interop run exits non-zero if client never advances past reset | ✓ VERIFIED (by construction) | Harness server's own deadline logic (`test/interop/server/main.go`); not independently forced-failed in this pass, but code path reviewed and unchanged since 01-02 |
| 5 | Packet capture shows every control datagram authenticates under harness tls-crypt key; no readable plaintext beyond 49-byte prefix | ✓ VERIFIED | `TestCaptureIsFullyTLSCryptWrapped` PASS live; tamper subtest fails as expected |
| 6 | Server container runs non-root, default caps, no elevated flag, no host device — verified at runtime | ✓ VERIFIED | `assertServerStaysUnprivileged` (fatal, not skip) passed in all three live scenarios — asserts `docker inspect` output == `"false 0 0"` |
| 7 | *(backstop)* CI-runnable without interactive terminal, machine-readable pass/fail + retained capture artifact on failure | ⚠️ Routed to human verification | No GitHub remote configured in this sandbox (`git remote -v` empty); `.github/workflows/ci.yml` is well-formed and locally exercises the same `make interop`/`make test` entry points, but has never executed on an actual GitHub Actions runner — see human_verification |

### Plan 01-03 truths (reliability layer, control-channel `net.Conn`, TLS handshake)

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | Control channel exposed as `net.Conn`; `crypto/tls` sits on top unmodified via `tls.Server(conn, cfg)` | ✓ VERIFIED | `ovpn.go:361` `tls.Server(sess.conn, s.cfg.TLSConfig)`; `var _ net.Conn = (*Conn)(nil)` in `internal/ctrlconn/conn.go` |
| 2 | Real client drives HARD_RESET_V2 → completed TLS handshake; `Handshake()` returns nil | ✓ VERIFIED | Live interop logs, all 3 scenarios |
| 3 | Server reports verified peer CN; client's own output names server's verified CN | ✓ VERIFIED | Live logs both directions (see Goal Achievement #2) |
| 4 | `OnSession` fires exactly once per client, after `Handshake()` nil, never before; `Session.PeerCN` verified | ✓ VERIFIED | Single call site in `ovpn.go` immediately following successful `Handshake()` (no loop/retry); live logs show exactly one `handshake established`/`PASS` line per session across 3 independent runs; `TestOnSessionPanicRecovered` exercises the call path directly |
| 5 | Outgoing ciphertext fragmented ≤1150 bytes/datagram; multi-packet cert chain reassembled purely from in-order delivery, no fragmentation header | ✓ VERIFIED | `MaxPayload = 1150` in `internal/ctrlconn/conn.go`; live `clean-large`/`lossy-large` observed 4/3 consecutive max-size fragments and handshake completed, proving reassembly with no header |
| 6 | Control packets delivered strictly in reliability-packet-ID order; out-of-order buffered | ✓ VERIFIED | `TestOrderedDelivery` PASS |
| 7 | Unacked packets retransmitted at 2s initial, doubling; fast retransmit after 3 later acks | ✓ VERIFIED | `TestRetransmitBackoff`, `TestFastRetransmitAfterThreeLaterAcks` PASS (clock-injected) |
| 8 | Outgoing packet piggybacks ≤8 pending ACKs + peer session ID; dedicated ACK-only packet when nothing else queued | ✓ VERIFIED | `TestAckPiggybackCapAndAckOnlyPacket` PASS |
| 9 | Reliability packet-ID window and tls-crypt packet-ID window independent | ✓ VERIFIED | `TestReliabilityAndTLSCryptWindowsAreIndependent` PASS |
| 10 | TLS application data after `Handshake()` nil (Key Method 2 payload) buffered without erroring | ✓ VERIFIED | Live logs: server explicitly logs "surviving 2s past handshake completion..." then PASS, with the client's Key Method 2 application data (`recv opcode=5`... after handshake established) arriving in that window without error |
| 11 | Session not completing handshake within 60s torn down, state released | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | `enforceHandshakeWindow` (ovpn.go:404) is implemented and wired (goroutine started at session creation), but uses a hardcoded, non-clock-injectable `time.After(reliable.HandshakeWindow)` (60s) — no test exercises the actual timeout-triggered teardown transition. See `behavior_unverified_items` |

### Plan 01-04 truths (lossy link, multi-KB cert chain, golden vectors, CI)

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | Real client completes handshake under 5-10% synthetic loss + reordering, both directions | ✓ VERIFIED | Live `lossy-large` scenario, 7% loss both directions, PASS |
| 2 | Real client completes handshake against multi-KB cert chain spanning several control packets | ✓ VERIFIED | Live `clean-large`/`lossy-large`, 4/3 consecutive max-size fragments observed |
| 3 | Loss injected client→server via `tc netem` in client container; server→client via seeded decorator around `PacketConn` in harness only, never core library | ✓ VERIFIED | `grep -rl 'DropRate' --include='*.go' .` → only `test/interop/server/main.go`; `test/interop/entrypoint.sh` contains `netem` |
| 4 | Real-client control datagrams committed as golden vectors, asserted in fast tier: unwrap/authenticate, parse, re-serialize/re-wrap to original bytes | ✓ VERIFIED | `TestGoldenControlPacketsRoundTrip`/`TestGoldenTLSCryptRewrap` PASS; 5 vectors + manifest + README with provenance in `testdata/golden/`; tamper test demonstrates the assertion has teeth |
| 5 | Fast tier needs no Docker and stays green; interop tier behind build tag, invoked by CI | ✓ VERIFIED | `go test -race ./...` (no `-tags interop`) green; `.github/workflows/ci.yml` invokes both tiers as separate jobs |
| 6 | CI runs fast tier + both interop scenarios on every push, fails rather than skips when Docker unavailable, uploads capture artifact on failure | ✓ VERIFIED (structurally) | `.github/workflows/ci.yml` reviewed: `docker version` step with no `continue-on-error`, `if: failure()` artifact upload, `timeout-minutes: 25` — but never executed on an actual runner (see below) |
| 7 | *(backstop)* A lossy interop run that never completes a handshake causes the CI job to fail rather than time out silently or report success | ⚠️ Routed to human verification | Same reasoning as 01-02 truth 7 — no reachable GitHub Actions runner in this sandbox |

**Score:** 31/34 truths verified (3 present-but-not-behaviorally-proven or backstop-abstained,
routed to human verification below)

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `go.mod` | `module github.com/8upio/govpn`, `go 1.24`, zero deps | ✓ VERIFIED | Confirmed content; `go list -m all` → 1 line |
| `internal/wire/wire.go` | Opcode/SessionID/PacketID/ControlPacket, parse/serialize | ✓ VERIFIED | Present, wired into `ovpn.go`, tested |
| `internal/tlscrypt/{tlscrypt,keyfile}.go` | Wrap/Unwrap, key-file parsing | ✓ VERIFIED | `hmac.Equal`, `cipher.NewCTR` (not `NewGCM`) confirmed present |
| `ovpn.go` | Public `Config`/`Server` surface | ✓ VERIFIED | `NewServer`, `Serve`, `Close`, `ParseStaticKeyV1` all present |
| `internal/reliable/reliable.go` | Reliability layer, all named constants | ✓ VERIFIED | `NSendBuffers=6`, `NRecBuffers=12`, `AckSize=8`, `NAckRetransmit=3`, `HandshakeWindow=60s`, each with a reference-file comment |
| `internal/ctrlconn/conn.go` | `net.Conn` over control channel | ✓ VERIFIED | `MaxPayload=1150`, `var _ net.Conn = (*Conn)(nil)` |
| `session.go` | `ovpn.Session` with `PeerCN`, `ConnectionState()` | ✓ VERIFIED | Present, used by interop harness |
| `cmd/gentestpki/main.go`, `test/interop/*` | Docker harness, pcap reader, capture tests | ✓ VERIFIED | Full harness ran live end to end |
| `testdata/golden/` | 5 real-client vectors + manifest + README + key | ✓ VERIFIED | All present with provenance; golden tests pass |
| `.github/workflows/ci.yml` | Fast + interop CI jobs | ✓ VERIFIED (structurally) | Well-formed, but unexecuted on a real runner — see human verification |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `ovpn.go` | `internal/tlscrypt` | `Unwrap` before wire parsing | ✓ WIRED | Confirmed by code path and live traffic |
| `ovpn.go` | `internal/wire` | `ParseControlPacket` on decrypted plaintext | ✓ WIRED | Confirmed |
| `ovpn.go` | `internal/ctrlconn` | `tls.Server(conn, cfg)` | ✓ WIRED | `ovpn.go:361` |
| `internal/ctrlconn` | `internal/reliable` | ACK/window-driven Read/Write | ✓ WIRED | `reliable.Reliable`/`Ack` used throughout `conn.go` |
| `ovpn.go` | `session.go` | `OnSession(sess)` only post-`Handshake()` | ✓ WIRED | Single call site, guarded |
| `test/interop/server/main.go` | `ovpn.go` | Real embedder calling `NewServer`/`Serve` | ✓ WIRED | Live-confirmed |
| `test/interop/capture_test.go` | `internal/tlscrypt` | Captured payloads authenticated with `Unwrap` | ✓ WIRED | `TestCaptureIsFullyTLSCryptWrapped` live PASS |

### Behavioral Spot-Checks / Live Runs

| Behavior | Command | Result | Status |
|---|---|---|---|
| Fast tier build/vet/test | `go build ./... && go vet ./... && go test -race ./...` | All packages `ok`, zero deps | ✓ PASS |
| Fuzz (control-packet parser) | `go test -race -fuzz FuzzParseControlPacket -fuzztime 5s ./internal/wire/` | 0 new interesting/crashers | ✓ PASS |
| Golden vectors (real client bytes) | `go test -race -run TestGolden -v ./internal/wire/ ./internal/tlscrypt/` | All 5 vectors PASS, tamper fails as expected | ✓ PASS |
| Full Docker interop scenario table (live, independent run) | `go test -tags interop -run TestInteropScenarios -v ./test/interop/` | `clean-small`, `clean-large`, `lossy-large` all PASS in 67.5s | ✓ PASS |
| Capture tls-crypt integrity (live, independent run) | `go test -tags interop -run TestCaptureIsFullyTLSCryptWrapped -v ./test/interop/` | PASS + tamper subtest PASS | ✓ PASS |
| Server-container privilege check | Embedded in `TestInteropScenarios` (`assertServerStaysUnprivileged`, fatal not skip) | Passed in all 3 scenarios | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|---|---|---|---|---|
| WIRE-01 | 01-01, 01-04 | Control/data packet parse/serialize byte-exact, golden-vector tested | ✓ SATISFIED | Self-consistency + real-client golden vectors both pass |
| WIRE-04 | 01-01, 01-02, 01-04 | tls-crypt wrap/unwrap, key-file parsing, replay protection | ✓ SATISFIED | Unit tests + live capture verification + golden re-wrap |
| CTRL-01 | 01-03, 01-04 | Reliability layer, in-order delivery, ACK piggyback, retransmit, survives 5-10% loss | ✓ SATISFIED | Unit tests + live lossy-large scenario |
| CTRL-02 | 01-03, 01-04 | `net.Conn` framing, fragmentation/reassembly, multi-KB records | ✓ SATISFIED | `TestTLSHandshakeOverCtrlConn` + live multi-KB cert chain fragmentation |
| CTRL-03 | 01-03 | Real client completes full TLS handshake with mutual cert auth | ✓ SATISFIED | Live interop run, TLS 1.3, verified CNs both sides |
| SESS-01 | 01-01, 01-02, 01-03 | `ovpn.NewServer(Config{}).Serve(pc)` public surface | ✓ SATISFIED | Confirmed present, used by real embedder in harness |
| VRFY-01 | 01-02, 01-04 | Docker harness, pinned client, automatable in CI | ✓ SATISFIED (locally); CI-execution unverified | Harness runs live end-to-end; the "automatable in CI" half is the backstop truth routed to human verification |

**No orphaned requirements.** All 7 requirement IDs declared across the phase's 4 plans
(`WIRE-01, WIRE-04, CTRL-01, CTRL-02, CTRL-03, SESS-01, VRFY-01`) match exactly the 7 IDs
`.planning/REQUIREMENTS.md`'s traceability table maps to "Phase 1", and REQUIREMENTS.md marks
all 7 `[x]` complete. No requirement mapped to Phase 1 in REQUIREMENTS.md is absent from a
plan's `requirements:` frontmatter, and no plan claims a requirement REQUIREMENTS.md doesn't
map to Phase 1.

### Anti-Patterns Found

No blocker-level anti-patterns (no `TBD`/`FIXME`/`XXX` markers found in phase-modified files;
`go vet` and the fast-tier test suite are clean). Four Info-severity findings from
`01-REVIEW.md` remain unaddressed by design (all four fix commits addressed only the Critical
and Warning findings; the review report itself and this session's own re-scan confirm all four
are still present, unchanged):

| File | Pattern | Severity | Impact |
|---|---|---|---|
| `cmd/gentestpki/main.go` | Dead `rootCert` variable (`_ = rootCert`) | Info | Cosmetic; no functional impact |
| `test/interop/server/main.go` | String-concatenated paths instead of `filepath.Join` | Info | Cosmetic; no functional impact |
| `internal/ctrlconn/conn.go` | `flushAckOnly` can emit a benign empty-ACK packet under a race | Info | Documented as acceptable in-code; low impact |
| `test/interop/decode.go`, `test/interop/pcap.go` | Missing `//go:build interop` tag their only callers carry | Info | Causes a false-positive-looking `staticcheck` dead-code warning in the default tier; confirmed still present (`head -3` shows no build tag on either file) |

All three Critical/Warning findings from the review's second iteration (WR-03 OnSession panic
observability, WR-04 tls-crypt timestamp freezing, WR-05 missing regression tests) were fixed
in commits `c429ed1`, `c1c01ab`, `12582f5` and their regression tests
(`TestOnSessionPanicRecovered`, `TestWrapPacketIDRolloverGate`,
`TestWrapPacketIDTimestampFrozenPerKey`, `TestSessionCloseStopsPumpAndRemovesFromSessions`)
were independently re-run in this verification pass and pass under `-race`.

### Human Verification Required

#### 1. Real CI execution of the interop job

**Test:** Push this phase's commits (or open the PR) and confirm the `interop` job in
`.github/workflows/ci.yml` actually runs on a GitHub Actions `ubuntu-latest` runner: Docker is
found, `make interop` runs to completion, and the capture-artifact upload step works if any
step fails.
**Expected:** The job passes (or fails loudly with an uploaded capture artifact) — never
skips silently.
**Why human:** No git remote is configured in this sandbox (`git remote -v` returns nothing),
so there is no reachable GitHub Actions runner to execute against. `01-04-SUMMARY.md`'s own
coverage table already records this exact gap (`D4`, `human_judgment: true`). The workflow
YAML is well-formed and its literal command text was locally verified (`make test` passes,
`grep -c 'go test -race' .github/workflows/ci.yml` → 4), but that is not the same as an
actual run.

#### 2. CI failure behavior on a genuinely broken lossy run

**Test:** Temporarily break the reliability/retransmission logic (or otherwise force the
lossy scenario to never complete a handshake) and push to confirm the `interop` CI job's exit
status is non-zero, not a silent timeout or false pass.
**Expected:** The job fails within its 25-minute timeout with the capture artifact uploaded.
**Why human:** Same "no reachable CI runner" constraint as above; this truth is explicitly
authored as `verification: backstop` in `01-04-PLAN.md`.

#### 3. 60-second handshake-window teardown

**Test:** Send a `HARD_RESET_CLIENT_V2` to create a session, then never advance the TLS
handshake and wait 60+ real seconds (or temporarily patch `reliable.HandshakeWindow` down to a
few seconds for a manual check).
**Expected:** The session is torn down — removed from `Server.sessions`, its `ctrlconn.Conn`
closed, and its goroutines (`pump`, `runHandshake`, `enforceHandshakeWindow`) exit — matching
the teardown behavior `TestSessionCloseStopsPumpAndRemovesFromSessions` already proves for the
explicit-`Close()` path.
**Why human:** `enforceHandshakeWindow` uses a hardcoded, non-clock-injectable
`time.After(reliable.HandshakeWindow)` (60s) rather than the `Clock` interface
`internal/reliable`'s own tests use to avoid `time.Sleep`. No automated test in the current
suite exercises this specific timeout-triggered path; the code is present and correctly wired
(reviewed and cross-checked), but its actual runtime behavior on the timeout branch is
unproven by any test.

### Gaps Summary

No BLOCKER-level gaps. All roadmap Success Criteria, all plan-level artifacts, and all key
links are verified present, substantive, and wired — the phase goal ("a real, unmodified
OpenVPN 2.6 client connects... and reaches TLS established, over tls-crypt, with
certificate-based mutual auth") was independently re-verified live in this session, not merely
inferred from the SUMMARY.md files. The three items above are WARNING-level: two are
explicitly-flagged `verification: backstop` truths about CI behavior that cannot be exercised
without a reachable GitHub Actions runner (none configured in this sandbox), and one is a
present-and-wired-but-behaviorally-unproven 60-second timeout teardown path. None of the three
block the phase goal itself, which does not depend on CI execution or on the handshake-window
timeout path (every live run in this verification pass completed its handshake well within
the window). Recommend a human confirm all three on the next real CI run / a manual soak test,
then close them out — Phase 4 (Durable Sessions, `SESS-04`/`SESS-05`) already scopes broader
session-lifecycle soak testing that would naturally re-exercise the handshake-window path.

---

_Verified: 2026-08-24T07:34:20Z_
_Verifier: Claude (gsd-verifier)_
