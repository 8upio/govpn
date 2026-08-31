---
phase: 04-durable-sessions
verified: 2026-08-28T13:00:00Z
status: passed
score: 15/15 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 4: Durable Sessions Verification Report

**Phase Goal:** A connected client stays usable for hours and leaves cleanly — key renegotiation does not break traffic, and dead sessions do not accumulate
**Verified:** 2026-08-28T13:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Roadmap Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A client renegotiates its keys and HTTP/UDP traffic keeps flowing across the rollover — `Session` stays open, no reconnect | ✓ VERIFIED | Independently re-ran `go test -tags interop -run TestInteropScenarios/reneg ./test/interop/` against a real, unmodified OpenVPN 2.6 client in Docker. Server PASS line: `renegotiations=3` (≥2 required); all 10 HTTP/UDP probe rounds `result=ok` spanning the rollovers; client log shows "exactly one completed initialization sequence" — zero reconnects. |
| 2 | A client sending explicit-exit-notify ends its session immediately; embedder observes `Session` closing rather than waiting for a timeout | ✓ VERIFIED | Same interop run: `exit_notify_close_after=47.447s` server-side wall time and test assertion `exit-notify closed the session 0s after the client's graceful stop (well under the 60s idle-reap window and the 15s threshold)`. Code: `session.go` `isExitNotify`/occMagic+occExit match on decrypted plaintext only, calls `Session.Close()` directly (`session.go:600-602`), wired ahead of the `ipInbound` delivery select. |
| 3 | Silent sessions time out and are reaped; `Session.Close()` tears down all state; soak run over many cycles shows goroutine/memory counts flat | ✓ VERIFIED | Code: `session.go` `startReap`/`runReap` (clock-injected, compares `lastAuthTraffic` against `s.srv.reapWindow`, tears down via existing `Close()`/`stopOnce`). Fast-tier `lifecycle_test.go` exercises this with an injected clock (part of the full `go test -race -count=1 ./...` pass, confirmed below). `04-04-SUMMARY.md` documents a 20-cycle real-client Docker soak with goroutine (baseline=5, final=4) and post-GC HeapAlloc (delta ~37-60 KiB within a 256 KiB tolerance) flatness, and — critically — both tolerances were proven capable of failing by deliberately injecting a goroutine leak (removed `runReap`'s `stopCh` case → delta=7, failed) and a heap leak (retained closed sessions in a slice → delta ~606-621 KiB, failed even against the initial too-loose 1 MiB tolerance, which was then tightened to 256 KiB) before being trusted. Not independently re-run (17-min six-run cost already paid during execution; evidence includes demonstrated-failing proof, not just a passing number). |

**Score:** 3/3 roadmap success criteria verified (all behaviorally proven, not just present-and-wired).

### Must-Haves by Plan (truths, artifacts, key links, prohibitions)

#### 04-01 (SESS-04 — renegotiation core)

| Must-have | Status | Evidence |
|---|---|---|
| Client-initiated SOFT_RESET_V1 at correct next key-id → full new handshake + KM2 on same session-ID pair; `Session` never replaced/re-handed/IP-or-peerID-changed | ✓ VERIFIED | `ovpn.go:beginRenegotiation`/`runRenegotiation` build a `newConn` via `ctrlconn.NewWithKeyID`, run `tls.Server(newConn,...).Handshake()` + `deriveKeyMethod2`, then swap only `sess.primary`/`sess.dataKeys` under `sess.mu` — no `pool.allocate`, no `OnSession`, no write to `assignedIP`/`peerID` anywhere in the function (confirmed by direct read and by `TestPhase4RenegotiationNeverRepeatsPushExchange` gate). |
| Old key stays decryptable via lame-duck slot until `transitionWindow` elapses, then refused | ✓ VERIFIED | `sess.lameDuck = sess.primary` demotion with `mustDie` deadline in `runRenegotiation`; dual-key `handleDataPacket` routing referenced throughout `session.go`. |
| Server's own reneg-sec timer fires with no inbound packet required, re-arms after rollover | ✓ VERIFIED | `Config.RenegSec`/`defaultRenegSec` (3600s), `s.renegSec` resolved once in `Serve` (`ovpn.go:337-339`); `startReneg`/`runReneg` pattern mirrors `startKeepalive`/`startReap`. |
| SOFT_RESET_V1 at wrong key-id refused, no state advance | ✓ VERIFIED | `nextKeyID` computed locally (`ovpn.go:211`); `TestPhase4KeyIDNeverTrustedFromPeer` gate passes. |
| Non-renegotiating session behaves exactly as Phase 3 | ✓ VERIFIED | Full `go test -race -count=1 ./...` passes with no weakened assertions; `gates` target's Phase 2/3 tests still pass unchanged. |
| Prohibitions (no PUSH re-run, no fresh wrapper, no OnSession twice, no new deps, no real-clock sleeps) | ✓ VERIFIED | `TestPhase4RenegotiationNeverRepeatsPushExchange`, `TestPhase4RenegotiationReusesSessionTLSCryptWrapper`, `TestPhase4NoNewModuleDependencies` all pass via `make gates`. |

#### 04-02 (SESS-05 — exit-notify, idle reap, teardown)

| Must-have | Status | Evidence |
|---|---|---|
| OCC exit-notify payload tears session down immediately, releases pool IP/peer-id | ✓ VERIFIED | `session.go:isExitNotify`/`occMagic`/`occExit`; independently confirmed live against real client above (0s close). |
| Authenticated inbound (control or data, either slot) resets idle timer | ✓ VERIFIED | `touchAuthTraffic` (`session.go:779-787`), called from control-delivery path (`ovpn.go`) and `handleDataPacket`. |
| No-traffic session reaped by server without client action, clock-injected | ✓ VERIFIED | `runReap` (`session.go:819-838`), driven by injectable tick channel; exercised in fast-tier `lifecycle_test.go` (part of the passing `go test -race` run). |
| Teardown from any cause → `Read`/`Write` return `io.EOF`, `Close` idempotent/concurrency-safe | ✓ VERIFIED | `stopOnce` guards `Close()`; `go test -race` passes with no data races flagged anywhere in the session/ovpn packages. |
| Every per-session goroutine exits once `Close` returns | ✓ VERIFIED | Soak run's flat goroutine count (04-04-SUMMARY, demonstrated-failing-then-passing) is direct behavioral proof, not just code inspection. |
| Prohibitions (post-decrypt-only exit-notify, no new teardown path, no `OnSessionClosed`, no real-clock reap, no new deps) | ✓ VERIFIED | `TestPhase4ExitNotifyCheckedOnlyPostDecrypt`, `TestPhase4TeardownAlwaysFlowsThroughClose`, `TestPhase4NoSessionClosedCallback` all pass via `make gates`. |

#### 04-03 (SESS-04 + SESS-05 — real-client interop proof)

| Must-have | Status | Evidence |
|---|---|---|
| Real OpenVPN 2.6 client renegotiates ≥2 times in one run; server reports rollovers | ✓ VERIFIED (independently re-run) | `renegotiations=3` observed live in this verification pass. |
| HTTP + UDP round-trip succeed before/between/after rollovers | ✓ VERIFIED (independently re-run) | All 10 `http_landing_rN`/`udp_echo_rN` probes `result=ok` in this verification pass. |
| Client log shows renegotiations with zero reconnects | ✓ VERIFIED (independently re-run) | Test assertion at `interop_test.go:427` passed: "exactly one completed initialization sequence." |
| Real client with explicit-exit-notify closes session within seconds, well inside 60s reap window | ✓ VERIFIED (independently re-run) | `0s after the client's graceful stop` in this verification pass. |
| Pre-existing clean-small/clean-large/lossy-large scenarios unaffected | ✓ VERIFIED (by inference) | Not re-run in this pass (context-budgeted to the new "reneg" scenario); `deferred-items.md` documents two pre-existing, unrelated flakes (netstack timing test, unseeded lossy-large netem) explicitly called out as NOT phase-4 regressions — consistent with 04-03/04-04 SUMMARY's own full 4-scenario runs during execution. |
| Prohibitions (no weakened prior assertions, no reconnect loophole, no privileged containers, single PROBE parser) | ✓ VERIFIED | `TestPhase4InteropClientConfigCarriesLifecycleDirectives`, `TestPhase3ServerContainerRequestsNoPrivileges` pass via `make gates`; docker-compose overlay reviewed, no `cap_add`/`privileged`/`devices`. |

#### 04-04 (SESS-05 — soak / leak-freedom)

| Must-have | Status | Evidence |
|---|---|---|
| 20-cycle soak, every cycle reaches tunnel-up and ends via exit-notify | ✓ VERIFIED | 04-04-SUMMARY: `soak_cycles_observed=20`, all 20 `http_landing_cN` probes `result=ok`. |
| Final goroutine count within documented tolerance of post-cycle-1 baseline | ✓ VERIFIED | baseline=5, final=4 (delta=-1, within ±2); tolerance proven capable of catching a real leak (delta=7 when injected). |
| Final post-GC HeapAlloc within documented tolerance of baseline | ✓ VERIFIED | baseline≈288KB, final≈349KB (delta≈61KB, within ±256KB); tolerance tightened from an initially-too-loose 1MiB after it failed to catch an injected ~606-621KB leak. |
| Every allocated IP/peer-id released; pool reused across cycles | ✓ VERIFIED | "1 distinct tunnel IP across 20 cycles" (04-04-SUMMARY). |
| Soak is a separate, longer-timeout target, does not slow `make test`/`make interop` | ✓ VERIFIED | `TestPhase4SoakIsNotInDefaultTargets` gate passes; `make soak` is its own Makefile target. |
| Prohibitions (observed-cycle-count assertion, cold-start-baseline ban, not in default targets, no prior assertions weakened, unprivileged containers, stdlib-only measurement) | ✓ VERIFIED | `TestPhase4SoakSamplesBaselineAfterFirstCycle`, `TestPhase4SoakAssertsObservedCycleCount`, `TestPhase4SoakIsNotInDefaultTargets` all pass via `make gates`. |

### Code-Level Verification (independent, not SUMMARY-sourced)

- `go build ./...` — clean.
- `go vet ./...` — clean.
- `go test -race -count=1 ./...` — all 12 packages pass, including the previously-flagged intermittent `netstack` flake (not reproduced this run) and every reneg/lifecycle/gates test.
- `make gates` (`TestPhase2*|TestPhase3*|TestPhase4*`, run with `-race`) — all 20 standing-prohibition gates pass, including 10 `TestPhase4*` gates covering every prohibition listed in the four plans' frontmatter.
- `go test -tags interop -count=1 -run TestInteropScenarios/reneg -v ./test/interop/` — **independently re-run in this verification pass** (not sourced from SUMMARY claims): real OpenVPN 2.6 client in Docker, 3 renegotiations observed, all probes `ok`, exit-notify closed the session in 0s, zero reconnects. Full log inspected directly.
- Direct code trace of `runRenegotiation`/`enforceRenegotiationWindow` in `ovpn.go` confirms the CR-03 fix (commit `e647f49`) is present exactly as described: the swap's critical section re-checks `sess.closing() || sess.pendingReneg != newConn` before committing, closing this verification's own top concern (a subtle promote-after-invalidated-watchdog race found and fixed during the phase's own 3-iteration review cycle).
- No `TBD`/`FIXME`/`XXX` debt markers found in any file this phase modified.

### Anti-Patterns Found

None blocking. One pre-existing info-level item carried forward and explicitly out-of-scope for this phase's fix iterations: `cmd/gentestpki/main.go`'s unused `rootCert` variable (IN-01 in `04-REVIEW.md`) — cosmetic dead-code, does not affect any must-have.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|---|---|---|---|---|
| SESS-04 | 04-01, 04-03 | Soft reset / key renegotiation survives with no traffic interruption | ✓ SATISFIED | Roadmap truth 1 above; live interop re-run this pass. |
| SESS-05 | 04-02, 04-03, 04-04 | Exit-notify handled, idle reap, `Close()` leak-free | ✓ SATISFIED | Roadmap truths 2 and 3 above; live interop re-run plus soak evidence. |

**Note (documentation-only, not a code gap):** `.planning/REQUIREMENTS.md` still shows SESS-04/SESS-05 as unchecked `[ ]` with traceability status "Pending" — this is a stale bookkeeping artifact from before this phase executed, not a functional gap. Recommend updating REQUIREMENTS.md's checkboxes and traceability table to "Complete" as part of phase close-out/ship.

### Human Verification Required

None. All roadmap success criteria and plan-level must-haves were either verified by direct code trace backed by a passing `-race` test suite and standing gates, or independently re-confirmed against a real, unmodified OpenVPN 2.6 client in this verification pass (not merely asserted by SUMMARY.md).

### Gaps Summary

No gaps. All three roadmap success criteria for Phase 4 are behaviorally proven: renegotiation preserves the session and traffic (independently re-run against a real client, 3 rollovers, zero reconnects), explicit-exit-notify closes sessions immediately (0s, independently re-run), and idle reap plus full goroutine/heap teardown are demonstrated both in fast-tier tests and a 20-cycle real-client soak whose tolerances were proven capable of catching real leaks before being trusted. The phase's own 3-iteration code review found and fixed a genuine race (CR-03) prior to this verification; the fix was independently confirmed present in the current code and covered by a dedicated regression test. Only a cosmetic documentation lag (REQUIREMENTS.md checkboxes) remains, noted above for close-out.

---

_Verified: 2026-08-28T13:00:00Z_
_Verifier: Claude (gsd-verifier)_
