---
phase: 2
slug: tunnel-up
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-24
---

# Phase 2 — Validation Strategy

> Per-phase validation contract. Map reconstructed at audit time from the four
> PLAN.md files' `<automated>` verify blocks (the template seeded at plan time
> was never filled by the planner; the plans themselves carried the commands).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `go test` (stdlib `testing`; no external test framework — core module is stdlib-only) |
| **Quick run command** | `go test -race ./<package-under-change>/` |
| **Full suite command** | `go test -race ./... && make gates && go test -tags interop -count=1 -timeout 900s -run TestInteropScenarios ./test/interop/` |
| **Estimated runtime** | fast tier ~20s; interop tier ~5-10 min (Docker, three real-client scenarios) |

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | Status |
|---------|------|------|-------------|-----------|-------------------|--------|
| 2-01-01 | 01 | 1 | WIRE-02, WIRE-03, CTRL-04 | unit (reference vector) | `go test -race -run 'TestPRFReferenceVector\|TestPRFOutputLengthNotBlockAligned\|TestKeyMethod2\|TestDeriveKeysEndToEnd' ./internal/keyderiv/` + vet/build/full race | ✅ green |
| 2-01-02 | 01 | 1 | WIRE-03 | unit (mutation check) | `go test -race -run 'TestKeyDirection\|TestServerSlots\|TestSlotSizes\|TestKey2RejectsWrongLength' ./internal/keyderiv/` | ✅ green |
| 2-01-03 | 01 | 1 | CTRL-04 | e2e (Docker, real client) | gentestpki + `go test -tags interop -run TestInteropScenarios` | ✅ green |
| 2-02-01 | 02 | 2 | CTRL-05 | unit + e2e (Docker) | `go test -race -run 'TestPushReply\|TestReadPushRequest' ./` + interop scenarios | ✅ green |
| 2-02-02 | 02 | 2 | SESS-03 | unit | `go test -race -run 'TestPool\|TestPeerIDs\|TestDuplicateCN' ./` | ✅ green |
| 2-02-03 | 02 | 2 | SESS-02 | unit (synthetic client) | `go test -race -run 'TestOnSession\|TestAssignedIP\|TestCloseIsIdempotentAfterTunnelUp' ./` | ✅ green |
| 2-03-01 | 03 | 3 | DATA-01, SESS-02 | unit + e2e (Docker) | `go test -race -run 'TestSeal\|TestOpen\|TestNonce\|TestPacketID\|TestSessionReadWrite' ./internal/datachan/ ./` + interop | ✅ green |
| 2-03-02 | 03 | 3 | DATA-02 | unit (deterministic) | `go test -race -run 'TestReplay\|TestAuthFailureDoesNotTouchWindow\|TestDataChannelWindowIndependent\|TestTamperHasTeeth\|TestConcurrentSeal\|TestPacketIDFailsClosed' ./internal/datachan/` | ✅ green |
| 2-03-03 | 03 | 3 | DATA-03 | unit | `go test -race -run 'TestPing\|TestServerEmitsPing' ./internal/datachan/ ./` | ✅ green |
| 2-04-01 | 04 | 4 | VRFY-03 | e2e (Docker, lossy) | interop scenarios incl. lossy-large ping round-trip assertion | ✅ green |
| 2-04-02 | 04 | 4 | WIRE-03, DATA-01, DATA-02 | unit (golden, real-client bytes) | `go test -race -run TestGolden ./internal/datachan/ ./internal/keyderiv/ ./internal/wire/ ./internal/tlscrypt/` | ✅ green |
| 2-04-03 | 04 | 4 | (prohibitions) | unit (AST gates) | `go test -race -run TestPhase2 ./` via `make gates` | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Manual-Only Verifications

None — every requirement carries an automated command. (Post-review fixes CR-01 and
WR-01..05 each added their own regression tests, all in the fast tier.)

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify — all 12 tasks
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] No watch-mode flags
- [x] Feedback latency < 30s for the fast tier
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-08-25 — fast-tier commands re-run live during this audit
(all green, including golden vectors and the `make gates` prohibition suite); Docker
interop tier independently re-run live by the phase verifier this session (all three
scenarios pass, see 02-VERIFICATION.md).

## Validation Audit 2026-08-25
| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 0 |
| Escalated | 0 |
