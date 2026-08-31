---
phase: 4
slug: durable-sessions
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: true) (#2117)
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-28
---

# Phase 4 — Validation Strategy

> Map reconstructed at audit time from the four PLAN.md files' automated verify blocks (12 tasks).

## Test Infrastructure
| Property | Value |
|----------|-------|
| **Framework** | `go test` (stdlib; clock-injected timers, synthetic client, AST gates) |
| **Full suite** | `go test -race ./... && make gates && make interop` (4 scenarios incl. reneg) + `make soak` (separate target) |

## Per-Task Verification Map
| Task group | Plan | Requirement | Test Type | Status |
|-----------|------|-------------|-----------|--------|
| Soft-reset reneg (client+server initiated, hardening) | 04-01 | SESS-04 | unit (synthetic client, clock-injected) + gates | ✅ green |
| Exit-notify + idle reap + EOF-everywhere | 04-02 | SESS-05 | unit (lifecycle_test.go, clock-injected) + gates | ✅ green |
| Real-client reneg + exit-notify scenarios | 04-03 | SESS-04, SESS-05 | e2e (Docker `reneg` scenario) | ✅ green |
| 20-cycle soak, flatness assertions | 04-04 | SESS-05 | e2e (Docker `make soak`, demonstrated-failing tolerances) | ✅ green |
| Review-fix regressions (CR-01..03, WR-01..03) | (review) | SESS-04/05 hardening | unit (deterministic race reproductions) | ✅ green |

## Manual-Only Verifications
None — every requirement carries an automated command.

## Validation Sign-Off
- [x] All tasks have automated verify — 12/12 (+6 review-fix regressions)
- [x] No watch-mode flags; fast tier fully clock-injected
- [x] `nyquist_compliant: true`

**Approval:** validated 2026-08-28 — fast tier re-run live during phase verification (all green);
reneg scenario independently re-run live by the verifier; soak evidence per 04-04-SUMMARY.md
(tolerances demonstrated failing on injected leaks). See 04-VERIFICATION.md.

## Validation Audit 2026-08-28
| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 0 |
| Escalated | 0 |
