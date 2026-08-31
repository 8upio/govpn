---
phase: 3
slug: in-process-termination
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: true) (#2117)
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-25
---

# Phase 3 — Validation Strategy

> Per-phase validation contract. Map reconstructed at audit time from the six
> PLAN.md files' `<automated>` verify blocks (17 automated commands across 17 tasks).

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `go test` (stdlib `testing`; deterministic fake-clock timers, fake Session) |
| **Quick run command** | `go test -race ./netstack/` |
| **Full suite command** | `go test -race ./... && make gates && make interop` |
| **Estimated runtime** | fast tier ~25s (netstack ~12s); interop tier ~10-25 min (Docker, 3 scenarios + probes) |

## Per-Task Verification Map

| Task group | Plan | Wave | Requirement | Test Type | Status |
|-----------|------|------|-------------|-----------|--------|
| Stack/IPv4/ICMP/dispatch + gates | 03-01 | 1 | NET-03, NET-04 | unit (fake Session) + e2e (Docker) + AST gates | ✅ green |
| ListenUDP PacketConn | 03-02 | 2 | NET-01, NET-04 | unit (deadlines, routing, checksums) | ✅ green |
| TCP segment/state/reliability/RST | 03-03 | 2 | NET-02 | unit (clock-injected, 44 tests) | ✅ green |
| Deadlines/CloseWrite + http.Serve proof | 03-04 | 3 | NET-02 | unit + integration (stdlib http over netstack) | ✅ green |
| tunnelweb example + site | 03-05 | 4 | XMPL-01 | unit (29 site tests, UI-SPEC contract checks) | ✅ green |
| End-to-end interop probes | 03-06 | 5 | VRFY-02 (+NET-01/02/03, XMPL-01) | e2e (Docker, real client: ICMP/UDP/HTTP/negative) | ✅ green |
| Post-review fixes CR-01/02, WR-01..04 | (review) | — | NET-02 hardening | unit regression (deterministic; WR-01 5000-trial invariant) | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

## Manual-Only Verifications

None — every requirement carries an automated command.

## Validation Sign-Off

- [x] All tasks have `<automated>` verify — 17/17
- [x] No watch-mode flags; no real sleeps in the fast tier (clock-injected timers)
- [x] Feedback latency < 30s for the fast tier
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-08-27 — fast tier re-run live during this audit (netstack,
examples, gates, vet all green); Docker interop tier independently re-run live by the
phase verifier this session (all 3 scenarios, all PROBE lines ok — see 03-VERIFICATION.md).

## Validation Audit 2026-08-27
| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 0 |
| Escalated | 0 |
