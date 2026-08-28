---
phase: 4
slug: durable-sessions
status: secured
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-08-28
---

# Phase 4 — Security

> Register authored at plan time (all four PLAN.md files carry <threat_model> blocks —
> 19 threats T-04-01..19 plus per-plan T-04-SC). Verified at ASVS L1 with register-named
> tests green and live-client behavioral evidence (04-VERIFICATION.md).

## Trust Boundaries
| Boundary | Data Crossing |
|----------|---------------|
| Authenticated control channel → reneg state machine | SOFT_RESET_V1, new TLS handshakes under new key-ids |
| Authenticated data channel → exit-notify/reap logic | OCC_EXIT magic, lastAuthTraffic updates |
| Docker harness → lifecycle scenarios | Test-only reneg/soak traffic |

## Threat Register (condensed — full registers in the four PLAN.md files)
| Threat IDs | Category | Severity | Disposition | Verified Mitigation | Status |
|-----------|----------|----------|-------------|---------------------|--------|
| T-04-01 (reneg flood) | DoS | high | mitigate | renegMinInterval rate limit scaled to active RenegSec; tls-crypt replay window as primary defense | closed |
| T-04-02 (key-id spoofing) | Spoofing | high | mitigate | nextKeyID computed locally, mismatch = hard error (TestForgedKeyIDRenegRejected; ssl.c:3983-3990) | closed |
| T-04-03 (lame-duck abuse) | Tampering | high | mitigate | mustDie transition-window enforcement + expiry sweep closing the demoted Conn | closed |
| T-04-04/05 (Conn leak / wrapper concurrency) | DoS/Tampering | high | mitigate | enforceRenegotiationWindow watchdog (+CR-02/CR-03 race refinements, commits de3a1e2/4f25152/e647f49); shared wrapper mutex-guarded | closed |
| T-04-06/07 (exit-notify & reap spoofing) | Spoofing | high | mitigate | OCC_EXIT honored only post-decrypt; forged packets never touch lastAuthTraffic (TestForgedPacketDoesNotResetReapTimer) | closed |
| T-04-08 (false-positive reap) | DoS | medium | mitigate | 60s reap window vs 10s ping cadence; every authenticated path resets the timer (incl. lame-duck decrypts) | closed |
| T-04-09/15/16 (goroutine/heap leaks) | DoS | high | mitigate | Teardown-through-Close gates; 20-cycle soak with demonstrated-failing flatness tolerances | closed |
| T-04-10 (no audit trail) | Repudiation | low | accept | See R-01 | closed |
| T-04-11/12 (scenario assertion spoofing) | Spoofing | medium | mitigate | Exactly-one-init-sequence assertion; exit-close observed at 0s vs 60s reap window | closed |
| T-04-13/14 (container/PKI hygiene) | EoP/InfoDisc | medium | mitigate | Unprivileged inspect re-run in reneg scenario; PKI/captures gitignored | closed |
| T-04-17 (pool exhaustion) | DoS | high | mitigate | Soak asserts tunnel-IP reuse across cycles | closed |
| T-04-18/19 (vacuous/slow soak) | Tampering/DoS | medium | mitigate | Baseline-after-first-cycle + observed-cycle-count gates; soak excluded from default targets | closed |
| T-04-SC (supply chain) | Tampering | high | mitigate | go.mod unchanged (1 module, verified live); standing no-deps gate | closed |

## Accepted Risks Log
| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-01 | T-04-10 | No audit log for lifecycle events; embedders can wrap OnSession/observe EOF. Revisit with an observability surface post-v1. | plan 04-02 threat model (plan-time) | 2026-08-28 |

## Security Audit Trail
| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-08-28 | 20 | 20 | 0 | gsd-secure-phase (L1, plan-time register; review-fix commits traced; live reneg scenario evidence via 04-VERIFICATION.md) |

## Sign-Off
- [x] All threats have a disposition
- [x] Accepted risks documented
- [x] `threats_open: 0` confirmed
