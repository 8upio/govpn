---
phase: 3
slug: in-process-termination
status: secured
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-08-27
---

# Phase 3 — Security

> Per-phase security contract. Register authored at plan time (all six PLAN.md files
> carry `<threat_model>` blocks — 36 unique threats T-03-01..36 plus the per-plan
> supply-chain threat T-03-SC). This audit verified mitigations at ASVS L1 depth;
> behavioral evidence comes from the register-named tests (all green in the fast tier)
> and the phase verifier's independent live interop re-run (03-VERIFICATION.md).

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Authenticated Session → netstack dispatch | Attacker-controlled IP packets from a tunneled client | Raw IPv4 bytes |
| Netstack parsers → TCP/UDP/ICMP handlers | Bounds-checked header fields only | Parsed segments/datagrams |
| netstack TCP conn → stdlib net/http | Reassembled attacker-influenced byte stream | HTTP requests |
| Example site ← user form input | Echo-test reflects client-supplied text | Escaped HTML output |
| Docker network → interop containers | Test-only traffic, unprivileged server | Synthetic tunnel traffic |

---

## Threat Register (condensed — full registers live in the six PLAN.md files)

| Threat ID | Category | Severity | Disposition | Verified Mitigation | Status |
|-----------|----------|----------|-------------|---------------------|--------|
| T-03-01/05/08/12/17/30/36 | Spoofing | high/med | mitigate | Per-session source-IP enforcement (`spoofedSourceDropped` counters in stack.go); routing keyed by assigned IP; peer-id/aead two-factor precedent | closed |
| T-03-02/10/19/23/25/33 | Tampering | high/med | mitigate | Bounds-checked IPv4/ICMP/UDP/TCP parsers with typed errors; RFC 1071 checksums verified; RST in-window check (4a344f7); AST gates cannot silently pass (gate-fails test) | closed |
| T-03-03/06/09/13/14/15/16/18/20/21/22/26/34 | DoS | high/med | mitigate | Receive-window enforcement on ingress (ebe12ba); named caps `defaultBacklog=16`, `maxHalfOpenPerSession=8`, `maxLiveConnsPerSession=64`, `maxPersistProbes=20` (tcp_timer.go:45-76); bounded reorder buffer; fixed-RTO give-up; probe-driven harness survival; http.Server timeouts (a5e1bcf) | closed |
| T-03-04/11/24/27/28/31/35 | Info Disclosure | high/low | mitigate (T-03-11 accept) | Site served only on the netstack listener (negative outside_tunnel probe passes live); html/template auto-escaping on reflected echo input; harness keys gitignored; ICMP responds for server IP only | closed |
| T-03-07/29/32 | EoP | high/med | mitigate | Server container uid 65534, no TUN, no CAP_NET_ADMIN — asserted at runtime via docker inspect in the live suite AND by a static compose gate | closed |
| T-03-SC | Tampering (supply chain) | high | mitigate | Zero external deps (`go list -m all` = 1, verified live); `TestPhase3StdlibOnlyImports` + import-boundary gates standing in `make gates` | closed |

*Status: open · closed. Only open threats at or above `workflow.security_block_on` (high) count toward threats_open.*

Post-review hardening (same audit window, all with regression tests): CR-01 ingress window
enforcement (ebe12ba), CR-02 live-conn cap + persist bound (e8b2f1d), WR-01 listener race
(3c6e599), WR-02 http timeouts (a5e1bcf), WR-03 RST validation (4a344f7), WR-04 oversized-
packet recovery (07f053d). Re-review confirmed all six with every teardown path traced.

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-01 | T-03-11 | Low-severity info disclosure accepted per plan 03-02's register (test-only diagnostic surface; non-secret values). | plan 03-02 threat model (plan-time) | 2026-08-25 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-08-27 | 37 | 37 | 0 | gsd-secure-phase (L1 grep-depth, plan-time register; register-named tests green; live interop + docker inspect evidence via 03-VERIFICATION.md) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
