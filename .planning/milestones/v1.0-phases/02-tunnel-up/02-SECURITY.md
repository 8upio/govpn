---
phase: 2
slug: tunnel-up
status: secured
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-08-25
---

# Phase 2 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Register authored at plan time (all four PLAN.md files carry `<threat_model>` blocks);
> this audit verified each mitigation exists in the implementation at ASVS L1 depth,
> with every register-named test re-run green during the audit.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| TLS stream → `keyderiv.ReadClientKeyMethod2` | Attacker-shaped (but TLS-authenticated) KM2 TLV fields | Length-prefixed strings, random material |
| Derived key material → `Session.dataKeys` / `datachan.Wrapper` | Master secret and 256-byte expansion | Secret key bytes (zeroed intermediates) |
| Internet → `handleDatagram` P_DATA path | Unauthenticated data-channel datagrams keyed by peer-id | Sealed AEAD packets |
| `datachan.Open` → `Session.ipInbound` → embedder `Read` | Only authenticated, replay-checked, non-ping plaintext | Raw IP packets |
| Server config → `buildPushReply` | Server-side values only; no client bytes interpolated | PUSH_REPLY option string |
| Committed golden corpus → public repository | Throwaway-PKI keys and real-client session bytes | Test fixtures with provenance |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-02-01 | Tampering | keyderiv.ReadClientKeyMethod2 | high | mitigate | io.ReadFull on every field (8 sites), 512-byte prefix caps, typed errors; TestKeyMethod2ReadRejectsTruncated | closed |
| T-02-02 | DoS | KM2 read in runHandshake | medium | mitigate | Runs inside the existing 60s handshake window teardown | closed |
| T-02-03 | Info Disclosure | master secret / key expansion | high | mitigate | Unexported fields; `defer zero(master)` (keyexpansion.go:131); harness prints booleans/lengths only | closed |
| T-02-04 | Spoofing | key-direction assignment | high | mitigate | Standalone keyDirection fn + mutation check + live-client gate + TestGoldenKeyDirectionWouldCatchAnInversion | closed |
| T-02-05 | Repudiation | key-exchange failure paths | low | accept | See Accepted Risks R-01 | closed |
| T-02-06 | Spoofing | PUSH_REQUEST handling | medium | mitigate | Honored only post-cert-verify, once per session (repeat resends same values); TestOnSessionFiresExactlyOnce | closed |
| T-02-07 | EoP | buildPushReply assembly | high | mitigate | Options assembled from server-side values only; no client bytes interpolated | closed |
| T-02-08 | DoS | ipPool exhaustion | high | mitigate | Non-blocking ErrPoolExhausted, release in Close's stopOnce; TestPoolExhaustionReturnsTypedError | closed |
| T-02-09 | Tampering | unbounded control-string read | high | mitigate | maxControlStringLen=1024 (push.go:37); TestReadPushRequestRejectsUnterminatedFlood | closed |
| T-02-10 | DoS | pool double-allocation race | high | mitigate | Single mutex-guarded pool; TestPoolConcurrentAllocationNeverDuplicates (200 goroutines, -race) | closed |
| T-02-11 | Info Disclosure | harness diagnostic output | low | accept | See Accepted Risks R-02 | closed |
| T-02-12 | Spoofing | peer-id routing table | high | mitigate | Peer-id selects candidate only; trust requires that session's aead.Open success (ssl.c:3605 two-factor pattern) | closed |
| T-02-13 | Tampering | Open tag/ciphertext reorder | high | mitigate | Tag from wire bytes 8..23 re-appended pre-Open; ErrAuth on tamper; TestOpenRejectsTamperedTag, TestTamperHasTeeth | closed |
| T-02-14 | Info Disclosure | GCM nonce reuse | high | mitigate | packetID‖implicitIV nonce, mutex-guarded monotonic counter, ErrPacketIDExhausted fail-closed at 0xFFFFFFFF (datachan.go:75-83); TestConcurrentSealNeverDuplicatesPacketID | closed |
| T-02-15 | Tampering | window mutation by unauthenticated packets | high | mitigate | aead.Open success strictly gates replay.accept; TestAuthFailureDoesNotTouchWindow | closed |
| T-02-16 | Tampering | data-packet replay | high | mitigate | 64-wide per-session per-direction window, independent instance; TestReplay* + TestDataChannelWindowIndependentOfTLSCrypt | closed |
| T-02-17 | DoS | unknown-peer-id flood | high | mitigate | Cheap ordered rejection (length/opcode → map miss → Open) with zero persistent state on failure | closed |
| T-02-18 | DoS | slow embedder blocking read loop | medium | mitigate | ipInbound bounded at 32, non-blocking drop-newest overflow | closed |
| T-02-19 | Info Disclosure | ping magic surfacing to embedder | low | mitigate | Absorbed in datachan pre-queue; TestPingNeverReachesSessionRead | closed |
| T-02-20 | Info Disclosure | committed golden keys | high | mitigate | Throwaway per-run PKI only; provenance README; TestPhase2GoldenCorpusIsTestOnly | closed |
| T-02-21 | Info Disclosure | harness key handoff file | medium | mitigate | Written only to gitignored harness output dir, single throwaway scenario | closed |
| T-02-22 | Tampering | silently-passing golden assertions | high | mitigate | TestGoldenDataChannelTamperHasTeeth + key-direction-inversion catch on real-client bytes | closed |
| T-02-23 | Tampering | forbidden-construction reintroduction | high | mitigate | AST-based prohibition gates in make test/gates + named CI step | closed |
| T-02-24 | DoS | flaky lossy CI assertions | medium | accept | See Accepted Risks R-03 | closed |
| T-02-25 | Repudiation | corpus regenerated without provenance | medium | mitigate | Regeneration only via explicit -update-golden/make golden; clean git status asserted post fast-tier | closed |
| T-02-SC | Tampering | Go module supply chain | high | mitigate | Zero require/replace directives (verified live); TestPhase2NoThirdPartyDependencies standing gate | closed |

*Status: open · closed · open — below high threshold (non-blocking)*

Post-review hardening (same audit window, all closed with regression tests): CR-01 ping-drop triage fix (cf88d33), WR-01 netmask normalization (de73298), WR-02 Open dst-buffer discipline (6bf164f), WR-03 Session field race (31f27c0), WR-04 Close release ordering (26fbc5a), WR-05 zombie-session/pool-leak window (812c2c8, lock-nesting argument verified by two independent reviewer passes).

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-01 | T-02-05 | No audit log for failed key exchanges; embedders can wrap OnSession/OnSessionPanic. Revisit if v1 grows an observability surface. | plan 02-01 threat model (plan-time) | 2026-08-24 |
| R-02 | T-02-11 | Interop PASS line prints assigned tunnel IP + peer-id — non-secret throwaway test values needed for harness debugging. | plan 02-02 threat model (plan-time) | 2026-08-24 |
| R-03 | T-02-24 | Lossy-scenario ping assertion deliberately tolerant (≥1 reply) because tc netem has no seedable PRNG; strict assertion still runs on both clean scenarios. | plan 02-04 threat model (plan-time) | 2026-08-24 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-08-25 | 26 | 26 | 0 | gsd-secure-phase (L1 grep-depth, plan-time register; register-named tests re-run green during audit; behavioral evidence from 02-VERIFICATION.md independent live interop run) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
