---
phase: 1
slug: handshake
status: secured
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-08-24
---

# Phase 1 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Register authored at plan time (all four PLAN.md files carry `<threat_model>` blocks);
> this audit verified each mitigation exists in the implementation at ASVS L1 depth.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Internet → `Server.Serve` ReadFrom loop | Arbitrary attacker-controlled UDP datagrams | Untrusted wire bytes |
| `tlscrypt.Unwrap` → `wire.ParseControlPacket` | Fail-closed authentication gate | Only HMAC-verified bytes |
| Embedder → `ovpn.Config` | Caller-supplied key material and TLS config | tls-crypt key, tls.Config |
| Authenticated control payload → `internal/reliable` | Attacker-chosen packet IDs / ACK arrays | Bounded buffers |
| `internal/ctrlconn` → `crypto/tls` | Reassembled byte stream into TLS state machine | Attacker-influenced bytes |
| `crypto/tls` peer cert → `Session.PeerCN` | Verified identity into embedder callback | CA-verified CommonName |
| Docker Hub / Debian archive → interop image | Third-party layers/packages (test-only) | Pinned by sha256 digest |
| Generated test PKI / golden corpus → repository | Throwaway key material in a public repo | Namespaced, documented |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-01-01 | DoS | Serve read loop triage | high | mitigate | 49-byte min / 2048-byte max / opcode range triage before allocation (ovpn.go:76-137) | closed |
| T-01-02 | Tampering | tlscrypt.Unwrap | critical | mitigate | Constant-time `hmac.Equal` before decrypt (tlscrypt.go:321); TestUnwrapRejectsTamperedPacket | closed |
| T-01-03 | Info Disclosure | wire.ParseControlPacket | high | mitigate | Bounds-checked parse, typed errors, FuzzParseControlPacket (20s run green 2026-08-24) | closed |
| T-01-04 | Tampering | tls-crypt replay window | medium | mitigate | 64-wide sliding window (tlscrypt.go:60-65); TestUnwrapRejectsReplay | closed |
| T-01-05 | Spoofing | session dispatch keying | medium | accept | See Accepted Risks R-01 | closed |
| T-01-06 | Info Disclosure | TLSCryptKey handling | medium | mitigate | Key never logged/errored/persisted; `/test/interop/pki/` gitignored | closed |
| T-01-07 | EoP | interop server container | high | mitigate | uid/gid 65534 (docker-compose.yml:22), runtime `docker inspect` assertion re-run live by verifier | closed |
| T-01-08 | Tampering | Docker base image | high | mitigate | sha256-digest-pinned bookworm-slim (Dockerfile:1), Debian-archive-only packages | closed |
| T-01-09 | Spoofing | test PKI mistaken for prod | medium | mitigate | `govpn-interop-` CN namespace, per-run regeneration, gitignored | closed |
| T-01-10 | Info Disclosure | retained pcap artifacts | low | accept | See Accepted Risks R-02 | closed |
| T-01-11 | Repudiation | vacuous interop pass | high | mitigate | Opcode-4 same-session assertion + per-payload tls-crypt auth + demonstrated tamper failure | closed |
| T-01-12 | Spoofing | client cert verification | critical | mitigate | RequireAndVerifyClientCert + pinned ClientCAs + MinVersion TLS 1.2 (server/main.go:170-171) | closed |
| T-01-13 | DoS | reliability windows | high | mitigate | 12-entry receive window, 2048-byte buffers, sequentiality refusal; deterministic tests | closed |
| T-01-14 | DoS | half-open session state | medium | mitigate | 60s handshake window teardown (ovpn.go handshakeWindow); TestHandshakeWindowTearsDownStalledSession (cf04830) | closed |
| T-01-15 | Tampering | reliability packet-ID replay | medium | mitigate | Window-floor + active-entry rejection; TestRejectsReplayAndOutOfWindow | closed |
| T-01-16 | EoP | OnSession peer identity | high | mitigate | OnSession gated on Handshake()==nil; PeerCN copied from verified chain only | closed |
| T-01-17 | Info Disclosure | buffered post-handshake TLS data | low | accept | See Accepted Risks R-03 | closed |
| T-01-18 | DoS | reliability under loss/reorder | high | mitigate | lossy-large scenario at 5-10% bidirectional loss passes live (re-verified 2026-08-23) | closed |
| T-01-19 | DoS | multi-KB flight vs send window | high | mitigate | Large-cert profile forces ≥2 max-size consecutive fragments; asserted in scenario table | closed |
| T-01-20 | Info Disclosure | committed golden corpus key | medium | mitigate | Throwaway key with provenance README; regeneration only via deliberate `make golden` | closed |
| T-01-21 | EoP | interop privilege asymmetry | high | mitigate | Server-side loss via userspace PacketConn decorator; docker inspect re-asserted in lossy run | closed |
| T-01-22 | Repudiation | silently skipped CI interop job | high | mitigate | Interop job fails (never skips) without Docker; no continue-on-error on test steps (`continue-on-error: true` exists only on the documented non-blocking lint step, ci.yml:51); failure uploads captures | closed |
| T-01-23 | Tampering | golden vector drift | medium | mitigate | README pins digest/version/date; `make golden` is the only regeneration path | closed |
| T-01-SC | Tampering | Go module supply chain | high | mitigate | Zero external packages (`go list -m all` = 1 module, verified 2026-08-24); count gate fails build on any addition | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above workflow.security_block_on count toward threats_open*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-01 | T-01-05 | Source-address spoofing accepted at L1: tls-crypt gates every packet before dispatch, mutual TLS gates establishment. Reference's session-ID HMAC hardening recorded as post-v1 item. | plan 01-01 threat model (plan-time) | 2026-08-23 |
| R-02 | T-01-10 | Retained captures contain only synthetic traffic under a throwaway per-run PKI; needed for debuggability; written to a gitignored directory. | plan 01-02 threat model (plan-time) | 2026-08-23 |
| R-03 | T-01-17 | Client's Key Method 2 payload buffered unread by design in Phase 1 (bounded by the 2048-byte cap); parsed in Phase 2 (CTRL-04). | plan 01-03 threat model (plan-time) | 2026-08-23 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-08-24 | 24 | 24 | 0 | gsd-secure-phase (L1 grep-depth, plan-time register; behavioral evidence from 01-VERIFICATION.md live re-run) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
