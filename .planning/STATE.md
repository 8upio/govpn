---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
current_phase: 04
status: completed
stopped_at: context exhaustion at 75% (2026-08-28)
last_updated: "2026-08-28T12:45:53.604Z"
last_activity: 2026-08-28
last_activity_desc: Phase 04 execution started
progress:
  total_phases: 4
  completed_phases: 4
  total_plans: 18
  completed_plans: 18
current_phase_name: Durable Sessions
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-08-22)

**Core value:** A real, unmodified OpenVPN 2.6 client can connect to a Go process embedding this library and exchange traffic through the tunnel — verified against the reference implementation, not approximated from memory.
**Current focus:** Phase 04 — Durable Sessions

## Current Position

Phase: 04
Plan: Not started
Status: All phases complete
Last activity: 2026-09-08 - Completed quick task 260908-fva: IPv4-Fragment-Reassembly (RFC 815) mit Per-Session-Bounds und Outbound-Fragmentierung ab konfigurierbarer MTU im netstack

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**

- Total plans completed: 18
- Average duration: —
- Total execution time: —

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01 | 4 | - | - |
| 02 | 4 | - | - |
| 03 | 6 | - | - |
| 04 | 4 | - | - |

**Recent Trend:**

- Last 5 plans: —
- Trend: —

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Phase 3: netstack declares its own minimal session interface (structural typing) — zero coupling both directions with core ovpn, enforced by AST gates
- Phase 3: TCP DoS bounds are named constants (defaultBacklog=16, maxHalfOpenPerSession=8, maxLiveConnsPerSession=64, maxPersistProbes=20); receive window enforced on ingress
- Phase 3: net/http conformance = real deadlines wrapping os.ErrDeadlineExceeded + CloseWrite; SetKeepAlive not needed
- Phase 2: Data-channel key direction is the mirror-opposite of tlscrypt's slot convention; P_DATA AEAD tag precedes ciphertext on the wire (explicit reorder around Go's Seal/Open)
- Phase 2: handleDatagram branches on opcode class before length triage (data-channel min < 49-byte control min — CR-01); data packets route via peer-id-keyed dataSessions
- Phase 2: Lock nesting order is sess.mu → srv.mu (WR-05 fix); allocate-then-publish in performPushExchange is atomic vs Close
- Phase 1: Per-session tls-crypt Wrapper (mirrors C's per-tls_session tls_wrap_ctx) — a shared wrapper's replay window rejects concurrent clients
- Phase 1: tls-crypt long-form packet-ID timestamp frozen per key (packet_id.c semantics); rollover gate fails closed
- Phase 1: Server.handshakeWindow test-injectable (default 60s reference --hand-window)
- Phase 1: Config.OnSession panics recovered; observable via Config.OnSessionPanic hook
- Init: tls-crypt in v1 (not plain TLS/tls-auth); renegotiation (soft reset) pulled INTO v1 (Phase 4)
- Init: Userspace netstack gets minimal server-side TCP for the tunnel-only example web server
- Init: Docker interop harness with synthetic packet loss is a v1 requirement, built in Phase 1
- Init: OpenVPN C reference checkout at /Users/svenloth/dev/openvpn-reference (release/2.6) is the protocol spec

### Pending Todos

None yet.

### Blockers/Concerns

- (resolved in Phase 2) Key Method 2 byte offsets verified against C source in 02-RESEARCH.md before data-channel code

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260908-fva | IPv4-Fragment-Reassembly (RFC 815) mit Per-Session-Bounds und Outbound-Fragmentierung ab konfigurierbarer MTU im netstack | 2026-09-08 | 78c3157 | [260908-fva-ipv4-fragment-reassembly-rfc-815-mit-per](./quick/260908-fva-ipv4-fragment-reassembly-rfc-815-mit-per/) |

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| *(none)* | | | |

## Session Continuity

Last session: 2026-08-28T12:27:16.588Z
Stopped at: context exhaustion at 75% (2026-08-28)
Resume file: None
