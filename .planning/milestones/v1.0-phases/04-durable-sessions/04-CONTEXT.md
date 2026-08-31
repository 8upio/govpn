# Phase 4: Durable Sessions - Context

**Gathered:** 2026-08-28
**Status:** Ready for planning

<domain>
## Phase Boundary

A connected client stays usable for hours and leaves cleanly — key renegotiation does not break traffic, and dead sessions do not accumulate. This phase delivers: TLS soft-reset renegotiation with the reference's lame-duck key transition, explicit-exit-notify handling, silent-session reaping, and soak-run verification of goroutine/memory flatness. Out of scope: TLS session resumption, server-sent exit-notify (unless trivial), configurable reap timeouts beyond the pushed keepalive, NCP.

</domain>

<decisions>
## Implementation Decisions

### Key renegotiation (soft reset)
- Bidirectional: handle client-initiated SOFT_RESET fully AND run the server's own `reneg-sec` timer (both sides run timers, first to fire wins — reference behavior)
- Lame-duck key transition per the C reference: new key negotiated under incremented key-id (mod 8, skipping 0 per ssl.c), old key stays valid for the transition window, decrypt accepts both keys during overlap, transmit switches once the new key is live; embedder's `Session` stays open with zero packet-visible interruption
- `Config.RenegSec time.Duration` (0 = default 3600s) — needed so the harness can shorten it; reneg-sec is NOT a pushed option
- Renegotiation = full new TLS handshake + Key Method 2 over the same control channel under the new key-id — reuses Phase 1 control-channel machinery and Phase 2 key derivation per-key

### Exit notify & timeouts
- Recognize the client's explicit-exit-notify (OCC `remote-exit` per occ.c — verify exact mechanism/bytes against the C reference during research) and tear the session down immediately
- Silent sessions reaped after no authenticated traffic for the pushed `ping-restart` window (60s), injectable clock for tests
- Embedder observability: `Session.Read`/`Write` return `io.EOF` after teardown from any cause; `Close()` idempotency contract holds; no new callback
- Reaping flows through the existing `Session.Close()` → netstack read-loop-error → `Detach` path — no new coupling

### Soak & leak verification
- New interop scenario with reneg interval shortened to ~20s on both sides; assert HTTP + UDP probes succeed before/during/after ≥2 rollovers; client log shows renegotiations and zero reconnects
- Docker-tier soak test (tagged, longer timeout): 20 connect/disconnect cycles with the real client; harness server asserts goroutine count and post-GC HeapAlloc return to baseline within tolerance
- Fast tier: synthetic-client unit tests for soft-reset rollover (clock-injected), exit-notify teardown, reap-on-silence — no Docker

### Claude's Discretion
- Internal structure of the key-slot/rollover state (extending Session.dataWrapper to a per-key-id map or two-slot structure)
- Exact lame-duck window duration (match the reference's transition-window semantics)
- Soak tolerances and cycle pacing

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- Phase 1 control channel (reliable/ctrlconn) already keys wrappers per session; key-id lives in the wire header — SOFT_RESET opcodes exist in internal/wire
- Phase 2 keyderiv (full KM2 exchange), datachan.Wrapper (per-key AEAD + replay window — a new wrapper per key-id fits the per-session precedent)
- Session teardown discipline: stopCh/stopOnce, sess.mu → srv.mu lock order, pool release ordering (WR-04/WR-05 fixes) — reaping and exit-notify MUST flow through Session.Close()
- reliable.Clock injectable-clock pattern; handshakeWindow injectable-duration precedent for RenegSec
- Interop harness scenario table + probe framework (03-06) — the reneg scenario extends it; the tunnelweb example is the traffic source

### Established Patterns
- Two-tier testing; deterministic clock-injected timer tests; golden vectors for wire changes if any
- Every wire/protocol claim verified against /Users/svenloth/dev/openvpn-reference (release/2.6): ssl.c (soft reset, key_state lifecycle, TM_ACTIVE/TM_LAME_DUCK), occ.c (exit notify), ssl_pkt.c (SOFT_RESET_V1 opcode)

### Integration Points
- handleDatagram: control packets with a new key-id must route to the renegotiation state; data packets carry key-id selecting the decrypt wrapper
- runHandshake/performPushExchange precedents for driving a TLS handshake — reneg runs the same machinery without the PUSH exchange
- test/interop scenario table + entrypoint probes

</code_context>

<specifics>
## Specific Ideas

- STATE.md init decision: renegotiation (soft reset) was explicitly pulled INTO v1 — this phase completes the v1 scope
- The exact SOFT_RESET flow and exit-notify bytes must be read from the C source before implementation (same research-gate discipline as Phase 2's Key Method 2)

</specifics>

<deferred>
## Deferred Ideas

- Server-sent explicit-exit-notify on shutdown (unless it falls out trivially)
- OnSessionClosed callback (until an embedder needs it)
- TLS session resumption, NCP/epoch keys

</deferred>
