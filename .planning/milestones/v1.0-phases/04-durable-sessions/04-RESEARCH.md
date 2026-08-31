# Phase 4: Durable Sessions - Research

**Researched:** 2026-08-28
**Domain:** OpenVPN control-channel soft-reset renegotiation, explicit-exit-notify, and idle-session reaping
**Confidence:** HIGH (protocol mechanics read directly from `/Users/svenloth/dev/openvpn-reference`, release/2.6) / MEDIUM (exact reap-timer wiring in `multi.c`, not fully traced due to size)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Key renegotiation (soft reset)**
- Bidirectional: handle client-initiated SOFT_RESET fully AND run the server's own `reneg-sec` timer (both sides run timers, first to fire wins — reference behavior)
- Lame-duck key transition per the C reference: new key negotiated under incremented key-id (mod 8, skipping 0 per ssl.c), old key stays valid for the transition window, decrypt accepts both keys during overlap, transmit switches once the new key is live; embedder's `Session` stays open with zero packet-visible interruption
- `Config.RenegSec time.Duration` (0 = default 3600s) — needed so the harness can shorten it; reneg-sec is NOT a pushed option
- Renegotiation = full new TLS handshake + Key Method 2 over the same control channel under the new key-id — reuses Phase 1 control-channel machinery and Phase 2 key derivation per-key

**Exit notify & timeouts**
- Recognize the client's explicit-exit-notify (OCC `remote-exit` per occ.c — verify exact mechanism/bytes against the C reference during research) and tear the session down immediately
- Silent sessions reaped after no authenticated traffic for the pushed `ping-restart` window (60s), injectable clock for tests
- Embedder observability: `Session.Read`/`Write` return `io.EOF` after teardown from any cause; `Close()` idempotency contract holds; no new callback
- Reaping flows through the existing `Session.Close()` → netstack read-loop-error → `Detach` path — no new coupling

**Soak & leak verification**
- New interop scenario with reneg interval shortened to ~20s on both sides; assert HTTP + UDP probes succeed before/during/after ≥2 rollovers; client log shows renegotiations and zero reconnects
- Docker-tier soak test (tagged, longer timeout): 20 connect/disconnect cycles with the real client; harness server asserts goroutine count and post-GC HeapAlloc return to baseline within tolerance
- Fast tier: synthetic-client unit tests for soft-reset rollover (clock-injected), exit-notify teardown, reap-on-silence — no Docker

### Claude's Discretion
- Internal structure of the key-slot/rollover state (extending Session.dataWrapper to a per-key-id map or two-slot structure)
- Exact lame-duck window duration (match the reference's transition-window semantics)
- Soak tolerances and cycle pacing

### Deferred Ideas (OUT OF SCOPE)
- Server-sent explicit-exit-notify on shutdown (unless it falls out trivially)
- OnSessionClosed callback (until an embedder needs it)
- TLS session resumption, NCP/epoch keys
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SESS-04 | Soft reset / key renegotiation: session survives client-initiated renegotiation (default `reneg-sec 3600`) with key rollover and no traffic interruption | §Architecture Patterns Pattern 1/2, §Code Examples, `ssl.c` citations for `key_state_soft_reset`/`tls_process`/receive-side symmetric reset |
| SESS-05 | Sessions end cleanly: explicit-exit-notify handled, idle sessions reaped, `Session.Close()` tears down without leaks | §Architecture Patterns Pattern 3/4, `occ.c`/`sig.c` citations for exit-notify wire format, `forward.c` ping_rec_timeout citations for reaping |
</phase_requirements>

## Summary

Phase 4 implements three independent but interacting lifecycle mechanisms, all verified directly against `/Users/svenloth/dev/openvpn-reference` (release/2.6):

1. **Soft-reset renegotiation** is NOT a new TLS session — it is a new `key_state` (key-id) grafted onto the *same* `tls_session` (same 8-byte session ID, same tls-crypt wrap context). `ssl.c`'s `key_state_soft_reset()` moves the current primary key into a lame-duck slot (`must_die = now + transition_window`) and reinitializes the primary slot with an incremented `key_id` (mod 8, skipping 0 back to 1). Both client and server run this independently against their own `reneg-sec` deadline (`tls_process` — `ks->established + renegotiate_seconds`), and whichever side's timer fires first sends `P_CONTROL_SOFT_RESET_V1`; the receiving side, on seeing that opcode while its own key is already `S_GENERATED_KEYS`, calls the identical `key_state_soft_reset()` locally — so key-id always advances in lockstep on both ends. This confirms the CONTEXT.md decision precisely: it's a full new TLS handshake + Key Method 2 exchange (NOT the PUSH exchange, which is gated to `key_id == 0` for P2P NCP paths and is otherwise a client-driven one-shot regardless of key-id) over a *new* `ctrlconn.Conn`/`tls.Conn` pair sharing the session's existing `tlscrypt.Wrapper` and session IDs.

2. **Explicit-exit-notify**, under this project's fixed-cipher no-NCP configuration, is the **classic OCC_EXIT message, not a control-channel message**: a 16-byte magic (`occ_magic`) + 1-byte type (`OCC_EXIT = 6`), sent as ordinary encrypted `P_DATA_V2` payload, checked unconditionally on every decrypted data-channel packet before handoff to tun (`forward.c:1204`, `is_occ_msg`). The newer control-channel variant (`send_control_channel_string(c, "EXIT", ...)`) only activates when the server has negotiated `IV_PROTO_CC_EXIT_NOTIFY` via P2P NCP — out of this project's scope (fixed cipher, no NCP) — so it will never fire against this server. Critically, **the client only sends this if its own config sets `explicit-exit-notify <n>`** (default off) — the interop harness's `client.conf` must add this directive or the success criterion is untestable against the real client.

3. **Idle-session reaping** is driven by `ping_rec_timeout` (`--ping-restart`/`--ping-exit`, set via `keepalive <send> <restart>` and pushed): any authenticated inbound packet (control OR data) resets `event_timeout_reset(&c->c2.ping_rec_interval)`; on expiry with no such packet, that instance's context is torn down. This is a per-client timer sitting entirely outside the TLS/key state machine — orthogonal to renegotiation.

**Primary recommendation:** Model the renegotiation state as a **two-slot key-state array per Session** (primary + lame-duck), each slot carrying its own `*ctrlconn.Conn`/`*tls.Conn` (for the control-channel handshake) and its own `*datachan.Wrapper` (for data), with a shared `*tlscrypt.Wrapper` and shared session IDs across both slots — directly mirroring `tls_session.key[KS_PRIMARY]`/`key[KS_LAME_DUCK]`. Route `handleDatagram` control packets by (existing session-id lookup) + received key-id against `session.primary.keyID`; route data packets by trying `primary` decrypt first, falling back to `lameDuck` decrypt until its `must_die` deadline. Drive reap via a per-session last-authenticated-traffic timestamp updated by both the control-packet path and the data-packet decrypt path, checked by a ticking goroutine (mirrors the existing `runKeepalive` pattern already in `session.go`).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Soft-reset trigger (timer) | API / Backend (`ovpn` package) | — | Pure timer logic layered on existing `Session`/`Server` state; no I/O beyond what `ctrlconn.Conn` already provides |
| Soft-reset handshake (new TLS+KM2 under new key-id) | API / Backend (`ovpn` package, reusing `internal/ctrlconn`, `internal/keyderiv`) | — | Identical machinery to the initial handshake (Phase 1/2), parameterized by key-id |
| Lame-duck dual-key decrypt | API / Backend (`internal/datachan`, `ovpn` package) | — | Wire-level AEAD scan-both-keys logic, same tier as existing `Wrapper` |
| Exit-notify detection | API / Backend (`ovpn` package, post-decrypt in `handleDataPacket`) | — | Requires the decrypted plaintext (data-channel authenticated payload) — must live after `Wrapper.Open`, before delivery to `Session.Read` |
| Idle-session reap timer | API / Backend (`ovpn` package, `Session`) | — | Per-session timer state, same tier as existing `runKeepalive` |
| Session teardown propagation | API / Backend → Netstack (`Session.Close()` → netstack `Detach`) | — | Existing established path (Phase 3); this phase only adds new *triggers* into the same `Close()` |

## Standard Stack

### Core
No new external libraries — this phase is pure protocol-state-machine logic on top of existing internal packages. Per CLAUDE.md, stdlib only.

| Component | Version | Purpose | Why Standard |
|-----------|---------|---------|---------------|
| `internal/ctrlconn` | existing | Control-channel `net.Conn` framing, per key-id | Already takes `wrapper *tlscrypt.Wrapper` + injectable `reliable.Clock` as constructor args — designed for exactly this reuse (`internal/ctrlconn/conn.go:101`) |
| `internal/datachan` | existing | AEAD data-channel wrap/unwrap, per key-id | `NewWrapper(keys, peerID, keyID)` already threads `keyID` through — Phase 2 built this parameter for Phase 4 (`internal/datachan/datachan.go:117`) |
| `internal/keyderiv` | existing | Key Method 2 derivation | Re-run per-key with the new TLS handshake's exported material, unchanged API |
| `internal/reliable` (Clock) | existing | Injectable time source for retransmit/timeout tests | `reliable.Clock` interface + `reliable.SystemClock{}` (`internal/reliable/reliable.go:79-89`) — the precedent this phase's `RenegSec`/reap-timer clock injection should follow |
| `internal/wire` | existing | `OpControlSoftResetV1` opcode already parsed (`internal/wire/wire.go:37`); `ParseHeaderByte`/`AppendHeaderByte` already round-trip key-id (`internal/wire/wire.go:104-112`) | No wire-format changes needed — the opcode and key-id field already exist end-to-end |

### Supporting
None — no new packages required.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Two-slot key array (mirrors C reference `KS_PRIMARY`/`KS_LAME_DUCK`) | A generic `map[uint8]*keySlot` keyed by key-id (all 7 possible ids) | The reference itself only ever needs 2 live slots (`KEY_SCAN_SIZE` is 3 only because of an edge case — a detached lame-duck *session*, TM_LAME_DUCK — not extra key-ids within one session). A map adds unbounded-key-id bookkeeping for no behavioral gain; two named fields (`primary`, `lameDuck`) match `[VERIFIED: ssl_common.h:448-451]` `#define KS_PRIMARY 0` / `#define KS_LAME_DUCK 1` / `#define KS_SIZE 2` exactly and are simpler to reason about and test. |
| Detecting OCC_EXIT via byte-prefix check on decrypted plaintext | A dedicated "control-channel exit" listener (CC_EXIT_NOTIFY) | Out of scope: `CO_USE_CC_EXIT_NOTIFY` only activates via P2P NCP peer-info negotiation (`ssl_ncp.c:428-430`), which this project does not implement (no NCP). The real client, absent NCP, always falls back to classic OCC_EXIT on the data channel. |

**Installation:** None — no new dependencies.

**Version verification:** N/A — no new packages.

## Package Legitimacy Audit

Not applicable — this phase introduces no new external packages (stdlib + existing internal packages only, per CLAUDE.md's stdlib-only constraint).

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────────────────────┐
                    │              Server.handleDatagram            │
                    │  (existing demux: control vs P_DATA_V1/V2)    │
                    └───────────────┬───────────────┬───────────────┘
                                    │ control pkt    │ data pkt
                                    ▼                ▼
                    ┌───────────────────────┐  ┌─────────────────────────┐
                    │ session lookup by       │  │ dataSessions[peerID]     │
                    │ (addr, session-id)      │  │ lookup (existing, D-16)  │
                    │ — SAME lookup whether   │  └───────────┬─────────────┘
                    │ this is initial HS or   │              │
                    │ a soft-reset (session-  │              ▼
                    │ id never changes)       │  ┌─────────────────────────┐
                    └───────────┬─────────────┘  │ Try primary.Wrapper.Open │
                                │                 │  on fail → try           │
                                ▼                 │  lameDuck.Wrapper.Open   │
                    ┌───────────────────────┐    │  (only if not expired)   │
                    │ key-id in header       │    └───────────┬─────────────┘
                    │  == primary.keyID?     │                │
                    │   yes → deliver to     │        success │  both fail
                    │   primary.ctrlconn     │                ▼        │
                    │  == SOFT_RESET_V1 &&   │    ┌──────────────────┐  │
                    │   keyID is NEXT id &&  │    │ check occ_magic +  │  │
                    │   primary established? │    │ OCC_EXIT byte      │  │
                    │   yes → START RENEG    │    │ (post-decrypt,      │  │
                    │   (spin up new         │    │ before delivery)    │  │
                    │   ctrlconn+tls.Conn    │    └────────┬───────────┘  │
                    │   under new key-id,    │         match│  no match   │
                    │   move old primary→    │             ▼      ▼      ▼
                    │   lameDuck, set        │      Session.Close()  ipInbound  drop
                    │   must_die deadline)   │      (immediate)      (deliver)  (silent)
                    └───────────┬─────────────┘
                                │ new handshake completes (TLS + KM2, NO push)
                                ▼
                    ┌───────────────────────┐
                    │ atomically swap:        │
                    │  session.dataWrapper    │
                    │  (primary) ← new wrapper│
                    │ transmit switches here; │
                    │ decrypt still tries old │
                    │ (now lameDuck) until    │
                    │ must_die                │
                    └───────────────────────┘

     (Parallel, orthogonal timer)
     ┌───────────────────────────────────────────────────┐
     │ per-Session lastAuthTraffic timestamp, updated by   │
     │  BOTH the control-packet path and the data-decrypt  │
     │  success path (any authenticated arrival resets it) │
     │  → reap goroutine (mirrors runKeepalive) compares    │
     │  against injectable clock; on expiry → Session.Close()│
     └───────────────────────────────────────────────────┘
```

### Recommended Project Structure

No new packages/directories. Extend existing files:
```
ovpn.go          # handleDatagram: route soft-reset by key-id; Config.RenegSec field
session.go       # Session: primary/lameDuck key-state slots, reap timer, exit-notify check
internal/datachan/datachan.go  # (if needed) helper for "try both wrappers" decrypt — likely stays in ovpn.go/session.go, Wrapper itself unchanged
```

### Pattern 1: Soft-reset key-state lifecycle (mirrors `ssl_common.h` KS_PRIMARY/KS_LAME_DUCK)
**What:** A `tls_session` has exactly 2 `key_state` slots. `key_state_soft_reset()` does NOT create a new session — it moves the current primary key_state into the lame-duck slot (preserving its crypto material and session-id-remote/remote-addr) and reinitializes the primary slot in place with an incremented `key_id`.
**When to use:** Every renegotiation, whether client- or server-triggered.
**Reference:**
```c
// Source: ssl.c:1926-1945 (key_state_soft_reset / tls_session_soft_reset)
static void
key_state_soft_reset(struct tls_session *session)
{
    struct key_state *ks = &session->key[KS_PRIMARY];
    struct key_state *ks_lame = &session->key[KS_LAME_DUCK];

    ks->must_die = now + session->opt->transition_window; /* remaining lifetime of old key */
    key_state_free(ks_lame, false);
    *ks_lame = *ks;

    key_state_init(session, ks);
    ks->session_id_remote = ks_lame->session_id_remote;
    ks->remote_addr = ks_lame->remote_addr;
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:1926-1945]`

**Key-id increment rule:**
```c
// Source: ssl.c:990-1002 (key_state_init)
ks->key_id = session->key_id;

/*
 * key_id increments to KEY_ID_MASK then recycles back to 1.
 * This way you know that if key_id is 0, it is the first key.
 */
++session->key_id;
session->key_id &= P_KEY_ID_MASK;
if (!session->key_id)
{
    session->key_id = 1;
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:990-1002]` where `P_KEY_ID_MASK = 0x07` `[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl_pkt.h:38]`. In Go terms: `nextKeyID := (currentKeyID + 1) & 0x07; if nextKeyID == 0 { nextKeyID = 1 }`. **Both sides run this identical formula in lockstep** — whichever side sends `P_CONTROL_SOFT_RESET_V1` next, the sequence 1,2,3,...,7,1,2,... never diverges because the receiver mirrors the sender's `key_state_soft_reset()` call (Pattern 2 below).

### Pattern 2: Symmetric receive-side soft reset + timer trigger (both sides race, first wins)
**What:** `tls_process()` checks its OWN `reneg-sec` deadline every event-loop iteration; independently, `tls_pre_decrypt`'s control-packet-classification path recognizes an *incoming* `P_CONTROL_SOFT_RESET_V1` and mirrors the sender's state transition locally.
**Trigger (either side, timer-based):**
```c
// Source: ssl.c:3098-3114 (tls_process)
if (ks->state >= S_GENERATED_KEYS
    && ((session->opt->renegotiate_seconds
         && now >= ks->established + session->opt->renegotiate_seconds)
        || (session->opt->renegotiate_bytes > 0
            && ks->n_bytes >= session->opt->renegotiate_bytes)
        || (session->opt->renegotiate_packets
            && ks->n_packets >= session->opt->renegotiate_packets)
        || (packet_id_close_to_wrapping(&ks->crypto_options.packet_id.send))))
{
    key_state_soft_reset(session);
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:3098-3114]` — default `renegotiate_seconds = 3600` `[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/options.c:878]`. Note the OR with `packet_id_close_to_wrapping` — the 32-bit data-channel packet-id nearing exhaustion is an independent, mandatory trigger, matching `session.go`'s existing `emitPing` comment ("the next tick tries again ... until Phase 4's renegotiation") `[VERIFIED: /Users/svenloth/dev/govpn/session.go:432-437, exact text: "ErrPacketIDExhausted or similar — nothing more to do; the next\n\t\t// tick tries again (and will fail the same way until Phase 4's\n\t\t// renegotiation, out of this phase's scope)."]`.

**Receive-side mirror (this is what makes both sides' key-id counters agree):**
```c
// Source: ssl.c:3882-3900
/*
 * Remote is requesting a key renegotiation.  We only allow renegotiation
 * when the previous session is fully established to avoid weird corner
 * cases.
 */
if (op == P_CONTROL_SOFT_RESET_V1 && ks->state >= S_GENERATED_KEYS)
{
    if (!read_control_auth(buf, tls_session_get_tls_wrap(session, key_id),
                           from, session->opt))
    {
        goto error;
    }
    key_state_soft_reset(session);
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:3882-3900]`. Immediately after, both sides enforce agreement:
```c
// Source: ssl.c:3983-3990
if (ks->key_id != key_id)
{
    msg(D_TLS_ERRORS,
        "TLS ERROR: local/remote key IDs out of sync (%d/%d) ID: %s",
        ks->key_id, key_id, print_key_id(multi, &gc));
    goto error;
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:3983-3990]` — a key-id mismatch is a hard protocol error, not a soft drop. **Planning implication:** the server's own reneg-sec timer must fire independent of client traffic (a goroutine/ticker per session, not just "check on next packet"), and the receive path must validate that an incoming `SOFT_RESET_V1`'s key-id is exactly the next expected value before accepting it — accepting an arbitrary key-id would desync the two sides' key-id counters.

### Pattern 3: Session ID and tls-crypt wrap context persist across soft reset
**What:** The renegotiated key-state keeps the SAME session-id-remote and remote-addr as the outgoing key, and — because the whole `key_state_soft_reset` operates within a single `tls_session` struct — the same `tls_wrap` (tls-crypt) context and its ongoing packet-id counter/replay-window, for plain tls-crypt (not tls-crypt-v2, which per-key-id-varies via `tls_session_get_tls_wrap` and is out of this project's scope).
```c
// Source: ssl.c:1936-1938
key_state_init(session, ks);
ks->session_id_remote = ks_lame->session_id_remote;
ks->remote_addr = ks_lame->remote_addr;
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:1936-1938]`
**Planning implication:** the Go implementation's renegotiation MUST reuse `sess.wrapper` (the existing `*tlscrypt.Wrapper`, `[VERIFIED: /Users/svenloth/dev/govpn/session.go:61-66, comment: "wrapper is this session's OWN tls-crypt state — an independent\n\t// send-sequence counter and an independent replay window, allocated\n\t// fresh per session"]`) and the existing `SessionID`/`clientSessionID` fields — do NOT allocate a fresh `tlscrypt.Wrapper` per key-id. Allocating a fresh one would reset the tls-crypt packet-id counter, creating a spurious replay-window discontinuity the real client never produces.

### Pattern 4: No PUSH exchange on renegotiation
**What:** `performKeyMethod2Exchange`-equivalent machinery repeats in full on reneg, but `performPushExchange` does not. The PUSH_REQUEST/PUSH_REPLY exchange is a one-shot, client-initiated application-level handshake step that a real client does not repeat on soft reset (it already has its tunnel IP/options); the `key_id == 0` gate in the reference (`ssl.c:2322-2328`) only concerns a P2P-mode NCP corner case, not the general PUSH flow, but corroborates that "first key only" special-casing exists structurally in the reference.
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:2322-2328]`
**Planning implication:** the renegotiation handshake driver should stop after Key Method 2 completes and the new data keys are derived — it must NOT call anything resembling `performPushExchange` a second time, and must NOT re-allocate `assignedIP`/`peerID` (those stay fixed for the session's lifetime).

### Pattern 5: Explicit-exit-notify — data-channel OCC_EXIT (the mechanism this project's client config will trigger)
**What:** A fixed 16-byte magic followed by a 1-byte opcode, sent as an ordinary encrypted data-channel payload (indistinguishable from IP traffic at the wire level until decrypted).
```c
// Source: occ.c:55-58
const uint8_t occ_magic[] = {
    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
    0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c
};
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/occ.c:55-58]`
```c
// Source: occ.h:29-30, 36-37, 67 (OCC_STRING_SIZE, opcodes, OCC_EXIT)
#define OCC_STRING_SIZE 16
#define OCC_REQUEST   0
#define OCC_REPLY     1
#define OCC_EXIT               6
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/occ.h:29-30,36-37,67]`
Receive-side unconditional check on every decrypted data packet (server or client), BEFORE handoff to tun:
```c
// Source: forward.c:1196-1207
if (is_ping_msg(&c->c2.buf))
{
    c->c2.buf.len = 0; /* drop packet */
}
if (is_occ_msg(&c->c2.buf))
{
    process_received_occ_msg(c);
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/forward.c:1196-1207]` where:
```c
// Source: occ.h:83-87
static inline bool
is_occ_msg(const struct buffer *buf)
{
    return buf_string_match_head(buf, occ_magic, OCC_STRING_SIZE);
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/occ.h:83-87]`
The OCC_EXIT case itself, on the RECEIVING side (this matters if this project ever needs to interpret server-side receipt symmetric to what the client does — the client's handling shown here proves the exact byte layout the server must also recognize):
```c
// Source: occ.c:429-432
case OCC_EXIT:
    dmsg(D_STREAM_ERRORS, "OCC exit message received by peer");
    register_signal(c->sig, SIGUSR1, "remote-exit");
    break;
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/occ.c:429-432]`

**Client only sends this if configured — NOT automatic:**
```c
// Source: sig.c:418-423
if (c->options.ce.explicit_exit_notification
    && ...)
{
    process_explicit_exit_notification_init(c);
}
```
```c
// Source: sig.c:352-372 (process_explicit_exit_notification_init)
static void
process_explicit_exit_notification_init(struct context *c)
{
    msg(M_INFO, "SIGTERM received, sending exit notification to peer");
    event_timeout_init(&c->c2.explicit_exit_notification_interval, 1, 0);
    ...
    if (cc_exit_notify_enabled(c))
    {
        send_control_channel_string(c, "EXIT", D_PUSH);
    }
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/sig.c:352-372, 418-423]`. `cc_exit_notify_enabled()` returns false unless `CO_USE_CC_EXIT_NOTIFY` was set, which requires P2P NCP negotiation (`ssl_ncp.c:428-430`) — never true against this project's fixed-cipher server. So in the ELSE branch (classic path), the client repeats sending `OCC_EXIT` on the data channel once per second (`event_timeout_init(..., 1, 0)`) until `explicit_exit_notification` seconds have elapsed, then sends itself `SIGTERM` and exits:
```c
// Source: sig.c:374-392 (process_explicit_exit_notification_timer_wakeup)
if (event_timeout_trigger(&c->c2.explicit_exit_notification_interval, ...))
{
    if (now >= c->c2.explicit_exit_notification_time_wait + c->options.ce.explicit_exit_notification)
    {
        register_signal(c->sig, SIGTERM, "exit-with-notification");
    }
    else if (!cc_exit_notify_enabled(c))
    {
        c->c2.occ_op = OCC_EXIT;
    }
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/sig.c:374-392]`
`explicit_exit_notification` is only non-zero if the client config sets `explicit-exit-notify <n>` `[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/options.c:6980, exact grep match: "streq(p[0], \"explicit-exit-notify\") && p[1] && !p[3]"]` and only applies to UDP (`options.c:3278` warns/ignores for TCP). **Planning implication:** the interop harness's `test/interop/pki/client.conf` (currently: `client / dev tun / proto udp / ... / cipher AES-256-GCM / verb 4` `[VERIFIED: /Users/svenloth/dev/govpn/test/interop/pki/client.conf:1-16]`, no `explicit-exit-notify` directive present) must gain an `explicit-exit-notify 1` line (in a new scenario-specific config or an env-templated addition) or the real-client exit-notify success criterion cannot be exercised end-to-end.

**Server-side detection design:** check every decrypted data-channel plaintext for a 16-byte prefix match against `occ_magic` followed by byte `0x06`, BEFORE delivering to `ipInbound` (i.e., inside `session.go`'s `handleDataPacket`, alongside the existing ping-absorption check). On match: do not deliver, do not treat as an error — call `Session.Close()` immediately (per CONTEXT.md decision).

### Pattern 6: Idle-session reaping via `ping_rec_timeout`, reset by ANY authenticated traffic
**What:** The reference resets its own `ping_rec_interval` timer on receipt of any successfully-decrypted control-channel packet, and (separately) on any data-channel packet:
```c
// Source: forward.c:1093-1103 (control-channel path)
if (tls_pre_decrypt(c->c2.tls_multi, &c->c2.from, &c->c2.buf, &co,
                    floated, &ad_start))
{
    interval_action(&c->c2.tmp_int);
    if (c->options.ping_rec_timeout)
    {
        event_timeout_reset(&c->c2.ping_rec_interval);
    }
}
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/forward.c:1093-1103]`
```c
// Source: forward.c:1184 (data-channel path — timer also reset there)
if (c->options.ping_rec_timeout && c->c2.buf.len > 0)
```
`[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/forward.c:1184]`
`ping_rec_timeout` is set from `keepalive <ping> <restart>` (`helper.c:543,549`) or directly via `--ping-restart n` (`options.c:6966`). Default configured value in this project's own push is 10s ping interval `[VERIFIED: /Users/svenloth/dev/govpn/ovpn.go:121-128, exact text: "pingIntervalSeconds is the fixed v1 keepalive schedule (D-11)"]`; CONTEXT.md's decision specifies a fixed 60s `ping-restart` window (not itself independently re-derived from the C source in this pass — flagged in Open Questions/Assumptions below since the exact reference default for `ping-restart` when only `ping <n>` is pushed without an explicit restart value was not traced to a specific line this session).
**Planning implication:** any successful control-packet delivery to `pump`/`conn.Deliver` AND any successful `dataWrapper.Open` (including both primary and lame-duck key attempts) must update a per-session `lastAuthTraffic` timestamp; a per-session ticking goroutine (same shape as the existing `runKeepalive`) compares `now - lastAuthTraffic` against the (test-injectable) reap window and calls `Session.Close()` on expiry.

### Anti-Patterns to Avoid
- **Allocating a fresh `tlscrypt.Wrapper` per renegotiation:** breaks the tls-crypt packet-id continuum the real client expects within one session (Pattern 3).
- **Re-running `performPushExchange` on renegotiation:** the reference never repeats PUSH on soft reset (Pattern 4); doing so would re-allocate a new tunnel IP/peer-id mid-session, breaking the "zero packet-visible interruption" success criterion.
- **Accepting a `SOFT_RESET_V1` at an arbitrary key-id:** the reference treats a key-id mismatch as a hard error (Pattern 2); the Go implementation must independently compute the expected next key-id and reject anything else, rather than trusting whatever key-id the peer supplies.
- **Checking for OCC_EXIT before decryption (on ciphertext):** the OCC magic is only meaningful post-`Wrapper.Open` — checking raw UDP bytes would never match (data channel is always encrypted first).
- **Treating exit-notify detection failure to match as an error:** absence of the OCC magic on a decrypted packet is the overwhelmingly common case (real IP traffic) — must be a cheap, silent, non-error branch, not a logged anomaly.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Constant-time / structured prefix match for `occ_magic` | A byte-by-byte loop with early-return (timing side-channel-prone, though low-value target here since this isn't a secret comparison) | `bytes.HasPrefix(plaintext, occMagic)` | This is a public 16-byte protocol constant, not a secret — no need for `crypto/subtle`; `bytes.HasPrefix` is the correct stdlib primitive and matches the reference's own non-constant-time `buf_string_match_head`. |
| Injectable time for reap/reneg timers | A bespoke timer abstraction | Reuse `internal/reliable.Clock` interface (`internal/reliable/reliable.go:79-89`) or the existing test-injectable-ticker-channel pattern already used for `startKeepalive`/`runKeepalive` (`session.go:391-421`) | Both precedents already exist in this codebase for exactly this purpose — a third timer abstraction would fragment the pattern for no benefit. |
| Two-key dual-decrypt AEAD scan | A generic priority-ordered cipher-suite negotiator | A simple `try primary, then try lameDuck (if not expired)` sequential `Open` call | The reference itself only ever scans 2-3 slots in a fixed, hardcoded order (`KEY_SCAN_SIZE`); no generality is needed or matches the spec. |

**Key insight:** every mechanism in this phase is a state-machine detail the reference implements in ~10-40 lines of C each — the risk is not complexity, it's silent semantic drift from the reference (e.g. a slightly different key-id formula, or checking OCC magic on ciphertext instead of plaintext) that only surfaces as a mysterious interop failure against the real client.

## Common Pitfalls

### Pitfall 1: Treating renegotiation as "restart the whole session"
**What goes wrong:** Tearing down and rebuilding the `Session`'s `assignedIP`/`peerID`/tunnel state on reneg, or allocating a brand new `tlscrypt.Wrapper` for the new key-id.
**Why it happens:** "New handshake" superficially looks like "new connection," but the reference explicitly keeps the `tls_session` (and everything hanging off it — session IDs, tls-crypt wrap, remote addr) alive across a soft reset; only the `key_state` (TLS BIOs, reliability layer, key material) is fresh.
**How to avoid:** Model exactly two key-state slots inside the existing `Session`, not two `Session`s.
**Warning signs:** A real client's tunnel IP or peer-id changing after a renegotiation in a capture; a fresh tls-crypt replay-window reset visible mid-session.

### Pitfall 2: Missing the "both sides run independent reneg-sec timers" requirement
**What goes wrong:** Only handling client-initiated `SOFT_RESET_V1` (easy, since it arrives as a packet) and skipping the server's OWN timer-driven trigger, since it requires no incoming packet to fire.
**Why it happens:** It's easy to build the receive-path handler first and forget the proactive send-path trigger needs its own goroutine/ticker per session, independent of any inbound traffic.
**How to avoid:** Implement the server-side `reneg-sec` timer as a per-session ticking goroutine (same shape as `runKeepalive`) from day one, gated by `Config.RenegSec` (0 → default 3600s).
**Warning signs:** The interop harness's shortened-reneg scenario (~20s) only shows renegotiations initiated by the client, never by the server, even though both sides configure the same short interval — check whichever side's clock fires marginally first in the harness logs.

### Pitfall 3: Forgetting the interop client config needs `explicit-exit-notify`
**What goes wrong:** Building server-side OCC_EXIT detection correctly, but the success criterion "client sending explicit-exit-notify ends its session immediately" is untestable against the real Docker client because the shipped `client.conf` never sets `explicit-exit-notify`.
**Why it happens:** The mechanism is entirely config-gated on the client side (Pattern 5) — a fresh reader of `occ.c` alone might assume it's unconditional.
**How to avoid:** Add `explicit-exit-notify 1` (and, for the shortened-reneg scenario, `reneg-sec 20`) to a new scenario-specific client config or template variable, verified via `[VERIFIED: /Users/svenloth/dev/govpn/test/interop/pki/client.conf:1-16]` (current file has neither directive).
**Warning signs:** Sending `SIGTERM`/graceful stop to the interop client container and observing the server's session close only after the idle-reap timeout, not immediately.

### Pitfall 4: Key-id validation gap allowing desync
**What goes wrong:** Accepting an incoming `SOFT_RESET_V1` at whatever key-id the packet claims, rather than validating it's exactly the locally-computed next value.
**Why it happens:** The wire already carries key-id in every header byte (`internal/wire`), so it's tempting to just trust it as a routing key without validating the increment rule.
**How to avoid:** Independently compute `nextKeyID := (currentKeyID+1) & 0x07; if nextKeyID == 0 { nextKeyID = 1 }` on the server, and reject (or resync, per the same hard-error posture as the reference, `[VERIFIED: ssl.c:3983-3990]`) any incoming reneg claiming a different value.
**Warning signs:** A test that forges an out-of-sequence key-id succeeding instead of being rejected.

### Pitfall 5: Data-decrypt dual-key scan leaking timing/behavior differences
**What goes wrong:** Trying `lameDuck` before `primary` (reversed priority), or leaving the lame-duck slot live indefinitely (never checking `must_die`), causing decrypt to silently accept traffic on an old key forever.
**Why it happens:** Without an explicit expiry check wired to the injectable clock, "the lame-duck key still works" is easy to leave unbounded during test-driven development.
**How to avoid:** Always try `primary` first (the common case, cheapest), fall back to `lameDuck` only if `primary.Open` fails AND `now < lameDuck.mustDie`; free `lameDuck` once its deadline passes (mirrors `lame_duck_must_die` `[VERIFIED: /Users/svenloth/dev/openvpn-reference/src/openvpn/ssl.c:1297-1322]`).
**Warning signs:** A soak test showing the lame-duck wrapper's replay window never getting garbage collected, or memory/goroutine counts drifting upward after many renegotiation cycles.

## Code Examples

### Key-id increment (Go translation of the verified C rule)
```go
// Source: derived from ssl.c:990-1002, ssl_pkt.h:38 (P_KEY_ID_MASK = 0x07)
const keyIDMask = 0x07

func nextKeyID(current uint8) uint8 {
	next := (current + 1) & keyIDMask
	if next == 0 {
		next = 1
	}
	return next
}
```

### OCC_EXIT detection (Go translation of the verified C constants)
```go
// Source: occ.c:55-58 (occ_magic), occ.h:29-30,67 (OCC_STRING_SIZE, OCC_EXIT)
var occMagic = []byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
}

const occExit = 0x06

func isExitNotify(plaintext []byte) bool {
	return len(plaintext) >= 17 &&
		bytes.Equal(plaintext[:16], occMagic) &&
		plaintext[16] == occExit
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Classic OCC_EXIT (data-channel byte magic) | Control-channel `"EXIT"` string via `CO_USE_CC_EXIT_NOTIFY` when P2P NCP negotiated | Introduced alongside P2P NCP support in later 2.x releases (`ssl_ncp.c`) | Not relevant to this project — the fixed-cipher, no-NCP server this project implements will never trigger the newer path; the real client always falls back to classic OCC_EXIT against it. |

**Deprecated/outdated:** None relevant — this phase deliberately targets the "classic"/pre-NCP mechanism, which is exactly what this project's fixed-cipher server exercises.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | Exact reference default for the effective `ping-restart`/reap window when only a bare `ping N` is pushed (vs. an explicit `keepalive N M` directive) was not traced to a specific `multi.c` line this session — CONTEXT.md's "60s" figure is taken as a given decision, not independently re-derived from source in this pass. | Pattern 6 / §Common Pitfalls | If the real client's actual restart threshold differs from 60s under this project's exact pushed options, the shortened-reneg/soak scenarios' timing assumptions could be off — low risk since CONTEXT.md already locks 60s as the value to implement, and the harness scenario is server-authoritative (the server enforces its own reap timer regardless of what the client believes). |
| A2 | `multi.c`'s exact per-client instance teardown call path on `ping_rec_timeout` expiry (which function closes that one client's context vs. the whole process) was not read directly this session due to file size — inferred from the shared `forward.c` timer-reset code being demonstrably per-context (each `struct context` is one client instance under `multi.c`'s multiplexing model). | Pattern 6 | Low risk: this project's own reap mechanism is being built fresh in Go against `Session.Close()`, not by porting `multi.c`'s C control flow — the only fact borrowed from the reference is "which events reset the timer," which is directly verified (Pattern 6's citations). |

## Open Questions

1. **Exact lame-duck transition-window duration to use**
   - What we know: the reference computes `must_die = now + session->opt->transition_window` (`[VERIFIED: ssl.c:1932]`); CONTEXT.md leaves the exact duration to Claude's discretion ("match the reference's transition-window semantics").
   - What's unclear: this session did not trace `transition_window`'s configured default value (the `--tran-window` option) to its exact default in `options.c`.
   - Recommendation: search `options.c` for `tran_window`/`transition_window` default during planning/implementation and use that reference default (commonly documented as 3600s in OpenVPN's man page, but re-verify against this exact checkout before hardcoding) unless the harness's shortened-reneg scenario needs a shorter test-only value (in which case make it configurable the same way `RenegSec` is).

2. **Whether `handleDatagram`'s existing `sessionKey{addr, sid}` lookup needs any change for reneg-originated control packets**
   - What we know: session ID never changes across a soft reset (Pattern 3), and `handleDatagram` already keys sessions by `(addr, session-id)` `[VERIFIED: /Users/svenloth/dev/govpn/ovpn.go:146-152]`.
   - What's unclear: whether the existing lookup path, once it finds the existing session, has anywhere to route "this is a soft-reset control packet, not ordinary post-handshake traffic" — currently `handleDatagram`'s existing-session branch was not fully traced past line 435 in this pass (time-boxed).
   - Recommendation: during planning, read `ovpn.go:334-449` in full to confirm exactly where a found-existing-session control packet is currently delivered (`sess.conn.Deliver`/`pump`), and design the reneg branch to intercept BEFORE that delivery when the incoming key-id differs from the session's current primary key-id.

## Environment Availability

Skipped — this phase has no new external dependencies beyond what Phases 1-3 already established (Docker + self-built OpenVPN 2.6 client image, already verified available in prior phases).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` (fast tier) + `-tags interop` Docker harness (`test/interop`) |
| Config file | `test/interop/docker-compose.yml` / `docker-compose.lossy.yml`; new scenario needs a new client config or env-templated `client.conf` variant |
| Quick run command | `go test -race ./...` |
| Full suite command | `go test -tags interop ./test/interop/...` (existing `make interop` target) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|--------------|
| SESS-04 | Soft-reset rollover: new key negotiated, old key valid during transition, transmit switches, no data loss | unit (synthetic client, clock-injected) | `go test -race -run TestSoftReset ./...` | ❌ Wave 0 |
| SESS-04 | Real client renegotiates under shortened `reneg-sec`; HTTP+UDP probes succeed across ≥2 rollovers | interop (Docker) | `go test -tags interop -run TestInteropScenarios ./test/interop/...` (new scenario entry) | ❌ Wave 0 — new scenario |
| SESS-05 | Explicit-exit-notify (OCC_EXIT) triggers immediate `Session.Close()` | unit (synthetic client sends forged OCC_EXIT payload) | `go test -race -run TestExitNotify ./...` | ❌ Wave 0 |
| SESS-05 | Silent session reaped after configured idle window (clock-injected) | unit | `go test -race -run TestReap ./...` | ❌ Wave 0 |
| SESS-05 | 20-cycle connect/disconnect soak: goroutine count and post-GC HeapAlloc return to baseline | interop (Docker, tagged, longer timeout) | `go test -tags interop -run TestSoak ./test/interop/...` | ❌ Wave 0 — new soak harness |

### Sampling Rate
- **Per task commit:** `go test -race ./...` (fast tier)
- **Per wave merge:** `go test -race ./... && go test -tags interop ./test/interop/...`
- **Phase gate:** Full suite (fast + interop, including the new reneg scenario and soak test) green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] Fast-tier synthetic-client tests for soft-reset rollover, exit-notify, and reap — none exist yet; follow the existing `ovpn_test.go` synthetic-client patterns (`sess := &Session{srv: srv, ...}` direct construction already used throughout `ovpn_test.go`)
- [ ] New interop scenario entry in `test/interop/interop_test.go`'s `scenarios` slice with a shortened `reneg-sec` client/server config
- [ ] New `client.conf` variant (or env-templated addition) with `explicit-exit-notify 1` and `reneg-sec 20`
- [ ] New Docker-tagged soak test driving 20 connect/disconnect cycles and asserting `runtime.NumGoroutine()`/`runtime.ReadMemStats` (`HeapAlloc`) return to baseline within tolerance

*(No existing test infrastructure covers renegotiation, exit-notify, or reaping — this is greenfield within the phase.)*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|--------------------|
| V2 Authentication | yes (renegotiation re-runs mutual cert auth) | Reuse existing `crypto/tls` `ClientAuth = tls.RequireAndVerifyClientCert` path unchanged — no new auth logic |
| V4 Access Control | yes (key-id validation gates whether a peer can advance session state) | Reject any `SOFT_RESET_V1` whose key-id isn't exactly the locally-computed next value (Pitfall 4) |
| V5 Input Validation | yes (OCC magic match on decrypted plaintext, key-id bounds) | `bytes.Equal`-based fixed-length prefix check; key-id masked to `0x07` range before any array/map indexing |
| V6 Cryptography | yes indirectly (lame-duck key must not outlive its window, or an attacker with a compromised old key gets an extended reuse window) | Enforce `mustDie` expiry strictly via the injectable clock, same as reap timers |

### Known Threat Patterns for this phase's stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|------------------------|
| Reneg-flood DoS: a client (or spoofed source) repeatedly sends forged `SOFT_RESET_V1` packets to force expensive handshake churn | Denial of Service | Rate-limit soft-reset acceptance per session (e.g. minimum interval between accepted renegotiations, reject a burst); the reference's own key-id-match requirement (Pattern 2) already rejects most naively-forged reneg attempts, but a well-formed reneg from the legitimate peer's IP:port at the correct next key-id could still be replayed rapidly if the attacker has captured a valid packet — tls-crypt's own replay window (already implemented, Phase 1) is the primary defense here since a replayed `SOFT_RESET_V1` packet is itself subject to the tls-crypt packet-id replay check before it ever reaches this logic. |
| Lame-duck window abuse: an attacker who compromises an old (about-to-expire) key tries to keep using it past its `mustDie` deadline, or forces repeated renegotiation to keep an old key alive longer than intended | Tampering / Elevation of Privilege | Strict `mustDie` enforcement checked against the injectable clock on every decrypt attempt against the lame-duck slot — never extend `mustDie` on a rejected/late-arriving reneg. |
| Exit-notify spoofing: an on-path or off-path attacker (without tls-crypt keys) tries to inject a forged OCC_EXIT to force premature session teardown | Denial of Service | Not exploitable without the tls-crypt key AND a valid data-channel AEAD key — the OCC magic is checked only AFTER `Wrapper.Open` succeeds (Pattern 5's ordering), meaning exit-notify "arrives on the authenticated data channel" (CONTEXT.md's own framing) — an attacker without both keys cannot produce a payload that decrypts successfully in the first place, let alone one matching the 16-byte magic. This is the same trust boundary already protecting all other data-channel traffic; no new mitigation needed beyond preserving the existing "check magic only post-decrypt" ordering. |

## Sources

### Primary (HIGH confidence)
- `/Users/svenloth/dev/openvpn-reference` (release/2.6 checkout, per STATE.md's own designation as this project's protocol spec), read directly this session:
  - `src/openvpn/ssl_common.h` (KS_PRIMARY/KS_LAME_DUCK/KS_SIZE, TM_ACTIVE/TM_INITIAL/TM_LAME_DUCK/TM_SIZE, KEY_SCAN_SIZE, S_INITIAL..S_ACTIVE state constants)
  - `src/openvpn/ssl.c` (key_state_init, key_state_soft_reset, tls_session_soft_reset, tls_process reneg trigger, receive-side soft-reset mirror, key-id mismatch error, session_move_active, PUSH-adjacent key_id==0 gate)
  - `src/openvpn/ssl_pkt.h` (P_KEY_ID_MASK = 0x07)
  - `src/openvpn/occ.c` / `occ.h` (occ_magic bytes, OCC_STRING_SIZE, OCC_EXIT opcode, is_occ_msg, cc_exit_notify_enabled)
  - `src/openvpn/sig.c` (process_explicit_exit_notification_init/timer_wakeup — proves exit-notify is config-gated and data-channel-based absent NCP)
  - `src/openvpn/forward.c` (is_occ_msg call site post-decrypt, ping_rec_timeout reset on control and data traffic)
  - `src/openvpn/options.c` (renegotiate_seconds default 3600, explicit-exit-notify directive parsing, TCP-ignore warning)
  - `src/openvpn/ssl_ncp.c` (CO_USE_CC_EXIT_NOTIFY only set via P2P NCP peer-info negotiation — confirms out-of-scope for this project)
  - `src/openvpn/multi.c` (CO_USE_CC_EXIT_NOTIFY import on server side, also NCP-gated)
- This project's own existing source, read directly this session: `session.go`, `ovpn.go` (Config, Server, handleDatagram/handleDataDatagram signatures, dataChannelKeyID constant and its Phase-4-forward-reference comment, pingIntervalSeconds), `internal/wire/wire.go` (OpControlSoftResetV1, ParseHeaderByte/AppendHeaderByte key-id round-trip), `internal/datachan/datachan.go` (NewWrapper keyID parameter), `internal/ctrlconn/conn.go` (New signature, injectable Clock), `internal/reliable/reliable.go` (Clock interface), `test/interop/interop_test.go` (scenario table), `test/interop/entrypoint.sh` (probe pattern), `test/interop/pki/client.conf` (current client config, missing reneg/exit-notify directives).

### Secondary (MEDIUM confidence)
- None used — all protocol claims in this document were verified directly against the reference checkout rather than via web search, per this project's own established research discipline (STATE.md: "OpenVPN C reference checkout ... is the protocol spec").

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; all reused internal APIs read directly this session
- Architecture (soft-reset/key-id lifecycle): HIGH — every claim cites a specific line range read this session
- Architecture (exit-notify mechanism): HIGH — full chain from client config gate through wire bytes to receive-side check verified
- Pitfalls: HIGH for reneg/exit-notify (directly sourced); MEDIUM for the exact per-client multi.c teardown call path (A2, not traced due to file size)
- Reap-timer exact default value: MEDIUM (A1) — mechanism verified, exact reference default duration not independently re-derived this session; CONTEXT.md's 60s figure taken as given

**Research date:** 2026-08-28
**Valid until:** Stable — this is a fixed protocol spec (OpenVPN 2.6), not a fast-moving dependency; re-verify only if the reference checkout is updated or if a later phase touches NCP (which would activate the CO_USE_CC_EXIT_NOTIFY path currently ruled out of scope).
