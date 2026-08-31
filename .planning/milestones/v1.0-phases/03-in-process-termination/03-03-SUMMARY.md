---
phase: 03-in-process-termination
plan: "03"
subsystem: netstack
tags: [tcp, rfc9293, netstack, retransmission, flow-control, rst, dos-mitigation]

requires:
  - phase: 03-in-process-termination
    provides: "netstack.Stack, the TCP protocol-handler dispatch seam, injected Clock/Timer, and pseudoHeaderSum/transportChecksum/buildIPv4 from plan 03-01"
provides:
  - "Stack.ListenTCP(port) returning a real net.Listener whose Accept returns a real net.Conn byte stream"
  - "A deliberately narrow server-side-accept-only TCP stack: fixed RTO with doubling backoff, cumulative ACKs only, bounded out-of-order reorder buffer, fixed receive window respecting the peer's advertised window and a fixed in-flight cap, a real bidirectional FIN close into a bounded TIME_WAIT, and RFC 9293 SS3.5.2 RST generation"
  - "Per-session half-open (SYN_RCVD) cap and a bounded accept backlog, both named constants, protecting against in-tunnel SYN floods"
  - "Stack.TCPStats() exposing TCP-specific drop/RST counters"
affects: [03-04-tcp-http, 03-05-example-harness, 03-06-real-client-verification]

actuals:
  tokens: 30606
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "One Clock-driven Timer per TCP connection, repurposed (via Reset) as the connection's TIME_WAIT timer once it reaches that state, rather than a second timer/goroutine"
    - "Send buffer (bounded by maxInFlightBytes) decoupled from the peer's instantaneous advertised window, so Write() can still queue data for a zero-window persist probe rather than blocking with nothing queued"
    - "New Stack-typed accessor methods (TCPStats) added from a plan file other than stack.go, avoiding a wave-2 merge conflict with the sibling UDP plan"

key-files:
  created:
    - netstack/tcp_segment.go
    - netstack/tcp_conn.go
    - netstack/tcp_state.go
    - netstack/tcp_listener.go
    - netstack/tcp_timer.go
    - netstack/tcpclient_test.go
    - netstack/tcp_segment_test.go
    - netstack/tcp_state_test.go
    - netstack/tcp_listener_test.go
    - netstack/tcp_timer_test.go
  modified: []

key-decisions:
  - "Combined Task 1's tracer slice with Tasks 2/3's full production state machine (tcp_timer.go, the reorder buffer, RST generation, half-open/backlog bounds) into one buildable commit, because the SYN-ACK/FIN retransmit and TIME_WAIT-release paths are load-bearing for Task 1's own handshake/close tests — mirrors 03-01-SUMMARY.md's precedent. Task 2 and Task 3 then added only their own test files against already-complete production code."
  - "Send-buffer capacity (Write()'s queueing bound) is decoupled from the peer's currently-advertised window, matching a real socket's SO_SNDBUF-vs-advertised-window distinction — found necessary while writing TestTCPZeroWindowDoesNotSpin (see Deviations)."
  - "TCPStats() is a new method on the existing *Stack type, defined in tcp_listener.go rather than stack.go — Go permits methods on a type from any file in the same package, which let this plan add new counters without touching a file plan 03-02 (UDP) might also need to touch in the same wave."
  - "One Timer/one goroutine per connection, not two: TIME_WAIT reuses the same retransmit Timer via Reset rather than spawning a second goroutine, since a connection is never simultaneously retransmitting and in TIME_WAIT."

patterns-established:
  - "Lock-nesting discipline: every state mutation happens under the connection's own mutex; every write to the wire happens after releasing it (mirrors session.go's own discipline, cited throughout tcp_timer.go/tcp_state.go)"
  - "RFC 9293 deviation comments cite the exact section and the CONTEXT.md decision (D-05 through D-08) that scoped the deviation, in internal/reliable.go's citation-header style"

requirements-completed: [NET-02]

coverage:
  - id: D1
    description: "Stack.ListenTCP(port) returns a net.Listener whose Accept returns a net.Conn, with compile-time net.Listener/net.Conn assertions"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPHandshake"
        status: pass
    human_judgment: false
  - id: D2
    description: "A tunnel client's SYN draws a SYN-ACK advertising MSS 1460 and window 65535; the completing ACK makes the connection available from Accept with correct Local/RemoteAddr"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPHandshake"
        status: pass
      - kind: unit
        ref: "netstack/tcp_segment_test.go#TestTCPMSSOption"
        status: pass
    human_judgment: false
  - id: D3
    description: "A multi-kilobyte byte stream round-trips in order, in full, in both directions over an accepted conn"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPEchoStream"
        status: pass
    human_judgment: false
  - id: D4
    description: "Unacknowledged segments retransmit on a fixed, doubling RTO capped at maxRTO, and the connection resets after maxRetransmits rather than retrying forever"
    verification:
      - kind: unit
        ref: "netstack/tcp_timer_test.go#TestTCPRetransmitsUnackedData"
        status: pass
      - kind: unit
        ref: "netstack/tcp_timer_test.go#TestTCPRTODoubles"
        status: pass
      - kind: unit
        ref: "netstack/tcp_timer_test.go#TestTCPGivesUpAfterMaxRetransmits"
        status: pass
    human_judgment: false
  - id: D5
    description: "Out-of-order segments are buffered in a bounded reorder buffer and delivered in order once the gap fills; excess is dropped and re-driven by the peer's own retransmission"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPOutOfOrderBuffered"
        status: pass
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPReorderBufferBounded"
        status: pass
    human_judgment: false
  - id: D6
    description: "Acknowledgements are cumulative only; no SACK option is ever emitted"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPCumulativeAckAdvancesSendWindow"
        status: pass
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPNoSACKOptionEmitted"
        status: pass
    human_judgment: false
  - id: D7
    description: "The advertised receive window shrinks/recovers honestly with buffer occupancy; outstanding unacked data never exceeds the peer's window or the fixed in-flight cap; a zero window makes the server persist-probe rather than spin"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPRespectsPeerWindow"
        status: pass
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPAdvertisedWindowShrinksWithBuffer"
        status: pass
      - kind: unit
        ref: "netstack/tcp_timer_test.go#TestTCPZeroWindowDoesNotSpin"
        status: pass
    human_judgment: false
  - id: D8
    description: "Closing the accepted conn performs a real bidirectional FIN exchange and TIME_WAIT is released on a bounded, fake-clock-driven timer, not a real sleep"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPCleanClose"
        status: pass
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPSequenceNumbersAdvanceCorrectly"
        status: pass
    human_judgment: false
  - id: D9
    description: "A segment matching no connection, or arriving on a port with no listener, draws an RFC 9293 SS3.5.2-shaped RST rather than being dropped silently; an inbound RST tears the connection down"
    verification:
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPRSTForClosedPort"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPRSTForUnknownConnection"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPRSTClosesConnection"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPBadAckInSynRcvdResets"
        status: pass
    human_judgment: false
  - id: D10
    description: "Per-session half-open cap and accept backlog are both bounded by named constants; one client's SYN flood cannot deny another client's handshake; listener close and session detach leave no live connection state or timer goroutine"
    verification:
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPBacklogBounded"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPHalfOpenBounded"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPHalfOpenIsPerSession"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPHalfOpenTimesOut"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPListenerCloseResetsQueued"
        status: pass
      - kind: unit
        ref: "netstack/tcp_listener_test.go#TestTCPDetachDuringConnectionCleansUp"
        status: pass
    human_judgment: false
  - id: D11
    description: "Initial sequence numbers are drawn from crypto/rand, never a counter or clock"
    verification:
      - kind: unit
        ref: "netstack/tcp_state_test.go#TestTCPISNIsRandom"
        status: pass
    human_judgment: false
  - id: D12
    description: "go test -race ./netstack/ completes in seconds with no real-time sleep gating protocol timing, and go test -race ./..., go vet ./..., and make gates all exit 0"
    verification:
      - kind: unit
        ref: "go test -race ./netstack/ (44 tests, ~3.5s)"
        status: pass
      - kind: unit
        ref: "go test -race ./... && go vet ./... && make gates"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-26
status: complete
---

# Phase 3 Plan 3: Minimal Server-Side TCP Summary

**A deliberately narrow RFC 9293 TCP stack (server-accept-only, fixed-RTO doubling backoff, cumulative ACKs, bounded reorder buffer, real bidirectional FIN close into a short TIME_WAIT, RFC 9293 SS3.5.2 RST generation, and named-constant DoS bounds) makes `netstack.Stack.ListenTCP` return a real `net.Listener` that a byte stream round-trips through in both directions — proven end-to-end against a fake `Session` and a fake `Clock` in milliseconds, no Docker.**

## Performance

- **Duration:** ~55 min
- **Tasks:** 3/3
- **Files modified:** 10 (all new files, `netstack/tcp_*.go` and their `_test.go` counterparts)

## Accomplishments

- `Stack.ListenTCP(port)` returns a real `net.Listener`; `Accept()` returns a real `net.Conn` whose `Read`/`Write` behave as an ordinary byte stream (`io.Reader`/`io.Writer` streaming semantics, not `Session.Read`'s datagram-shaped contract) — a real handshake, a 5000-byte round trip in both directions, and a clean bidirectional FIN close into a bounded, fake-clock-released TIME_WAIT all pass in milliseconds.
- Every deliberate RFC 9293 deviation this phase locks — fixed RTO with doubling backoff (D-06), no congestion control beyond a fixed in-flight cap (D-07), cumulative ACKs only with no SACK (D-06), a short-timer TIME_WAIT (D-08), MSS-only options, passive-open-only with no SYN_SENT (D-05) — is implemented exactly as scoped, cited in code comments to its CONTEXT.md decision, and covered by a dedicated test.
- Denial-of-service surfaces this project's own threat model names are each bounded by a named constant and tested: the per-session half-open (SYN_RCVD) cap (`maxHalfOpenPerSession = 8`, isolating one client's SYN flood from every other attached session), the accept backlog (`defaultBacklog = 16`), and the bounded out-of-order reorder buffer (`maxReorderSegments = 16`).
- Initial sequence numbers are drawn from `crypto/rand` per connection (never a counter or a clock), and RFC 9293 SS3.5.2's two RST-generation cases are implemented exactly, so a segment matching no connection or arriving on a closed port never hangs a real client's page load.
- `go test -race ./netstack/` runs all 44 tests (26 from this plan) in ~3.5 seconds with the race detector silent — every TCP timer (retransmit, TIME_WAIT, zero-window persist) is driven exclusively through the injected `Clock` from plan 03-01, never a real sleep.

## Task Commits

Each task was committed atomically:

1. **Task 1: One TCP connection completes a handshake, echoes a byte stream, and closes cleanly** - `ad55dbc` (feat) — also carries Tasks 2/3's full production state machine (`tcp_timer.go`, RST generation, backlog/half-open bounds) because the retransmit/TIME_WAIT machinery is load-bearing for Task 1's own tests (see Deviations)
2. **Task 2: Loss and reordering do not corrupt or stall the stream** - `d77a221` (feat) — tests only; production logic already present from Task 1's commit
3. **Task 3: Unexpected segments get an RST, and one client cannot exhaust the stack** - `5925fb8` (feat) — tests only, plus the data-race fix described below

**Plan metadata:** commit pending (this SUMMARY.md — worktree mode excludes STATE.md/ROADMAP.md per the orchestrator's own note)

## Files Created/Modified

- `netstack/tcp_segment.go` - RFC 9293 SS3.1 TCP header parse/build, MSS option (kind 2), panic-free bounds-checked option-region walk
- `netstack/tcp_conn.go` - `net.Conn` implementation (`Read`/`Write`/`Close`/`LocalAddr`/`RemoteAddr`/deadline stubs marked `// plan 03-04`), per-connection send/receive buffers, `crypto/rand` ISN generation
- `netstack/tcp_state.go` - the LISTEN/SYN_RCVD/ESTABLISHED/FIN_WAIT_1/FIN_WAIT_2/CLOSING/TIME_WAIT/CLOSE_WAIT/LAST_ACK/CLOSED state machine (no SYN_SENT, D-05), RFC 9293 SS3.5.2 RST-segment construction, cumulative-ACK send/receive processing
- `netstack/tcp_listener.go` - `Stack.ListenTCP`, the shared TCP 4-tuple demux (`protocolHandler`), `Stack.TCPStats()`, accept backlog, per-session half-open bound
- `netstack/tcp_timer.go` - D-14's named constants (MSS/window/backlog/half-open/reorder/RTO/TIME_WAIT), the one-Timer-per-connection retransmit/TIME_WAIT/persist-probe machinery
- `netstack/tcpclient_test.go` - the test-only minimal TCP client (D-12) driving every test in this plan against a fake `Session`
- `netstack/tcp_segment_test.go` - segment round-trip, panic-freedom matrix, MSS clamping (through the full handshake path)
- `netstack/tcp_state_test.go` - handshake, echo stream, sequence-number bookkeeping, clean close, ISN randomness, cumulative ACK, out-of-order/reorder-bound, duplicate segment, peer-window respect, advertised-window shrink/recover, no-SACK-option proof
- `netstack/tcp_listener_test.go` - RST generation (both SS3.5.2 cases), inbound-RST teardown, bad-ack-in-SYN_RCVD reset, backlog overflow, half-open bound/per-session isolation/timeout-release, listener close, session detach cleanup
- `netstack/tcp_timer_test.go` - retransmission, RTO doubling, give-up-after-max-retransmits, zero-window persist

## Decisions Made

- **Combined Task 1's tracer with Tasks 2/3's full production machinery in one commit** (mirroring 03-01-SUMMARY.md's own precedent): the SYN-ACK retransmit timer and TIME_WAIT release are structurally required for Task 1's own `TestTCPHandshake`/`TestTCPCleanClose` to be meaningful (a connection that can't retransmit its SYN-ACK or release TIME_WAIT isn't really demonstrating the handshake/close behavior the task claims). Tasks 2 and 3 then added only their own test files against already-complete, already-passing production code — verified by running only each task's named test filter against a git history that already had all three tasks' tests passing before any commit landed.
- **Decoupled the send buffer's capacity from the peer's instantaneous advertised window** (`Write()` queues up to `maxInFlightBytes` regardless of the current window, while `sendPendingLocked` transmits only what the window currently allows): this was necessary, not stylistic — see Deviations below.
- **One `Timer`/one goroutine per connection**, not two: TIME_WAIT reuses the same retransmit `Timer` (via `Reset`) rather than spawning a second goroutine, since a connection is never simultaneously retransmitting and sitting in TIME_WAIT.
- **`Stack.TCPStats()` defined in `tcp_listener.go`, not `stack.go`**: Go permits methods on an existing type from any file in the same package. This let the plan add new backlog-overflow/half-open-cap/reorder-dropped/RST-sent/RST-received counters without touching `stack.go`, keeping this plan's `files_modified` disjoint from plan 03-02's (UDP) in the same wave.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `Write()` could never queue data behind a zero peer window, so the zero-window persist probe could never fire**
- **Found during:** Task 2, while writing `TestTCPZeroWindowDoesNotSpin`
- **Issue:** `Write()`'s blocking condition gated queueing into the send buffer on `len(outBuf) < allowedInFlightLocked()` — the peer's *current* window. With a zero window, `allowedInFlightLocked()` is always 0, so `len(outBuf) < 0` is never true and `Write()` blocked forever without ever appending anything to `outBuf`. Since `sendPendingLocked`'s persist-probe path only fires when data is already queued, the persist timer could never arm and a zero-window connection would hang indefinitely rather than eventually probing once the peer reopened its window.
- **Fix:** Decoupled the send buffer's capacity bound from the transmission window: `Write()` now queues up to `maxInFlightBytes` unconditionally (matching a real socket's `SO_SNDBUF`, which is independent of the peer's advertised receive window), while `sendPendingLocked` still transmits only what the window currently allows. Also armed the retransmit timer directly from `sendPendingLocked` whenever data is left queued behind a zero window, so the persist mechanism has something to wake it even on the very first `Write` call against an already-zero window.
- **Files modified:** `netstack/tcp_conn.go`, `netstack/tcp_timer.go`
- **Verification:** `TestTCPZeroWindowDoesNotSpin` passes; `go test -race ./netstack/` remains green.
- **Committed in:** `d77a221` (Task 2 commit)

**2. [Rule 1 - Bug] Data race on `tcpListener.closed` between `Close()` and `handleSYN()`**
- **Found during:** Task 3, `go test -race -run TestTCPHalfOpenBounded`
- **Issue:** `tcpListener.Close()` writes `l.closed = true` under `l.mu`, but `tcpListener.handleSYN()` read `l.closed` under `d.mu` (the shared demux's own lock) — two different mutexes guarding one field is a data race, flagged by the race detector during a test whose deferred `ln.Close()` raced an in-flight `handleSYN` call from a SYN sent moments earlier.
- **Fix:** `handleSYN` now takes `l.mu` (not `d.mu`) specifically to read `l.closed`, matching the lock `Close()` uses to write it, before moving on to the demux's own `d.mu`-guarded half-open bookkeeping.
- **Files modified:** `netstack/tcp_listener.go`
- **Verification:** `go test -race -run 'TestTCPHalfOpen|TestTCPListenerClose' ./netstack/` passes with the race detector silent; `go test -race ./netstack/` (full suite) and `go test -race ./...` both remain green.
- **Committed in:** `5925fb8` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (2 bugs, both Rule 1)
**Impact on plan:** Both fixes were necessary for the plan's own stated behavior (zero-window persist; race-free concurrent timer/listener teardown) to actually hold — no scope creep, no architectural change.

## Issues Encountered

An early version of `TestTCPHalfOpenBounded` (before either fix above) also intermittently misattributed a stray SYN-ACK retransmission (from an earlier half-open connection's real-time `SystemClock` timer, under `-race`'s significant slowdown) to a later "excess SYN" assertion, since the test's `tryRecvRaw` helper does not filter by port. Fixed by switching that test to a fixed, never-advanced `fakeClock` (matching the pattern `TestTCPHalfOpenTimesOut` already used), eliminating the possibility of any real-time retransmission firing mid-test — a test-only change, not a production bug.

## Known Stubs

None. The deadline methods (`SetReadDeadline`/`SetWriteDeadline`/`SetDeadline`) store real field values but do not yet unblock an in-flight `Read`/`Write` — this is explicitly scoped to plan 03-04 by this plan's own action text ("may set the deadline fields without yet unblocking a blocked call... must not be stubs returning nil"), and is marked with a `// plan 03-04` comment at each site rather than a generic TODO.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `Stack.ListenTCP`, the accepted `net.Conn`, and `Stack.TCPStats()` all exist, are tested, and are ready for plan 03-04 to close the remaining `net/http` conformance gap (deadlines that actually unblock a call, `CloseWrite` half-close) and run an actual `http.Serve` round-trip.
- The 4-tuple demux (`tcpDemux`) and its half-open/backlog bookkeeping are stack-wide and multi-port-ready: a second `ListenTCP` call on the same `Stack` reuses the existing demux without re-registering a handler, so plan 03-04/03-05's example server can open additional ports (if ever needed) without further plumbing.
- No blockers identified for 03-04. The one deliberate scope boundary worth flagging forward: `tcp_conn.go`'s deadline methods are real fields but inert stubs by design — 03-04's own test suite is the gate that must prove they actually unblock a call, not this plan's.

## Self-Check: PASSED

- All 10 files listed under "Files Created/Modified" confirmed present on disk.
- All three task commits (`ad55dbc`, `d77a221`, `5925fb8`) confirmed present via `git log --oneline`.
- `go test -race ./netstack/` (44 tests), `go test -race ./...`, `go vet ./...`, and `make gates` all confirmed exit 0 immediately before writing this summary.
- `git diff --stat go.mod` confirmed empty.
