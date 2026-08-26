---
phase: 03-in-process-termination
reviewed: 2026-08-27T00:00:00Z
depth: standard
files_reviewed: 14
files_reviewed_list:
  - netstack/tcp_conn.go
  - netstack/tcp_state.go
  - netstack/tcp_listener.go
  - netstack/tcp_timer.go
  - netstack/stack.go
  - netstack/tcp_conn_test.go
  - netstack/tcp_state_test.go
  - netstack/tcp_listener_test.go
  - netstack/tcp_timer_test.go
  - netstack/stack_test.go
  - examples/tunnelweb/main.go
  - examples/tunnelweb/main_test.go
  - test/interop/server/main.go
  - test/interop/server/main_test.go
findings:
  critical: 0
  warning: 0
  info: 2
  total: 2
status: clean
---

# Phase 03: Code Review Report

**Reviewed:** 2026-08-27T00:00:00Z
**Depth:** standard
**Files Reviewed:** 14
**Status:** clean

## Summary

Iteration-2 re-review of the six fix commits (`ebe12ba`, `e8b2f1d`, `3c6e599`,
`a5e1bcf`, `4a344f7`, `07f053d`) addressing the prior review's CR-01, CR-02,
WR-01, WR-02, WR-03, and WR-04. `go build ./...` succeeds and
`go test -race -count=1 ./...` passes, including the full `./netstack/...`
suite (13.4s) with no data races.

Each fix was traced against RFC 9293 semantics and re-verified by hand,
independent of the accompanying tests, with particular attention to the
regression risks called out in the review brief:

- **CR-01 (receive-window enforcement, `tcp_state.go` `handleEstablishedDataLocked`)** —
  `recvWindowRemainingLocked` now counts both `recvBuf` and every buffered
  `reorder` segment, and both the in-order-accept path and the out-of-order
  admission path clamp against it before mutating state. The reorder-drain
  loop that follows a successful in-order accept is itself gated on
  `fullyAccepted`, so draining never re-exceeds the window it just enforced,
  and moving bytes from `reorder` into `recvBuf` is capacity-neutral (no
  double-count). `TestTCPReceiveWindowEnforcedOnIngress` exercises the
  clamp directly (66000 bytes sent, exactly `defaultReceiveWindow` admitted,
  advertised window reaches exactly 0) and `TestTCPReorderBufferBounded`
  confirms the interaction between the bound and gap-filling still delivers
  a byte-correct stream. No interaction bug found between the window clamp
  and zero-window persist: persist governs the *send* side (`sndWnd`, the
  peer's advertised window), which is orthogonal to the local receive-side
  clamp (`advertisedWindowLocked`) CR-01 touches — the two never share state.

- **CR-02 (live-connection cap, `tcp_listener.go`/`tcp_timer.go`)** — every
  teardown path that can end a connection's life was traced and confirmed to
  call `demux.removeConn`, which unconditionally calls both
  `releaseHalfOpen` and `releaseLiveConn`: the inbound-RST branch and the
  `SYN_RCVD` bad-ACK branch in `tcp_state.go`'s `handleSegment`, the
  `LAST_ACK`→`stateClosed` transition, `tcp_timer.go`'s `onRTOFired`
  (both the `giveUp`/`maxRetransmits`-exceeded path and the
  `inTimeWait`-expired path), `onAttachmentDetached` (session/attachment
  detach), and `abort()` (backlog overflow and listener `Close`). Both
  `releaseHalfOpen` and `releaseLiveConn` are idempotent via their own
  `*Counted` flags, so a connection reachable from two different teardown
  paths in a race cannot double-decrement. `TestTCPLiveConnCapPerSession`
  confirms the cap itself is enforced; there is no dedicated regression test
  exercising the *release* side (see IN-02 below), but manual trace across
  every call site did not find a leaked path.

- **WR-01 (enqueue/Close race, `tcp_listener.go`)** — `enqueue` now performs
  its `l.closed` check and the non-blocking backlog send under one
  `l.mu` critical section, giving `enqueue` and `Close` a total order.
  `TestTCPListenerEnqueueCloseRaceLeavesNothingBehind` runs 5000 trials
  racing a completing ACK's asynchronous `enqueue` against a concurrent
  `Close`, asserting the demux's `conns` map always empties out — this is
  a lost-update regression the race detector alone would not catch (both
  steps are individually lock-protected), and the test's own framing
  correctly targets it that way. Verified clean under `-race` as well.

- **WR-02 (`http.Server` timeouts)** — both `examples/tunnelweb/main.go` and
  `test/interop/server/main.go` now build their `*http.Server` via a shared
  `newHardenedHTTPServer` helper setting `ReadHeaderTimeout`/`ReadTimeout`/
  `WriteTimeout`/`IdleTimeout`, each covered by a direct unit test asserting
  every field is positive.

- **WR-03 (RST in-window check + missing broadcast)** — `rstInWindowLocked`
  correctly special-cases a zero receive window (accepting only
  `seg.seq == rcvNxt`, mirroring RFC 9293 §3.4's zero-window-probe
  acceptability carve-out) and otherwise checks
  `seqGE(seg.seq, rcvNxt) && seqGT(rcvNxt+wnd, seg.seq)`. The `SYN_RCVD`
  bad-ACK branch now calls `broadcastLocked()` before unlocking, matching
  every sibling terminal-state transition.
  `TestTCPRSTOutOfWindowIgnored`/`TestTCPSynRcvdBadAckBroadcastsBeforeUnlock`
  cover both halves directly.

- **WR-04 (oversized-packet detach, `stack.go` `readLoop`)** — the retry is
  provably bounded to at most one extra `Session.Read` call per failure:
  `buf` grows from `readBufferSize` (2048) to `maxReadRetryBufferSize`
  (65535) exactly once, and the `len(buf) < maxReadRetryBufferSize` guard
  is false on the second failure regardless of cause, falling through to
  `detachAttachment`. No unbounded-loop path exists.
  `TestReadLoopRecoversFromShortBuffer` exercises the recoverable case
  end-to-end (oversized ICMP echo delivered, route stays alive, a
  subsequent normal-sized packet still round-trips) via `fakeSession`'s
  faithful reproduction of `Session.Read`'s documented retain-and-error
  contract.

All prior CR/WR findings are resolved. IN-01 from the previous review
(unchecked `uint16(...)` truncating casts in wire-building helpers) remains
open, unchanged: `ipv4.go`, `tcp_segment.go`, and `udp.go` were not touched
by any of the six fix commits and are outside this iteration's file scope,
so the info-level finding is carried forward rather than re-verified here.
One new info-level observation (test-coverage gap on the live-conn release
path) is added below.

## Info

### IN-01: Wire-building helpers truncate oversized lengths silently (carried forward, unchanged)

**File:** `netstack/ipv4.go:144-169` (`buildIPv4`), `netstack/tcp_segment.go:175-208` (`buildTCP`), `netstack/udp.go:112-136` (`buildUDP`)
**Issue:** All three builders compute their wire length fields via
`uint16(totalLen)`-style casts with no validation that `totalLen` actually
fits in 16 bits. Every current call site happens to bound its payload first
(TCP by MSS, UDP `WriteTo` by `maxUDPPayload`, ICMP/raw builders by the
2048-byte read buffer — now also true of `readLoop`'s bounded
`maxReadRetryBufferSize` growth from WR-04), so this remains unreachable
today, but these are shared, low-level primitives with no defensive check
of their own.
**Fix:** Add an explicit bounds check (returning an error, or at minimum an
assertion/panic in a debug build) in each builder for `len(payload)` against
the field's real limit, rather than relying on every present and future
caller to remember to pre-bound it.

### IN-02: No regression test exercises the live-connection cap's release side

**File:** `netstack/tcp_listener.go:199-224` (`releaseLiveConn`)
**Issue:** `TestTCPLiveConnCapPerSession` proves the cap is *enforced* (a
session that opens `maxLiveConnsPerSession` connections and never closes
any of them has its next SYN dropped), but nothing in the suite closes one
of those live connections (via RST, a clean FIN sequence, `onRTOFired`'s
give-up path, or `Close`/listener-`Close`) and then asserts a *new*
connection is admitted afterward — the way `TestTCPHalfOpenTimesOut` does
for the sibling half-open budget. Manual trace of every teardown path
(`handleSegment`'s RST and bad-ACK branches, `LAST_ACK` completion,
`onRTOFired`'s give-up and TIME_WAIT-expiry branches,
`onAttachmentDetached`, `abort`) confirms each one reaches
`demux.removeConn` → `releaseLiveConn`, so this is not a known defect
today — but the release path is exactly the kind of multi-call-site
invariant ("every teardown must free the budget") that a future edit could
silently break without a red test to catch it.
**Fix:** Add a test that saturates `maxLiveConnsPerSession`, tears down one
connection through each of the distinct teardown paths (RST, clean
close/TIME_WAIT expiry, `onRTOFired` give-up), and asserts a fresh SYN is
admitted after each, mirroring `TestTCPHalfOpenTimesOut`'s shape for the
half-open budget.

---

_Reviewed: 2026-08-27T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
