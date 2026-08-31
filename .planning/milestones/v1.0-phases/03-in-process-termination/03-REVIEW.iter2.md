---
phase: 03-in-process-termination
reviewed: 2026-08-27T00:00:00Z
depth: standard
files_reviewed: 37
files_reviewed_list:
  - Makefile
  - examples/tunnelweb/README.md
  - examples/tunnelweb/main.go
  - examples/tunnelweb/site/pages.go
  - examples/tunnelweb/site/site.go
  - examples/tunnelweb/site/site_test.go
  - examples/tunnelweb/site/style.css
  - gates_test.go
  - netstack/clock.go
  - netstack/deadline.go
  - netstack/deadline_test.go
  - netstack/fakesession_test.go
  - netstack/icmp.go
  - netstack/icmp_test.go
  - netstack/ipv4.go
  - netstack/ipv4_test.go
  - netstack/stack.go
  - netstack/stack_test.go
  - netstack/tcp_conn.go
  - netstack/tcp_conn_test.go
  - netstack/tcp_http_test.go
  - netstack/tcp_listener.go
  - netstack/tcp_listener_test.go
  - netstack/tcp_segment.go
  - netstack/tcp_segment_test.go
  - netstack/tcp_state.go
  - netstack/tcp_state_test.go
  - netstack/tcp_timer.go
  - netstack/tcp_timer_test.go
  - netstack/tcpclient_test.go
  - netstack/udp.go
  - netstack/udp_test.go
  - netstack/udpaddr_test.go
  - test/interop/Dockerfile
  - test/interop/entrypoint.sh
  - test/interop/interop_test.go
  - test/interop/server/main.go
findings:
  critical: 2
  warning: 4
  info: 1
  total: 7
status: issues_found
---

# Phase 03: Code Review Report

**Reviewed:** 2026-08-27T00:00:00Z
**Depth:** standard
**Files Reviewed:** 37
**Status:** issues_found

## Summary

This phase's userspace netstack (IPv4/ICMP/UDP/minimal server-side TCP) and
the `tunnelweb` example were reviewed against the deliberate scope cuts
documented in the plans (fragments dropped, no SACK, fixed RTO,
server-accept-only, short TIME_WAIT). Those documented cuts are not treated
as defects here. The parsers (`parseIPv4`, `parseTCP`, `parseUDP`) are
careful and well-tested against adversarial/truncated input — no panics or
out-of-bounds reads were found, and the accompanying `TestParseIPv4NeverPanics`
/ `TestTCPParseNeverPanics` / `TestUDPParseNeverPanics` suites genuinely
exercise the boundary cases they claim to.

The main gap this review surfaces is in the TCP receive-side resource
accounting: the stack advertises a receive window but never enforces it on
ingress, and nothing bounds the number of concurrently *established* TCP
connections a single attached session can hold open (only the number of
*half-open* SYN_RCVD connections is capped, and that budget is released the
instant a handshake completes). Given this review's own threat model — an
authenticated OpenVPN client is still untrusted input to the netstack — both
are exploitable by a single legitimate peer to grow server memory/CPU usage
without bound. A handful of narrower concurrency and robustness issues round
out the warnings below.

## Critical Issues

### CR-01: TCP receive window is advertised but never enforced on inbound data

**File:** `netstack/tcp_state.go:242-301` (`handleEstablishedDataLocked`), `netstack/tcp_conn.go:552-561` (`advertisedWindowLocked`)
**Issue:** `advertisedWindowLocked` correctly shrinks the window it *advertises*
as `recvBuf` fills (`defaultReceiveWindow - len(recvBuf)`, capped at 0), and
`TestTCPAdvertisedWindowShrinksWithBuffer` confirms the *advertised* value is
honest. However, `handleEstablishedDataLocked`'s in-order branch
(`case seg.seq == c.rcvNxt:`) unconditionally appends `seg.payload` to
`c.recvBuf` with no check that doing so would exceed the window this stack
itself last advertised:

```go
case seg.seq == c.rcvNxt:
    if dataLen > 0 {
        c.recvBuf = append(c.recvBuf, seg.payload...)   // no window check
        c.rcvNxt += dataLen
    }
```

A peer that ignores the advertised window (any of: a compromised/custom
OpenVPN client, a buggy TCP stack, or simply a client that never calls
`Read` on the accepted `net.Conn`'s peer side while continuing to push
in-order segments) can grow `recvBuf` without bound for as long as the
application doesn't drain it fast enough — which is exactly the "slow
reader" scenario `advertisedWindowLocked`'s own doc comment claims to guard
against. Since the review's threat model treats an authenticated VPN client
as untrusted input to the netstack, this is an unbounded per-connection
memory-growth vector, not merely a spec nicety.

**Fix:** Before appending, clamp/reject the accepted portion of `seg.payload`
to what remains within the last-advertised window (e.g. track the window
high-water mark and trim or drop bytes beyond it, re-ACKing the actual
`rcvNxt` as today), mirroring how `sendPendingLocked` already clamps the
*send* side to `allowedInFlightLocked()`. At minimum, add a hard cap (e.g.
`defaultReceiveWindow` plus the bounded reorder buffer's worth) past which
further in-order data is dropped rather than buffered.

### CR-02: No cap on the number of live (ESTABLISHED) TCP connections per session

**File:** `netstack/tcp_listener.go:172-191` (`releaseHalfOpen`), `netstack/tcp_listener.go:251-307` (`handleSYN`), `netstack/tcp_timer.go:289-296` (zero-window persist branch)
**Issue:** `maxHalfOpenPerSession` (8) bounds only the number of *concurrent,
incomplete* SYN_RCVD connections per attached session (T-03-13's own stated
scope). The moment a handshake completes, `handleSegment`'s `stateSynRcvd`
success path calls `c.demux.releaseHalfOpen(c)` before enqueuing the
connection — freeing that budget slot immediately:

```go
if enqueueToListener {
    c.demux.releaseHalfOpen(c)
    c.listener.enqueue(c)
}
```

Nothing in `tcpDemux`/`tcpListener` bounds the total number of *established*
connections a single session can accumulate over time. A single
authenticated (but, per this review's own stated threat model, untrusted)
VPN client can complete handshakes as fast as the half-open budget allows
(8 at a time, refilled instantly on each completion) and simply never close
them, building an unbounded number of live `tcpConn` structs — each backed
by its own `timerLoop` goroutine (`tcp_timer.go`) that runs for the
connection's entire lifetime.

This is compounded by the zero-window persist-probe branch in `onRTOFired`
(`tcp_timer.go:289-296`), which is explicitly exempted from
`maxRetransmits`/give-up accounting:

```go
case c.sndWnd == 0 && uint32(len(c.outBuf)) > c.sentBytes:
    // Zero-window persist (RFC 9293 §3.8) ...
    c.sendPendingLocked(&toSend, true)
    c.rtoTimer.Reset(c.rto)
```

A peer can advertise a permanently zero window on every one of these
connections and go silent forever; the connection (and its timer goroutine)
is retried indefinitely and never torn down until the *session itself*
detaches. Combined with CR-01 and the unbounded connection count, one
misbehaving/hostile client can indefinitely grow the server's live
goroutine and memory footprint, degrading or starving every other tenant
sharing the process — squarely the "per-session caps actually enforced on
all paths" property this phase's own scope calls out (SYN flood is capped;
completed-connection accumulation is not).

**Fix:** Track and cap the number of *live* (non-CLOSED) connections per
session (by attachment IP), independent of the half-open counter, releasing
it only on `removeConn`. Consider also bounding total persist-probe duration
(or wall-clock connection age) separately from `maxRetransmits`, since RFC
9293 §3.8 does not itself mandate indefinite persistence.

## Warnings

### WR-01: `tcpListener.Close()` / `enqueue()` race can leak a connection past Close

**File:** `netstack/tcp_listener.go:315-370`
**Issue:** `enqueue` checks `l.closed` under `l.mu`, releases the lock, and
only then attempts `l.backlog <- c`. `Close` sets `l.closed = true`, closes
`closeCh`, and drains `l.backlog` to `abort()` everything currently queued —
but if `enqueue`'s closed-check happens to observe `false` just before
`Close` runs, and `Close`'s own drain loop finds the channel empty and
returns *before* `enqueue`'s subsequent `l.backlog <- c` executes, the
connection is pushed into a backlog channel nobody will ever read from
again (Accept has already unblocked with `ErrTCPListenerClosed` via
`closeCh`). The connection stays ESTABLISHED in the demux's `conns` map with
its `timerLoop` goroutine running, un-Accepted and un-aborted, until the
owning *session* eventually detaches — silently defeating the doc comment's
claim that `Close` "resets every connection still sitting in the backlog
that was never accepted" (T-03-14/T-03-18).
**Fix:** Re-check `l.closed` (or select on `l.closeCh`) *after* a successful
`l.backlog <- c` send in `enqueue`, aborting the connection if `Close` won
the race in the interim; or have `Close` close `l.backlog` itself (after
which a lingering `enqueue` send would panic — needs a compare-and-swap-style
guard) so the two paths cannot both believe they "won."

### WR-02: `examples/tunnelweb/main.go`'s `http.Server` has no read/write/idle timeouts

**File:** `examples/tunnelweb/main.go:81-86`
**Issue:**

```go
httpSrv := &http.Server{Handler: site.Handler(site.Options{
    Cipher:    "AES-256-GCM",
    StartedAt: time.Now(),
})}
```

No `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, or `IdleTimeout` is
set. A client that opens a connection and sends headers slowly (or not at
all) ties up an `http.Server` goroutine indefinitely, since `net/http` only
arms a read deadline on the connection when one of these fields is
configured. The project's own test harness demonstrates it knows the fix —
`netstack/tcp_http_test.go`'s `TestHTTPIdleKeepAliveDoesNotReset` explicitly
sets `ReadHeaderTimeout: 100 * time.Millisecond` on its harness server and
asserts the connection is closed, not hung — but the shipped example (the
one a reader is expected to copy) does not apply the same mitigation.
Combined with CR-02 (no cap on live connections), this is a real Slowloris-
style resource-exhaustion path for anything built from this example.
**Fix:** Set `ReadHeaderTimeout` (and ideally `ReadTimeout`/`WriteTimeout`/
`IdleTimeout`) on `httpSrv` in `examples/tunnelweb/main.go` (and the interop
harness's `test/interop/server/main.go`, which has the identical gap via a
bare `http.Serve` call).

### WR-03: Inbound-RST handling skips RFC 9293's in-window sequence check; one teardown path skips `broadcastLocked`

**File:** `netstack/tcp_state.go:74-86`, `netstack/tcp_state.go:93-103`
**Issue:** `handleSegment`'s top-of-function RST handling tears the
connection down for *any* inbound RST regardless of its sequence number:

```go
if seg.flags&flagRST != 0 {
    c.demux.stats.rstsReceived.Add(1)
    c.err = ErrTCPConnReset
    c.state = stateClosed
    ...
```

RFC 9293 §3.10.7.4 requires validating the RST's sequence number falls
within the current receive window before accepting it (the classic
blind-reset mitigation). Because this stack's dispatch already restricts a
segment's 4-tuple to the same session that owns the connection (spoofed
source IPs are dropped in `Stack.deliver` before reaching here), the
practical blast radius is limited to a peer resetting its own connection —
but it is still a spec deviation worth closing, especially if this code is
ever reused in a context with a less-restrictive dispatch boundary.

Separately, the `stateSynRcvd` "bad ACK" branch a few lines below is the
only teardown path in this function that does **not** call
`c.broadcastLocked()` before releasing `c.mu`:

```go
case stateSynRcvd:
    if seg.flags&flagACK == 0 || seg.ack != c.sndUna+1 {
        rst := buildRSTSegment(seg)
        c.state = stateClosed
        c.stopTimersLocked()
        c.mu.Unlock()          // <- no broadcastLocked() first
        c.demux.removeConn(c)
        ...
```

Every other terminal-state transition in this file and in
`tcp_timer.go` (`onRTOFired`'s `giveUp` path, `onAttachmentDetached`,
`abort`) calls `broadcastLocked()` before unlocking. This particular branch
is currently harmless because a SYN_RCVD connection has never been handed
to an application (no `Read`/`Write` caller can be blocked on its
`notifyCh` yet), but the inconsistency is a maintenance hazard: a later
change that exposes pre-Accept connection state to a waiter would silently
reintroduce a missed-wakeup bug here.
**Fix:** Validate the RST's sequence number against the receive window
before accepting it; add the missing `c.broadcastLocked()` call to the
`stateSynRcvd` bad-ACK branch for consistency with every sibling teardown
path.

### WR-04: `readLoop` conflates "buffer too small, packet retained" with a fatal read error

**File:** `netstack/stack.go:337-371` (`readLoop`)
**Issue:** `readLoop` treats every non-nil `Session.Read` error identically
as the sole, permanent detach trigger (`D-02`):

```go
n, err := a.sess.Read(buf)
if err != nil {
    s.detachAttachment(a)
    return
}
```

`fakesession_test.go`'s own doc comment states this mirrors the real
`ovpn.Session.Read`'s documented contract: given a buffer too small for a
pending decrypted packet, `Session.Read` returns an error *while retaining*
the packet for a future call with a larger buffer — it is not necessarily a
terminal I/O failure. `readBufferSize` is a fixed 2048 bytes and never
grows. A single decrypted IP packet larger than that — which a
non-conforming or hostile client can trivially produce, since the pushed
`tun-mtu 1500` is only advisory and not enforced by anything upstream of
this loop — causes `readLoop` to permanently and silently tear down netstack
routing for that entire session (`detachAttachment` removes the route and
stops the read loop; the underlying `ovpn.Session` itself is untouched per
D-02, so the client's tunnel stays up while all of its traffic is now
silently dropped by the netstack). This is self-inflicted by the sending
client in the common case, but it is still a real availability bug: it
converts a documented, recoverable "retry with a bigger buffer" contract
into an unrecoverable, silent session-routing failure with no diagnostic
signal (no counter, no log) distinguishing it from a genuine session
teardown.
**Fix:** Distinguish the "buffer too small" sentinel from other read errors
(e.g. via `errors.Is`) and either retry with a larger buffer or drop just
that one packet while keeping the attachment alive, reserving
`detachAttachment` for errors that genuinely indicate the session is gone.

## Info

### IN-01: Wire-building helpers truncate oversized lengths silently

**File:** `netstack/ipv4.go:144-169` (`buildIPv4`), `netstack/tcp_segment.go:175-208` (`buildTCP`), `netstack/udp.go:112-136` (`buildUDP`)
**Issue:** All three builders compute their wire length fields via
`uint16(totalLen)`-style casts with no validation that `totalLen` actually
fits in 16 bits. Every current call site happens to bound its payload first
(TCP by MSS, UDP `WriteTo` by `maxUDPPayload`, ICMP/raw builders by the
2048-byte read buffer), so this is not reachable today, but these are
shared, low-level primitives with no defensive check of their own — a
future caller that forgets to bound its input would silently emit a packet
whose length field lies about its own size rather than failing loudly.
**Fix:** Add an explicit bounds check (returning an error, or at minimum an
assertion/panic in a debug build) in each builder for `len(payload)` against
the field's real limit, rather than relying on every present and future
caller to remember to pre-bound it.

---

_Reviewed: 2026-08-27T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
