---
phase: 04-durable-sessions
reviewed: 2026-08-28T00:00:00Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - Makefile
  - cmd/gentestpki/main.go
  - gates_test.go
  - internal/ctrlconn/conn.go
  - lifecycle_test.go
  - ovpn.go
  - ovpn_test.go
  - reneg_test.go
  - session.go
  - test/interop/docker-compose.reneg.yml
  - test/interop/docker-compose.soak.yml
  - test/interop/entrypoint.sh
  - test/interop/interop_test.go
  - test/interop/server/main.go
findings:
  critical: 1
  warning: 2
  info: 1
  total: 4
status: issues_found
---

# Phase 04: Code Review Report

**Reviewed:** 2026-08-28T00:00:00Z
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues_found

## Summary

Phase 4 adds soft-reset key renegotiation, explicit-exit-notify teardown, and
idle-session reaping on top of the Phase 1-3 control/data channel. The
concurrency discipline documented in the code (`sess.mu` → `srv.mu` lock
ordering, snapshot-under-lock-then-operate-outside-lock for the data-channel
decrypt path, `stopOnce`-gated teardown) was traced through the renegotiation
swap, the lame-duck expiry sweep, `Close()`'s teardown, and the reneg
rate-limit / SOFT_RESET dedup fix, and holds up: no lock-order inversion, no
double-release of pool state, no use-after-close panic was found, and the
04-03 dedup fix for the both-sides-initiate-at-once race genuinely resolves
it (the routing table match happens under the same `sess.mu` that publishes
`pendingReneg`, so there is no window where a fresh, correctly-keyed
SOFT_RESET_V1 can be dropped instead of delivered to the already-pending
`Conn`).

However, one significant gap was found: **an in-flight renegotiation has no
timeout of its own**, unlike the initial handshake (which is protected by
`enforceHandshakeWindow`). A renegotiation that starts and then stalls (client
disappears mid-handshake, packet loss beyond what the reliability layer
recovers, etc.) leaks the `runRenegotiation` goroutine and its `Conn`'s
retransmit loop forever, and — more importantly — permanently disables all
further renegotiation for that session, because `sess.pendingReneg` never
clears. Ordinary data traffic on the still-live old primary key keeps
`lastAuthTraffic` fresh, so the idle-session reaper never rescues the session
either: it can run for its entire remaining lifetime on a key that was
supposed to have been rotated away from reneg-sec ago, silently defeating the
one behavior this phase exists to add. This is classified as a blocker.

Two further issues are classified as warnings: an inconsistency between the
locked write and unlocked read of `Session.dataKeys` (a real, if narrow, data
race for a caller of the public `DebugDataKeys`/`DebugKeyMethod2Material`
accessors), and residual routing of already-queued packets to closed `Conn`s
after `Close()` returns. One info-level dead-code item is also noted.

## Critical Issues

### CR-01: In-flight renegotiation has no timeout — a stalled reneg leaks a goroutine and permanently disables future rekeying for the session

**File:** `ovpn.go:994-1141` (`startRenegotiation`, `beginRenegotiation`, `runRenegotiation`); compare `ovpn.go:1146-1153` (`enforceHandshakeWindow`)

**Issue:** The *initial* control-channel handshake is protected by a
companion goroutine, `enforceHandshakeWindow` (started at `ovpn.go:546`
alongside `runHandshake`), which tears the session down if the handshake
doesn't complete within `s.handshakeWindow` (60s in production). No
equivalent exists for a *renegotiation* handshake: `runRenegotiation`
(`ovpn.go:1073`) calls `tls.Server(newConn, s.cfg.TLSConfig).Handshake()`
(line 1084) and `s.deriveKeyMethod2(...)` (line 1089) with no deadline ever
set on `newConn`, and no watchdog goroutine racing it. `ctrlconn.Conn.Read`
(`internal/ctrlconn/conn.go:244-266`) blocks indefinitely when no read
deadline has been set, so if the peer never completes this handshake (goes
silent, drops the network mid-exchange, or simply never responds to a
server-initiated bare `SOFT_RESET_V1` from `checkReneg`), `runRenegotiation`
blocks forever.

While it's blocked:

1. The `runRenegotiation` goroutine and `newConn`'s own `retransmitLoop`
   goroutine (started inside `ctrlconn.NewWithKeyID`, `conn.go:139`) both leak
   for the remaining lifetime of the process or session.
2. `sess.pendingReneg` (set at `ovpn.go:1039`) never clears. Every subsequent
   check in `startRenegotiation` (`ovpn.go:1008-1013`, "a renegotiation is
   already in flight ... the timer tick or a second SOFT_RESET_V1 is a
   no-op") now refuses *every* future renegotiation attempt for this
   session — both the server's own `checkReneg` timer (`session.go:735-762`)
   and any further client-initiated `SOFT_RESET_V1` — for as long as the
   session lives. The session's data-channel key is never rotated again.
3. This is not caught by the idle-session reaper (`session.go:804-822`):
   the *old* primary key slot is untouched until the atomic swap at the end
   of `runRenegotiation` (`ovpn.go:1120-1125`), so ordinary data/control
   traffic on the still-live old key keeps calling `touchAuthTraffic()`
   (`session.go:576`, `session.go:661`) and the session looks perfectly
   healthy to the reaper indefinitely — it just silently never rekeys again.
4. Nothing surfaces this to the embedder: `checkReneg`'s
   `if !ok { return }` (`session.go:753-755`) and `beginRenegotiation`'s
   `if !ok { return }` (`ovpn.go:1057-1059`) are both silent no-ops, so
   there is no diagnostic signal that a session's renegotiation capability
   is permanently stuck.

`lifecycle_test.go`'s `TestNoGoroutineLeakAcrossSessionLifecycle` and
`reneg_test.go`'s renegotiation tests all exercise a renegotiation that
*completes* successfully; none of them exercise a stalled/abandoned
renegotiation, so this gap is untested as well as unmitigated.

**Fix:** Add a renegotiation-scoped watchdog mirroring
`enforceHandshakeWindow`, e.g.:

```go
// enforceRenegotiationWindow tears the in-flight renegotiation newConn down
// (mirroring abandon()'s own cleanup) if it hasn't completed within the same
// handshake-window budget the initial handshake gets.
func (s *Server) enforceRenegotiationWindow(sess *Session, newConn *ctrlconn.Conn, done <-chan struct{}) {
	select {
	case <-done:
		return
	case <-time.After(s.handshakeWindow):
		sess.mu.Lock()
		if sess.pendingReneg == newConn {
			sess.pendingReneg = nil
		}
		sess.mu.Unlock()
		_ = newConn.Close() // unblocks the stalled Handshake()/deriveKeyMethod2 call
	}
}
```

started alongside `go s.runRenegotiation(sess, newConn, keyID)` at both call
sites (`session.go:761`, `ovpn.go:1061`), with `runRenegotiation` closing a
`done` channel on every return path (success, `abandon()`, and the
`sess.closing()` early-outs) so the watchdog goroutine itself doesn't leak
once the reneg finishes normally.

## Warnings

### WR-01: `Session.dataKeys` is written under `sess.mu` in `runRenegotiation` but read without any lock in `DebugDataKeys`/`DebugKeyMethod2Material`

**File:** `session.go:436-468` (accessors), `session.go:224-238` (`mu`'s own
doc comment enumerating guarded fields), `ovpn.go:1128` (the write site)

**Issue:** `runRenegotiation` writes `sess.dataKeys = dataKeys` at
`ovpn.go:1128`, inside the same `sess.mu`-guarded critical section
(`ovpn.go:1095-1137`) that publishes `sess.primary`/`sess.lameDuck`/
`sess.renegotiations`. But `Session.mu`'s own doc comment
(`session.go:224-238`) enumerates exactly which fields it guards —
`assignedIP, peerID, primary, lameDuck, pendingReneg, pendingRenegKeyID,
lastRenegAccepted, and lastAuthTraffic` — and conspicuously omits
`dataKeys`. Consistent with that omission, `DebugDataKeys()`
(`session.go:463-468`) and `DebugKeyMethod2Material()` (`session.go:448-453`)
read `s.dataKeys`/`s.clientKM`/`s.serverKM` with no locking at all.

Every call site in this phase's own test suite happens to be safe only
because it is preceded by a separate `sess.mu.Lock()/Unlock()` poll (e.g.
`waitForPrimaryKeyID` in `reneg_test.go:77-92`) that incidentally
establishes a happens-before edge with the writer's critical section. But
these are public, documented-as-debug-but-exported accessors
(`session.go:436-447`'s own doc comment: "so a test harness can
independently re-run keyderiv.DeriveKeys"), and nothing stops an embedder or
a harness from calling `DebugDataKeys()` from an unrelated goroutine
concurrently with a live renegotiation, with no intervening synchronization
point — which `go test -race` would flag as a genuine data race on
`s.dataKeys`.

**Fix:** Either guard the read with `sess.mu` (cheapest, and consistent with
the rest of the type's locking discipline):

```go
func (s *Session) DebugDataKeys() (keys keyderiv.DataKeys, ok bool) {
	s.mu.Lock()
	dataKeys := s.dataKeys
	s.mu.Unlock()
	if dataKeys == nil {
		return keyderiv.DataKeys{}, false
	}
	return dataKeys.ServerSlots(), true
}
```

and add `dataKeys` to the `mu` doc comment's guarded-field list — or, if
`dataKeys`/`clientKM`/`serverKM` are meant to stay unguarded (single-writer
during bootstrap only), stop writing to `sess.dataKeys` under `sess.mu` in
`runRenegotiation` and instead use a separate, dedicated mechanism (e.g. an
`atomic.Pointer[keyderiv.Key2]`) so the locking story for this field is
unambiguous either way.

### WR-02: Packets already queued before `Close()` can still be routed to an already-closed `Conn`

**File:** `ovpn.go:650-667` (`pump`), `session.go:611-632`
(`routeControlPacket`), `session.go:868-944` (`Close`)

**Issue:** `pump()`'s loop selects on `case cp := <-sess.inbound:` and
`case <-sess.stopCh:` with no priority between them. Once `Close()` closes
`stopCh` (`session.go:870`, before it closes any of the session's `Conn`s),
a packet already sitting in `sess.inbound` can still be selected on the same
iteration, routed via `routeControlPacket` to a `Conn` that `Close()` is
about to (or has just) called `.Close()` on, and delivered via
`target.Deliver(cp)`. `Conn.absorb` (`internal/ctrlconn/conn.go:181-209`)
does not check `c.closed` before mutating `sendRel`/`recvRel`/`readBuf`, so
this delivery proceeds against a `Conn` whose retransmit loop has already
exited. This causes no crash or leak (the mutated `readBuf` is never read by
anyone once the session is torn down), but it is dead-session state
mutation that the teardown discipline elsewhere in this file otherwise goes
out of its way to make impossible (see `Close`'s own extensive WR-05
commentary on avoiding exactly this class of "state published after
teardown decided" race for `assignedIP`/`peerID`/`dataSessions`).

**Fix:** Have `pump()` check `sess.closing()` before dispatching a packet it
happened to win the race on, or restructure the `select` to give `stopCh` an
explicit fast-path check first:

```go
case cp := <-sess.inbound:
    if sess.closing() {
        continue
    }
    if target := sess.routeControlPacket(cp.KeyID); target != nil {
        ...
```

## Info

### IN-01: Dead variable `rootCert` in `cmd/gentestpki/main.go`

**File:** `cmd/gentestpki/main.go:122-193`

**Issue:** `rootCert` is declared, assigned in both the `profileSmall` and
`profileLarge` branches (`rootCert = caCert` at lines 140 and 160), and then
immediately discarded via `_ = rootCert` at line 193 — it is never read for
any purpose. This is dead code that adds a variable and a blank-assignment
line for no behavioral effect.

**Fix:** Remove the `rootCert` variable and its two assignments along with
the `_ = rootCert` line, since nothing downstream uses it.

---

_Reviewed: 2026-08-28T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
