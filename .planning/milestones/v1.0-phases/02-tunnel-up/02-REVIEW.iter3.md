---
phase: 02-tunnel-up
reviewed: 2026-08-24T12:00:00Z
depth: standard
files_reviewed: 34
files_reviewed_list:
  - .github/workflows/ci.yml
  - Makefile
  - gates_test.go
  - internal/datachan/datachan.go
  - internal/datachan/datachan_test.go
  - internal/datachan/golden_test.go
  - internal/datachan/ping.go
  - internal/datachan/ping_test.go
  - internal/datachan/replay.go
  - internal/datachan/replay_test.go
  - internal/keyderiv/golden_test.go
  - internal/keyderiv/keyexpansion.go
  - internal/keyderiv/keyexpansion_test.go
  - internal/keyderiv/keymethod2.go
  - internal/keyderiv/keymethod2_test.go
  - internal/keyderiv/prf.go
  - internal/keyderiv/prf_test.go
  - internal/tlscrypt/golden_test.go
  - internal/wire/golden_test.go
  - ippool.go
  - ippool_test.go
  - ovpn.go
  - ovpn_test.go
  - push.go
  - push_test.go
  - session.go
  - test/interop/Dockerfile
  - test/interop/decode.go
  - test/interop/entrypoint.sh
  - test/interop/golden_export.go
  - test/interop/interop_test.go
  - test/interop/server/Dockerfile
  - test/interop/server/main.go
  - testdata/golden/README.md
  - testdata/golden/data-channel-km2.json
  - testdata/golden/manifest.json
findings:
  critical: 0
  warning: 1
  info: 0
  total: 1
status: issues_found
---

# Phase 02: Code Review Report (Re-review, iteration 2)

**Reviewed:** 2026-08-24T12:00:00Z
**Depth:** standard
**Files Reviewed:** 34
**Status:** issues_found

## Summary

Re-reviewed the five fixes applied since the previous pass (`cf88d33`, `de73298`,
`6bf164f`, `31f27c0`, `26fbc5a`) against CR-01 and WR-01 through WR-04, with
`go build ./...` and `go test -race -count=1 ./...` both clean across every
package. All five prior findings are correctly and completely resolved:

- **CR-01** (min-length gate dropping client pings): `handleDatagram` now
  branches into `handleDataDatagram` before applying `minDatagramSize`
  (`ovpn.go:295-326`), and the new `TestHandleDatagramAcceptsShortDataChannelPing`
  drives a real 40-byte sealed ping through the full accept path and proves
  (via a subsequent `ErrReplay`) that it actually reached `Wrapper.Open`
  rather than being dropped pre-opcode. Verified correct.
- **WR-01** (netmask normalization): `normalizeIPv4Mask` is now shared
  between `newIPPool` and `buildPushReply` (`ippool.go:48-61`, `push.go:84`),
  with a regression test forcing the 16-byte mask shape. Verified correct.
  (`buildPushReply`'s `network` argument is always a value that already
  passed `newIPPool`'s own 4-byte-after-normalization check by the time it's
  called, so the shared helper closes the gap completely — no
  Config-supplied network can reach `buildPushReply` un-normalized.)
- **WR-02** (replay-rejection plaintext leaking into `dst`): `Wrapper.Open`
  now decrypts into a `nil`-backed scratch buffer and only `append`s into the
  caller's `dst` after both the AEAD tag check and the replay check pass
  (`internal/datachan/datachan.go:250-274`). The regression test correctly
  proves the fix by asserting a pre-filled sentinel `dst` backing array is
  byte-for-byte unchanged after a replay-rejected `Open`. Verified correct.
- **WR-03** (unsynchronized `assignedIP`/`peerID`/`dataWrapper` access): a new
  `Session.mu` now guards all three fields, and both write sites
  (`performPushExchange`, `ovpn.go:585-603`) and all read sites (`Close`,
  `AssignedIP`, `PeerID`, `session.go`) take it consistently. The specific
  race the finding described — `enforceHandshakeWindow`'s independent
  timeout goroutine calling `Close` concurrently with `performPushExchange`'s
  writes — is now correctly synchronized, and `go test -race` is clean
  including the new `TestPerformPushExchangeFieldWritesRaceSafeAgainstClose`
  (50 iterations, forced-overlap barrier). Verified correct.
- **WR-04** (release-before-routing-cleanup ordering): `Close` now removes
  the `dataSessions` entry before releasing `peerID` back to the pool
  (`session.go:459-477`), and the new `TestCloseRemovesRoutingEntryBeforeReleasingPeerID`
  makes the ordering assertion structural (via holding `srv.mu` across the
  check window) rather than timing-dependent. Verified correct.

**Lock-ordering / deadlock check on the new `Session.mu`:** every call site
that takes both `sess.mu` and `s.srv.mu` (i.e. `Close`) does so in
back-to-back, non-nested critical sections — `sess.mu.Lock()/Unlock()`
completes and returns before `s.srv.mu.Lock()` is ever attempted, and vice
versa nowhere in `ovpn.go`/`session.go` is `s.srv.mu` held while attempting
`sess.mu.Lock()`. No lock is ever held across a blocking operation (channel
send/receive, I/O) either. No lock-ordering cycle or deadlock risk found
between `Session.mu`, `Server.mu`, and the `stopOnce`/`stopCh` teardown path.

One new issue was found while tracing the exact race window WR-03 targets
(concurrent `Close` from `enforceHandshakeWindow` vs. the in-flight
`performPushExchange` goroutine): the *data race* on the three fields is now
fixed, but nothing stops `performPushExchange` from **continuing to allocate
and publish session state after `Close` has already run** for the same
session, because none of its steps consult `stopCh`/`doneCh` and the one
I/O call that touches the already-closed control channel (`w.Write(reply)`)
does not reliably fail closed. This is pre-existing (not introduced by these
five commits) but is a real, currently-reachable resource-lifecycle bug
directly adjacent to WR-03's fixed race — see WR-05 below.

## Warnings

### WR-05: `performPushExchange` can allocate and publish session state after `enforceHandshakeWindow` has already closed the session, permanently leaking the pool IP/peer-id and the `dataSessions` routing entry

**File:** `ovpn.go:556-630` (`performPushExchange`), `ovpn.go:699-706`
(`enforceHandshakeWindow`), `session.go:443-485` (`Close`),
`internal/ctrlconn/conn.go:285-306` (`waitForSendSlot`)

**Issue:**

`enforceHandshakeWindow` calls `sess.Close()` on its own goroutine as soon as
`s.handshakeWindow` elapses, independently of whatever `performPushExchange`
is doing on the `runHandshake` goroutine at that exact moment
(`sess.doneCh` is deliberately not closed until the whole bring-up sequence
finishes, precisely so this can race). WR-03 correctly fixed the *data race*
on reading/writing `assignedIP`/`peerID`/`dataWrapper` across that
interleaving. But `performPushExchange` itself never checks whether the
session has, in the meantime, already been torn down — it has no `select`
on `stopCh`/`doneCh` anywhere in its body:

```go
// ovpn.go: performPushExchange, abbreviated
ip, peerID, err := s.pool.allocate()
...
sess.mu.Lock(); sess.assignedIP = ip; sess.peerID = peerID; sess.mu.Unlock()
dataWrapper, err := datachan.NewWrapper(...)
sess.mu.Lock(); sess.dataWrapper = dataWrapper; sess.mu.Unlock()
s.mu.Lock(); s.dataSessions[peerID] = sess; s.mu.Unlock()
sess.startKeepalive()

reply := buildPushReply(sess.assignedIP, s.cfg.Network, sess.peerID, cipher)
if _, err := w.Write(reply); err != nil {   // the only step that touches I/O
    return fmt.Errorf(...)
}
```

The intended (implicit) interruption mechanism is that once `Close` has
called `s.conn.Close()`, the subsequent `w.Write(reply)` should fail and
propagate an error up through `runHandshake`, which then calls `sess.Close()`
again (a no-op, since `stopOnce` already ran). But `ctrlconn.Conn.Write` →
`writeChunk` → `waitForSendSlot` checks `c.sendRel.Next()` for a free window
slot *before* ever consulting `c.closed`:

```go
// internal/ctrlconn/conn.go
func (c *Conn) waitForSendSlot() (int, error) {
	for {
		if idx, ok := c.sendRel.Next(); ok {
			return idx, nil   // returns success even if c.closed is already true
		}
		...
		closed := c.closed
		...
	}
}
```

For a `PUSH_REPLY` — normally the very first payload sent on a fresh send
window, so `Next()` almost always has a free slot on the first call — `Write`
succeeds and transmits the reply over the (still-open, server-wide)
`net.PacketConn` regardless of whether `Close` already ran for this session.
`performPushExchange` then returns `nil`, and `runHandshake` proceeds to
`close(sess.doneCh)` and invoke `Config.OnSession(sess)` for a `Session`
whose `stopCh` (and control-channel `Conn`) were already closed by the
handshake-window timeout.

Consequences, if `enforceHandshakeWindow`'s `Close()` lands in the narrow
window between `s.pool.allocate()` and the fields/`dataSessions` publish (or
anywhere before `w.Write(reply)` returns):

1. **Permanent leak of the allocated tunnel IP and peer-id.** `Close`'s
   `stopOnce.Do` body already ran once (with `assignedIP`/`peerID` still nil
   at that time, since the timeout fired *before* `performPushExchange`
   assigned them) — release only ever happens inside that one-shot block, so
   the IP/peer-id `s.pool.allocate()` just handed out can never be released.
   On a small `Config.Network` (e.g. a `/28` or `/29`, plausible for a small
   deployment), repeated occurrences of this race exhaust the pool for
   legitimate clients — the exact `ErrPoolExhausted` scenario the pool's own
   docs say "never blocks... a session that races into exhaustion is closed
   rather than queued" assumes can't happen from a leak, not that it can't
   leak at all.
2. **A permanently stale `srv.dataSessions[peerID]` entry** pointing at a
   session whose `stopCh` is already closed — never removed, because
   `Close`'s routing-table cleanup (WR-04's fix) also only runs inside that
   same already-consumed `stopOnce.Do`.
3. **`Config.OnSession` can fire for a session that is not "immediately
   usable"** (violating this project's own D-08 contract, `ovpn.go:63-69`):
   the handed-out `Session`'s `Read` will return `io.EOF` essentially
   immediately (its `stopCh` is already closed, racing the `ipInbound`
   case in the same `select`), while `Write` will still appear to succeed
   (it doesn't consult `stopCh` at all) — a zombie session an embedder has
   no way to distinguish from a healthy one except by its behavior.

This is independent of, and not introduced by, the five fix commits under
review — it existed before WR-03 too — but it sits squarely in the same
"concurrent `Close` vs. in-flight `performPushExchange`" scenario WR-03's
fix targeted, and the data-race fix does nothing to close it (by design: a
correctly-synchronized read of a field doesn't prevent that field from being
written *after* the object is supposed to be dead). Triggering it reliably
requires winning a race against `enforceHandshakeWindow`'s fixed timer
(default 60s, but `Server.handshakeWindow` is attacker-uninfluenceable
directly — though an attacker fully controls how long they wait before
sending `PUSH_REQUEST`, so they can aim for the boundary and get many
independent attempts across reconnects).

**Fix:** Have `performPushExchange` check for a "session already closing"
signal at the point it's about to publish state, and undo the allocation if
so — e.g., add a `closing` flag (or reuse `stopCh`) checked under `sess.mu`
in the same critical section that writes `assignedIP`/`peerID`, and have
`Close` set that flag before doing anything else so the two sides can never
both believe they're the one responsible for the resource:

```go
// performPushExchange, after s.pool.allocate() succeeds:
sess.mu.Lock()
if sess.closing {
    sess.mu.Unlock()
    s.pool.release(ip, peerID) // undo the allocation nothing else will free
    return errors.New("ovpn: session closed during push exchange")
}
sess.assignedIP = ip
sess.peerID = peerID
sess.mu.Unlock()
```

```go
// Close, as the very first thing inside stopOnce.Do, before anything else:
s.mu.Lock()
s.closing = true
assignedIP, peerID, dataWrapper := s.assignedIP, s.peerID, s.dataWrapper
s.mu.Unlock()
```

Alternatively, make `waitForSendSlot` check `c.closed` before (not only
after) `sendRel.Next()`, so the existing "let the write fail and propagate"
design actually works as intended — but that alone doesn't close the earlier
sub-window (the field assignment, `dataSessions` publish, and
`startKeepalive` all happen *before* the `Write` call and are already
irreversible by the time `Write` could fail). The `sess.mu`-guarded
"closing" check is the more complete fix since it covers the whole
allocate-then-publish sequence, not just the trailing I/O step.

Add a regression test analogous to `TestCloseRemovesRoutingEntryBeforeReleasingPeerID`
that forces `Close()` to run (e.g., by holding a lock or using a fake
`io.Writer` that blocks) strictly between `s.pool.allocate()` returning and
`performPushExchange` returning, then asserts the allocated IP/peer-id
become releasable/reusable rather than permanently stuck.

---

_Reviewed: 2026-08-24T12:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Iteration: 2 (re-review of fixes for CR-01, WR-01, WR-02, WR-03, WR-04)_
