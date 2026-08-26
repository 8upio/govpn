---
phase: 03-in-process-termination
fixed_at: 2026-08-27T01:30:00Z
review_path: .planning/phases/03-in-process-termination/03-REVIEW.md
iteration: 1
findings_in_scope: 6
fixed: 6
skipped: 0
status: all_fixed
---

# Phase 03: Code Review Fix Report

**Fixed at:** 2026-08-27T01:30:00Z
**Source review:** .planning/phases/03-in-process-termination/03-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 6 (2 Critical, 4 Warning)
- Fixed: 6
- Skipped: 0

**Verification environment:** all edits were made and verified inside an isolated git
worktree (`.claude/worktrees/rf-03-30837-*`, branch `gsd-reviewfix/03-30837`), per
`workflow.use_worktrees` (unset, defaults to `true`). `go build ./...`, `go vet ./...`,
`go test -race -count=1 ./...`, and `make gates` (`go test -race -run
'TestPhase2|TestPhase3' -v ./`) were run after every fix from inside that worktree before
committing. `make interop` (real OpenVPN 2.6 client via Docker) was run once at the end,
also from inside the worktree, since Docker was available in this environment — see its
result below. The worktree's commits were fast-forwarded onto the branch that was checked
out when this run started before the worktree was torn down, so these results are
reproducible from that branch's current `HEAD` in the main checkout.

## Fixed Issues

### CR-01: TCP receive window is advertised but never enforced on inbound data

**Files modified:** `netstack/tcp_conn.go`, `netstack/tcp_state.go`, `netstack/tcp_state_test.go`
**Commit:** ebe12ba
**Applied fix:** Added `recvWindowRemainingLocked()` (counting both `recvBuf` and
reorder-buffered bytes) and used it to clamp `handleEstablishedDataLocked`'s in-order
admission to what remains under `defaultReceiveWindow`, dropping bytes beyond it instead
of buffering them unconditionally. The out-of-order (`seqGT`) branch and the reorder-drain
loop were updated to respect the same budget, and `advertisedWindowLocked` now reports
this same total so the window it advertises and what it actually enforces agree.
**Regression test:** `TestTCPReceiveWindowEnforcedOnIngress` — sends 33 in-order 2000-byte
chunks (66000 bytes total, deliberately kept under `readBufferSize` per chunk so this test
does not also exercise WR-04) with the application never reading; asserts the cumulative
ACK admits exactly `defaultReceiveWindow` bytes and `Read` never delivers more than that.
Verified to fail (returns the full oversized amount) with the fix reverted.

### CR-02: No cap on the number of live (ESTABLISHED) TCP connections per session

**Files modified:** `netstack/tcp_conn.go`, `netstack/tcp_listener.go`, `netstack/tcp_listener_test.go`, `netstack/tcp_state.go`, `netstack/tcp_timer.go`, `netstack/tcp_timer_test.go`
**Commit:** e8b2f1d
**Applied fix:** Added a `maxLiveConnsPerSession` (64) cap tracked in a new
`tcpDemux.liveConns` map, incremented in `handleSYN` alongside the existing half-open
check (both under the same lock) and released only from `removeConn` via a new
`releaseLiveConn` — independent of `releaseHalfOpen`, which still fires the instant a
handshake completes. Separately, added `persistProbeCount` (bounded by
`maxPersistProbes = 20`, reset in `handleAckLocked` whenever the peer's window reopens) to
`onRTOFired`'s zero-window persist branch, closing the gap where a peer that ACKs each
probed byte individually (keeping `sentBytes` at zero) never triggers the ordinary
`sentBytes > 0` retransmit case's own `maxRetransmits` accounting.
**Regression tests:** `TestTCPLiveConnCapPerSession` (completes `maxLiveConnsPerSession`
handshakes on one session, keeping every connection open, then asserts a further SYN is
dropped and `LiveConnCapHits` increments — even though the half-open budget has room) and
`TestTCPZeroWindowPersistGivesUpEventually` (ACKs each zero-window persist probe
individually across `maxPersistProbes` fake-clock ticks, then asserts the connection is
reset on the next tick rather than persisting forever). Both verified to fail with their
respective guard reverted (the persist test reproduces the true indefinite-persist
scenario only when each probe is individually ACKed — un-acked probes are already bounded
today via the ordinary retransmit path, which the test's comment explains).

### WR-01: `tcpListener.Close()` / `enqueue()` race can leak a connection past Close

**Files modified:** `netstack/tcp_listener.go`, `netstack/tcp_listener_test.go`
**Commit:** 3c6e599
**Applied fix:** `enqueue` now holds `l.mu` across both the closed-check and the
(non-blocking) backlog send, matching the critical section `Close` uses to flip
`l.closed` — forcing a total order between the two so an enqueue call either completes
entirely before `Close` observes/sets `l.closed`, or entirely after (and aborts).
**Regression test:** `TestTCPListenerEnqueueCloseRaceLeavesNothingBehind` — races a
handshake's completing ACK (processed asynchronously on the stack's read-loop goroutine,
where `enqueue` runs) against a concurrent `Close()`, across 5000 trials, asserting the
demux's `conns` map always ends up empty after an Accept-drain loop. This is a logic race
(lost update between two lock-protected steps), not a data race in the `-race`-detector
sense, so the regression signal is the functional assertion, not `-race` itself — the
window is narrow enough that ~200 trials did not reliably reproduce it, but ~400 trials
did with the fix reverted; 5000 trials gives comfortable margin while still running in
single-digit seconds.

### WR-02: `examples/tunnelweb/main.go`'s `http.Server` has no read/write/idle timeouts

**Files modified:** `examples/tunnelweb/main.go`, `examples/tunnelweb/main_test.go`, `test/interop/server/main.go`, `test/interop/server/main_test.go`
**Commit:** a5e1bcf
**Applied fix:** Both the tunnelweb example (which already used an `*http.Server` literal)
and the interop harness (which used the bare `http.Serve(httpLn, instrumented)` function —
no `*http.Server` to configure at all, so it needed restructuring, not just field
assignment) now build their server via a small `newHardenedHTTPServer` helper setting
`ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`.
**Regression tests:** `TestNewHardenedHTTPServerSetsTimeouts` in each package, asserting
every timeout field is positive. Verified to fail against the pre-fix zero-valued
`&http.Server{Handler: ...}` literal shape.

### WR-03: Inbound-RST handling skips RFC 9293's in-window sequence check; one teardown path skips `broadcastLocked`

**Files modified:** `netstack/tcp_state.go`, `netstack/tcp_state_test.go`
**Commit:** 4a344f7
**Applied fix:** Added `rstInWindowLocked` (RFC 9293 §3.10.7.4's in-window validation,
with the same zero-window special case §3.4's general segment-acceptability test uses) and
gated `handleSegment`'s top-of-function RST teardown on it. Added the missing
`c.broadcastLocked()` call to the `stateSynRcvd` bad-ACK branch, matching every sibling
teardown path in this file and in `tcp_timer.go`.
**Regression tests:** `TestTCPRSTOutOfWindowIgnored` (an out-of-window RST is ignored; the
connection stays usable for a subsequent legitimate data exchange) and
`TestTCPSynRcvdBadAckBroadcastsBeforeUnlock` (white-box: captures `notifyCh` before
triggering the bad-ACK path and asserts it closes). Both verified to fail with their
respective fix reverted.

### WR-04: `readLoop` conflates "buffer too small, packet retained" with a fatal read error

**Files modified:** `netstack/stack.go`, `netstack/stack_test.go`
**Commit:** 07f053d
**Applied fix:** `readLoop` now grows its buffer once (to `maxReadRetryBufferSize =
65535`, the largest IPv4 datagram this stack can parse) and retries on any `Session.Read`
error, before falling back to `detachAttachment`. The review's literal suggestion
(`errors.Is` against the "buffer too small" sentinel) is not reachable here:
`TestPhase3NetstackDoesNotImportCoreLibrary` forbids `netstack` from importing the core
`ovpn` module where that sentinel lives, and `Session` is deliberately a local structural
interface with no such sentinel of its own — so the fix is adapted to grow-and-retry
instead of type-distinguishing the error, which needs no cross-package knowledge and costs
at most one extra non-blocking `Read` call on a genuinely closed session. A new
`Stats().ShortReadBufferGrown` counter gives this outcome the diagnostic signal the review
noted was missing.
**Regression test:** `TestReadLoopRecoversFromShortBuffer` — sends an ICMP echo request
larger than `readBufferSize` but under `maxReadRetryBufferSize`, asserts the reply still
arrives, `ShortReadBufferGrown` increments, and the route survives for a subsequent normal
packet. Verified to fail (times out) with the fix reverted.

## Skipped Issues

None — all 6 in-scope findings (CR-01, CR-02, WR-01, WR-02, WR-03, WR-04) were fixed.
IN-01 was out of scope for this run (`fix_scope: critical_warning`).

## Verification

Run after every commit, from inside the isolated worktree:

- `go build ./...` — clean
- `go vet ./...` — clean
- `go test -race -count=1 ./...` — all packages pass
- `make gates` (`go test -race -run 'TestPhase2|TestPhase3' -v ./`) — all 9 assertions pass,
  including `TestPhase3NetstackDoesNotImportCoreLibrary` (relevant to WR-04's adapted fix)

`make interop` (real, version-pinned OpenVPN 2.6 client via Docker) was run once at the
end. **Result: PASS** — all three scenarios green (`clean-small`, `clean-large`,
`lossy-large`), including every HTTP probe (`http_landing`, `http_status`, `http_echo`,
`http_headers`), the UDP echo probe, the ICMP ping round trip (9/10 on the lossy scenario,
tolerated loss), and the outside-tunnel negative check. The CR-01/CR-02/WR-01/WR-03
changes all sit under the live TCP data path the interop harness's HTTP probes exercise
(`examples/tunnelweb/site` served over `netstack.ListenTCP`), so a real client completing
four full HTTP page loads (including a POST) through the fixed receive-window clamp,
live-connection cap, enqueue/Close fix, and RST validation is direct end-to-end
confirmation none of the six fixes regressed ordinary interop behavior.

---

_Fixed: 2026-08-27T01:30:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
