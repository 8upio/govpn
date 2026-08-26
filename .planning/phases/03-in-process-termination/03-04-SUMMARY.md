---
phase: 03-in-process-termination
plan: "04"
subsystem: netstack
tags: [tcp, http, net-http, deadlines, closewrite, rfc9293, netstack]

requires:
  - phase: 03-in-process-termination
    provides: "Stack.ListenTCP, the accepted net.Conn (tcp_conn.go/tcp_state.go/tcp_timer.go), plan 03-01's deadlineTimer, and tcpclient_test.go's minimal test TCP client — all from plan 03-03"
provides:
  - "Real SetReadDeadline/SetWriteDeadline/SetDeadline on the TCP net.Conn: net.Error-shaped, os.ErrDeadlineExceeded-wrapping, clearable, cross-goroutine-safe, non-terminal to the connection, driven by wall-clock time independent of the injected protocol Clock"
  - "CloseWrite() error on the TCP net.Conn — a genuine RFC 9293 half-close found structurally by net/http's own unexported closeWriter interface"
  - "Proof that unmodified stdlib http.Serve(stack.ListenTCP(port), handler) serves complete HTTP/1.1 traffic (single requests, keep-alive sequences, 200KB bodies in both directions, Connection: close) to an unmodified stdlib http.Client, with no Docker"
affects: [03-05-example-harness, 03-06-real-client-verification]

actuals:
  tokens: 13392
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Channel-based notifyCh (close-then-replace, the sync.Cond.Broadcast equivalent for select) replaces tcpConn's sync.Cond entirely, because Read/Write must select over a state-change notification alongside a deadline's own wait channel and sync.Cond.Wait cannot be combined with select"
    - "Close() delegates its FIN-sending step to CloseWrite() (sync.Once-guarded), so the two entry points can never race each other into emitting two FINs"
    - "A second, independent net.Conn adapter (netTestConn) over the plan 03-03 test TCP client, kept deliberately non-sharing with the production tcpConn, so a symmetric bug in one cannot cancel out against the other in the HTTP round-trip tests"

key-files:
  created:
    - netstack/tcp_http_test.go
    - netstack/tcp_conn_test.go
  modified:
    - netstack/tcp_conn.go
    - netstack/tcp_state.go
    - netstack/tcp_timer.go

key-decisions:
  - "Replaced tcpConn's sync.Cond with a channel-based notifyCh (close-and-replace under mu) rather than layering a deadline-aware wrapper around sync.Cond: Cond.Wait cannot be combined with select, and the plan's own action text requires Read/Write to select over the deadline's wait channel alongside the data-ready signal — every existing cond.Broadcast() call site (tcp_state.go, tcp_timer.go) became broadcastLocked() with no other behavior change."
  - "Close() now calls CloseWrite() for its own FIN-sending step instead of duplicating the ESTABLISHED/CLOSE_WAIT switch — CloseWrite's sync.Once guarantees exactly one FIN regardless of which method (or both, in either order, from either goroutine) is called first; Close() keeps only the SYN_RCVD hard-abort case, which CloseWrite() never needs to handle."
  - "The HTTP test harness's net.Conn adapter (netTestConn) performs its own TCP handshake using ONLY non-fatal primitives (tryRecvRaw), never the fatal recvRaw/connect helpers tcpclient_test.go exposes for the main-goroutine test style — because http.Transport's DialContext runs in its own internally-spawned goroutine, and calling t.Fatal from any goroutine other than the one running the test function has unspecified (in practice hang-inducing) behavior. An early version of this harness hung indefinitely for exactly this reason before the fix."
  - "netTestConn.Write releases its own mutex before the blocking sendRaw channel send on every chunk, never holding it across that block — an earlier version held the lock for the whole call and deadlocked TestHTTPLargeRequestBody against the fake session's own bounded inbound/outbound channels (Write blocked with the conn's lock held; the server's read loop, and this adapter's own readLoop, both needed that same lock to drain the channels that would have unblocked Write)."

patterns-established:
  - "Deadline checks in Read/Write run at the TOP of every loop iteration, before the data/buffer-space check — an already-past deadline returns the timeout error immediately without consuming buffered data or queuing anything, matching real net.Conn behavior (TestTCPReadDeadlineInThePast, TestTCPWriteDeadlineTimesOut)."
  - "A fired deadline is a per-call outcome only: no segment emitted, connection state (err, peerClosed, outBuf, recvBuf) left untouched — asserted directly (TestTCPDeadlineDoesNotKillConnection checks RSTsSent==0 and that data still flows after the deadline is cleared) rather than only documented in a comment."

requirements-completed: [NET-02]

coverage:
  - id: D1
    description: "http.Serve(stack.ListenTCP(port), handler), called directly with no wrapper or adapter, serves a complete HTTP/1.1 request/response to a real http.Client through the netstack"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestHTTPServeOverNetstack"
        status: pass
    human_judgment: false
  - id: D2
    description: "A Read blocked past its read deadline returns an error satisfying net.Error with Timeout()==true and errors.Is(err, os.ErrDeadlineExceeded)"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPReadDeadlineTimesOut"
        status: pass
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPWriteDeadlineTimesOut"
        status: pass
    human_judgment: false
  - id: D3
    description: "SetReadDeadline/SetWriteDeadline/SetDeadline are safe to call from another goroutine and unblock an already-blocked Read/Write; a deadline expiring never kills the connection and is cleared/extended normally on the next call"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPDeadlineFromAnotherGoroutine"
        status: pass
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPDeadlineDoesNotKillConnection"
        status: pass
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPReadDeadlineInThePast"
        status: pass
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPSetDeadlineSetsBoth"
        status: pass
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPDeadlineAfterClose"
        status: pass
      - kind: unit
        ref: "netstack/tcp_conn_test.go#TestTCPDeadlineUsesWallClockNotProtocolClock"
        status: pass
    human_judgment: false
  - id: D4
    description: "The accepted conn implements CloseWrite() error, found by net/http's own unexported closeWriter interface, and performs a genuine half-close (read side stays open, a second CloseWrite is a no-op)"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestTCPConnImplementsCloseWriter"
        status: pass
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestCloseWriteIsHalfClose"
        status: pass
    human_judgment: false
  - id: D5
    description: "An HTTP/1.1 keep-alive sequence of three requests is served over a single accepted connection, and a Connection: close response completes cleanly with no RST"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestHTTPKeepAliveSequence"
        status: pass
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestHTTPConnectionCloseCompletes"
        status: pass
    human_judgment: false
  - id: D6
    description: "A 200KB request body and a 200KB response body are each fully reassembled/delivered byte-for-byte, exercising multi-segment TCP in both directions"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestHTTPLargeRequestBody"
        status: pass
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestHTTPLargeResponseBody"
        status: pass
    human_judgment: false
  - id: D7
    description: "A real http.Server's own ReadHeaderTimeout closes an idle, silent connection gracefully (no RST, no listener wedge) and a second client is served normally afterward — proving the deadline wiring is what makes net/http's own DoS defense effective on this transport"
    requirement: "NET-02"
    verification:
      - kind: unit
        ref: "netstack/tcp_http_test.go#TestHTTPIdleKeepAliveDoesNotReset"
        status: pass
    human_judgment: false
  - id: D8
    description: "go test -race ./netstack/ completes in seconds with no Docker and no wall-clock protocol waits; go test -race ./..., go vet ./..., and make gates all exit 0; go.mod is unmodified"
    verification:
      - kind: unit
        ref: "go test -race ./netstack/ (86 tests, ~5s)"
        status: pass
      - kind: unit
        ref: "go test -race ./... && go vet ./... && make gates"
        status: pass
    human_judgment: false
---

# Phase 3 Plan 4: net/http Conformance (Deadlines + CloseWrite) Summary

**Wired real, net.Error-shaped deadlines and a genuine RFC 9293 half-close (`CloseWrite`) into the TCP `net.Conn`, then proved unmodified stdlib `http.Serve` and `http.Client` exchange complete HTTP/1.1 traffic — single requests, three-request keep-alive, 200KB bodies both directions, `Connection: close`, and a real `ReadHeaderTimeout` closing an idle connection — across the netstack with no Docker.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 2/2
- **Files modified:** 5 (3 modified, 2 new)

## Accomplishments

- `SetReadDeadline`/`SetWriteDeadline`/`SetDeadline` on the TCP `net.Conn` now drive plan 03-01's `deadlineTimer` for real: a blocked `Read`/`Write` unblocks the moment a deadline fires (even from another goroutine), returns an error satisfying `net.Error` with `Timeout()==true` and `errors.Is(err, os.ErrDeadlineExceeded)`, and leaves the connection completely healthy — no segment emitted, no state touched — so `net/http`'s own idle-keep-alive-then-clear-deadline cycle keeps working exactly as it does against a real socket.
- `tcpConn.Read`/`Write` replaced `sync.Cond` with a channel-based `notifyCh` (closed-and-replaced under the connection's mutex) specifically because `sync.Cond.Wait` cannot be combined with `select` — the mechanism a deadline-aware blocking call needs. Every `cond.Broadcast()` call site in `tcp_state.go`/`tcp_timer.go` became `broadcastLocked()` with zero behavior change elsewhere.
- `CloseWrite() error` is implemented (RFC 9293's half-close): `net/http`'s own unexported `closeWriter` interface check finds it structurally on the value `Accept` returns. `Close()` now delegates its FIN-sending step to `CloseWrite()` (guarded by `sync.Once`), so calling both — in either order, from either goroutine — can never emit two FINs.
- `netstack/tcp_http_test.go` builds a second, independent `net.Conn` adapter over plan 03-03's minimal test TCP client and drives a real `http.Client`/`http.Transport` against a real `http.Serve(stack.ListenTCP(port), mux)` — the exact, unmodified stdlib call ROADMAP Phase 3 success criterion 3's first clause requires. Eight HTTP-shaped tests cover a single request, a three-request keep-alive sequence on one accepted connection, 200KB bodies in both directions, `Connection: close`, the `CloseWrite` compile-time/runtime proof, the half-close's read-side-stays-open behavior, and a real `http.Server`'s `ReadHeaderTimeout` closing an idle connection without wedging the listener for the next client.
- `netstack/tcp_conn_test.go` hardens the deadline contract against every sequence `net/http` actually produces: clearability, a past deadline not consuming buffered data, `Write` reporting the true byte count on a timeout, cross-goroutine `SetReadDeadline`, `SetDeadline` arming both directions, the closed-conn error wrapping `net.ErrClosed`, and — as a structural guard against a future "tidying" regression — proof that advancing the injected protocol `Clock` by an hour never fires a wall-clock read deadline.
- `go test -race ./netstack/` runs all 86 tests (18 new from this plan) in ~5 seconds, no Docker; `go test -race ./...`, `go vet ./...`, and `make gates` all exit 0; `go.mod` is unmodified.

## Task Commits

Each task was committed atomically:

1. **Task 1: stdlib http.Serve serves a real HTTP response over the netstack listener** - `c1714cb` (feat)
2. **Task 2: The deadline contract holds under the conditions net/http actually creates** - `99f075a` (test)

**Plan metadata:** commit pending (this SUMMARY.md — worktree mode excludes STATE.md/ROADMAP.md per the orchestrator's own note)

## Files Created/Modified

- `netstack/tcp_conn.go` - real `SetReadDeadline`/`SetWriteDeadline`/`SetDeadline` driving `deadlineTimer`; `Read`/`Write` select over `notifyCh` + the deadline's wait channel; `CloseWrite() error` and the `closeWriter` compile-time assertion; `Close()` delegates to `CloseWrite()`; `sync.Cond` removed in favor of `notifyCh`/`broadcastLocked`
- `netstack/tcp_state.go` - `cond.Broadcast()` → `broadcastLocked()` (behavior-preserving rename to match the new notification mechanism)
- `netstack/tcp_timer.go` - `cond.Broadcast()` → `broadcastLocked()` (same)
- `netstack/tcp_http_test.go` - the `netTestConn` net.Conn adapter, `dialTCPTestConn`, `countingListener`, `httpTestHarness`, and eight HTTP-shaped tests (`TestHTTPServeOverNetstack`, `TestHTTPKeepAliveSequence`, `TestHTTPLargeResponseBody`, `TestHTTPLargeRequestBody`, `TestHTTPConnectionCloseCompletes`, `TestTCPConnImplementsCloseWriter`, `TestCloseWriteIsHalfClose`, `TestHTTPIdleKeepAliveDoesNotReset`)
- `netstack/tcp_conn_test.go` - `establishedTestConn`/`assertTimeoutErr` helpers and eight deadline-hardening tests (`TestTCPReadDeadlineTimesOut`, `TestTCPDeadlineDoesNotKillConnection`, `TestTCPReadDeadlineInThePast`, `TestTCPWriteDeadlineTimesOut`, `TestTCPDeadlineFromAnotherGoroutine`, `TestTCPSetDeadlineSetsBoth`, `TestTCPDeadlineAfterClose`, `TestTCPDeadlineUsesWallClockNotProtocolClock`)

## Decisions Made

- **Channel-based `notifyCh` replaces `sync.Cond`** in `tcpConn` — the only mechanism that lets `Read`/`Write` `select` over a state-change notification alongside a deadline's own wait channel, which `sync.Cond.Wait` cannot do.
- **`Close()` delegates to `CloseWrite()`** for its FIN-sending step rather than duplicating the ESTABLISHED/CLOSE_WAIT switch a second time — `CloseWrite`'s `sync.Once` is the single source of truth for "has a FIN already been sent," so the two public methods can never race into a double FIN.
- **The HTTP test harness's dial path uses only non-fatal test primitives** (`tryRecvRaw`), never the fatal `recvRaw`/`connect` helpers — because `http.Transport.DialContext` runs in its own internally-spawned goroutine, and the `testing` package's own contract restricts `t.Fatal`/`FailNow` to the goroutine running the test function.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `DialContext` hung indefinitely calling fatal test helpers from a non-test goroutine**
- **Found during:** Task 1, first run of `TestHTTPServeOverNetstack`
- **Issue:** The initial `dialTCPTestConn` implementation called `tcpTestClient.connect()`, which internally calls the fatal `recvRaw` (`t.Fatalf` on timeout). `http.Transport` invokes `DialContext` from its own internally-spawned dial goroutine, not the test's own goroutine. The `testing` package's documented contract is that `FailNow` (which `t.Fatal` calls) "must be called from the goroutine running the test... function, not from other goroutines" — calling it elsewhere left the dial goroutine silently vanish via `runtime.Goexit()` without ever returning to the `Transport` that was blocked waiting on it, hanging every HTTP test that dials through the harness.
- **Fix:** Rewrote `dialTCPTestConn` to perform the handshake using only non-fatal primitives (`tryRecvRaw`, `sendRaw`), returning a plain `error` on failure instead of calling `t.Fatal` — the error then surfaces normally through `http.Client`'s own `Get`/`Do`/`Post` return value.
- **Files modified:** `netstack/tcp_http_test.go`
- **Verification:** All eight HTTP-shaped tests pass; no hangs across 5 consecutive `go test -race` runs.
- **Committed in:** `c1714cb` (Task 1 commit)

**2. [Rule 1 - Bug] `netTestConn.Write` held its own mutex across a blocking channel send, deadlocking `TestHTTPLargeRequestBody`**
- **Found during:** Task 1, first run of `TestHTTPLargeRequestBody` (200KB POST body)
- **Issue:** `netTestConn.Write` held `nc.mu` (via `defer nc.mu.Unlock()`) for its entire segmentation loop, including the blocking `sendRaw` call that pushes onto the fake session's bounded (16-slot) inbound channel. Once that channel filled, `Write` blocked while still holding `nc.mu`. The adapter's own `readLoop` — which must acquire `nc.mu` to process inbound ACKs and, critically, to drain the fake session's *outbound* channel that the server's own write path was blocked on — could never proceed, producing a classic circular deadlock: `Write` waiting on the server to drain `inbound`; the server waiting on `readLoop` to drain `outbound`; `readLoop` waiting on `nc.mu`, which `Write` was holding.
- **Fix:** Restructured `Write` to acquire `nc.mu` only long enough to check state and to read/advance `sndNext` for each chunk, releasing it before every `sendRaw` call — matching the production `tcpConn`'s own documented "never hold the lock across a blocking call" discipline.
- **Files modified:** `netstack/tcp_http_test.go`
- **Verification:** `TestHTTPLargeRequestBody` passes; full `go test -race ./netstack/` remains green with the race detector silent.
- **Committed in:** `c1714cb` (Task 1 commit)

**3. [Rule 1 - Bug] A dialed test client's IP collided with the server's own tunnel IP**
- **Found during:** Task 1, first run of every HTTP-shaped test
- **Issue:** The harness's `DialContext` generated client IPs as `10.8.x.y`, the same `/24` as `testServerIP()` (`10.8.0.1`); the first dial (`n=1`) produced `10.8.0.1` itself, and `Stack.Attach`'s own fail-closed check correctly rejected a session attaching as the server's own tunnel IP.
- **Fix:** Moved the harness's dialed client IPs to `10.9.x.y`, a distinct `/16` from the server's `10.8.0.0/24`.
- **Files modified:** `netstack/tcp_http_test.go`
- **Verification:** All HTTP-shaped tests pass.
- **Committed in:** `c1714cb` (Task 1 commit)

**4. [Rule 1 - Bug] Pre-existing gofmt misalignment in `tcp_conn.go`'s struct field block**
- **Found during:** Task 1, pre-commit `gofmt -l` check
- **Issue:** `finSent`/`finAcked`/`finSeq`'s column alignment (from plan 03-03) was one space off per `gofmt`'s canonical formatting — unrelated to this plan's own edits, but touched incidentally in the same struct block this plan modified.
- **Fix:** Ran `gofmt -w netstack/tcp_conn.go`.
- **Files modified:** `netstack/tcp_conn.go`
- **Verification:** `gofmt -l netstack/*.go` reports no files; `go build`/`go vet`/`go test -race` all remain green.
- **Committed in:** `c1714cb` (Task 1 commit)

---

**Total deviations:** 4 auto-fixed (4 bugs, all Rule 1)
**Impact on plan:** All four fixes were necessary for the plan's own stated behavior (a real, non-hanging HTTP round trip; a 200KB request body actually completing; dialed test clients not colliding with the server's own address; consistent formatting) to hold. No scope creep, no architectural change — all four are internal to the test harness or a pre-existing formatting nit, not to the production TCP conn under test.

## Issues Encountered

None beyond the four auto-fixed deviations above, each resolved and verified before proceeding to the next test.

## Known Stubs

None. Every deadline method (`SetReadDeadline`/`SetWriteDeadline`/`SetDeadline`) now unblocks a genuinely blocked call, and `CloseWrite` performs a real half-close — the two gaps plan 03-03 explicitly left open (`// plan 03-04` markers) for this plan to close are both closed and tested.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `Stack.ListenTCP`'s accepted `net.Conn` now honors every contract `net/http` actually depends on: deadlines, half-close, and clean connection teardown — proven with unmodified stdlib `http.Serve` and `http.Client` on both ends, no Docker.
- Plan 03-05's example server (`examples/tunnelweb`) can be written directly against `http.Serve(stack.ListenTCP(port), handler)` without any further transport-layer work — this plan is the last gap between "a working TCP transport" and "stdlib `net/http` serves a page over it."
- Plan 03-06's real-client `curl` probe is now confirming behavior already proven at the fast tier (deadlines, half-close, keep-alive, large bodies, idle-timeout handling) rather than discovering it for the first time against a live Docker client.
- No blockers identified for 03-05 or 03-06.

## Self-Check: PASSED

- All 5 files listed under "Files Created/Modified" confirmed present on disk.
- Both task commits (`c1714cb`, `99f075a`) confirmed present via `git log --oneline`.
- `go test -race ./netstack/` (86 tests, ~5s), `go test -race ./...`, `go vet ./...`, and `make gates` all confirmed exit 0 immediately before writing this summary.
- `git diff --stat go.mod` confirmed empty.

---
*Phase: 03-in-process-termination*
*Completed: 2026-08-26*
