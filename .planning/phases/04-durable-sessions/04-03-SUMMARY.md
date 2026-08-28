---
phase: 04-durable-sessions
plan: "03"
subsystem: testing
tags: [openvpn, interop, docker, renegotiation, exit-notify, tls-crypt, reneg-sec]

# Dependency graph
requires:
  - phase: 04-durable-sessions
    provides: "04-01's two-slot key state, renegotiation driver, Config.RenegSec, Session.RenegotiationCount-ready atomic swap"
  - phase: 04-durable-sessions
    provides: "04-02's OCC_EXIT detection, idle-session reaper, and completed io.EOF teardown contract"
  - phase: 03-in-process-termination
    provides: "03-06's PROBE line format, parseProbeResults/assertProbe framework, and scenario table this plan extends"
provides:
  - "A new 'reneg' interop scenario proving a real, unmodified OpenVPN 2.6 client renegotiates against the library at least twice while HTTP/UDP traffic keeps flowing, with zero reconnects"
  - "The same scenario's explicit-exit-notify closing the server's Session within seconds of a graceful client stop, well under the 60s idle-reap window"
  - "cmd/gentestpki -client-directive: a repeatable flag appending scenario-specific client.conf directives, defaulting to none so pre-existing scenarios stay byte-identical"
  - "Session.RenegotiationCount() diagnostic accessor"
  - "Two production bug fixes in ovpn.go's renegotiation machinery, found and fixed by running this scenario against a real client: Server.renegMinInterval now scales with the active reneg-sec instead of a hardcoded 60s floor, and an incoming SOFT_RESET_V1 for an already-in-flight key-id is now delivered to the existing pendingReneg Conn instead of being silently dropped"
affects: [04-04]

# Actuals (#2632)
actuals:
  tokens: 15508
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "scenario.composeOverlay generalizes the old lossy-boolean-only overlay selection, letting a scenario pick a compose overlay independent of the lossy strictness convention"
    - "Round-suffixed PROBE names (http_landing_rN/udp_echo_rN) driven by ROUND_COUNT/ROUND_INTERVAL env vars, so a multi-round scenario needs no new parser — only new probe call sites, matching 03-06's own stated design goal"
    - "EXIT_NOTIFY_STOP-gated graceful stop in entrypoint.sh — an unconditional early client self-stop was tried first and discovered, by actually running the harness, to break every other scenario via --abort-on-container-exit racing the server's own survival window"
    - "sessionCloseObserver wraps the *ovpn.Session attached to netstack purely to time when Read returns io.EOF, preserving Session.Read's single-reader-goroutine contract since Attach still starts exactly one reader"
    - "-hold and session-close detection merged into one reactive poll loop rather than a fixed sleep followed by a separate check — the fixed-sleep-then-check ordering was the root cause of the first close-detection bug"

key-files:
  created:
    - test/interop/docker-compose.reneg.yml
    - .planning/phases/04-durable-sessions/deferred-items.md
  modified:
    - session.go
    - ovpn.go
    - cmd/gentestpki/main.go
    - test/interop/interop_test.go
    - test/interop/server/main.go
    - test/interop/entrypoint.sh
    - reneg_test.go
    - gates_test.go

key-decisions:
  - "reneg-sec 15 on the client (via -client-directive) and -reneg-sec 15s on the server, deliberately shorter than RESEARCH's own '~20s' suggestion, chosen to fit comfortably inside the scenario's own -hold/contextTimeout budget"
  - "The renegotiation and exit-notify proofs share ONE scenario entry ('reneg') and one overlay rather than two, since the graceful-stop step runs strictly after every probe round and subpage probe has already finished — no timing conflict"
  - "renegMinInterval computed as Server.renegSec/60 (renegMinIntervalDivisor), resolved once in Serve alongside renegSec, rather than the old fixed defaultRenegSec/60 constant — preserves the original 1/60 defense-in-depth ratio while scaling with whatever RenegSec is actually configured"
  - "A SOFT_RESET_V1 whose key-id already matches sess.pendingRenegKeyID is routed to that existing Conn via sess.routeControlPacket before ever considering it a new renegotiation attempt — closes the race where both sides' independent reneg-sec timers fire within the same poll tick"
  - "assertNoReconnect and the reconnect-forcing acceptance criterion were demonstrated via a throwaway Go-level test (constructing a synthetic scenarioResult with a forged double 'Initialization Sequence Completed') rather than forcing an actual OpenVPN client reconnect in Docker — a faster, equally rigorous proof of the assertion logic itself, deleted before the final commit"

patterns-established:
  - "Any future interop scenario carrying a shortened Config.RenegSec must also budget for Server.renegMinInterval scaling with it — a fixed floor derived from the reference's own 3600s default would silently block renegotiation cycling below 60s"
  - "A scenario adding a graceful client-side stop step must gate it behind a scenario-specific env var, never make it unconditional — --abort-on-container-exit reacts to ANY container's exit, not just the server's"

requirements-completed: [SESS-04, SESS-05]

coverage:
  - id: D1
    description: "A real, unmodified OpenVPN 2.6 client renegotiates its keys against the library at least twice in one automated harness run while HTTP and UDP probes keep succeeding across the rollovers, and the client's own log shows exactly one completed initialization sequence (zero reconnects)"
    requirement: "SESS-04"
    verification:
      - kind: integration
        ref: "go test -tags interop -run TestInteropScenarios/reneg (server PASS line: renegotiations=3; every http_landing_rN/udp_echo_rN probe result=ok; client log shows exactly one 'Initialization Sequence Completed')"
        status: pass
    human_judgment: false
  - id: D2
    description: "The reconnect-detection assertion (assertNoReconnect) is proven meaningful: it fails on a forged double-reconnect log and passes on a legitimate single-reconnect log"
    verification:
      - kind: unit
        ref: "throwaway TestDemoAssertNoReconnectCatchesReconnect (deleted before final commit) — shouldFail subtest correctly failed on a synthetic double 'Initialization Sequence Completed', shouldPass correctly passed on a single occurrence"
        status: pass
    human_judgment: false
  - id: D3
    description: "A real client's explicit-exit-notify (graceful SIGTERM) closes the server's Session within seconds — observed via Session.Read returning io.EOF — comfortably under the 60s idle-reap window, proving the teardown came from exit-notify and not the reap timer"
    requirement: "SESS-05"
    verification:
      - kind: integration
        ref: "go test -tags interop -run TestInteropScenarios/reneg (assertExitNotifyClosesPromptly: 0s elapsed between client's graceful stop and server's observed close, threshold 15s)"
        status: pass
    human_judgment: false
  - id: D4
    description: "No pre-existing Phase 1/2/3 interop assertion is deleted, weakened, or made conditional; the three pre-existing scenarios (clean-small, clean-large, lossy-large) keep their existing client.conf and pass unchanged"
    verification:
      - kind: integration
        ref: "go test -tags interop -run TestInteropScenarios (all 4 scenarios pass in one run, interop-task23d.log); go run ./cmd/gentestpki -profile small with no -client-directive flag produces a byte-identical client.conf to before this plan"
        status: pass
    human_judgment: false
  - id: D5
    description: "The server container's unprivileged posture (no cap_add, no privileged, no devices) is re-asserted on the new 'reneg' scenario, and no new go.mod dependency was introduced"
    verification:
      - kind: unit
        ref: "gates_test.go#TestPhase3ServerContainerRequestsNoPrivileges, #TestPhase4NoNewModuleDependencies; interop_test.go#assertServerStaysUnprivileged run on the reneg scenario"
        status: pass
    human_judgment: false
  - id: D6
    description: "A standing gate prevents a future edit from silently dropping either the reneg-sec or explicit-exit-notify directive from the reneg scenario's client config, leaving it passing vacuously"
    verification:
      - kind: unit
        ref: "gates_test.go#TestPhase4InteropClientConfigCarriesLifecycleDirectives"
        status: pass
    human_judgment: false
duration: ~45min
completed: 2026-08-28
status: complete
---

# Phase 4 Plan 03: Real-Client Renegotiation and Exit-Notify Interop Summary

**A real, unmodified OpenVPN 2.6 client renegotiates against the library three times in one run while HTTP/UDP traffic keeps flowing (zero reconnects), then its explicit-exit-notify closes the server's Session within a second of a graceful stop — proving both of Phase 4's success criteria against the reference implementation, not just a synthetic client.**

## Performance

- **Duration:** ~45 min (commit span 12:02–12:43 CEST 2026-08-28, plus preceding research/reading)
- **Tasks:** 3/3
- **Files modified:** 10 (2 created: `test/interop/docker-compose.reneg.yml`, `.planning/phases/04-durable-sessions/deferred-items.md`)

## Accomplishments

- A new `reneg` scenario joins the interop table: `cmd/gentestpki` gains a repeatable `-client-directive` flag appending scenario-specific `client.conf` lines (default none, so the three pre-existing scenarios' generated config stays byte-identical), wired through a new `docker-compose.reneg.yml` overlay and `scenario.composeOverlay`/`clientDirectives`/`minRenegotiations`/`probeRounds` fields generalizing the old lossy-only overlay selection.
- `test/interop/server/main.go` gains `-reneg-sec`/`-hold` flags (`Config.RenegSec` passthrough and an extra survival window), a `renegotiations=` PASS-line field sourced from the new `Session.RenegotiationCount()` diagnostic accessor, and a `sessionCloseObserver` that times when a real client's explicit-exit-notify closes the session (`exit_notify_close_after=` on the PASS line, a distinct `close_observed_epoch=` log line).
- `entrypoint.sh` gains `ROUND_COUNT`/`ROUND_INTERVAL`-driven multi-round HTTP/UDP probes (round-suffixed `PROBE` names, no new parser) and an `EXIT_NOTIFY_STOP`-gated graceful client stop that actually transmits explicit-exit-notify rather than being killed outright by compose teardown.
- `interop_test.go` asserts, on the `reneg` scenario: at least 2 reported rollovers (`assertRenegotiation`), every round's probes `result=ok` (`assertMultiRoundProbes`), exactly one client-side "Initialization Sequence Completed" alongside genuine `TLS: soft reset` evidence (`assertNoReconnect`, T-04-11), and the exit-notify close observed comfortably under the 60s reap window (`assertExitNotifyClosesPromptly`, T-04-12) — while every pre-existing Phase 1/2/3 assertion still runs, unweakened, on the three original scenarios.
- **Two real production bugs found and fixed by actually running this scenario against a real client** (not caught by 04-01's synthetic-client fast-tier tests): `Server.renegMinInterval` was hardcoded from the reference's own 3600s default (`/60 = 60s`) regardless of the *active* `Config.RenegSec`, silently refusing every renegotiation after the first whenever a shortened reneg-sec was configured; and `handleDatagram` always treated an incoming `SOFT_RESET_V1` as "begin a new attempt", dropping a real client's ClientHello-bearing retransmission forever whenever it raced the server's own independently-fired reneg-sec timer to the same next key-id. Both fixed in `ovpn.go`, verified by three full Docker runs showing 1, then 3 renegotiations complete cleanly.
- `gates_test.go` gains `TestPhase4InteropClientConfigCarriesLifecycleDirectives`, a static AST gate ensuring the `reneg` scenario's client directives can never quietly lose either the reneg-sec or explicit-exit-notify line.

## Task Commits

Each task was committed atomically:

1. **Task 1: A real OpenVPN 2.6 client renegotiates against the library and keeps loading pages** - `93c7cf6` (feat)
2. **Task 2: Traffic survives two rollovers, and the client never reconnects** - `684d467` (feat)
3. **Task 3: A real client says goodbye and the server notices at once** - `934b4a5` (feat)

_No separate TDD RED/GREEN commits: `tdd_mode` is `false` in this project's config, matching 04-01/04-02's own precedent._

_Tracer feedback gate (Task 1): the full Docker interop suite was re-run end-to-end immediately after Task 1's commit (all four scenarios, including the new "reneg" entry, PASS) before proceeding to Task 2 — this worktree-isolated parallel wave agent has no interactive checkpoint-resume path for a plan with no `checkpoint:*` tasks, the same judgment call 03-01's and 03-06's own summaries recorded for this identical situation._

## Files Created/Modified

- `session.go` - `Session.renegotiations` field; `RenegotiationCount()` diagnostic accessor
- `ovpn.go` - `sess.renegotiations++` inside `runRenegotiation`'s atomic swap; `Server.renegMinInterval` field (resolved in `Serve` as `renegSec/renegMinIntervalDivisor`, replacing the old fixed `renegMinInterval` constant); `handleDatagram`'s `SOFT_RESET_V1` branch now checks `sess.routeControlPacket` for an already-in-flight match before calling `beginRenegotiation`
- `cmd/gentestpki/main.go` - `clientDirectiveFlag`/`-client-directive` repeatable flag; `writeClientConf` appends extra directives verbatim
- `test/interop/docker-compose.reneg.yml` - new overlay: server `-reneg-sec 15s -hold 60s -deadline 60s`; client `ROUND_COUNT=5 ROUND_INTERVAL=8 EXIT_NOTIFY_STOP=1` (created)
- `test/interop/server/main.go` - `-reneg-sec`/`-hold` flags; `establishedSession`/`sessionCloseObserver`; merged hold+close-detection survival loop; `renegotiations=`/`exit_notify_close_after=` PASS-line fields; `close_observed_epoch=` log line
- `test/interop/entrypoint.sh` - `ROUND_COUNT`/`ROUND_INTERVAL`-driven probe round loop (`round_suffix` helper); `EXIT_NOTIFY_STOP`-gated graceful stop (`PROBE exit_notify_stop_issued epoch=`)
- `test/interop/interop_test.go` - `scenario.composeOverlay`/`clientDirectives`/`minRenegotiations`/`probeRounds` fields; `reneg` scenario entry; `assertRenegotiation`, `assertMultiRoundProbes`, `assertNoReconnect`, `assertExitNotifyClosesPromptly`; `renegotiationsRe`/`exitNotifyStopIssuedRe`/`sessionCloseObservedRe` regexes
- `reneg_test.go` - `TestRenegFloodRateLimited`'s hand-built `Server` sets `renegMinInterval` explicitly (mirrors `handshakeWindow`/`reapWindow`'s own precedent for hand-built Servers bypassing `NewServer`'s defaults)
- `gates_test.go` - `TestPhase4InteropClientConfigCarriesLifecycleDirectives`
- `.planning/phases/04-durable-sessions/deferred-items.md` - two out-of-scope discoveries logged (created)

## Decisions Made

- `reneg-sec 15` (client) / `-reneg-sec 15s` (server) — shorter than RESEARCH's own "~20s" suggestion, chosen to fit the scenario's `-hold`/`contextTimeout` budget while still producing 2+ rollovers reliably.
- One shared `reneg` scenario carries both the renegotiation and exit-notify proofs (not two scenarios sharing an overlay) — the graceful stop always runs after every probe round and subpage probe, so there's no timing conflict.
- `renegMinInterval` is now `Server.renegSec / renegMinIntervalDivisor` (60), resolved once in `Serve`, not a fixed package constant — preserves the original 1/60 defense-in-depth ratio while scaling with whatever `RenegSec` is actually configured (04-01's own fixed-60s design implicitly assumed reneg-sec would never be shortened below 60s in practice, which this interop scenario's own D-23 requirement immediately violates).
- A `SOFT_RESET_V1` matching `sess.pendingRenegKeyID` is delivered to the existing `pendingReneg` Conn via `sess.routeControlPacket` before `beginRenegotiation` ever runs — closes the race where both sides' independent reneg-sec timers fire within the same poll tick and the loser's own ClientHello would otherwise be silently and permanently dropped.
- `assertNoReconnect`'s "proven meaningful" acceptance criterion was satisfied via a throwaway Go-level unit test (a synthetic `scenarioResult` with a forged double "Initialization Sequence Completed" string) rather than forcing an actual OpenVPN client reconnect inside Docker — equally rigorous proof of the assertion's own logic, at a fraction of the cost, deleted before the final commit.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `Server.renegMinInterval` blocked every renegotiation after the first under a shortened reneg-sec**
- **Found during:** Task 2, first full Docker run of the multi-round "reneg" scenario (`renegotiations=1` reported no matter how many times the client's own 15s timer re-fired)
- **Issue:** `renegMinInterval` was a package constant fixed at `defaultRenegSec/60` (3600s/60 = 60 seconds) regardless of the server's actually-configured `Config.RenegSec`. With `-reneg-sec 15s` (this scenario's own shortened value), every renegotiation after the first legitimate one arrived well within that fixed 60-second floor and was silently refused by the T-04-01 rate-limit guard in `startRenegotiation` — a design gap that only surfaces once a harness actually configures a reneg-sec shorter than 60 seconds.
- **Fix:** Added `Server.renegMinInterval time.Duration`, resolved once in `Serve()` as `s.renegSec / renegMinIntervalDivisor` (still 1/60th, but of the *active* value), replacing the fixed constant everywhere it was read.
- **Files modified:** `ovpn.go`, `reneg_test.go` (the hand-built `TestRenegFloodRateLimited` fixture needed the field set explicitly, per this codebase's own established precedent for hand-built `Server`s bypassing `NewServer`'s defaults).
- **Verification:** Full `go test -race -count=1 ./...` and `make gates` still pass; a subsequent full Docker run showed 2 rollovers within the scenario window.
- **Committed in:** `684d467` (Task 2 commit).

**2. [Rule 1 - Bug] A `SOFT_RESET_V1` racing an already-in-flight renegotiation was silently and permanently dropped**
- **Found during:** Task 2, second full Docker run — even after fixing deviation 1, the SECOND rollover's TLS handshake never completed: the server sent one `opcode=3` (its own server-initiated `SendReset`) and then went silent, while the real client kept retransmitting its own `SOFT_RESET_V1` (carrying its ClientHello) with exponential backoff, always rejected.
- **Issue:** `handleDatagram`'s `SOFT_RESET_V1` branch unconditionally called `beginRenegotiation`, which refuses any request when `sess.pendingReneg != nil` (T-04-01's in-flight-wins guard). Because both sides run independent, symmetric reneg-sec timers that reset from nearly the same completion moment after every rollover, they can fire within the same 1-second poll tick: when the server's own `checkReneg` won the race locally and published a bare, payload-less `pendingReneg` Conn first, the real client's own independently-triggered `SOFT_RESET_V1` — carrying its actual ClientHello — was refused outright and its bytes never delivered anywhere. The client's reliability layer then retransmitted the identical, forever-doomed packet.
- **Fix:** Before calling `beginRenegotiation`, `handleDatagram` now checks `sess.routeControlPacket(cp.KeyID)` — the same routing logic `pump` already uses for ordinary post-handshake traffic — and delivers the packet directly to the existing `pendingReneg` Conn if one already matches that key-id, treating the "losing" side's own initiation as simply the other side's ClientHello finally arriving.
- **Files modified:** `ovpn.go`.
- **Verification:** Full `go test -race -count=1 ./...`, `make gates`, and three subsequent full Docker interop runs, all showing 2-3 completed rollovers with real TLS handshake traffic (`opcode=4`) flowing on the new key-id, not just retransmitted `opcode=3` resets.
- **Committed in:** `684d467` (Task 2 commit).

**3. [Rule 1 - Bug] Unconditional early client self-stop broke every pre-existing scenario**
- **Found during:** Task 3, first full Docker run after adding the graceful-stop step
- **Issue:** An initial version sent `kill -TERM` to the OpenVPN client process unconditionally, on every scenario, immediately after the probe sequence finished. For the three pre-existing scenarios (which finish their brief probe sequence well before the server's own probe-driven survival window ends), this made the CLIENT container exit first — and docker compose's `--abort-on-container-exit` tears the whole run down the instant *any* container exits, killing the server mid-flight, well before it ever printed PASS (`govpn-interop-server exited with code 2`).
- **Fix:** Gated the graceful-stop step behind a new `EXIT_NOTIFY_STOP` env var, defaulting to `0` (every pre-existing scenario, unaffected — the client stays blocked in `wait "$OVPN_PID"` exactly as before), set to `1` only by `docker-compose.reneg.yml`'s client environment.
- **Files modified:** `test/interop/entrypoint.sh`, `test/interop/docker-compose.reneg.yml`.
- **Verification:** Full Docker interop run showing all three pre-existing scenarios exiting cleanly (server exit code 0) alongside the reneg scenario's own exit-notify success.
- **Committed in:** `934b4a5` (Task 3 commit).

**4. [Rule 1 - Bug] `-hold`'s unconditional fixed sleep raced the client's own early exit**
- **Found during:** Task 3, second full Docker run (after fixing deviation 3) — the reneg scenario itself still failed: the client's own explicit-exit-notify closed and self-terminated (exit code 0) well before the server's fixed 60-second `-hold` sleep completed, so `--abort-on-container-exit` again killed the server mid-sleep (exit code 2) before it ever reached the close-detection check that ran only *after* that sleep.
- **Fix:** Merged the `-hold` sleep and the session-close-detection check into one reactive poll loop (200ms granularity) that exits as soon as EITHER condition is met — `-hold`'s deadline elapsing (preserving every pre-existing scenario's exact behavior, since none of them ever observe a close) or `sessionCloseObserver.observedClose()` reporting true. The server now reacts to a real client's exit-notify within one poll tick, comfortably before the client's own configured `explicit-exit-notify` grace period expires and it self-terminates — so the server's own clean exit is what triggers the abort, exactly as `--exit-code-from server` intends.
- **Files modified:** `test/interop/server/main.go`.
- **Verification:** Full Docker interop run: server exit code 0, `close_observed_epoch=` printed within the same second as the client's graceful stop, `exit_notify_close_after=` reported on the PASS line.
- **Committed in:** `934b4a5` (Task 3 commit).

---

**Total deviations:** 4 auto-fixed (4 Rule 1 bugs — two genuine library-level renegotiation bugs and two test-harness orchestration bugs, all discovered by actually running the real-client interop scenario this plan exists to build, and all fixed before their respective task's commit).
**Impact on plan:** No scope creep beyond `ovpn.go` (not in the plan's stated `files_modified` list, but required by Task 1's own action text to instrument `runRenegotiation`, and subsequently required by these two bug fixes to make the scenario the plan itself specifies actually pass against a real client). Every fix is a correctness fix directly caused by this plan's own new scenario; nothing outside that scope was touched.

## Issues Encountered

- **Pre-existing, unrelated `lossy-large` interop flake:** one of four full Docker interop runs during this plan's execution saw the pre-existing (Phase 1/2, unmodified) `lossy-large` scenario fail `assertKeyExchangeCompleted` because the client's own unseeded `tc netem` loss caused one abandoned handshake attempt before a successful retry — the client's log then contains the literal "TLS key negotiation failed" string from the abandoned attempt even though the scenario otherwise completed normally. Two of the four runs (including the one immediately preceding this plan's final commits) passed `lossy-large` cleanly. Logged in `deferred-items.md` as out of scope: this plan's three tasks never touch `docker-compose.lossy.yml` or the lossy-large scenario's own configuration.
- **Pre-existing, unrelated flaky `TestTCPRespectsPeerWindow`** (netstack package, Phase 3): observed once during fast-tier verification, passed on immediate re-run and on every subsequent full-suite run. Logged in `deferred-items.md`; `netstack/` is untouched by any of this plan's tasks.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running for `make interop` (a plan precondition, verified via `docker info` at the start of execution).

## Next Phase Readiness

- ROADMAP Phase 4 success criteria 1 and 2 are both closed against a real client: renegotiation with HTTP/UDP traffic flowing across 3 rollovers and zero reconnects, and explicit-exit-notify ending the session within a second of a graceful stop.
- Plan `04-04`'s soak test can reuse this plan's overlay pattern, the `-hold` flag, and the graceful-stop step to drive its own connect/disconnect cycles — `sessionCloseObserver` and the merged hold/close-detection loop are directly reusable for observing repeated teardown events.
- No blockers. `go build ./... && go vet ./... && go test -race -count=1 ./...`, `make gates`, and `make test` all exit 0. `git diff --stat go.mod go.sum` produces no output — the core module stays stdlib-only.

---
*Phase: 04-durable-sessions*
*Completed: 2026-08-28*

## Self-Check: PASSED

- All key files confirmed present on disk: `session.go`, `ovpn.go`, `cmd/gentestpki/main.go`, `test/interop/docker-compose.reneg.yml`, `test/interop/server/main.go`, `test/interop/entrypoint.sh`, `test/interop/interop_test.go`, `reneg_test.go`, `gates_test.go`, `.planning/phases/04-durable-sessions/deferred-items.md`.
- All three task commits confirmed present in `git log --oneline`: `93c7cf6`, `684d467`, `934b4a5`.
- `go build ./...`, `go vet ./...`, `go vet -tags interop ./test/interop/...`, `go test -race -count=1 ./...`, `make gates`, and `make test` all confirmed exit 0 on the final committed state.
- Full `go test -tags interop -run TestInteropScenarios` run (all four scenarios) confirmed passing clean on the exact committed code (`interop-task23d.log`, 134.262s): `renegotiations=3`, exactly one client-side "Initialization Sequence Completed", `exit_notify_close_after=47.386s`, all pre-existing assertions green.
- `git diff --diff-filter=D --name-only` produced no output across all three task commits — no accidental deletions.
- `git diff --stat go.mod go.sum` produced no output — the core module stays stdlib-only.
