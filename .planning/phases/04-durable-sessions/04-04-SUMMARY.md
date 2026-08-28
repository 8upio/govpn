---
phase: 04-durable-sessions
plan: "04"
subsystem: testing
tags: [openvpn, interop, docker, soak, goroutine-leak, heap-leak, session-lifecycle]

# Dependency graph
requires:
  - phase: 04-durable-sessions
    provides: "04-02's OCC_EXIT detection, idle-session reaper, and completed io.EOF/goroutine teardown contract — the soak measures exactly this contract's completeness over 20 real cycles"
  - phase: 04-durable-sessions
    provides: "04-03's reneg scenario, sessionCloseObserver, the merged -hold/close-detection reactive poll loop, and scenario.composeOverlay/clientDirectives fields — all reused directly for the soak's own overlay and close-detection"
provides:
  - "A tagged, longer-timeout soak test (make soak) proving one long-lived server process serves 20 real connect/use/clean-disconnect cycles from an unmodified OpenVPN 2.6 client, every cycle ending through explicit-exit-notify"
  - "Goroutine-count and post-GC HeapAlloc flatness assertions (baseline sampled after cycle 1 closes, final after cycle 20 closes), both demonstrated failing on an injected regression before being trusted"
  - "A tunnel-IP pool-reuse assertion: all 20 cycles served from the same single address, proving Close releases the allocation back to the pool every time"
  - "Three standing TestPhase4Soak* gates enforcing this plan's own prohibitions against a vacuous soak"
affects: []

# Actuals (#2632)
actuals:
  tokens: 11293
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "soakTracker: counts cycle opens/closes and gates two one-shot channels (firstClosed for the baseline trigger, allClosed for the soak's own survival condition) from inside watchClose's per-session poll loop, mirroring 04-03's sessionCloseObserver polling precedent rather than adding a second reader of the *ovpn.Session"
    - "runSoak is dispatched from main() entirely separately from run() — no shared code path, no branch inside run()'s tightly-coupled single-session channel/select logic — so every pre-existing scenario's probe-driven behavior is provably untouched by this plan's existence"
    - "entrypoint.sh's run_soak_cycles is gated behind CYCLE_COUNT>1, guarding the ENTIRE new connect/probe/exit-notify/disconnect loop as one branch rather than threading cycle-awareness through the pre-existing linear script"
    - "Tolerances are chosen from real observed run data, not guessed: the plan's own instruction to run first and observe before hardcoding — and the heap tolerance was caught being too loose (1 MiB) by Task 3's own failure demonstration, then tightened to 256 KiB against real leak vs. real noise numbers"

key-files:
  created:
    - test/interop/docker-compose.soak.yml
  modified:
    - test/interop/server/main.go
    - test/interop/entrypoint.sh
    - test/interop/interop_test.go
    - Makefile
    - gates_test.go

key-decisions:
  - "runSoak is a wholly separate function from run(), dispatched in main() before run() is ever called — zero risk to any pre-existing scenario's behavior, at the cost of ~80 lines of setup duplication (loadConfig/stack/httpLn/udpConn), a trade explicitly worth it given the plan's own prohibition against weakening any pre-existing assertion"
  - "TestSoak is its own test function, never folded into the `scenarios` table TestInteropScenarios drives — interop_test.go's TestMain gained a runFlagOnlyTargets(\"TestSoak\") guard so `-run 'TestSoak'` skips the unrelated scenario table's own Docker runs entirely, keeping the soak's own timeout meaningful"
  - "Each soak cycle runs exactly one HTTP probe (http_landing_cN) and a short 3-count ping — not the full multi-page probe suite reneg's ROUND_COUNT loop runs — since 20 cycles' own per-cycle cost (fresh handshake, tun0 wait, graceful stop) already dominates the run's total time"
  - "SOAK_FINAL_HOLD (300s ceiling): after the client's own last cycle exits, the client container must stay alive until the SERVER's own exit triggers --abort-on-container-exit — the same ordering lesson 04-03-SUMMARY.md's Deviations 3-4 recorded (whichever container exits first wins the abort race) — in practice this ceiling is never reached since compose collapses within a poll tick of the server's own clean exit"
  - "soakGoroutineTolerance=2, soakHeapToleranceBytes=256 KiB, soakMaxDistinctIPs=2 — all three chosen from real 20-cycle run data (baseline/final goroutines 5/4, heap 282816-331824 bytes across three clean runs) and validated by Task 3's own failure demonstrations, not picked a priori"

patterns-established:
  - "A future test function that needs its own Docker timeout independent of the scenarios table should follow TestSoak's own pattern: call runScenario directly with a one-off scenario value, and extend TestMain's runFlagOnlyTargets guard for its own -run name"
  - "Any new soak-style measurement (goroutine/heap/other) must be demonstrated failing on a real injected regression before its tolerance is trusted — Task 3's own heap-tolerance near-miss (1 MiB passed a 621 KiB leak) is the concrete argument for why this discipline exists, not merely a plan instruction"

requirements-completed: [SESS-05]

coverage:
  - id: D1
    description: "A single tagged harness run drives 20 connect/disconnect cycles of a real, unmodified OpenVPN 2.6 client against one long-lived server process, and every cycle reaches tunnel-up and ends through explicit-exit-notify"
    requirement: "SESS-05"
    verification:
      - kind: integration
        ref: "make soak (go test -tags interop -run 'TestSoak'): soak_cycles_observed=20, every cycle's http_landing_cN probe result=ok, each cycle's session closed via observed io.EOF from the graceful stop, not the deadline or idle-reap timer"
        status: pass
    human_judgment: false
  - id: D2
    description: "The server's goroutine count after the final cycle is within a documented tolerance of the baseline sampled after the first cycle — no per-session goroutine accumulates across cycles"
    requirement: "SESS-05"
    verification:
      - kind: integration
        ref: "make soak: goroutine count baseline=5 final=4 (delta=-1, within +/-2); demonstrated failing (delta=7) when runReap's stopCh case was temporarily removed, then confirmed re-passing clean after restore"
        status: pass
    human_judgment: false
  - id: D3
    description: "The server's post-GC HeapAlloc after the final cycle is within a documented tolerance of the same baseline — no per-session heap state accumulates"
    requirement: "SESS-05"
    verification:
      - kind: integration
        ref: "make soak: HeapAlloc baseline=283584-291136 final=321056-349152 bytes across three clean runs (delta ~37-60 KiB, within +/-256 KiB); demonstrated failing (delta=605832-621224 bytes) when every closed session was temporarily retained in a package-level slice, then confirmed re-passing clean after restore"
        status: pass
    human_judgment: false
  - id: D4
    description: "Every tunnel IP and peer-id allocated during the soak was released: the pool serves cycle 20 from the same small address range cycle 1 used"
    requirement: "SESS-05"
    verification:
      - kind: integration
        ref: "make soak: assertSoakIPsReused — all 20 cycles' assigned tunnel IPs identical (10.8.0.2), 1 distinct address, within the soakMaxDistinctIPs=2 bound"
        status: pass
    human_judgment: false
  - id: D5
    description: "The soak is a separate, longer-timeout target and does not slow the default make test or the existing make interop run"
    verification:
      - kind: unit
        ref: "gates_test.go#TestPhase4SoakIsNotInDefaultTargets (Makefile's test/interop recipes never mention TestSoak or soak; .DEFAULT_GOAL stays test)"
        status: pass
    human_judgment: false
  - id: D6
    description: "The soak cannot pass vacuously: it asserts the observed cycle count against the configured one, and the baseline sample cannot be silently moved to a cold-start sample"
    verification:
      - kind: unit
        ref: "gates_test.go#TestPhase4SoakAssertsObservedCycleCount, #TestPhase4SoakSamplesBaselineAfterFirstCycle"
        status: pass
    human_judgment: false
  - id: D7
    description: "No pre-existing Phase 1/2/3/4 interop assertion is deleted, weakened, or made conditional; run() and every pre-existing scenario's behavior is untouched by the soak's existence"
    verification:
      - kind: integration
        ref: "go test -tags interop -run TestInteropScenarios (all 4 pre-existing scenarios — clean-small, clean-large, lossy-large, reneg — pass unchanged in the same run this plan's own code produced)"
        status: pass
    human_judgment: false
duration: ~2h
completed: 2026-08-28
status: complete
---

# Phase 4 Plan 04: Soak Test — 20 Cycles, Flat Goroutines, Flat Heap Summary

**A `make soak` target drives one long-lived server process through 20 real connect/use/clean-disconnect cycles of an unmodified OpenVPN 2.6 client, proving goroutine count and post-GC HeapAlloc both return to their post-first-cycle baseline and the tunnel-IP pool is reused rather than climbing — both flatness assertions demonstrated failing on injected regressions (a leaked goroutine, retained sessions) before being trusted.**

## Performance

- **Duration:** ~2h (including six full 20-cycle Docker soak runs totaling ~17 minutes of pure test time, used to observe real numbers, tighten a tolerance, and demonstrate two failure modes)
- **Tasks:** 3/3
- **Files modified:** 6 (1 created: `test/interop/docker-compose.soak.yml`)

## Accomplishments

- **Task 1 — the mechanism, proven small first:** `test/interop/server/main.go` gained a `-soak-cycles` flag dispatched to a wholly separate `runSoak` function (never touching `run()`'s single-session, probe-driven path), a `soakTracker` counting cycle opens/closes via the same `sessionCloseObserver` polling pattern 04-03 established, and a `soak_cycles_observed=` PASS-line field. `entrypoint.sh` gained `run_soak_cycles`, gated behind `CYCLE_COUNT>1` so every pre-existing scenario's flow is byte-for-byte unchanged: each cycle starts a fresh `openvpn` client, waits for `tun0`, pings, runs one `http_landing_cN` probe, gracefully stops (transmitting real explicit-exit-notify), and waits for the client to actually exit. A 3-cycle run proved the whole mechanism end-to-end before scaling up.
- **Task 2 — 20 cycles, flat numbers:** `takeSoakSample` (two forced GCs, a settle delay, then `runtime.NumGoroutine`/`ReadMemStats().HeapAlloc`) is called once after cycle 1's session closes (never at process start — a cold-start baseline would hide lazy runtime initialization) and once after cycle 20's. `soakGoroutineTolerance` (2) and `soakHeapToleranceBytes` (initially 1 MiB, see Task 3) are named constants whose doc comments record the real observed baseline/final numbers. `assertSoakIPsReused` confirms all 20 cycles' tunnel IPs come from the same small address range. The Makefile's own `soak` target regenerates the PKI and runs only `TestSoak`, deliberately outside `test`/`interop`.
- **Task 3 — proven, not decorative:** Temporarily removing `runReap`'s `stopCh` exit case leaked one goroutine per cycle and failed the goroutine assertion (delta=7, want ±2). Temporarily retaining every closed session in a package-level slice inflated HeapAlloc by ~606 KiB — which the ORIGINAL 1 MiB tolerance did not catch, so this demonstration also caught an insufficiently tight tolerance before it shipped; tightening to 256 KiB (still ~6-7x the ~40 KiB of observed clean-run noise) made the same leak fail cleanly. Both regressions were reverted and `make soak` re-verified green before any commit. Three new `TestPhase4Soak*` gates enforce the plan's own prohibitions against a vacuous soak.

## Task Commits

Each task was committed atomically:

1. **Task 1: Three clean cycles against one server process** - `767cdfb` (feat)
2. **Task 2: Twenty cycles, and the numbers come back flat** - `48802c7` (feat)
3. **Task 3: Prove the soak can actually fail** - `8c362e8` (feat)

_No separate TDD RED/GREEN commits: `tdd_mode` is `false` in this project's config, matching every prior Phase 4 plan's own precedent._

_Task 1's Docker changes were split into two commits during authoring (server/main.go's sampling code was drafted ahead of schedule, then reverted to a Task-1-only shape, committed, and reapplied for Task 2) purely to keep each task's own commit an accurate, independently-revertable snapshot of that task's own scope — no functional difference from a linear Task 1 -> Task 2 authoring order._

## Files Created/Modified

- `test/interop/server/main.go` — `-soak-cycles` flag; `runSoak` (dispatched separately from `run()`); `soakTracker` (opens/closes/ips, `firstClosed`/`allClosed` one-shot channels); `takeSoakSample`/`soakSample`; `soak_cycles_observed=`/`soak_goroutines_baseline=`/`soak_goroutines_final=`/`soak_heap_baseline=`/`soak_heap_final=`/`soak_ips=` PASS-line fields
- `test/interop/entrypoint.sh` — `CYCLE_COUNT`/`CYCLE_PAUSE`/`SOAK_PING_COUNT`/`SOAK_FINAL_HOLD` env vars; `run_soak_cycles` (gated behind `CYCLE_COUNT>1`, entirely separate from the pre-existing single-connection flow)
- `test/interop/docker-compose.soak.yml` — new overlay: 20 cycles, 2s pause, server `-deadline 600s -soak-cycles 20` (created)
- `test/interop/interop_test.go` — `runFlagOnlyTargets` (TestMain guard); `TestSoak` (its own test function); `soakCycleCount`/`soakContextTimeout`/`soakGoroutineTolerance`/`soakHeapToleranceBytes`/`soakMaxDistinctIPs`; `assertSoakCyclesObserved`/`assertSoakProbesOK`/`assertSoakGoroutinesFlat`/`assertSoakHeapFlat`/`assertSoakIPsReused`
- `Makefile` — `soak` target (own long timeout, outside `test`/`interop`), added to `.PHONY`
- `gates_test.go` — `TestPhase4SoakSamplesBaselineAfterFirstCycle`, `TestPhase4SoakIsNotInDefaultTargets` (+ `makefileTargetRecipe` helper), `TestPhase4SoakAssertsObservedCycleCount`

## Decisions Made

- `runSoak` is a wholly separate function from `run()`, dispatched in `main()` before `run()` is ever reached — zero risk to any pre-existing scenario, at the cost of ~80 lines of setup duplication, an explicit trade given the plan's own "no pre-existing assertion weakened" prohibition.
- `TestSoak` drives its own scenario directly rather than joining the `scenarios` table; `runFlagOnlyTargets("TestSoak")` in `TestMain` skips the unrelated table's own Docker runs when `-run 'TestSoak'` is passed, keeping the soak's own timeout meaningful rather than always paying for four other scenarios first.
- Each cycle runs exactly one HTTP probe (not reneg's full multi-page suite) — 20 cycles' own per-cycle cost (handshake, tun0 wait, graceful stop) already dominates total runtime.
- `SOAK_FINAL_HOLD` (300s ceiling): the client container holds after its last cycle's client process exits, so the SERVER's own clean exit is what triggers `--abort-on-container-exit` — reusing 04-03-SUMMARY.md's own documented ordering lesson from the opposite direction.
- Tolerances (`soakGoroutineTolerance=2`, `soakHeapToleranceBytes=256 KiB`, `soakMaxDistinctIPs=2`) were chosen from real 20-cycle run data and validated by deliberately injecting failures, not picked a priori — Task 3 caught the initial 1 MiB heap tolerance being too loose before it ever shipped.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Initial heap tolerance (1 MiB) did not catch the injected leak**
- **Found during:** Task 3, first heap-leak demonstration run
- **Issue:** Retaining every closed session in a package-level slice grew HeapAlloc by ~621 KiB — comfortably under the Task 2-chosen 1 MiB tolerance, so `make soak` passed even with a genuine per-session heap leak injected. A tolerance that cannot fail on a real leak is exactly the vacuous-assertion risk this plan's own threat register (T-04-16) flags.
- **Fix:** Tightened `soakHeapToleranceBytes` from 1 MiB to 256 KiB — still ~6-7x the ~40 KiB of ordinary allocator noise observed across three independent clean runs, but well under the ~606-621 KiB the injected leak produces. Re-ran the same injected leak to confirm it now fails (delta=605832, want within +/-262144), then restored the demo code and re-verified `make soak` green.
- **Files modified:** `test/interop/interop_test.go` (constant value and its doc comment, updated to record both the real leak numbers and the real clean-run noise numbers this margin was chosen against).
- **Verification:** Three full `make soak` runs — leak fails with 1 MiB tolerance shown incorrect, leak fails with 256 KiB tolerance, clean code passes with 256 KiB tolerance.
- **Committed in:** `8c362e8` (Task 3 commit) — the initial 1 MiB choice from Task 2 (`48802c7`) is superseded here, not left as a latent gap.

---

**Total deviations:** 1 auto-fixed (1 Rule 1 bug — a test-tolerance correctness issue caught by the very failure-demonstration discipline the plan itself mandated, not a production code defect).
**Impact on plan:** No scope creep. This is precisely what Task 3's "prove the soak can actually fail" exists to catch — a tolerance loose enough to pass vacuously — and it was caught and fixed before any commit relied on it, rather than shipping a soak test that could never fail on a real heap leak.

## Issues Encountered

None beyond the deviation above. Six full 20-cycle Docker soak runs (each ~160-171s) were used across the three tasks to: (1) prove the 3-cycle mechanism, (2) observe real 20-cycle baseline numbers, (3) re-verify after finalizing tolerances, (4) demonstrate the goroutine leak, (5) demonstrate the heap leak (twice, after tightening the tolerance), (6) final clean close-out run — all documented inline above rather than as separate incidents, since each was an intentional, planned verification step rather than an unplanned problem.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running for `make soak`/`make interop` (this plan's own precondition, verified via `docker info` at the start of execution).

## Next Phase Readiness

- ROADMAP Phase 4's third and final success criterion is closed against a real client: dead sessions do not accumulate over 20 real connect/disconnect cycles, backed by goroutine and heap flatness assertions that have both been observed catching a real injected regression.
- This is Phase 4's final plan: no downstream plan depends on it. `go build ./... && go vet ./... && go test -race -count=1 ./...`, `make gates`, `make test`, `make interop` (all 4 pre-existing scenarios), and `make soak` all exit 0 in one final clean pass. `git diff --stat go.mod` produces no output — the core module stays stdlib-only throughout this plan.
- No blockers.

---
*Phase: 04-durable-sessions*
*Completed: 2026-08-28*

## Self-Check: PASSED

- All key files confirmed present on disk: `test/interop/docker-compose.soak.yml`, `test/interop/server/main.go`, `test/interop/entrypoint.sh`, `test/interop/interop_test.go`, `Makefile`, `gates_test.go`.
- All three task commits confirmed present in `git log --oneline`: `767cdfb`, `48802c7`, `8c362e8`.
- `go build ./...`, `go vet ./...`, `go vet -tags interop ./test/interop/...`, `go test -race -count=1 ./...`, `make gates`, and `make test` all confirmed exit 0 on the final committed state.
- Full `go test -tags interop -run TestInteropScenarios` run (all four pre-existing scenarios) confirmed passing clean on the exact committed code.
- Final `make soak` run confirmed passing clean on the exact committed code: `soak_cycles_observed=20`, all 20 `http_landing_cN` probes `result=ok`, goroutines baseline=5 final=4 (delta=-1), heap baseline=288208 final=349152 bytes (delta=60944, within +/-262144), 1 distinct tunnel IP across 20 cycles.
- `git diff --diff-filter=D --name-only` produced no output across all three task commits — no accidental deletions.
- `git diff --stat go.mod` produced no output — the core module stays stdlib-only.
