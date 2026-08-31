---
phase: 03-in-process-termination
plan: "06"
subsystem: testing
tags: [interop, docker, netstack, udp, http, icmp, gates, tunnelweb]

requires:
  - phase: 03-in-process-termination
    provides: "netstack.Stack (ICMP/UDP/TCP), Stack.ListenTCP/ListenUDP, Stack.Stats() — plans 03-01 through 03-04"
  - phase: 03-in-process-termination
    provides: "examples/tunnelweb/site.Handler — the pages the interop harness now serves and probes — plan 03-05"
provides:
  - "One automated `make interop` run verifying ICMP echo, a UDP round-trip, and an HTTP page load (landing/status/echo/headers) through the tunnel from a real, unmodified OpenVPN 2.6.14 client, with the server container proven unprivileged both at runtime (docker inspect) and statically (a compose-file gate)"
  - "A negative probe proving the tunnelweb site is unreachable from outside the tunnel (a direct curl at the server container's own Docker-network address is refused)"
  - "A probe-driven post-handshake survival window (waitForProbes) replacing the old fixed 20-second sleep, with a raised 45-second ceiling as the fallback"
affects: []

actuals:
  tokens: 10568
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Structured PROBE line format (`entrypoint: PROBE <name> result=<ok|fail> ...`) parsed by one regexp and one assertProbe(t, res, name, required) helper — every new probe this plan or a future one adds needs no new parser, only a new call site"
    - "Probe-driven survival window: waitForProbes polls Stack.Stats()/atomic counters every 200ms and proceeds once ICMP+UDP+HTTP have each been observed once (plus a settle delay), with the old fixed sleep's duration repurposed as a ceiling fallback rather than the normal path"
    - "Inverted-sense negative probe (outside_tunnel): result=ok means the command FAILED (connection refused/timed out) — commented explicitly at the call site because a probe whose success is a command's failure is exactly the kind of code a later reader 'fixes' by accident"
    - "Comment-stripping static gate over a non-Go file (test/interop/docker-compose.yml): TestPhase3ServerContainerRequestsNoPrivileges isolates the server: service block by indentation, drops '#'-prefixed lines before scanning, mirroring gates_test.go's own AST-vs-text-matching discipline applied to YAML instead of Go"

key-files:
  created: []
  modified:
    - test/interop/server/main.go
    - test/interop/entrypoint.sh
    - test/interop/interop_test.go
    - test/interop/Dockerfile
    - gates_test.go

key-decisions:
  - "nc -u -w <N> blocks for the FULL N seconds even after receiving a reply (UDP has no EOF signal) — confirmed empirically against a real UDP echo server before choosing values. Fixed by lowering the probe's per-attempt timeout to 1s and raising the server's post-condition settle delay to 5s, rather than assuming nc returns early on success."
  - "The probe-driven survival trigger (ICMP+UDP+HTTP each observed once) fires well before entrypoint.sh's later probes (http_status/echo/headers, outside_tunnel) run, because ICMP is already true from the pre-existing ping and HTTP is already true from the very first HTTP probe (http_landing) — the settle delay, not the trigger condition itself, is what has to cover the remaining probe sequence. Documented explicitly in probeSettleDelay's doc comment so a future reader doesn't shrink it back to '2 seconds is surely enough'."
  - "docker-compose.yml is unchanged by design (per the plan's own prohibition) — the server service already models the required unprivileged posture; Task 3 only adds a static gate re-asserting it stays that way."

patterns-established:
  - "assertProbe(t, res, name, required) as the one call site every PROBE-line assertion goes through, parameterized by the existing !sc.lossy strictness convention (assertPingRoundTrip's own precedent)"

requirements-completed: [VRFY-02, NET-01, NET-02, NET-03, XMPL-01]

coverage:
  - id: D1
    description: "make interop exits 0 with all three scenarios PASSing, and the clean-small scenario's server PASS line carries non-zero ping_rx=/ping_tx=/udp_rx=/udp_tx=/http_requests= — one automated run verifying ICMP, a UDP round-trip, and an HTTP page load through the tunnel from a real client (VRFY-02)"
    requirement: "VRFY-02"
    verification:
      - kind: integration
        ref: "go test -tags interop -count=1 -timeout 1500s ./test/interop/ -run TestInteropScenarios -v (clean-small, clean-large, lossy-large all PASS)"
        status: pass
    human_judgment: false
  - id: D2
    description: "A UDP datagram sent from the client container to (server tunnel IP, ListenUDP port) is echoed back and observed by the client — the netstack's UDP demux/ListenUDP live path, not a stub (NET-01 live half)"
    requirement: "NET-01"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#assertUDPRoundTrip (PROBE udp_echo result=ok on all three scenarios this run; server udp_rx=1 udp_tx=1)"
        status: pass
    human_judgment: false
  - id: D3
    description: "curl inside the client container loads the landing page and the /status, /echo, and /headers subpages through the tunnel, each asserted against a UI-SPEC content marker, including a POST whose request and response bodies both cross the netstack's TCP (NET-02, XMPL-01 live halves)"
    requirement: "NET-02"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#assertHTTPPageLoad, #assertHTTPSubpages (PROBE http_landing/http_status/http_echo/http_headers all result=ok on clean-small/clean-large; http_landing result=ok on lossy-large)"
        status: pass
    human_judgment: false
  - id: D4
    description: "The Phase-2 hand-rolled ICMP responder stays gone from the harness — every ICMP echo reply comes from netstack, re-asserted via the pre-existing ping_rx=/ping_tx= assertion this plan left untouched (NET-03 live half)"
    requirement: "NET-03"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#assertPingRoundTrip (unchanged; ping_rx=10 ping_tx=10 observed this run on all three scenarios)"
        status: pass
    human_judgment: false
  - id: D5
    description: "The interop server embeds netstack and serves the actual examples/tunnelweb/site pages (imported, not duplicated), so the curl content-marker assertions check byte-identical markup to what a developer sees in a browser (XMPL-01 live half)"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "go vet -tags interop ./test/interop/... (server/main.go imports github.com/8upio/govpn/examples/tunnelweb/site; go build ./... confirms no duplicated markup/template exists in the harness)"
        status: pass
      - kind: integration
        ref: "clean-small server log line 'http GET / -> 200' plus PROBE http_landing result=ok, both from the same served response"
        status: pass
    human_judgment: false
  - id: D6
    description: "A direct curl from the client container at the server container's own Docker-network address fails, proving the site is reachable only through the tunnel (ROADMAP SC 3)"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#assertUnreachableOutsideTunnel (PROBE outside_tunnel result=ok on all three scenarios including lossy-large)"
        status: pass
    human_judgment: false
  - id: D7
    description: "docker inspect re-asserts the server container runs unprivileged with zero added capabilities and zero mapped devices while the netstack actively serves ICMP/UDP/TCP, AND a static gate holds the compose file to the same posture on every make test (ROADMAP SC 4)"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#assertServerStaysUnprivileged (privilegeCheck == \"false 0 0\" on all three scenarios)"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase3ServerContainerRequestsNoPrivileges; manually confirmed to fail when a cap_add key was temporarily added to docker-compose.yml's server block, then reverted (git diff --stat produced no output)"
        status: pass
    human_judgment: false
  - id: D8
    description: "Every pre-existing Phase-1 and Phase-2 assertion is still called and still green: handshake completion with verified peer CN, Key Method 2 completion, tunnel-up, ping round-trip with its existing strictness rule, server-unprivileged, certificate-flight fragmentation on large-cert scenarios, and the lossy scenario's load-factor/retransmission-evidence checks"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#TestInteropScenarios full run: assertHandshakeCompleted, assertKeyExchangeCompleted, assertTunnelUp, assertPingRoundTrip, assertServerStaysUnprivileged (every scenario); assertCertificateFlightFragmented (clean-large, lossy-large); assertLossyLoadFactorsInBand, logRetransmissionEvidence (lossy-large) — all pass this run"
        status: pass
    human_judgment: false

duration: ~40min
completed: 2026-08-27
status: complete
---

# Phase 3 Plan 6: Real-Client Interop Verification Summary

**`make interop` now drives ICMP echo, a UDP round-trip, and four HTTP page loads — including a form POST whose request and response bodies both cross the netstack's TCP — from a real, unmodified OpenVPN 2.6.14 client through the tunnel, plus a negative probe proving the site is unreachable outside it, closing the phase's final gate (ROADMAP Phase 3 success criteria 3 and 4, VRFY-02).**

## Performance

- **Duration:** ~40 min (2026-08-27T00:19 -> 2026-08-27T00:39, plus setup/verification runs)
- **Tasks:** 3/3
- **Files modified:** 5 (all existing files, no new files created)

## Accomplishments

- `test/interop/server/main.go` now embeds `examples/tunnelweb/site.Handler` over `stack.ListenTCP(-http-port)` behind a request-counting/logging middleware, and a UDP echo service over `stack.ListenUDP(-udp-port)` — the interop harness serves the exact pages a developer loads in a browser, imported rather than duplicated, so a passing `curl` content-marker assertion is a marker on the page that actually shipped.
- The post-handshake survival window is now probe-driven (`waitForProbes`): PASS prints once at least one ICMP echo, one UDP datagram, and one HTTP request have all been observed, plus a settle delay — replacing the old fixed 20-second sleep, which is now a 45-second ceiling fallback rather than the normal path.
- `test/interop/entrypoint.sh` runs six new probes after the pre-existing ping — `http_landing`, `udp_echo`, `http_status`, `http_echo`, `http_headers`, `outside_tunnel` — all through one structured `PROBE <name> result=<ok|fail>` line format that `interop_test.go`'s one parser and `assertProbe` helper consume, so a future probe needs no new regexp.
- `test/interop/interop_test.go` asserts every new probe via `assertHTTPPageLoad`, `assertUDPRoundTrip`, `assertHTTPSubpages`, and `assertUnreachableOutsideTunnel`, all parameterized by the pre-existing `!sc.lossy` strictness convention `assertPingRoundTrip` established; scenario timeouts were raised (clean-small 2→3min, clean-large 3→4min, lossy-large 8→10min) to absorb the new probes.
- `gates_test.go` gains `TestPhase3ServerContainerRequestsNoPrivileges`: a static, comment-stripping gate over `docker-compose.yml`'s `server:` service block, run on every `make test` with no Docker required — independent of and complementary to the existing runtime `docker inspect` check. Manually confirmed to fail when a `cap_add` key was temporarily added, then reverted clean.
- A real `curl` from the client container at the server container's own Docker-network alias is refused in every scenario including the lossy one, proving the tunnelweb site binds no OS TCP socket for HTTP at all — the only way to reach it is through the tunnel.
- All three interop scenarios (`clean-small`, `clean-large`, `lossy-large`) pass with every new and pre-existing assertion green, `make gates` and `make test` both exit 0, and `go.mod` is unmodified.

## Task Commits

Each task was committed atomically:

1. **Task 1: A real client loads the example landing page through the tunnel** - `049616d` (feat)
2. **Task 2: ICMP, UDP, and the remaining pages all pass in one run** - `a3b74fe` (feat)
3. **Task 3: The site is unreachable outside the tunnel, and the container stays unprivileged** - `60d1a7a` (test)

**Plan metadata:** commit pending (this SUMMARY.md — worktree mode excludes STATE.md/ROADMAP.md per the orchestrator's own note)

## Files Created/Modified

- `test/interop/server/main.go` - `-http-port`/`-udp-port` flags, `newRequestCountingHandler` (HTTP request counter + per-request log line), `runUDPEcho` (UDP echo goroutine with rx/tx counters), `waitForProbes` (probe-driven survival window), PASS line gains `udp_rx=`/`udp_tx=`/`http_requests=`
- `test/interop/entrypoint.sh` - `HTTP_PORT`/`UDP_PORT` variables, the `PROBE <name> result=<ok|fail>` line format, and six new probes: `http_landing`, `udp_echo`, `http_status`, `http_echo`, `http_headers`, `outside_tunnel`
- `test/interop/interop_test.go` - the `PROBE` line parser (`parseProbeResults`) and `assertProbe` helper, `assertHTTPPageLoad`, `assertUDPRoundTrip`, `assertHTTPSubpages`, `assertUnreachableOutsideTunnel`, content-marker constants citing their UI-SPEC sections, raised scenario `contextTimeout`s, `assertServerStaysUnprivileged`'s extended failure message
- `test/interop/Dockerfile` - `curl` and `netcat-openbsd` added to the pinned client image's install line, with resolved versions recorded in the existing comment block
- `gates_test.go` - `TestPhase3ServerContainerRequestsNoPrivileges`, `serverServiceBlock`, `stripYAMLCommentLines`

## Decisions Made

- **`nc -u -w <N>` blocks for the full `N` seconds even after receiving a reply** (UDP has no EOF signal telling it "no more data is coming") — confirmed empirically against a real UDP echo server (a throwaway Go program on the host, reached from a Debian/netcat-openbsd container via `host.docker.internal`) before choosing values, rather than assumed. Fixed by lowering the probe's per-attempt timeout to 1s and raising `probeSettleDelay` (the server's post-condition wait) to 5s.
- **The probe-driven survival trigger fires well before entrypoint.sh's full probe sequence completes**, because ICMP is already true from the pre-existing ping and HTTP is already true from the very first HTTP probe (`http_landing`) — so `probeSettleDelay`, not the trigger condition itself, is what has to cover the remaining `http_status`/`http_echo`/`http_headers`/`outside_tunnel` probes plus the UDP probe's own remaining block time. Documented explicitly in the constant's doc comment.
- **`docker-compose.yml` is unchanged by design**, per the plan's own prohibition — the server service already models the required unprivileged posture; Task 3 only adds a static gate re-asserting it stays that way.
- **Tracer feedback gate (Task 1) proceeded without an interactive pause**: `workflow._auto_chain_active`/`workflow.auto_advance` are both `false` (interactive run per auto-mode detection), but this plan declares zero `checkpoint:*` tasks anywhere and carries `autonomous: true` in its own frontmatter (Pattern A: fully autonomous), and this execution is a worktree-isolated parallel wave agent with no interactive checkpoint-resume path defined for a plan with no checkpoint tasks — the exact same judgment call plan 03-01's own summary recorded for this identical situation. Task 1's `<verify>` had already passed in full (all three Docker scenarios) before this decision point.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Probe-driven survival's settle delay was too short, letting the server exit before later probes ran**
- **Found during:** Task 2, first full `make interop`-equivalent run after adding the UDP echo service and probe-driven survival window
- **Issue:** The initial implementation used a 2-second settle delay after the ICMP+UDP+HTTP trigger condition fired. Because that condition becomes true almost as soon as `udp_echo` completes (ICMP was already true from the pre-existing ping, HTTP already true from `http_landing`), the server printed PASS and exited only ~2 seconds later — while `entrypoint.sh`'s `nc -u -w 3` UDP probe was still blocked (confirmed empirically that `nc` waits out its full idle timeout even after receiving a reply) and the three remaining HTTP probes (`http_status`/`http_echo`/`http_headers`) had not yet run. Docker Compose's `--abort-on-container-exit` tore down the whole run the instant the server exited, killing the client mid-script; those three `PROBE` lines never appeared in the captured output, and the test correctly failed (transiently masked by a second, unrelated bug below, which is why this was caught first).
- **Fix:** Lowered `nc`'s per-attempt timeout from 3s to 1s (still generous for a local Docker bridge network reply arriving in single-digit milliseconds) and raised `probeSettleDelay` from 2s to 5s, with the reasoning documented in the constant's own doc comment so a future reader doesn't shrink it back down.
- **Files modified:** `test/interop/server/main.go`, `test/interop/entrypoint.sh`
- **Verification:** Re-ran the full three-scenario `make interop`-equivalent test; all six `PROBE` lines (including `http_status`/`http_echo`/`http_headers`) now appear before the server exits, on all three scenarios.
- **Committed in:** `a3b74fe` (Task 2 commit)

**2. [Rule 1 - Bug] The new probe-driven log message dropped the literal word a pre-existing assertion greps for**
- **Found during:** Task 2, the same first full interop run above (surfaced as `assertHandshakeCompleted` failing with "server output does not show it entered the post-handshake survival window")
- **Issue:** `assertHandshakeCompleted` (a Phase 1 assertion, untouched by this plan) asserts on the literal substring `"surviving"` appearing in the server's log output. The new probe-driven survival log line was reworded away from the old `"surviving %s past handshake completion..."` phrasing, silently dropping that word and breaking a pre-existing, unrelated assertion — exactly the kind of regression this plan's own prohibition list forbids ("No existing Phase-1 or Phase-2 assertion is deleted, weakened, or made conditional").
- **Fix:** Restored the literal word `"surviving"` in the new log line, with a comment noting why it must stay even though the window is now probe-driven rather than fixed.
- **Files modified:** `test/interop/server/main.go`
- **Verification:** `assertHandshakeCompleted` passes again on all three scenarios in the same corrected run.
- **Committed in:** `a3b74fe` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (2 bugs, both Rule 1, both discovered and fixed within Task 2 before that task's commit)
**Impact on plan:** Both were self-inflicted implementation bugs in this plan's own new code (the settle-delay/nc-timeout interaction, and a log-wording regression against a pre-existing assertion), caught by actually running the full Docker interop suite rather than trusting the design on paper. No scope creep, no architectural change, no weakening of any existing assertion — the second deviation exists precisely to *prevent* a weakening.

## Issues Encountered

None beyond the two deviations above, which were fully resolved within Task 2's own verification loop before that task was committed.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running for `make interop` (a plan precondition, already verified at the start of Task 1).

## Next Phase Readiness

- Phase 3's ROADMAP success criteria 3 ("unreachable from outside the tunnel") and 4 ("one automated harness run verifies ICMP, a UDP round-trip, and an HTTP page load through the tunnel from the real client, with no `/dev/net/tun` and no `CAP_NET_ADMIN` in the server container") are both fully closed, proven at runtime and statically.
- VRFY-02, the live-client halves of NET-01/NET-02/NET-03, and XMPL-01 are all closed per the `requirements-completed` list above.
- No blockers identified. This was the phase's final plan per the wave/dependency structure (`depends_on: ["03-05"]`, no downstream plan lists `03-06` as a dependency).

## Self-Check: PASSED

- All 5 files listed under "Files Created/Modified" confirmed present on disk with the expected content (re-read is unnecessary per the harness's own guidance — Edit/Write would have errored on failure — but each file's diff was reviewed via `git show` during commit staging).
- All three task commits (`049616d`, `a3b74fe`, `60d1a7a`) confirmed present via `git log --oneline`.
- `go build ./...`, `go vet ./...`, `go test -race ./...`, `make gates`, and `make test` all confirmed exit 0 immediately before writing this summary.
- `git diff --diff-filter=D --name-only` produced no output for any of the three task commits — no accidental deletions.
- `git diff --stat go.mod` produced no output — the core module stays stdlib-only.
- The full three-scenario `go test -tags interop -count=1 -timeout 1500s ./test/interop/ -run TestInteropScenarios -v` was run three separate times during this plan's execution (once per task) and passed clean on the final run, with every `PROBE` line and every PASS-line field (`ping_rx=`/`ping_tx=`/`udp_rx=`/`udp_tx=`/`http_requests=`) observed non-zero/`ok` as required.

---
*Phase: 03-in-process-termination*
*Completed: 2026-08-27*
