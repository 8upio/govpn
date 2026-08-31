# Deferred Items — Phase 4

Out-of-scope discoveries logged during plan execution, per the executor's
scope-boundary rule (only auto-fix issues directly caused by the current
task's changes).

## 04-03: Flaky `TestTCPRespectsPeerWindow` (netstack package)

- **Found during:** Plan 04-03's fast-tier verification runs.
- **Symptom:** `netstack/tcp_state_test.go:676` occasionally fails with a
  segment-sequence mismatch (`seq = 4243726543, want 4243726079`) under
  `go test -race`.
- **Reproducibility:** Intermittent — 1 failure observed across many runs
  of the full fast-tier suite during this plan's execution; re-running the
  same test in isolation (`go test -race -run TestTCPRespectsPeerWindow
  -count=5 ./netstack/...`) passed cleanly every time.
- **Why deferred:** `netstack/` is not in this plan's `files_modified` list
  and was not touched by any of 04-03's three tasks — this is a pre-existing
  flake in Phase 3's own TCP retransmission/window test, unrelated to
  renegotiation, exit-notify, or the interop harness this plan adds.
- **Suggested next step:** Investigate `TestTCPRespectsPeerWindow` for a
  timing-sensitive assumption about sequence-number wraparound or window
  update ordering; consider whether the test needs an injected clock rather
  than real timers.

## 04-03: Pre-existing `lossy-large` interop scenario flake (unseeded client netem loss)

- **Found during:** Plan 04-03's own confirmatory `go test -tags interop`
  runs (not the "reneg" scenario this plan adds — `lossy-large`, a
  Phase-1/2 scenario, unmodified by any of this plan's three tasks).
- **Symptom:** `assertKeyExchangeCompleted` (`interop_test.go`, Phase 1/2's
  own pre-existing assertion) occasionally fails with "client output
  reports a TLS key negotiation failure" — the client's own log contains
  the literal string from an ABANDONED first handshake attempt (timed out
  under the client-side `tc netem`'s 7% loss/reorder), even though a
  second attempt then succeeds and the scenario otherwise completes
  normally (PASS line, all probes, all other assertions green).
- **Reproducibility:** Intermittent — 2 of 3 full interop runs during this
  plan's execution passed lossy-large cleanly (documented in this plan's
  own SUMMARY.md); 1 run hit this flake.
- **Why deferred:** `docker-compose.lossy.yml` and the lossy-large scenario
  entry are unmodified by any of 04-03's three tasks. The root cause is
  already acknowledged in this codebase's own comments
  (`assertPingRoundTrip`'s doc: "loss has no user-controllable seed on the
  client's egress") — the client container's own `tc netem` has no seed
  flag, unlike the server-to-client decorator's own `-seed`, so a run's
  exact loss pattern is not reproducible or controllable from this harness.
- **Suggested next step:** Either accept a bounded number of client-side
  handshake retries as non-fatal for the lossy scenario specifically (the
  assertion would need to allow the literal failure string when followed
  by a subsequent successful handshake), or pin the client's own `tc
  netem` loss with a seeded PRNG if `iproute2`/the kernel's netem module
  supports one, to make the lossy-large scenario's pass/fail fully
  reproducible run to run.
