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
