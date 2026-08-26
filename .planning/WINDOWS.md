---
schema_version: 1
open_count: 2
waived_count: 0
fixed_count: 0
total_count: 2
last_updated: 2026-08-26T21:01:20.704Z
---

# Broken Windows Ledger

> Cross-phase defect register. With `workflow.windows_enforce` enabled, `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 03 | deviation | .planning/phases/03-in-process-termination/03-01-PLAN.md |  | Task 2 (tdd=true): clock.go/deadline.go implementation and full test suite committed together with Task 1's tracer slice in a single commit (fe546d2), not as separate RED/GREEN commits — the two tasks' code is interdependent (Stack.New/WithClock needs Clock to exist to compile). | open |  | 2026-08-26T20:43:04.026Z |  |
| 2 | 03 | deviation | netstack/udp.go |  | All three plan 03-02 tasks (round-trip, port lifecycle, deadline/close) landed in one commit rather than three per-task commits - same files, interdependent implementation; see 03-02-SUMMARY.md Deviations | open |  | 2026-08-26T21:01:20.704Z |  |

````json
[
  {
    "id": 1,
    "kind": "deviation",
    "phase": "03",
    "file": ".planning/phases/03-in-process-termination/03-01-PLAN.md",
    "line": null,
    "description": "Task 2 (tdd=true): clock.go/deadline.go implementation and full test suite committed together with Task 1's tracer slice in a single commit (fe546d2), not as separate RED/GREEN commits — the two tasks' code is interdependent (Stack.New/WithClock needs Clock to exist to compile).",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-26T20:43:04.026Z",
    "resolved_at": null
  },
  {
    "id": 2,
    "kind": "deviation",
    "phase": "03",
    "file": "netstack/udp.go",
    "line": null,
    "description": "All three plan 03-02 tasks (round-trip, port lifecycle, deadline/close) landed in one commit rather than three per-task commits - same files, interdependent implementation; see 03-02-SUMMARY.md Deviations",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-26T21:01:20.704Z",
    "resolved_at": null
  }
]
````
