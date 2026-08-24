---
status: testing
phase: 01-handshake
source: [01-VERIFICATION.md]
started: 2026-08-24T07:36:45Z
updated: 2026-08-24T07:36:45Z
---

## Current Test

number: 1
name: Real CI execution of the interop GitHub Actions job (deferred until a GitHub remote exists)
expected: |
  After pushing the repo to GitHub, the .github/workflows/ci.yml fast job passes,
  and the Docker-gated interop job runs the real-client handshake scenarios and passes.
awaiting: user response

## Tests

### 1. Real CI execution of the interop GitHub Actions job
expected: After pushing to GitHub, the fast job and the Docker-gated interop job both pass on an actual Actions runner (no git remote exists in this sandbox, so the workflow has only been verified locally).
result: [pending]

### 2. CI failure behavior on a genuinely broken lossy run
expected: When the lossy interop scenario genuinely breaks, the interop CI job fails loudly (does not silently skip) — verifiable by a deliberate breakage on a branch.
result: [pending]

### 3. 60-second handshake-window teardown
expected: A client that stalls mid-handshake is torn down after reliable.HandshakeWindow (60s).
result: passed — Server.handshakeWindow made injectable; TestHandshakeWindowTearsDownStalledSession covers the timeout-triggered teardown (commit cf04830).

## Summary

total: 3
passed: 1
issues: 0
pending: 2
skipped: 0
blocked: 0

## Gaps
