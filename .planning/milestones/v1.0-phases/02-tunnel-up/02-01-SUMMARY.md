---
phase: 02-tunnel-up
plan: 01
subsystem: crypto
tags: [go, openvpn, key-method-2, tls-1.0-prf, key-derivation, aes-256-gcm, docker-interop]

# Dependency graph
requires:
  - phase: 01-03
    provides: "internal/reliable, internal/ctrlconn, session.go's Session, ovpn.go's runHandshake with TLS handshake complete and the client's Key Method 2 payload already buffered unread in sess.conn"
provides:
  - "internal/keyderiv: hand-rolled TLS 1.0 PRF (openvpn_PRF/tls1_P_hash) verified byte-exact against the OpenVPN reference's own committed test vector, bounds-checked Key Method 2 reader/writer, two-stage master-secret/key-expansion derivation, and the inverted per-direction key/implicit-IV slot mapping (keyDirection/Key2.ServerSlots)"
  - "runHandshake's Key Method 2 continuation: reads the client's buffered KM2, writes the server's own, derives 256 bytes of data-channel key material onto Session.dataKeys — a session that fails this exchange is closed before OnSession ever fires"
  - "a live-client gate (test/interop) proving a real OpenVPN 2.6.14 client accepts the server's Key Method 2 message and sends PUSH_REQUEST, without any key material appearing in harness output"
affects: [02-02, 02-03, 02-04]

# Actuals (#2632)
actuals:
  tokens: 11400
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "internal/keyderiv mirrors internal/tlscrypt's package-doc citation-header convention (reference commit + bulleted src/openvpn/<file>.c:<lines> (<C symbol>) map) and its 'prefix of a 64-byte slot' pattern (Key2.slot), but its key-direction mapping (keyDirection) is the deliberate mirror-opposite of tlscrypt.NewWrapper's — documented inline with an explicit cross-reference so a future edit copying tlscrypt's convention here is caught by TestKeyDirectionIsOppositeOfTLSCrypt, not merely warned about in a comment"
    - "runHandshake's Key Method 2 continuation wraps tlsConn in a bufio.Reader (D-15) stored on Session.tlsReader rather than modifying internal/ctrlconn.Conn — plan 02-02's PUSH_REQUEST/PUSH_REPLY continuation reads from the same buffered stream"
    - "watchForPushRequest runs as a bounded background goroutine (10s read deadline via tlsConn.SetReadDeadline) started after the Key Method 2 exchange succeeds but before OnSession fires — the real client's PUSH_REQUEST can arrive during, not before, the post-handshake survival window, so this is deliberately async rather than a blocking read inside performKeyMethod2Exchange"

key-files:
  created:
    - internal/keyderiv/prf.go
    - internal/keyderiv/prf_test.go
    - internal/keyderiv/keyexpansion.go
    - internal/keyderiv/keyexpansion_test.go
    - internal/keyderiv/keymethod2.go
    - internal/keyderiv/keymethod2_test.go
  modified:
    - ovpn.go
    - session.go
    - test/interop/server/main.go
    - test/interop/interop_test.go

key-decisions:
  - "Session gained an exported PushRequestSeen() bool accessor (backed by an unexported atomic.Bool field) so test/interop/server/main.go — an external package — can observe the background watcher's result; the plan's own field list named pushRequested as unexported but didn't anticipate the harness needing to read it from outside the ovpn package, so a minimal accessor was added rather than exporting the field itself (Rule 2 — missing critical: the harness's acceptance criterion is otherwise unreachable)."
  - "pushRequested is sync/atomic.Bool, not a plain bool as the plan's field list literally states, because watchForPushRequest sets it from a background goroutine running concurrently with (not before) Config.OnSession firing and the interop harness reading it after the 2s post-handshake survival window — a plain bool would be a data race under go test -race."
  - "km2=ok in the interop harness's PASS line is printed unconditionally rather than queried from Session state: by construction, OnSession only fires after performKeyMethod2Exchange has already succeeded (a session whose exchange fails is closed and OnSession never runs for it), so no new Session surface was needed for that half of the diagnostic."

patterns-established:
  - "internal/keyderiv's DeriveKeys/ReadClientKeyMethod2/WriteServerKeyMethod2 seam is the stable interface later plans build on: plan 02-02's PUSH_REQUEST/PUSH_REPLY continuation reads from the same sess.tlsReader this plan established, and plan 02-03's internal/datachan.Wrapper consumes Key2.ServerSlots() directly."

requirements-completed: [WIRE-02, WIRE-03, CTRL-04]

coverage:
  - id: D1
    description: "The hand-rolled TLS 1.0 PRF (openvpn_PRF/tls1_P_hash) reproduces the OpenVPN reference's own committed 32-byte test vector byte-for-byte, with zero tolerance"
    requirement: "WIRE-02"
    verification:
      - kind: unit
        ref: "internal/keyderiv/prf_test.go#TestPRFReferenceVector"
        status: pass
      - kind: unit
        ref: "internal/keyderiv/prf_test.go#TestPRFOutputLengthNotBlockAligned"
        status: pass
    human_judgment: false
  - id: D2
    description: "Key expansion and the inverted per-direction key/implicit-IV slot mapping are asserted against independently-stated reference byte ranges (128:160, 192:200, 0:32, 64:72), with a live mutation check proving the assertion has teeth"
    requirement: "WIRE-03"
    verification:
      - kind: unit
        ref: "internal/keyderiv/keyexpansion_test.go#TestServerSlotsMatchReferenceByteRanges"
        status: pass
      - kind: unit
        ref: "internal/keyderiv/keyexpansion_test.go#TestKeyDirectionServerIsInverse"
        status: pass
      - kind: unit
        ref: "internal/keyderiv/keyexpansion_test.go#TestKeyDirectionIsOppositeOfTLSCrypt"
        status: pass
      - kind: other
        ref: "manual mutation check: flipped keyDirection's return values, observed 3 test failures (TestKeyDirectionServerIsInverse, TestKeyDirectionIsOppositeOfTLSCrypt, TestServerSlotsMatchReferenceByteRanges), reverted — see Deviations/Task Commits for the observed failure output"
        status: pass
    human_judgment: false
  - id: D3
    description: "A real OpenVPN 2.6.14 client's Key Method 2 message parses field-by-field, the server's own message is accepted, and the client proceeds to request its tunnel configuration (PUSH_REQUEST) — proven live, across all three interop scenarios"
    requirement: "CTRL-04"
    verification:
      - kind: unit
        ref: "internal/keyderiv/keymethod2_test.go#TestKeyMethod2ReadRejectsTruncated"
        status: pass
      - kind: unit
        ref: "internal/keyderiv/keymethod2_test.go#TestKeyMethod2ServerWriteLayout"
        status: pass
      - kind: integration
        ref: "test/interop/interop_test.go#assertKeyExchangeCompleted (called from TestInteropScenarios for clean-small, clean-large, lossy-large)"
        status: pass
      - kind: other
        ref: "make interop equivalent run (go run ./cmd/gentestpki -out test/interop/pki -profile large && go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -v): live run, all 3 scenarios PASS, server PASS line 'km2=ok push_request=seen'"
        status: pass
    human_judgment: false

duration: ~35min
completed: 2026-08-24
status: complete
---

# Phase 2 Plan 1: Key Method 2 Data-Channel Key Derivation Summary

**A hand-rolled TLS 1.0 PRF verified byte-exact against the OpenVPN reference's own test vector, feeding a two-stage Key Method 2 exchange that derives 256 bytes of data-channel key material — live-verified end to end against a real, unmodified OpenVPN 2.6.14 client that completes the exchange and sends PUSH_REQUEST across all three interop scenarios.**

## Performance

- **Duration:** ~35 min
- **Completed:** 2026-08-24
- **Tasks:** 3
- **Files modified:** 10 (6 created, 4 modified)

## Accomplishments

- `internal/keyderiv`: `PRF`/`pHash`/`openvpnPRF` (RFC 2246 §5.6.4.1's TLS 1.0 PRF, MD5+SHA1 P_hash halves XORed together) reproducing the OpenVPN reference's own committed 32-byte test vector byte-for-byte — closes the STATE.md Phase-2 blocker ("Key Method 2 byte offsets... must be verified against C source") mechanically, with a passing test
- `ReadClientKeyMethod2`/`WriteServerKeyMethod2`: bounds-checked Key Method 2 wire codec — every fixed-length field via `io.ReadFull`, every length-prefixed string checked against `TLS_OPTIONS_LEN`=512 before allocation, never panics on truncated or adversarial input (proven over every prefix length of a well-formed message)
- `DeriveKeys`: the two-stage master-secret → key-expansion derivation (256 deterministic bytes), plus `keyDirection`/`Key2.ServerSlots` implementing the data channel's key-direction convention — the exact mirror opposite of `internal/tlscrypt.NewWrapper`'s convention for the same `server` boolean, asserted against independently-stated reference byte ranges (not merely self-consistent round-trip tests) with a live mutation check proving the assertion has teeth
- `runHandshake` now performs the full exchange after the TLS handshake completes: reads the client's already-buffered KM2, writes the server's own, derives keys onto `Session.dataKeys` — a session that fails any step is closed and `OnSession` never fires for it
- A background, bounded (`10s`) watcher observes the real client's `PUSH_REQUEST`, exposed via `Session.PushRequestSeen()`; live-verified against a real OpenVPN 2.6.14 client across all three interop scenarios — the server's PASS line reads `km2=ok push_request=seen`, with no key material ever printed

## Task Commits

1. **Task 1: A real client's Key Method 2 message derives live data-channel keys end to end** - `b1c4708` (feat)
2. **Task 2: The data-channel key direction is the mirror opposite of tls-crypt's — proven, not assumed** - `34d1987` (test)
3. **Task 3: A real OpenVPN 2.6.14 client accepts the server's key exchange and asks for its config** - `4f8fb96` (feat)

_Note: Task 1 is `type="tracer"` — committed, then its own `<verify>` re-run end-to-end (autonomous worktree execution, no interactive user to checkpoint to, exactly matching 01-03's own precedent for this phase) before expanding into Tasks 2 and 3. Task 2 is `tdd="true"`: `internal/keyderiv/keyexpansion.go`'s production code (`keyDirection`, `Key2.ServerSlots`) was written in Task 1 alongside `DeriveKeys`, and this task's own tests passed against it immediately — see TDD Gate Compliance below. Task 2's mutation check was performed as its own acceptance criterion requires: `keyDirection`'s two return statements were swapped, `go test ./internal/keyderiv/` was run and observed to fail 3 tests (output captured below), then the swap was reverted and the full suite re-confirmed green._

### Task 2 mutation-check observed output (captured, then reverted)

```
--- FAIL: TestKeyDirectionServerIsInverse (0.00s)
    keyexpansion_test.go:14: keyDirection(true) = (0, 1), want (1, 0)
--- FAIL: TestKeyDirectionIsOppositeOfTLSCrypt (0.00s)
    keyexpansion_test.go:35: keyDirection(true) encrypt index = 0, which matches internal/tlscrypt's server encrypt index (0) — the data-channel convention must be the mirror opposite (RESEARCH.md Pitfall 1)
--- FAIL: TestServerSlotsMatchReferenceByteRanges (0.00s)
    keyexpansion_test.go:63: EncryptCipher = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f, want 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f (key2[128:160])
```

## Files Created/Modified

- `internal/keyderiv/prf.go` - `pHash`, `PRF`, `openvpnPRF`; `//nolint:gosec` (G401/G505) annotated MD5/SHA1 imports with rationale
- `internal/keyderiv/prf_test.go` - `TestPRFReferenceVector` (the reference's own committed test vector), `TestPRFOutputLengthNotBlockAligned`
- `internal/keyderiv/keyexpansion.go` - `KeySource`/`KeySource2`, `Key2`/`NewKey2`, `keyDirection`, `DataKeys`, `Key2.ServerSlots`, `DeriveKeys`
- `internal/keyderiv/keyexpansion_test.go` - key-direction and slot-range tests, including the tls-crypt-mirror-opposite assertion
- `internal/keyderiv/keymethod2.go` - `ReadClientKeyMethod2`, `WriteServerKeyMethod2`, `ClientOptions`, `ErrKeyMethod`/`ErrStringTooLong`
- `internal/keyderiv/keymethod2_test.go` - truncation/wrong-key-method/oversized-string rejection tests, write-layout test, `TestDeriveKeysEndToEnd`
- `ovpn.go` - `runHandshake` gains `performKeyMethod2Exchange` and `watchForPushRequest`; `serverKM2Options`/`pushRequestLiteral` constants
- `session.go` - `tlsReader *bufio.Reader`, `dataKeys *keyderiv.Key2`, `clientKM *keyderiv.KeySource`, `pushRequested atomic.Bool` + exported `PushRequestSeen()`
- `test/interop/server/main.go` - PASS line gains `km2=ok push_request=<seen|not-seen>`
- `test/interop/interop_test.go` - `assertKeyExchangeCompleted`, called from `TestInteropScenarios` for every scenario

## Decisions Made

- **`Session.PushRequestSeen()` exported accessor added.** The plan's field list named `pushRequested` as unexported, but `test/interop/server/main.go` (an external package) needs to read it to build the PASS line's `push_request=` field — a minimal exported accessor was the smallest change satisfying that without exposing the field itself. (Rule 2 — missing critical functionality: the harness's own acceptance criterion is otherwise unreachable.)
- **`pushRequested` is `sync/atomic.Bool`, not a plain `bool`.** `watchForPushRequest` sets it from a background goroutine that runs concurrently with `Config.OnSession` firing (started before `OnSession` is called, since the real client's `PUSH_REQUEST` can arrive during the harness's 2-second post-handshake survival window, not necessarily before). A plain `bool` read by the harness after that window would race under `go test -race` against the watcher's write. (Rule 1 — bug: the plan's literal `bool` field type would have produced a genuine data race.)
- **`km2=ok` printed unconditionally in the harness, not queried from Session state.** `Config.OnSession` only ever fires after `performKeyMethod2Exchange` has already succeeded — a session whose exchange fails is closed and `OnSession` never runs for it — so by construction, reaching the code that prints the PASS line already proves KM2 succeeded. No new Session surface was needed for that half of the diagnostic.
- **`assertKeyExchangeCompleted` is called for every scenario, not only `clean-small`.** The plan's acceptance criteria named `clean-small` specifically, but since the `km2=`/`push_request=` fields appear in every scenario's PASS line by construction (the harness code path is scenario-independent), asserting on all three scenarios gives strictly stronger coverage for the same implementation, consistent with "reuse the existing scenario table" (no new scenario or compose file was added).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added `Session.PushRequestSeen()` exported accessor**
- **Found during:** Task 3, wiring `test/interop/server/main.go`'s PASS line
- **Issue:** The plan's own field list for `session.go` names `pushRequested bool` as unexported, but Task 3's acceptance criteria require `test/interop/server/main.go` — a separate `package main`, outside `package ovpn` — to read that value to build its PASS line. An unexported field is invisible across that package boundary; without an accessor, the acceptance criterion is structurally unreachable.
- **Fix:** Added `func (s *Session) PushRequestSeen() bool { return s.pushRequested.Load() }`, kept the underlying field unexported.
- **Files modified:** `session.go`
- **Verification:** `go build ./...`, `go vet ./...`, live interop run's PASS line correctly reports `push_request=seen`
- **Committed in:** `4f8fb96` (Task 3 commit)

**2. [Rule 1 - Bug] `pushRequested` changed from `bool` to `sync/atomic.Bool`**
- **Found during:** Task 3, reasoning through `watchForPushRequest`'s goroutine lifecycle relative to `Config.OnSession` and the interop harness's own read of the field after its 2-second survival window
- **Issue:** The plan's field list states `pushRequested bool`. A plain `bool` set by a background goroutine (`watchForPushRequest`, started before `OnSession` fires so the client's `PUSH_REQUEST` — which can arrive during the post-handshake window, not only before it — isn't missed) and read later by `test/interop/server/main.go` (a different goroutine, after `postHandshakeSurvival` elapses) is an unsynchronized concurrent read/write — a data race `go test -race` would catch the moment a race-instrumented interop-adjacent test exercised this path concurrently.
- **Fix:** Changed the field to `sync/atomic.Bool`, using `.Store(true)`/`.Load()` instead of direct assignment/read.
- **Files modified:** `session.go`, `ovpn.go`
- **Verification:** `go test -race ./...` clean; live interop run confirms the flag is still observed correctly (`push_request=seen`)
- **Committed in:** `4f8fb96` (Task 3 commit — the race never reached a committed state)

---

**Total deviations:** 2 auto-fixed (1 missing-critical-functionality addition, 1 data-race bug caught before commit). Both necessary for the plan's own stated acceptance criteria and for `go test -race` correctness. No scope creep.

## TDD Gate Compliance

Task 2 carries `tdd="true"`. Like plan 01-03's own Task 2 (and this phase's own Task 1), Task 1 already implemented `keyDirection` and `Key2.ServerSlots` as part of building `DeriveKeys` for the tracer's end-to-end `<behavior>` (`TestDeriveKeysEndToEnd`), so Task 2's own job was writing dedicated tests against already-complete production code plus the mandated live mutation check — not driving new implementation from a failing test. Every test in `internal/keyderiv/keyexpansion_test.go` passed on first run; there is a `test(...)` commit (`34d1987`) but no separate `feat(...)` GREEN-phase commit, because none was needed. This is a legitimate outcome per the same precedent 01-03-SUMMARY.md documents, not a skipped gate — and it is reinforced here by the mutation check itself, which is the acceptance criterion's own proof that the tests have teeth regardless of commit shape.

## Issues Encountered

None beyond the two items documented in Deviations, both caught and fixed via the plan's own stated verification commands (`go build ./...`, `go vet ./...`, `go test -race ./...`) before their task's commit. One pre-existing, out-of-scope issue was observed and left untouched: `go build -tags interop ./...` fails on `test/interop/golden_export.go` referencing `readTLSCryptKey`/`copyFile`, which are defined in `interop_test.go` (a `_test.go` file, invisible to non-test builds of the same package). Confirmed via `git stash` that this predates this plan's changes; `go vet -tags interop ./test/interop/...` (which, like `go test`, does include test files) passes cleanly, and the plan's own verify command (`go test -tags interop ...`) is unaffected. Logged for awareness, not fixed — out of this plan's scope per the deviation rules' scope boundary.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running locally for Task 3's interop harness (already an established Environment Availability item from Phase 1, not new setup for this plan); confirmed running and used for a live 3-scenario interop run during this plan's execution.

## Next Phase Readiness

- `internal/keyderiv` is a stable, tested building block: `Session.dataKeys` (`*keyderiv.Key2`) is the single input plan 02-03's `internal/datachan.Wrapper` will consume directly via `Key2.ServerSlots()`.
- `Session.tlsReader` (the `bufio.Reader` wrapping `tlsConn`, created once in `runHandshake`) is retained specifically so plan 02-02's PUSH_REQUEST/PUSH_REPLY continuation can keep reading from the same buffered stream — starting a second `bufio.Reader` over `tlsConn` would lose whatever bytes this plan's `watchForPushRequest` (or the KM2 read itself) already pulled into the first one's internal buffer. Plan 02-02 should read from `sess.tlsReader`, not create a new reader.
- This plan's `watchForPushRequest` goroutine already reads and discards the client's first `PUSH_REQUEST`; per RESEARCH.md, the reference client retransmits `PUSH_REQUEST` on its own timer, so plan 02-02's own PUSH_REQUEST read (over the same `sess.tlsReader`) will still see one — no coordination needed between this plan's diagnostic-only read and plan 02-02's protocol-level handling, but plan 02-02 should be aware this plan already consumed one occurrence of the literal.
- `OnSession` still fires at the end of `runHandshake` in this plan, immediately after the Key Method 2 exchange succeeds — plan 02-02 owns moving it past `PUSH_REPLY` per decision D-08 (`OnSession` fires only once data-channel keys AND the pushed IP are both live).
- No blockers for plan 02-02.

---
*Phase: 02-tunnel-up*
*Completed: 2026-08-24*

## Self-Check: PASSED

All 6 created files (`internal/keyderiv/prf.go`, `internal/keyderiv/prf_test.go`, `internal/keyderiv/keyexpansion.go`, `internal/keyderiv/keyexpansion_test.go`, `internal/keyderiv/keymethod2.go`, `internal/keyderiv/keymethod2_test.go`) confirmed present on disk; all 3 task commits (`b1c4708`, `34d1987`, `4f8fb96`) confirmed present in `git log --oneline --all`.
