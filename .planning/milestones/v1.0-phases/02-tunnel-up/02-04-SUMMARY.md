---
phase: 02-tunnel-up
plan: 04
subsystem: testing
tags: [go, openvpn, aes-256-gcm, data-channel, golden-vectors, docker-interop, ast-lint-gate]

# Dependency graph
requires:
  - phase: 02-01
    provides: "internal/keyderiv (Key Method 2 key derivation, openvpn_PRF, DeriveKeys, Key2.ServerSlots)"
  - phase: 02-02
    provides: "tunnel-IP pool allocation, PUSH_REQUEST/PUSH_REPLY exchange, Server.dataSessions routing scaffolding"
  - phase: 02-03
    provides: "internal/datachan (AES-256-GCM Wrapper Seal/Open, replay window, ping absorption), Session.dataWrapper/dataKeys, the live client ping round-trip through Session.Read/Write, test/interop's harness ICMP responder"
provides:
  - "VRFY-03: the lossy-large scenario asserts tunnel-up and ping round-trip fatally (not just the handshake), tolerant of loss, alongside Phase 1's existing fragmentation/loss-band/privilege checks"
  - "A committed real-client data-channel golden corpus (testdata/golden/006-008.bin, data-channel.key, data-channel-km2.json) that opens, re-seals byte-exactly, and catches both a tag-region tamper and a key-direction inversion in the fast tier, no Docker"
  - "internal/keyderiv.golden_test.go: DeriveKeys reproduces the real client's own captured Key Method 2 randoms/session IDs byte-for-byte against the committed derived key material (WIRE-03 against live evidence)"
  - "gates_test.go: five AST-based fast-tier tests enforcing this phase's own standing prohibitions (stdlib-only go.mod, no TLS keying-material export, annotated weak-hash imports, no epoch packet-ID format, golden corpus is test-only), wired into `make gates`/`make test` and a named CI step"
  - "internal/datachan.Wrapper.SealWithPacketID and session.go's DebugKeyMethod2Material/DebugDataKeys debug-only accessors — the reproduction-only surface the golden-vector export/verification chain needed"
affects: []

# Actuals (#2632)
actuals:
  tokens: 25000
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "test/interop/decode.go's decodeCapture gained an optional dataChannelKeyMaterial parameter (backward-compatible for every pre-existing caller) so control and data packets share one decoder — P_DATA_V2 opcode class is now determined BEFORE any tls-crypt-specific length check, since a data packet is legitimately shorter than the tls-crypt prefix."
    - "The data channel's mirror-opposite key-direction convention (RESEARCH Pitfall 1) is expressed as a single field-swap helper (mirrorDataKeys, duplicated once per consuming package per this project's established per-package-manifest-struct convention) rather than a new keyderiv accessor: given the server's own ServerSlots() output, the client's own perspective is exactly the four fields swapped — no re-derivation needed."
    - "Debug/test-only accessors on the public Session type (DebugKeyMethod2Material, DebugDataKeys) are the sanctioned seam for a test harness that needs a live session's internal crypto material — named and documented as debug-only so a production embedder has no reason to reach for them."
    - "A scratch-based Docker image's writable working directory must be prepared in the build stage AND copied in with COPY --from=<stage> --chown=<uid>:<gid> explicitly — COPY --from resets ownership to root regardless of what an upstream RUN chown set, confirmed live via docker export + tar tv."

key-files:
  created:
    - internal/datachan/golden_test.go
    - internal/keyderiv/golden_test.go
    - gates_test.go
    - testdata/golden/006-client-to-server-icmp-echo-request.bin
    - testdata/golden/007-server-to-client-icmp-echo-reply.bin
    - testdata/golden/008-server-to-client-ping-keepalive.bin
    - testdata/golden/data-channel.key
    - testdata/golden/data-channel-km2.json
  modified:
    - test/interop/interop_test.go
    - test/interop/decode.go
    - test/interop/golden_export.go
    - test/interop/server/main.go
    - test/interop/server/Dockerfile
    - test/interop/entrypoint.sh
    - internal/datachan/datachan.go
    - internal/wire/golden_test.go
    - internal/tlscrypt/golden_test.go
    - session.go
    - ovpn.go
    - testdata/golden/manifest.json
    - testdata/golden/README.md
    - Makefile
    - .github/workflows/ci.yml

key-decisions:
  - "Task 1's ping widened from 4 packets @0.2s to 10 packets @1s, and postHandshakeSurvival raised 5s->20s (uniform across all scenarios, not per-scenario) so a 10-second ping has headroom before --abort-on-container-exit tears the compose run down. docker-compose.lossy.yml itself was NOT modified for this — the shared Go constant already covers the lossy scenario's own timing needs, so the plan's own files_modified guess for that file did not apply; documented here rather than made as a silent no-op."
  - "decode.go's pre-existing tls-crypt-minimum-length check ran BEFORE opcode classification, so short P_DATA_V2 packets (now present in every scenario's capture once ping round-trip runs on all three, not only clean-small's) failed with a misleading 'shorter than the tls-crypt prefix' error instead of being skipped. Fixed by determining opcode class first (Rule 1 bug, caught by Task 1's own live verify before any commit)."
  - "session.go/ovpn.go gained two debug-only accessors (DebugKeyMethod2Material, DebugDataKeys) not listed in Task 2's own <files> — required because TestGoldenKeyExpansionFromCapture's own stated behavior (DeriveKeys reproducing a live session's derived keys from its own captured randoms) is structurally unachievable without a way to get that ephemeral material out of a real session; no other listed file could provide this (Rule 2 - missing critical functionality)."
  - "test/interop/server/Dockerfile needed a writable /tmp added to its scratch base image (not listed in Task 2's <files>) so the harness server can hand its derived key material to `docker cp` before teardown — scratch has no filesystem beyond what's explicitly COPYed in. Required two live-diagnosed fixes: first a chmod 1777 attempt failed (COPY --from resets ownership to root, confirmed via `docker export`+`tar tv`), then `COPY --from=build --chown=65534:65534` fixed it (Rule 3 - blocking, required for Task 2's own acceptance criteria)."
  - "internal/wire/golden_test.go and internal/tlscrypt/golden_test.go (not listed in Task 2's <files>) needed a filter excluding data-channel manifest entries (KeyFile != \"\") from their control-channel-only unwrap/re-wrap loops — the manifest schema extension broke Phase 1's own golden tests, which is exactly the acceptance criterion (\"Phase 1's existing corpus and loaders are unbroken by the manifest extension\") that made this fix mandatory, not optional (Rule 1 bug)."

patterns-established:
  - "internal/datachan.Wrapper.SealWithPacketID (reproduction-only, never touches sendSeq) mirrors internal/tlscrypt.WrapWithPacketID's own established precedent — any future data-channel golden-vector or replay-debugging work has an explicit-packet-ID seal path to build on."
  - "test/interop's dataChannelKeyMaterial/mirrorDataKeys pattern is the vocabulary any future interop assertion needing to decode (not just skip) data-channel traffic should reuse."

requirements-completed: [VRFY-03, WIRE-03, DATA-01, DATA-02]

coverage:
  - id: D1
    description: "The lossy-large scenario asserts, fatally, that the tunnel itself (not merely the handshake) survives a 5-10% bidirectional loss/reorder link: tunnel-up with a Config.Network address and a ping round-trip with at least one reply, alongside Phase 1's existing fragmentation/loss-band/privilege checks, with no scenario reporting SKIP"
    requirement: "VRFY-03"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#TestInteropScenarios (all three scenarios; assertPingRoundTrip parameterized strict/tolerant by scenario)"
        status: pass
      - kind: other
        ref: "live docker interop run (make interop, three separate live runs during this plan): all 3 scenarios PASS every time; lossy-large observed 8/10 and 10/10 ping replies across runs (0% and 20% client-observed loss, both accepted by the tolerant assertion); grep -c 't.Skip' test/interop/interop_test.go returns 1, entirely from a pre-existing doc-comment substring predating this plan (git show HEAD:test/interop/interop_test.go confirmed), not an actual t.Skip call"
        status: pass
    human_judgment: false
  - id: D2
    description: "Real OpenVPN 2.6.14 client data-channel packets (client-to-server ICMP echo request, server-to-client echo reply, ping keepalive) are committed with provenance and open byte-exactly in the fast tier against the key material captured alongside them"
    requirement: "DATA-01"
    verification:
      - kind: unit
        ref: "internal/datachan/golden_test.go#TestGoldenDataChannelOpen"
        status: pass
      - kind: unit
        ref: "internal/datachan/golden_test.go#TestGoldenDataChannelReseal"
        status: pass
      - kind: unit
        ref: "internal/datachan/golden_test.go#TestGoldenDataChannelTamperHasTeeth"
        status: pass
      - kind: unit
        ref: "internal/datachan/golden_test.go#TestGoldenKeyDirectionWouldCatchAnInversion"
        status: pass
      - kind: other
        ref: "go test -race -run TestGolden ./internal/datachan/ ./internal/keyderiv/ ./internal/wire/ ./internal/tlscrypt/ (live run, exit 0, all PASS)"
        status: pass
    human_judgment: false
  - id: D3
    description: "The committed data-channel vectors' manifest is complete (no orphan .bin file, no dangling manifest entry) and every .bin under testdata/golden/ traces to a manifest entry"
    requirement: "DATA-02"
    verification:
      - kind: unit
        ref: "internal/datachan/golden_test.go#TestGoldenManifestCoversEveryFile"
        status: pass
    human_judgment: false
  - id: D4
    description: "The key material a real client actually used is reproduced byte-for-byte by keyderiv.DeriveKeys from the captured Key Method 2 randoms and session IDs — WIRE-03 verified against live evidence, not only the reference's own PRF test vector"
    requirement: "WIRE-03"
    verification:
      - kind: unit
        ref: "internal/keyderiv/golden_test.go#TestGoldenKeyExpansionFromCapture"
        status: pass
    human_judgment: false
  - id: D5
    description: "Every prohibition this phase declared (stdlib-only go.mod, no TLS keying-material export, annotated weak-hash imports, no epoch packet-ID format, golden corpus is test-only) is enforced by a fast-tier test wired into the default Make target and the CI fast job"
    verification:
      - kind: unit
        ref: "gates_test.go#TestPhase2NoThirdPartyDependencies"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase2NoTLSKeyingMaterialExport"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase2WeakHashImportsAreAnnotated"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase2NoEpochDataFormat"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase2GoldenCorpusIsTestOnly"
        status: pass
      - kind: other
        ref: "make gates, make test, go test -race ./... (all live-run, exit 0); TestPhase2NoTLSKeyingMaterialExport passes while CLAUDE.md/.planning still name ExportKeyingMaterial in prose"
        status: pass
    human_judgment: false

duration: ~40min
completed: 2026-08-24
status: complete
---

# Phase 2 Plan 4: Lossy-Link Ping Round-Trip, Real-Client Data-Channel Golden Vectors, and Phase Prohibition Gates Summary

**The lossy-large scenario now proves the tunnel (not just the handshake) survives a 5-10% loss/reorder link; real OpenVPN 2.6.14 client P_DATA_V2 bytes are committed with provenance and open/re-seal byte-exactly in the fast tier, catching both a tag-region tamper and a key-direction inversion; `keyderiv.DeriveKeys` reproduces the real client's own captured Key Method 2 material byte-for-byte; and every prohibition this phase declared is now an AST-based `go test` gate wired into `make test` and CI.**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-08-24
- **Tasks:** 3
- **Files modified:** 29 (8 created, 21 modified)

## Accomplishments

- `test/interop/interop_test.go`'s `assertPingRoundTrip` (renamed/extended from `assertDataChannelRoundTrip`) now runs on every scenario, strict zero-loss on the clean scenarios and tolerant (at least one reply, not zero loss) on `lossy-large` — closing VRFY-03. `entrypoint.sh`'s ping widened to 10 packets at 1s intervals and `postHandshakeSurvival` raised to 20s give the longer ping room before the compose run tears down. A pre-existing `decode.go` ordering bug (tls-crypt length check before opcode classification) that this change exposed was fixed live before commit.
- A representative real-client data-channel corpus — one client-to-server ICMP echo request, one server-to-client echo reply, one ping keepalive — is committed under `testdata/golden/` with the derived AES-256-GCM key material (`data-channel.key`) and the raw Key Method 2 seed material (`data-channel-km2.json`) that produced it, extending `manifest.json`'s schema (`peer_id`/`data_packet_id`/`key_file`/`sender_slot`) rather than introducing a second format.
- `internal/datachan/golden_test.go` proves, against real client bytes: `Open` succeeds and re-seal (`SealWithPacketID`, a new reproduction-only method) reproduces the original byte-for-byte; a tag-region bit flip is caught; and — the one assertion round-trip self-consistency cannot make — opening a real client-to-server vector with the key-direction slots swapped fails.
- `internal/keyderiv/golden_test.go#TestGoldenKeyExpansionFromCapture` proves `DeriveKeys`, run against the real client's own captured randoms and session IDs, reproduces the committed derived key material byte-for-byte — required adding two debug-only accessors (`Session.DebugKeyMethod2Material`/`DebugDataKeys`) to get that ephemeral material out of a live session at all.
- `gates_test.go` turns this phase's own declared prohibitions into five AST-based fast-tier tests (stdlib-only dependencies, no TLS keying-material export, annotated weak-hash imports, no epoch packet-ID format, golden corpus is test-only) wired into a new `make gates` target (`test` now depends on it) and a named CI step.

## Task Commits

1. **Task 1: The tunnel comes up and a ping round-trips over a 5-10% lossy, reordering link** - `5ed71d5` (feat)
2. **Task 2: Real-client data-channel bytes are committed and re-sealed byte-exactly in the fast tier** - `721ff6d` (feat)
3. **Task 3: The phase's prohibitions become a test that runs on every commit** - `b20d965` (test)

_Note: Task 1 is `type="tracer"` — committed, then its own `<verify>` (the full live `make interop` run) re-run end-to-end before expanding into Tasks 2/3, matching this phase's own established precedent (autonomous worktree execution, no interactive user to checkpoint to). The tracer's first live run surfaced the `decode.go` ordering bug documented below; it was fixed and the full scenario table re-verified green before the task commit._

## Files Created/Modified

- `gates_test.go` - `TestPhase2NoThirdPartyDependencies`, `TestPhase2NoTLSKeyingMaterialExport`, `TestPhase2WeakHashImportsAreAnnotated`, `TestPhase2NoEpochDataFormat`, `TestPhase2GoldenCorpusIsTestOnly`, `walkGoFiles`/`skipDir` shared AST-walk helpers
- `internal/datachan/datachan.go` - `SealWithPacketID` (reproduction-only), `sealWithSeq` (shared Seal/SealWithPacketID implementation)
- `internal/datachan/golden_test.go` - `TestGoldenDataChannelOpen`, `TestGoldenDataChannelReseal`, `TestGoldenDataChannelTamperHasTeeth`, `TestGoldenKeyDirectionWouldCatchAnInversion`, `TestGoldenManifestCoversEveryFile`, `wrapperForVector`/`mirrorDataKeys` helpers
- `internal/keyderiv/golden_test.go` - `TestGoldenKeyExpansionFromCapture`
- `internal/wire/golden_test.go`, `internal/tlscrypt/golden_test.go` - `controlChannelEntries` filter excluding data-channel manifest entries
- `session.go` - `serverKM` field, `DebugKeyMethod2Material`/`DebugDataKeys` debug-only accessors
- `ovpn.go` - `sess.serverKM = serverKM` in `performKeyMethod2Exchange`
- `test/interop/decode.go` - `dataChannelKeyMaterial`/`mirrorDataKeys`, P_DATA_V2 open path in `decodeCapture` (opcode-class-before-length-check fix), `IsDataPacket`/`IsPing`/`PeerID`/`DataPacketID`/`Plaintext` on `decodedPacket`
- `test/interop/golden_export.go` - data-channel vector selection (`isICMPEchoRequest`/`isICMPEchoReply`), extended `goldenManifestEntry`, `readDataChannelKeyExport`
- `test/interop/server/main.go` - `writeDataChannelKeyExport`/`writeKeyMethod2Export`, `postHandshakeSurvival` 5s→20s
- `test/interop/server/Dockerfile` - writable, correctly-owned `/tmp` for the key-export handoff
- `test/interop/entrypoint.sh` - ping widened to 10 packets @1s
- `test/interop/interop_test.go` - `assertPingRoundTrip` (renamed/extended), `dockerCopyFromContainer`, `scenarioResult.dataKeysPath`/`keyMethod2Path`
- `testdata/golden/` - 3 new data-channel `.bin` vectors, `data-channel.key`, `data-channel-km2.json`, extended `manifest.json`, extended `README.md`
- `Makefile` - `gates` target, `test` depends on it
- `.github/workflows/ci.yml` - named "Phase prohibition gates (make gates)" step

## Decisions Made

See `key-decisions` in frontmatter above — summarized: the ping-timing fix lives entirely in the shared `postHandshakeSurvival` constant rather than a per-scenario `docker-compose.lossy.yml` override; a pre-existing `decode.go` bug (opcode classification order) was fixed before it could block Task 1's own acceptance criteria; two debug-only `Session` accessors and a scratch-image `/tmp` fix (with a documented `COPY --from` ownership pitfall) were both required, not optional, for Task 2's stated behavior; and Phase 1's own golden tests needed a data-channel-entry filter to keep passing against the extended manifest schema.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `decode.go`'s opcode classification ran after the tls-crypt length check**
- **Found during:** Task 1's own tracer `<verify>` re-run (first `make interop`-equivalent attempt after extending the ping assertion to every scenario)
- **Issue:** `decodeCapture` checked `len(p.Payload) < tlscrypt.OffCT` before determining the packet's opcode. Once `assertPingRoundTrip` started exercising the data channel on `clean-large`/`lossy-large` (not only `clean-small`), short `P_DATA_V2` payloads legitimately shorter than the tls-crypt prefix appeared in those captures too, and `assertCertificateFlightFragmented`'s call to `decodeCapture` failed with "shorter than the tls-crypt prefix" instead of skipping them as data-channel traffic.
- **Fix:** Determine opcode class first (needs only 1 byte), skip `P_DATA_V1`/`P_DATA_V2` before the tls-crypt-specific length check.
- **Files modified:** `test/interop/decode.go`
- **Verification:** Full `make interop`-equivalent run — all 3 scenarios PASS.
- **Committed in:** `5ed71d5` (Task 1 commit)

**2. [Rule 2 - Missing Critical] `Session.DebugKeyMethod2Material`/`DebugDataKeys` accessors**
- **Found during:** Task 2, planning `TestGoldenKeyExpansionFromCapture`
- **Issue:** The raw Key Method 2 seed material (server's own random1/random2 in particular) is a local variable inside `ovpn.go`'s `performKeyMethod2Exchange`, never stored anywhere reachable outside the package — `TestGoldenKeyExpansionFromCapture`'s own stated behavior (reproducing a live session's derived keys from its own captured randoms) is structurally unachievable without exposing this material.
- **Fix:** Added a `serverKM` field to `Session` (mirroring the existing `clientKM` field) and two debug-only exported accessors returning the raw KM2 material and the derived `DataKeys`.
- **Files modified:** `session.go`, `ovpn.go`
- **Verification:** `go test -race -run TestGoldenKeyExpansionFromCapture ./internal/keyderiv/` passes against a live-captured session.
- **Committed in:** `721ff6d` (Task 2 commit)

**3. [Rule 3 - Blocking] `test/interop/server/Dockerfile` had no writable filesystem for the key-material handoff**
- **Found during:** Task 2, first `-update-golden` run
- **Issue:** The server image is `FROM scratch` — no `/tmp`, no shell. `writeDataChannelKeyExport`/`writeKeyMethod2Export` failed with "no such file or directory". A first fix (`RUN mkdir -p /out/tmp && chmod 1777 /out/tmp` in the build stage, plain `COPY --from=build`) still failed with "permission denied" — confirmed via `docker export` + `tar tv` that `COPY --from=<stage>` resets ownership to root regardless of an upstream `RUN chown`.
- **Fix:** `COPY --from=build --chown=65534:65534 /out/tmp /tmp` in the final stage — `--chown` on the `COPY` instruction itself is load-bearing.
- **Files modified:** `test/interop/server/Dockerfile`
- **Verification:** `-update-golden` run succeeds with no "warning: failed to write" log lines; `docker cp` retrieves both files successfully.
- **Committed in:** `721ff6d` (Task 2 commit)

**4. [Rule 1 - Bug] Phase 1's own golden tests broke against the extended manifest schema**
- **Found during:** Task 2, first `go test -race -run TestGolden ./internal/wire/ ./internal/tlscrypt/` run after regenerating the corpus
- **Issue:** `internal/wire/golden_test.go` and `internal/tlscrypt/golden_test.go` iterate every manifest entry and try to tls-crypt-unwrap it — the new data-channel entries (never tls-crypt wrapped) failed authentication, exactly the acceptance criterion ("Phase 1's existing corpus and loaders are unbroken by the manifest extension") this plan itself requires to hold.
- **Fix:** Added a `KeyFile` field and a `controlChannelEntries` filter (excluding entries with `KeyFile != ""`) to both files' manifest-loading path.
- **Files modified:** `internal/wire/golden_test.go`, `internal/tlscrypt/golden_test.go`
- **Verification:** `go test -race -run TestGolden ./internal/wire/ ./internal/tlscrypt/` passes, all 5 control-channel vectors still asserted.
- **Committed in:** `721ff6d` (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (2 bugs caught live before their respective task's commit, 1 missing-critical-functionality API addition required by the plan's own stated test behavior, 1 blocking infrastructure fix required to make Task 2's acceptance criteria reachable at all). No scope creep — all four are necessary for this plan's own stated acceptance criteria or for a pre-existing test this plan's new manifest schema affected.

## Issues Encountered

None beyond the four items documented in Deviations, all caught and fixed via the plan's own stated verification commands (`go build ./...`, `go vet ./...`, `go test -race ./...`, live `make interop`/`-update-golden` runs) before each task's commit.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running locally for the interop harness (already an established Environment Availability item from prior plans); confirmed running and used for five live 3-scenario interop runs during this plan's execution (one Task 1 verify, three Task 2 `-update-golden` iterations while diagnosing the Dockerfile permission issue, one final Task 3 confirmation).

## Next Phase Readiness

- Phase 2's five success criteria are now all met: the tunnel (not just the handshake) survives a lossy link (criterion 5, this plan), and criteria 2-4 (data-channel encryption, replay protection, keepalive) are made non-regressable in the fast tier by the new golden corpus.
- `testdata/golden/`'s manifest schema is extended, not replaced — a future phase adding its own committed real-client vectors (e.g. renegotiation traffic, Phase 4) can follow the same `key_file`/`sender_slot` pattern this plan established for a second AEAD key family.
- Every prohibition this phase declared is now a standing, automatically-enforced gate — a future phase that accidentally reintroduces a forbidden construction (a third-party dependency, the TLS keying-material export, an unannotated weak-hash import, an epoch packet-ID field, or a committed non-throwaway key) fails a normal `go test` run immediately, not at review time.
- `gates_test.go`'s `walkGoFiles` helper (AST-based repository walk, skips `.git`/`.planning`/`testdata` and itself) is a reusable pattern for any future phase wanting its own prohibitions enforced the same way.
- No blockers for Phase 3.

---
*Phase: 02-tunnel-up*
*Completed: 2026-08-24*
