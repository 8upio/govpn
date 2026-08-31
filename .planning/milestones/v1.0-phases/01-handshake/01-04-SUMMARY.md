---
phase: 01-handshake
plan: 04
subsystem: testing
tags: [go, openvpn, docker, netem, tls-crypt, golden-vectors, ci, github-actions]

# Dependency graph
requires:
  - phase: 01-01
    provides: "internal/wire (opcode/session-ID/control-packet parsing), internal/tlscrypt (Wrapper/NewWrapper/ParseStaticKeyV1)"
  - phase: 01-02
    provides: "cmd/gentestpki, test/interop Docker Compose harness, test/interop/pcap.go's stdlib-only pcap reader"
  - phase: 01-03
    provides: "internal/reliable (reliability layer), internal/ctrlconn (control-channel net.Conn), a completed real-client TLS handshake through the harness"
provides:
  - "cmd/gentestpki -profile flag: small (original ECDSA, unchanged) and large (three-level RSA-4096 root->intermediate->leaf chain, leaf+intermediate DER > 3000 bytes)"
  - "Bidirectional synthetic loss/reorder injection: tc netem on the client container's egress (test/interop/entrypoint.sh) for client-to-server, a seeded lossyPacketConn decorator around the PacketConn passed to ovpn.Serve (test/interop/server/main.go) for server-to-client"
  - "test/interop/interop_test.go: TestInteropScenarios scenario table (clean-small, clean-large, lossy-large) driven from TestMain, asserting completed handshake, unprivileged server, certificate-flight fragmentation, and (lossy scenario) loss configured within [5,10]% on both directions"
  - "test/interop/decode.go: decodeCapture, a shared tls-crypt-unwrap + control-packet-parse helper reused by capture_test.go, interop_test.go's fragmentation assertion, and golden_export.go"
  - "test/interop/golden_export.go: ExportGolden, driven by interop_test.go's -update-golden flag / make golden, selecting a representative real-client vector corpus into testdata/golden"
  - "testdata/golden/: 5 committed real-client control datagrams + manifest.json + tls-crypt.key + README.md with full provenance"
  - "internal/wire/golden_test.go, internal/tlscrypt/golden_test.go: fast-tier (no build tag, no Docker) byte-exact parse/serialize/unwrap/re-wrap assertions against real OpenVPN 2.6 client bytes"
  - "internal/tlscrypt.Wrapper.WrapWithPacketID: re-wrap using an explicit tls-crypt packet ID, needed for byte-exact golden-vector reproduction"
  - ".github/workflows/ci.yml: fast job (vet/build/race, non-blocking golangci-lint) and interop job (Docker-gated, fails loudly rather than skipping, uploads captures on failure) on every push/PR"
  - "Makefile: test (default), interop, golden targets — the same entry points CI invokes"
affects: [phase-02]

# Actuals (#2632)
actuals:
  tokens: 23668
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Scenario-table interop testing: TestMain runs all docker-compose-driven scenarios sequentially before any Test function executes (Go compiles/orders test files alphabetically, so setup must live in TestMain to be visible to every Test regardless of file/declaration order — the same constraint 01-03 already worked around), preserving each scenario's capture, tls-crypt key, and docker-inspect privilege-check output (captured before teardown) under scenario-specific names so later Test functions can assert on them without re-running Docker."
    - "Direction-asymmetric loss injection: client-to-server loss lives entirely in test/interop/entrypoint.sh (tc netem on the container's own egress, unseeded — matches tc's own lack of a user-controllable PRNG seed), server-to-client loss lives entirely in a userspace PacketConn decorator (test/interop/server/main.go's lossyPacketConn, seeded via -seed for reproducibility) wrapping the exact net.PacketConn handed to the public ovpn.Serve seam — never inside the core library."
    - "Golden-vector export is a deliberate, flagged act (-update-golden / make golden) driven from the same interop test binary that runs the scenario table, not a separate tool — decodeCapture (test/interop/decode.go) is the single tls-crypt-unwrap + control-packet-parse path shared by capture_test.go's byte-exactness check, interop_test.go's fragmentation assertion, and golden_export.go's vector selection."
    - "Byte-exact golden re-wrap requires reproducing the ORIGINAL SENDER's role, not the unwrapping role: Wrap/WrapWithPacketID always encrypt with Wrapper.encrypt, so a client-to-server vector must be re-wrapped with a client-role Wrapper (server=false), the opposite of the server-role Wrapper (server=true) used to unwrap it — the exact inverse relationship documented in internal/tlscrypt/golden_test.go after a first failed run caught it live."

key-files:
  created:
    - test/interop/decode.go
    - test/interop/golden_export.go
    - test/interop/docker-compose.lossy.yml
    - internal/wire/golden_test.go
    - internal/tlscrypt/golden_test.go
    - testdata/golden/README.md
    - testdata/golden/manifest.json
    - testdata/golden/tls-crypt.key
    - testdata/golden/001-client-to-server-client-hard-reset.bin
    - testdata/golden/002-server-to-client-server-hard-reset.bin
    - testdata/golden/003-server-to-client-ack-only.bin
    - testdata/golden/004-server-to-client-max-fragment.bin
    - testdata/golden/005-server-to-client-final-small.bin
    - .github/workflows/ci.yml
  modified:
    - cmd/gentestpki/main.go
    - test/interop/entrypoint.sh
    - test/interop/docker-compose.yml
    - test/interop/server/main.go
    - test/interop/interop_test.go
    - test/interop/capture_test.go
    - internal/tlscrypt/tlscrypt.go
    - Makefile

key-decisions:
  - "Certificate size padding lives only in OrganizationalUnit, never CommonName — a real OpenVPN 2.6 client truncates/rejects a CN over 64 characters ('VERIFY ERROR: could not extract CN ... field length is limited to 64 characters'), caught live on the first docker run of the large-certificate scenario and fixed before any commit."
  - "The CI interop job runs on ubuntu-latest, not the same OS (macOS) this harness was developed and manually verified on — documented in-file: GitHub-hosted macOS runners have no usable Docker daemon at all, and the lossy scenario's tc netem + NET_ADMIN specifically need a genuine Linux Docker host, so ubuntu-latest is the only GitHub-hosted OS this job can run on, not merely the fastest."
  - "The fast tier's `go test -race` command appears both as its own explicit CI step (satisfying the plan's literal grep-based verify command and CLAUDE.md's own mandate) and again inside a `make test` step, so the raw commands and the Makefile entry point a developer uses locally can never silently drift apart."
  - "The privilege check (docker inspect ... govpn-interop-server) runs inside runScenario, before docker compose down tears the container down — not inside the Test function, which by design runs after all three scenarios (and their teardowns) have already completed. An earlier version called docker inspect from the Test function and used t.Skip on failure, which silently skipped the whole subtest (including the fragmentation and loss-band assertions) once the container was already gone; caught and fixed before committing."
  - "The lossy scenario's retransmission-evidence check (logRetransmissionEvidence) is deliberately non-fatal (t.Log only): tc netem's loss has no user-controllable seed, so a run where every datagram happens to arrive on the first try at 7% loss is unlikely but not impossible — this is the automated stand-in for the plan's human-check verification step, not a hard CI gate."

patterns-established:
  - "test/interop/decode.go's decodedPacket/decodeCapture pair is the vocabulary any future interop assertion needing decoded (not just raw) capture bytes should reuse, rather than re-deriving tls-crypt-unwrap + control-packet-parse logic per test file."
  - "testdata/golden/manifest.json's schema (file/direction/opcode/packet_id) is the format later phases extending this corpus (e.g. Phase 2's data-channel golden vectors) should follow, so a single loader pattern works across packages."

requirements-completed: [CTRL-01, CTRL-02, VRFY-01, WIRE-01, WIRE-04]

coverage:
  - id: D1
    description: "The real OpenVPN 2.6 client completes the full handshake to TLS established across three scenarios (clean-small, clean-large, lossy-large), including a 5-10% lossy, reordering link carrying a fragmented multi-kilobyte certificate chain, without the server container ever gaining a privilege it wouldn't have in production"
    requirement: "CTRL-01"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#TestInteropScenarios (subtests clean-small, clean-large, lossy-large)"
        status: pass
      - kind: other
        ref: "go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -v (live run: all three scenarios PASS in ~56s, 4 and 3 consecutive max-size fragments observed in clean-large/lossy-large, both loss directions measured 7% within [5,10])"
        status: pass
    human_judgment: false
  - id: D2
    description: "Control datagrams captured from a real OpenVPN 2.6 client session are committed as golden vectors with full provenance and asserted byte-exactly (parse/serialize/unwrap/re-wrap) in the fast test tier, with no Docker dependency"
    requirement: "WIRE-01"
    verification:
      - kind: unit
        ref: "internal/wire/golden_test.go#TestGoldenControlPacketsRoundTrip"
        status: pass
      - kind: unit
        ref: "internal/tlscrypt/golden_test.go#TestGoldenTLSCryptRewrap"
        status: pass
      - kind: other
        ref: "go test -race -run TestGolden ./internal/wire/ ./internal/tlscrypt/ (live run, exit 0, PASS)"
        status: pass
    human_judgment: false
  - id: D3
    description: "The byte-exactness assertion has teeth: flipping one byte in a committed vector's authentication tag makes the corresponding golden test fail rather than silently pass"
    requirement: "WIRE-04"
    verification:
      - kind: unit
        ref: "internal/tlscrypt/golden_test.go#TestGoldenVectorTamperHasTeeth (observed failure logged: \"tlscrypt: authentication failed\")"
        status: pass
      - kind: unit
        ref: "internal/wire/golden_test.go#TestGoldenManifestTamperDetection"
        status: pass
    human_judgment: false
  - id: D4
    description: "Both test tiers run in CI on every push and pull request: the fast tier gates every commit without Docker, and the interop tier runs the real-client scenario table, uploading the packet capture on failure and failing loudly rather than skipping when Docker is unavailable"
    requirement: "VRFY-01"
    verification:
      - kind: other
        ref: "make test && test -f .github/workflows/ci.yml && grep -c 'go test -race' .github/workflows/ci.yml (the plan's own Task 3 verify command; live run exits 0, 4 matches)"
        status: pass
      - kind: manual_procedural
        ref: ".github/workflows/ci.yml (no GitHub Actions runner available in this sandbox to execute the workflow itself)"
        status: unknown
    human_judgment: true
    rationale: "The workflow YAML's structure, triggers, job composition, and literal command text are all verified locally (make test passes, the required strings are present), but actually running it on a GitHub Actions runner — confirming the interop job's Docker availability check, artifact upload, and timeout behave as designed in that environment — cannot be exercised from this sandbox and needs a real CI run (e.g. the plan's own PR) to close the loop."

duration: ~70min
completed: 2026-08-23
status: complete
---

# Phase 1 Plan 4: Lossy-Link Handshake, Real-Client Golden Vectors, and CI Summary

**Real OpenVPN 2.6 client handshake verified across clean-small/clean-large/lossy-large Docker scenarios (5-10% bidirectional loss, multi-KB fragmented certificate chain), with the session's own bytes committed as byte-exact fast-tier golden vectors and both test tiers wired into GitHub Actions.**

## Performance

- **Duration:** ~70 min
- **Completed:** 2026-08-23
- **Tasks:** 3
- **Files modified:** 22 (14 created, 8 modified)

## Accomplishments

- `cmd/gentestpki -profile large` issues a three-level RSA-4096 chain (root -> intermediate -> leaf) whose leaf+intermediate DER exceeds 3000 bytes, forcing the server's TLS Certificate message across multiple 1150-byte control fragments — live-verified: clean-large observed 4 consecutive maximum-size fragments, lossy-large observed 3
- Bidirectional synthetic loss injection: `tc netem` on the client container's own egress interface (client-to-server, unseeded — matches `tc`'s own lack of a user-controllable PRNG) and a seeded `lossyPacketConn` decorator wrapping the exact `net.PacketConn` handed to `ovpn.Serve` (server-to-client) — never inside the core library, keeping the server container unprivileged in every scenario (`docker inspect` asserted `false 0 0` even in the lossy run)
- `TestInteropScenarios` runs all three scenarios from a single Docker Compose harness in ~56s: the real client completes the TLS handshake, both sides report the verified peer CommonName, negotiated TLS >= 1.2, and — live-verified on one run — 5 duplicate reliability packet IDs proved the lossy scenario's handshake completed through genuine retransmission, not by chance
- Real captured control datagrams (client hard reset, server hard reset, ack-only, a maximum-size certificate-flight fragment, a final small control packet) are committed to `testdata/golden/` with full provenance, and `internal/wire/golden_test.go` / `internal/tlscrypt/golden_test.go` prove byte-exact parse/serialize/unwrap/re-wrap against them in the fast tier — no Docker needed, closing RESEARCH Open Question 1
- `.github/workflows/ci.yml` runs the fast tier (vet, build, race, golden vectors) and the interop tier (Docker-gated, fails loudly rather than skipping, uploads captures on failure) on every push and pull request

## Task Commits

1. **Task 1: Handshake completes end to end over a lossy link with a multi-kilobyte certificate chain** - `ec1cc48` (feat)
2. **Task 2: Commit real-client golden vectors and assert byte-exactness in the fast tier** - `5943823` (feat)
3. **Task 3: Wire both test tiers into CI** - `162d6e2` (ci)

_Note: Task 1 is `type="tracer"` — committed and its own `<verify>` re-run end-to-end (autonomous worktree execution, no interactive user to checkpoint to) before expanding into Tasks 2 and 3, per plan 01-03's own established pattern._

## Files Created/Modified

- `cmd/gentestpki/main.go` - `-profile small|large` flag; RSA-4096 root->intermediate->leaf chain generation with size padding confined to OrganizationalUnit
- `test/interop/entrypoint.sh` - `tc netem` loss+reorder on the client's egress, gated by `NETEM_ENABLED`
- `test/interop/docker-compose.yml` - env-var-driven client netem settings and server `-drop-rate`/`-reorder-rate`/`-deadline` flags, defaulting to clean-link behavior
- `test/interop/docker-compose.lossy.yml` - overlay fixing loss/reorder at 7% (mid-band) and a generous server deadline for the lossy scenario
- `test/interop/server/main.go` - `lossyPacketConn` decorator (`DropRate`, `-seed`), multi-cert-chain `loadConfig`
- `test/interop/decode.go` - `decodeCapture`, the shared tls-crypt-unwrap + control-packet-parse helper
- `test/interop/golden_export.go` - `ExportGolden`, vector selection and manifest/key export
- `test/interop/interop_test.go` - `TestInteropScenarios` scenario table, `TestMain` orchestration, `-update-golden` flag
- `test/interop/capture_test.go` - retargeted at the clean-small scenario's preserved capture/key
- `internal/tlscrypt/tlscrypt.go` - `Wrapper.WrapWithPacketID` for deterministic golden-vector re-wrap
- `internal/wire/golden_test.go`, `internal/tlscrypt/golden_test.go` - fast-tier golden vector tests
- `testdata/golden/` - 5 vectors, manifest, tls-crypt key, README with provenance
- `.github/workflows/ci.yml` - fast + interop CI jobs
- `Makefile` - `test`/`interop`/`golden` targets

## Decisions Made

See `key-decisions` in frontmatter above — summarized: CN length must stay under 64 characters (caught live against a real client), the interop CI job runs on `ubuntu-latest` rather than macOS despite local development happening on macOS (documented rationale: GitHub-hosted macOS runners have no usable Docker daemon at all), the privilege check must be captured before `docker compose down` rather than re-inspected afterward, and the lossy scenario's retransmission-evidence check is intentionally non-fatal since `tc netem`'s loss has no user-controllable seed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Real client's Certificate message rejected the padded CommonName**
- **Found during:** Task 1, first live run of the `clean-large` scenario
- **Issue:** Certificate size padding (added to reliably clear the plan's >3000-byte DER threshold) was appended directly to the intermediate and leaf certificates' `CommonName`. The real OpenVPN 2.6 client's CN extraction from the X509 subject string is limited to 64 characters; the padded CN produced `VERIFY ERROR: could not extract CN from X509 subject string (...) -- note that the field length is limited to 64 characters`, and the handshake failed.
- **Fix:** Moved all size padding into `OrganizationalUnit`, leaving `CommonName` at the original short, namespaced values (`govpn-interop-server`, `govpn-interop-intermediate-ca`). The combined DER size (server.crt + intermediate.crt) still comfortably exceeds 3000 bytes (3610-3968 bytes observed across runs).
- **Files modified:** `cmd/gentestpki/main.go`
- **Verification:** Re-ran the full scenario table; all three scenarios PASS, `VERIFY OK` for every certificate in the chain.
- **Committed in:** `ec1cc48` (Task 1 commit — caught and fixed before the first commit)

**2. [Rule 1 - Bug] Privilege check silently skipped the entire subtest**
- **Found during:** Task 1, first live run of the full scenario table
- **Issue:** `assertServerStaysUnprivileged` called `docker inspect` from inside the `Test` function, which runs after `TestMain` has already run every scenario's `docker compose down` — the container was always already gone by then. The original implementation called `t.Skipf` on that failure, which aborts the ENTIRE subtest (not just that one check), silently skipping the fragmentation and loss-band assertions too. All three subtests reported `SKIP`, not `PASS`.
- **Fix:** Moved the `docker inspect` call into `runScenario`, immediately after `docker compose up` completes and before `docker compose down` tears the container down; the captured string is stored on `scenarioResult` and asserted (fatally, not skip) in the `Test` function.
- **Files modified:** `test/interop/interop_test.go`
- **Verification:** Re-ran the full scenario table; all three subtests report `PASS`, not `SKIP`.
- **Committed in:** `ec1cc48` (Task 1 commit — caught and fixed before the first commit)

**3. [Rule 1 - Bug] Golden vector re-wrap used the wrong Wrapper role**
- **Found during:** Task 2, first run of `TestGoldenTLSCryptRewrap`
- **Issue:** The re-wrap step reused the SAME `server` boolean used to `Unwrap` the vector. Since `Wrap`/`WrapWithPacketID` always encrypt with `Wrapper.encrypt`, reproducing a captured datagram requires a Wrapper built in the ORIGINAL SENDER's role — the opposite of the role used to unwrap it (unwrap needs `Wrapper.decrypt` to match the sender's encrypt slot; re-wrap needs `Wrapper.encrypt` to match it directly). All five vectors failed with a completely different tag and ciphertext.
- **Fix:** Built the re-wrap Wrapper with `!unwrapAsServer` instead of reusing the unwrap-side boolean.
- **Files modified:** `internal/tlscrypt/golden_test.go`
- **Verification:** `go test -race -run TestGolden ./internal/wire/ ./internal/tlscrypt/` — all vectors PASS, byte-for-byte equality confirmed.
- **Committed in:** `5943823` (Task 2 commit — caught and fixed before the first commit)

**4. [Rule 2 - Missing Critical] `tlscrypt.Wrapper` had no way to reproduce a historical packet ID**
- **Found during:** Task 2, implementing the byte-exact re-wrap assertion
- **Issue:** `Wrap` always generates a fresh tls-crypt packet ID using an auto-incrementing counter and `time.Now()` for the timestamp component — it can never reproduce a specific historical capture's exact packet ID, making byte-exact re-wrap structurally impossible without an API change.
- **Fix:** Added `Wrapper.WrapWithPacketID`, which performs the identical wrap algorithm but accepts an explicit 8-byte packet ID instead of auto-generating one, and does not touch the Wrapper's own `sendSeq` counter (so it can never be mistaken for the live-traffic path).
- **Files modified:** `internal/tlscrypt/tlscrypt.go`
- **Verification:** `go test -race ./internal/tlscrypt/` — all existing tests plus the new golden re-wrap test pass.
- **Committed in:** `5943823` (Task 2 commit)

**5. [Rule 3 - Blocking] `go test` custom-flag ordering**
- **Found during:** Task 2, first attempt to run `-update-golden`
- **Issue:** `go test -tags interop -update-golden ./test/interop/` (custom flag before the package pattern) causes `go test` (cmd/go) to swallow everything from the first unrecognized flag onward as test-binary arguments, leaving no explicit package pattern — it silently defaults to `.` (the module root) and fails there with `flag provided but not defined`, an extremely confusing failure mode unrelated to the actual root cause.
- **Fix:** Package pattern must precede custom test flags: `go test -tags interop ./test/interop/ -run ... -update-golden`. Applied this ordering in `interop_test.go`'s own usage guidance, the `Makefile`'s `interop`/`golden` targets, and `.github/workflows/ci.yml`.
- **Files modified:** `Makefile`, `.github/workflows/ci.yml` (both authored with the correct ordering from the start once discovered)
- **Verification:** `make interop` and `make golden` both run correctly with this ordering.
- **Committed in:** `162d6e2` (Task 3 commit, and retroactively confirmed correct in Task 2's `5943823`)

---

**Total deviations:** 5 auto-fixed (3 bugs caught live against the real client / real test output before any commit, 1 missing-critical-functionality API addition required by the plan's own byte-exactness requirement, 1 blocking tooling-behavior fix). No scope creep: all five are necessary for the correctness or acceptance criteria this plan itself specifies.

## Issues Encountered

None beyond the five items documented in Deviations, all caught and fixed via the plan's own stated verification commands before their respective task's commit.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running locally (already an Environment Availability item from `01-RESEARCH.md` and prior plan summaries).

## Next Phase Readiness

- Phase 1's four success criteria are all met: the real client completes the handshake (criterion 1, plans 01-01 through 01-03), both sides report verified peer identity (criterion 2), the wire is fully tls-crypt wrapped (criterion 3, plan 01-02), and the handshake survives a realistic multi-kilobyte fragmented certificate chain under 5-10% synthetic loss (criterion 4, this plan).
- `testdata/golden/`'s manifest schema (file/direction/opcode/packet_id) is ready to be extended by Phase 2's data-channel work if it wants its own committed real-client vectors — the loader pattern in `internal/wire/golden_test.go`/`internal/tlscrypt/golden_test.go` is directly reusable.
- `test/interop/decode.go`'s `decodeCapture` is a stable, reusable seam for any future interop assertion needing decoded (not just raw) capture bytes.
- CI is wired but has not yet been exercised on an actual GitHub Actions runner from this sandbox (see coverage D4's `human_judgment: true` — needs a real CI run, e.g. this plan's own PR, to close the loop).
- No blockers for Phase 2 (Key Method 2, AES-256-GCM data channel).

---
*Phase: 01-handshake*
*Completed: 2026-08-23*

## Self-Check: PASSED

All 14 created files confirmed present on disk (`test/interop/decode.go`, `test/interop/golden_export.go`, `test/interop/docker-compose.lossy.yml`, `internal/wire/golden_test.go`, `internal/tlscrypt/golden_test.go`, `testdata/golden/README.md`, `testdata/golden/manifest.json`, `testdata/golden/tls-crypt.key`, 5 `testdata/golden/*.bin` vectors, `.github/workflows/ci.yml`); all 3 task commits (`ec1cc48`, `5943823`, `162d6e2`) confirmed present in `git log --oneline`.
