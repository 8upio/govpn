---
phase: 01-handshake
plan: 02
subsystem: interop-testing
tags: [docker, openvpn, tls-crypt, pcap, x509, ci, go]

# Dependency graph
requires:
  - phase: 01-01
    provides: "internal/wire (opcode/session-ID/control-packet parsing), internal/tlscrypt (Wrapper/NewWrapper/ParseStaticKeyV1), ovpn.NewServer/Serve with the HARD_RESET exchange"
provides:
  - "cmd/gentestpki: Go-only CA/server/client cert chain + tls-crypt Static key V1 generator, no easy-rsa"
  - "test/interop: digest-pinned real OpenVPN 2.6 client (Dockerfile), harness server embedding ovpn.NewServer (server/main.go + server/Dockerfile), two-service docker-compose.yml"
  - "test/interop/pcap.go: stdlib-only pcap reader (ReadUDPPayloads), no gopacket"
  - "test/interop/interop_test.go: TestMain-driven harness runner (TestRealClientFirstContact)"
  - "test/interop/capture_test.go: TestCaptureIsFullyTLSCryptWrapped, proves every captured control-channel datagram tls-crypt-authenticates in its correct direction"
  - "Makefile: test (fast tier) and interop (full Docker harness) targets"
affects: [01-03, 01-04]

# Actuals (#2632)
actuals:
  tokens: 9860
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Interop harness observes protocol events by wrapping net.PacketConn (ReadFrom/WriteTo), reading only the cleartext-but-authenticated header byte + session ID — never reaching into ovpn's internals or decrypting anything itself"
    - "Server container built FROM scratch via a multi-stage golang:1.24-bookworm build, run as uid/gid 65534 with no added capabilities and no host device — asymmetric to the client container, which legitimately needs NET_ADMIN + /dev/net/tun as the real kernel-tun-creating OpenVPN client"
    - "pcap parsing keys off the global header's link-type field (Ethernet, Linux SLL, Linux SLL2) rather than assuming one, and hard-errors on anything else"
    - "Capture-integrity verification uses a fresh tlscrypt.Wrapper per captured payload (not one long-lived Wrapper per direction) specifically so legitimate client retransmissions don't trip anti-replay rejection — anti-replay itself is unit-tested elsewhere"
    - "TestMain drives the docker-compose lifecycle exactly once per test binary invocation, independent of file/declaration order or -run filtering, streaming live output to os.Stdout while also capturing it for per-test t.Log"

key-files:
  created:
    - cmd/gentestpki/main.go
    - test/interop/Dockerfile
    - test/interop/docker-compose.yml
    - test/interop/entrypoint.sh
    - test/interop/server/main.go
    - test/interop/server/Dockerfile
    - test/interop/interop_test.go
    - test/interop/pcap.go
    - test/interop/capture_test.go
    - Makefile
    - .dockerignore
  modified: []

key-decisions:
  - "cmd/gentestpki reuses internal/tlscrypt.ParseStaticKeyV1 to self-check its own generated tls-crypt key file round-trips through the real production parser, rather than duplicating parsing logic — a generator whose own project's parser can't read its output back would be a silent harness bug."
  - "Server container has its own test/interop/server/Dockerfile (multi-stage golang:1.24-bookworm build -> scratch), not in the plan's stated file list — necessary infrastructure Rule 3 deviation; nothing else could build a runnable server image."
  - "Capture-integrity verification (capture_test.go) builds a fresh tlscrypt.Wrapper per captured payload instead of one long-lived Wrapper per direction, because Phase 1's server intentionally never ACKs past the reset (RESEARCH Pitfall 5), so the real client legitimately retransmits its post-reset control packet byte-for-byte — a persistent anti-replay window correctly (by tls-crypt's own design) rejects the second copy, which is not what this test is checking."
  - "Harness's docker-compose lifecycle (PKI generation + compose up/down) lives in a TestMain in interop_test.go, not inside TestRealClientFirstContact's own body, because Go compiles same-package test files alphabetically (capture_test.go before interop_test.go) — a body-local setup would run too late for TestCaptureIsFullyTLSCryptWrapped's dependency on already-generated pki/capture artifacts."

patterns-established:
  - "cmd/{name}/main.go pattern for standalone Go tools that are part of the core module but not the public library surface (mirrors cmd/gentestpki for any future generator/tool)."
  - "test/interop/*_test.go behind //go:build interop stays entirely separate from the fast go test ./... tier; TestMain owns all Docker lifecycle so any number of interop tests share one harness run."

requirements-completed: [VRFY-01, WIRE-04, SESS-01]

coverage:
  - id: D1
    description: "One command (`make interop`) generates the PKI, builds the pinned client image, and runs the interop project end to end; a real, unmodified OpenVPN 2.6 client's HARD_RESET_CLIENT_V2 is authenticated and answered by the library, and the client sends a subsequent P_CONTROL_V1 from the same session"
    requirement: "VRFY-01"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#TestRealClientFirstContact"
        status: pass
      - kind: other
        ref: "make interop (full harness: gentestpki + docker compose build/up/down)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every control-channel datagram captured on the wire during the real client run authenticates and decrypts under the harness tls-crypt key in its correct direction (Phase 1 success criterion 3), verified with a stdlib-only pcap reader (no gopacket)"
    requirement: "WIRE-04"
    verification:
      - kind: integration
        ref: "test/interop/capture_test.go#TestCaptureIsFullyTLSCryptWrapped"
        status: pass
      - kind: integration
        ref: "test/interop/capture_test.go#TestCaptureIsFullyTLSCryptWrapped/tamper_detection_proves_the_assertion_has_teeth"
        status: pass
    human_judgment: false
  - id: D3
    description: "The interop harness server container runs unprivileged: non-root uid/gid 65534, no added Linux capabilities, no host device mapping, no privileged flag — asserted at runtime via docker inspect on the live container"
    requirement: "SESS-01"
    verification:
      - kind: other
        ref: "docker inspect -f '{{.HostConfig.Privileged}} {{len .HostConfig.CapAdd}} {{len .HostConfig.Devices}}' govpn-interop-server -> \"false 0 0\""
        status: pass
    human_judgment: false
  - id: D4
    description: "The fast tier (go test ./...) remains Docker-free and green; the interop tier is fully excluded by the //go:build interop tag"
    verification:
      - kind: unit
        ref: "go test ./... (all packages)"
        status: pass
    human_judgment: false

duration: 40min
completed: 2026-08-23
status: complete
---

# Phase 1 Plan 2: Interop Harness — Real Client Hard Reset and Wire-Verified tls-crypt Summary

**A real, unmodified OpenVPN 2.6.14 client (Debian bookworm, digest-pinned) authenticates and accepts the library's HARD_RESET_SERVER_V2 answer over a Docker Compose harness, and an independent stdlib-only pcap reader proves every captured control-channel datagram is tls-crypt wrapped in the correct direction — with a demonstrated-to-fail tamper check.**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-08-23
- **Tasks:** 2
- **Files modified:** 11 (all created; no pre-existing files touched)

## Accomplishments

- `cmd/gentestpki`: generates a throwaway CA + server/client certs (ECDSA P-256, `x509.CreateCertificate`, namespaced `govpn-interop-` CommonNames) and a 256-byte tls-crypt Static key V1 file entirely in Go — no easy-rsa, no shelling out to `openvpn --genkey`; self-checks its own key file by round-tripping it through `internal/tlscrypt.ParseStaticKeyV1`
- `test/interop/Dockerfile`: `debian:bookworm-slim@sha256:abd67ff...` (digest-pinned, resolved 2026-08-23), installs `openvpn` 2.6.14-0+deb12u2, `tcpdump` 4.99.3-1, `iproute2` 6.1.0-3
- `test/interop/server`: a real embedder of `ovpn.NewServer`/`Serve`, observing protocol events (opcode + session ID) by wrapping the `net.PacketConn` — never reaching into the library's internals or client log text — and exiting 0 only after seeing a `P_CONTROL_V1` from the same session that sent an accepted `HARD_RESET_CLIENT_V2`
- `test/interop/docker-compose.yml`: server runs as uid/gid 65534 with no added capabilities and no host device (`docker inspect` confirms `false 0 0`); client gets `NET_ADMIN` + `/dev/net/tun` because it is the real client creating a kernel tun device — documented asymmetry
- **Live-verified**: a real OpenVPN 2.6.14 client's hard reset is authenticated, answered, and followed by an opcode-4 control packet from the same session (`recv opcode=7` -> `send opcode=8` -> `recv opcode=4`, same session ID)
- `test/interop/pcap.go`: minimal stdlib pcap reader (`ReadUDPPayloads`), handles Ethernet, Linux cooked capture (SLL, link type 113) and its newer SLL2 variant (link type 276, confirmed via a real capture from `tcpdump -i any` inside the client container), hard-errors on any other link type
- `test/interop/capture_test.go`: `TestCaptureIsFullyTLSCryptWrapped` decrypts every captured datagram under the correct-direction tls-crypt key, asserts a minimum of 2 client-to-server payloads (no hardcoded total), and a nested `tamper detection` subtest proves a corrupted tag byte is rejected
- Manually demonstrated the assertion has teeth: flipping byte offset 20 of a real captured hard-reset payload changes `Unwrap`'s result from success to `tlscrypt: authentication failed` (see Deviations below for the full observed output)

## Task Commits

1. **Task 1: Real OpenVPN 2.6 client reaches the library and accepts its reset answer** - `cf74fa4` (feat)
2. **Task 2: Prove on the wire that every control-channel datagram is tls-crypt wrapped** - `8775272` (feat)

## Files Created/Modified

- `cmd/gentestpki/main.go` - Go-only CA/server/client cert generator + tls-crypt Static key V1 writer
- `test/interop/Dockerfile` - digest-pinned real OpenVPN 2.6 client image, runs `entrypoint.sh`
- `test/interop/entrypoint.sh` - starts `tcpdump -i any`, runs the client in the foreground, flushes the capture on exit
- `test/interop/server/main.go` - harness server: real `ovpn.NewServer` embedder + protocol-event observer
- `test/interop/server/Dockerfile` - multi-stage build (`golang:1.24-bookworm` -> `scratch`) for the harness server image
- `test/interop/docker-compose.yml` - two-service topology on a user-defined bridge network
- `test/interop/interop_test.go` - `TestMain`-driven harness lifecycle + `TestRealClientFirstContact`
- `test/interop/pcap.go` - stdlib-only pcap reader, `ReadUDPPayloads`
- `test/interop/capture_test.go` - `TestCaptureIsFullyTLSCryptWrapped` + tamper-detection subtest
- `Makefile` - `test` (fast tier) and `interop` (full harness) targets
- `.dockerignore` - keeps the server image's build context (repo root) free of `.git`/`.planning`/generated PKI/captures

## Decisions Made

- **`cmd/gentestpki` self-checks against the real production parser.** Rather than duplicating `internal/tlscrypt`'s Static key V1 envelope parsing inside the generator, `cmd/gentestpki` imports `internal/tlscrypt` directly and round-trips its own output through `ParseStaticKeyV1` before exiting 0 — a stronger guarantee than a hand-duplicated parser that could silently drift.
- **Capture-integrity verification uses a fresh `tlscrypt.Wrapper` per payload, not one per direction.** Discovered while running Task 2's own verify command: the real client, upon never receiving an ACK for its post-reset control packet (Phase 1's server intentionally stops after the reset per RESEARCH Pitfall 5), legitimately retransmits that same already-tls-crypt-wrapped buffer — byte-for-byte, including the same tls-crypt packet ID. A single long-lived Wrapper's anti-replay window correctly rejects the retransmitted copy as a replay (this is tls-crypt's actual designed behavior, and a real protocol-complete server would never see it because it would have ACKed the first copy). Since anti-replay enforcement is already unit-tested byte-exactly in `internal/tlscrypt/tlscrypt_test.go`, and this test's job is to prove every datagram authenticates and decrypts correctly (not to re-verify anti-replay), constructing a fresh Wrapper per payload was the correct fix rather than working around or suppressing the legitimate retransmission.
- **Harness lifecycle moved into `TestMain`.** Found while running Task 2's verify command with both tests together: Go compiles/orders same-package test files alphabetically, so `capture_test.go` (which needs `pki`/`captures` artifacts) would run before `interop_test.go` (which produces them), regardless of the `-run` regex's own ordering. Moving PKI generation + `docker compose up`/`down` into a single `TestMain` makes the harness run exactly once, before any test function, independent of file order or which subset `-run` selects.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `test/interop/server/Dockerfile` and `.dockerignore`, not in the plan's Task 1 file list**
- **Found during:** Task 1, writing `docker-compose.yml`
- **Issue:** The plan's `<files>` list for Task 1 names `test/interop/Dockerfile` (the pinned OpenVPN client image) but the server service also needs a buildable image, and no file in the plan's list accounts for one.
- **Fix:** Added a multi-stage `test/interop/server/Dockerfile` (`golang:1.24-bookworm` build stage -> `scratch` final stage) and a repo-root `.dockerignore` to keep its build context small.
- **Files modified:** `test/interop/server/Dockerfile`, `.dockerignore`
- **Verification:** `docker compose build` succeeds; `docker inspect` confirms the resulting container is unprivileged, uid/gid 65534, no added capabilities, no devices
- **Committed in:** `cf74fa4` (Task 1 commit)

**2. [Rule 3 - Blocking] Modified `test/interop/Dockerfile` in Task 2 to wire in `entrypoint.sh`, not in Task 2's stated file list**
- **Found during:** Task 2, adding packet capture
- **Issue:** Task 1's Dockerfile execs `openvpn` directly (`ENTRYPOINT ["openvpn", "--config", "/pki/client.conf"]`); Task 2's file list adds `test/interop/entrypoint.sh` but does not list `test/interop/Dockerfile` as modified, yet the entrypoint script has no other way to run without the Dockerfile `COPY`ing and referencing it.
- **Fix:** Modified the Dockerfile to `COPY entrypoint.sh /entrypoint.sh`, `chmod +x`, and `ENTRYPOINT ["/entrypoint.sh"]`.
- **Files modified:** `test/interop/Dockerfile`
- **Verification:** rebuilt client image, ran the full harness, capture file produced and non-empty
- **Committed in:** `8775272` (Task 2 commit)

**3. [Rule 1 - Bug] Capture-verification test used one long-lived `Wrapper` per direction and failed on legitimate client retransmissions**
- **Found during:** Task 2, running the plan's own verify command with both tests together
- **Issue:** `TestCaptureIsFullyTLSCryptWrapped` initially built a single `serverWrapper`/`clientWrapper` pair reused across all captured payloads. The real client retransmits its post-reset `P_CONTROL_V1` (since Phase 1's server never ACKs it), reusing the same tls-crypt packet ID on the wire. The persistent anti-replay window correctly rejected the retransmitted copy: `tlscrypt: packet ID replay`.
- **Fix:** Construct a fresh `tlscrypt.Wrapper` per captured payload instead of one per direction — see Decisions Made above for the full rationale.
- **Files modified:** `test/interop/capture_test.go`
- **Verification:** `go test -tags interop -run 'TestRealClientFirstContact|TestCaptureIsFullyTLSCryptWrapped' -v ./test/interop/` passes cleanly
- **Committed in:** `8775272` (Task 2 commit)

**4. [Rule 1 - Bug] Test-file alphabetical ordering would run the capture test before its dependency was generated**
- **Found during:** Task 2, running both interop tests together for the first time
- **Issue:** `capture_test.go`'s `TestCaptureIsFullyTLSCryptWrapped` needs `test/interop/pki/tls-crypt.key` and `test/interop/captures/interop.pcap`, both produced by `interop_test.go`'s harness-driving logic. Go orders same-package test files alphabetically for compilation, and `capture_test.go` sorts before `interop_test.go`, so a test-body-local setup in `TestRealClientFirstContact` would run too late.
- **Fix:** Moved PKI generation and the `docker compose up`/`down` lifecycle into a package-level `TestMain` in `interop_test.go`, executed exactly once before `m.Run()` regardless of file order or `-run` filtering.
- **Files modified:** `test/interop/interop_test.go`
- **Verification:** `go test -tags interop -run 'TestRealClientFirstContact|TestCaptureIsFullyTLSCryptWrapped' -v ./test/interop/` — both tests pass in either declared order
- **Committed in:** `8775272` (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (2 missing-infrastructure/blocking, 2 bugs caught while running the plan's own verify commands)
**Impact on plan:** All four are necessary for the harness to build and pass its own stated verification — no scope creep beyond what Task 1/Task 2's own acceptance criteria require. The `tlscrypt.Wrapper`/`NewWrapper` and `wire.ParseControlPacket` interfaces from plan 01-01 are unchanged.

## Tamper-detection manual demonstration (Task 2 acceptance criterion)

Ran a one-off, non-committed test against the real captured `interop.pcap`: took the captured hard-reset payload (54 bytes), verified it authenticates cleanly, then flipped byte offset 20 (inside the tls-crypt HMAC tag, `TLS_CRYPT_OFF_TAG..OFF_CT` = bytes 17-48) and re-verified:

```
BASELINE: untampered payload (len=54) authenticated successfully
TAMPERED: payload with byte 20 flipped -> Unwrap result: tlscrypt: authentication failed
```

Confirms the capture-integrity assertion is not vacuous: a single corrupted byte in a real captured control payload is detected and rejected. This is also covered permanently by the committed `capture_test.go`'s `"tamper detection proves the assertion has teeth"` subtest (which corrupts a copy of a payload in-memory rather than the on-disk capture, so it can run safely as part of every `make interop` invocation without needing a pre-existing tampered fixture file).

## Acceptance-criteria wording note

Two acceptance criteria (Task 1 and Task 2) specify running `go test -tags interop -run <TestName> ./test/interop/` **without** `-v` and expect the output to contain the literal string `PASS`. Verified empirically (both against this project and an isolated throwaway module) that Go's `go test` tool without `-v` prints only `ok  \t<package>\t<time>` for a passing run — it buffers and discards all other output, including direct `fmt.Println`/`os.Stdout` writes from within the test binary (confirmed: a trivial `fmt.Println` inside a passing `TestXxx` does not appear without `-v`). This is standard, unconfigurable `go test` behavior, not a bug in this plan's code. Both commands do exit 0 as required; the literal `PASS` substring requires `-v` (Task 1's own broader verify script, and the interop_test.go/capture_test.go verify command in Task 2, both already specify `-v`, which does show `PASS` — demonstrated throughout this summary's "Task Commits" verification runs).

## Issues Encountered

None beyond the four items documented in Deviations, all caught and fixed before their respective task's commit while running that task's own stated verify command.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running locally (or a Docker daemon in CI) to run `make interop`; this was already an Environment Availability item in `01-RESEARCH.md`, not new setup.

## Next Phase Readiness

- The interop harness (`make interop`) is a stable, reusable gate: plan 01-03 (TLS handshake + reliability layer + real `Session`) and plan 01-04 can extend `test/interop/server/main.go`'s protocol-event observation and `test/interop/capture_test.go`'s wire-format assertions incrementally as the server progresses past the hard reset.
- `test/interop/server`'s `observingConn` wrapper pattern (log opcode+session from the cleartext header, detect protocol milestones without decrypting) generalizes cleanly to asserting on later milestones (TLS handshake completion, Key Method 2) in later plans.
- Known, expected, and now-documented behavior for later plans to account for: with the current Phase 1 server (stops after the reset), the real client both resets-and-retries in some runs (RESEARCH Open Question 2) and retransmits its post-reset control packet indefinitely (this plan's Deviation 3) — both are transient states that stop occurring once plan 01-03 adds real ACKing past the reset.
- The generated `test/interop/pki/client.conf` already declares `topology subnet` and `cipher AES-256-GCM` from this first run, so no client-config changes are anticipated when plan 01-03 and Phase 2 start relying on them.
- No blockers for plan 01-03.

---
*Phase: 01-handshake*
*Completed: 2026-08-23*

## Self-Check: PASSED

All 11 created files confirmed present on disk; both task commits (`cf74fa4`, `8775272`) confirmed present in `git log --oneline --all`.
