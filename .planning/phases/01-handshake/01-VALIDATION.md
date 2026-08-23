---
phase: 1
slug: handshake
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-23
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `go test` (stdlib `testing`, table-driven; no external test framework — the core module is stdlib-only) |
| **Config file** | none — greenfield repo. Wave 0 creates `go.mod` (`module github.com/8upio/govpn`, `go 1.24`) |
| **Quick run command** | `go test -race ./<package-under-change>/` — e.g. `go test -race ./internal/wire/` |
| **Full suite command** | `go test -race ./... && go test -tags interop -count=1 -timeout 900s ./test/interop/` |
| **Estimated runtime** | fast tier ~15s; interop tier ~5-10 min (Docker image build + three real-client scenarios) |

The Docker-dependent interop tier is isolated behind the `interop` build tag so
`go test ./...` never touches Docker and stays fast enough for per-commit sampling.

---

## Sampling Rate

- **After every task commit:** Run `go test -race ./...` (fast tier, no Docker)
- **After every plan wave:** Run `go test -race ./... && go test -tags interop -count=1 ./test/interop/`
- **Before `/gsd-verify-work`:** Full suite must be green, including all three interop scenarios
- **Max feedback latency:** 30 seconds for the fast tier

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 1-01-01 | 01 | 1 | WIRE-01, WIRE-04, SESS-01 | T-01-01 / T-01-02 / T-01-06 | Length + opcode triage before allocation; `hmac.Equal` tag check before decrypt; session IDs from `crypto/rand` | unit (tracer, e2e over loopback UDP) | `go build ./... && go vet ./... && go test -race -run 'TestHardResetRoundTrip\|TestConcurrentSessions\|TestServeClose' -v .` | ❌ W0 (created by this task) | ⬜ pending |
| 1-01-02 | 01 | 1 | WIRE-01, WIRE-04 | T-01-03 / T-01-04 | Bounds-checked parse returns typed errors, never panics; tls-crypt replay window rejects reused sequence numbers | unit (golden vector + fuzz) | `go test -race ./internal/... && go test -race -run Fuzz -fuzz FuzzParseControlPacket -fuzztime 20s ./internal/wire/` | ❌ W0 (created by this task) | ⬜ pending |
| 1-02-01 | 02 | 2 | VRFY-01, SESS-01 | T-01-07 / T-01-08 / T-01-09 / T-01-11 | Server container unprivileged and capability-clean; base image digest-pinned; PKI namespaced and per-run | integration/e2e (Docker) | `go run ./cmd/gentestpki -out test/interop/pki && go test -tags interop -count=1 -timeout 300s -run TestRealClientFirstContact -v ./test/interop/` | ❌ W0 (created by this task) | ⬜ pending |
| 1-02-02 | 02 | 2 | WIRE-04, VRFY-01 | T-01-10 / T-01-11 | Every wire datagram authenticates under the tls-crypt key; assertion demonstrated to fail on a tampered capture | integration (pcap assertion) | `go test -tags interop -count=1 -timeout 300s -run 'TestRealClientFirstContact\|TestCaptureIsFullyTLSCryptWrapped' -v ./test/interop/` | ❌ W0 (created by this task) | ⬜ pending |
| 1-03-01 | 03 | 3 | CTRL-01, CTRL-02, CTRL-03, SESS-01 | T-01-12 / T-01-16 / T-01-17 | Mutual cert verification with pinned CA pool and explicit TLS 1.2 floor; `OnSession` gated on a successful handshake | unit (tracer, loopback TLS over two real `Conn`s) | `go build ./... && go vet ./... && go test -race -run TestTLSHandshakeOverCtrlConn -v ./internal/ctrlconn/ && go test -race ./...` | ❌ W0 (created by this task) | ⬜ pending |
| 1-03-02 | 03 | 3 | CTRL-01 | T-01-13 / T-01-14 / T-01-15 | Bounded windows and sequentiality refusal prevent unbounded buffering; replay and out-of-window IDs rejected | unit (clock-injected, deterministic) | `go test -race -count=2 ./internal/reliable/ ./internal/ctrlconn/ -v` | ❌ W0 (created by this task) | ⬜ pending |
| 1-03-03 | 03 | 3 | CTRL-03, VRFY-01 | T-01-12 / T-01-17 | Both sides report the CA-verified peer CommonName; post-handshake application data does not reset the session | integration/e2e (Docker) | `go run ./cmd/gentestpki -out test/interop/pki && go test -tags interop -count=1 -timeout 300s -v ./test/interop/` | ✅ (extends 1-02-01) | ⬜ pending |
| 1-04-01 | 04 | 4 | CTRL-01, CTRL-02, VRFY-01 | T-01-18 / T-01-19 / T-01-21 | Loss injected without granting the server container any production-absent privilege; `docker inspect` re-asserted in the lossy scenario | integration/e2e (Docker, tracer) | `go run ./cmd/gentestpki -out test/interop/pki -profile large && go test -tags interop -count=1 -timeout 900s -run TestInteropScenarios -v ./test/interop/` | ✅ (extends 1-02-01) | ⬜ pending |
| 1-04-02 | 04 | 4 | WIRE-01, WIRE-04 | T-01-20 / T-01-23 | Committed corpus key marked throwaway with full provenance; regeneration is a deliberate `make golden` act | unit (golden vector, real-client bytes, fast tier) | `go test -race -run 'TestGolden' -v ./internal/wire/ ./internal/tlscrypt/ && go test -race ./...` | ❌ W0 (created by this task) | ⬜ pending |
| 1-04-03 | 04 | 4 | VRFY-01 | T-01-22 | Interop CI job fails rather than skips when Docker is unavailable; no `continue-on-error` on the test step | CI wiring | `make test && test -f .github/workflows/ci.yml && grep -c 'go test -race' .github/workflows/ci.yml` | ❌ W0 (created by this task) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Greenfield repository — zero source files exist. Every item below is created inside the phase
by the task named, so no task's automated command references infrastructure that no task
produces.

- [ ] `go.mod` — module init, `go 1.24` directive, zero dependencies (task 1-01-01)
- [ ] `ovpn_test.go` — end-to-end reset round trip over loopback UDP (task 1-01-01)
- [ ] `internal/wire/wire_test.go` — WIRE-01 table vectors + `FuzzParseControlPacket` (task 1-01-02)
- [ ] `internal/tlscrypt/tlscrypt_test.go`, `internal/tlscrypt/keyfile_test.go` — WIRE-04 vectors (task 1-01-02)
- [ ] `cmd/gentestpki/main.go` — Go-generated CA, certs, tls-crypt key and client `.conf` (task 1-02-01)
- [ ] `test/interop/Dockerfile` (digest-pinned `debian:bookworm-slim` + `openvpn`/`tcpdump`/`iproute2`), `test/interop/docker-compose.yml`, `test/interop/server/main.go`, `test/interop/interop_test.go` (task 1-02-01)
- [ ] `test/interop/pcap.go`, `test/interop/capture_test.go`, `test/interop/entrypoint.sh` (task 1-02-02)
- [ ] `Makefile` — `test` / `interop` targets (task 1-02-01), `golden` target (task 1-04-03)
- [ ] `internal/ctrlconn/conn_test.go` (task 1-03-01), `internal/reliable/reliable_test.go` (task 1-03-02)
- [ ] `testdata/golden/` corpus + README, `internal/wire/golden_test.go`, `internal/tlscrypt/golden_test.go` (task 1-04-02)
- [ ] `.github/workflows/ci.yml` (task 1-04-03)

---

## Manual-Only Verifications

`workflow.human_verify_mode` is `end-of-phase`, so these are `<verify><human-check>` items
rather than blocking checkpoints. Each sits alongside an automated assertion — none of them
is the sole evidence for a requirement.

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| The observed opcode sequence is a client hard reset, a server hard reset, then a client control packet from the same session — not a repeating reset loop | VRFY-01 | The automated gate proves the opcode-4 packet arrived; distinguishing "arrived after one clean exchange" from "arrived after several client retries" is a judgement about the shape of the log, and RESEARCH Open Question 2 flags client retry as an unverified behaviour | Read the retained `govpn-interop-server` stdout from the passing run of task 1-02-01 and confirm the sequence appears once, not in a loop |
| The handshake completed once and stayed up — no server-initiated reset, no client reset loop after the first success | CTRL-03 | The automated gate proves a handshake completed; proving it then remained stable is an observation over the whole retained capture rather than a single assertion | Open the retained capture and both containers' output from task 1-03-03 and confirm no further hard-reset opcodes follow the first successful handshake |
| The lossy run completed through genuine retransmission rather than the injected loss having missed every packet by chance | CTRL-01 | Loss injection is probabilistic; the automated gate proves the handshake completed at the configured loss rate but cannot prove any packet was actually dropped in that particular run | Inspect the lossy-run capture from task 1-04-01 for duplicate reliability packet IDs on the wire, confirming retransmission actually occurred |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies — all 10 tasks carry an `<automated>` command
- [x] Sampling continuity: no 3 consecutive tasks without automated verify — every task has one
- [x] Wave 0 covers all MISSING references — each Wave 0 item is created by a named task before any command depends on it
- [x] No watch-mode flags — no `-watch`, no `--watch`; the fuzz step is time-boxed with `-fuzztime 20s`
- [x] Feedback latency < 30s for the fast tier
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending — set `status: validated` after the phase executes and the map's Status column is filled in.
