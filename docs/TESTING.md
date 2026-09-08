<!-- generated-by: gsd-doc-writer -->
[← Back to README](../README.md)

# Testing

`govpn`'s correctness claim rests on two independent layers of evidence: fast, Docker-free unit and golden-vector tests that run on every commit, and a Docker-based interop harness that drives a real, unmodified OpenVPN 2.6 client against the library with full packet capture. Neither layer alone is sufficient — the fast tier proves internal self-consistency and byte-exactness against previously captured real-client traffic, while the interop tier is what actually produces that captured traffic and proves live interoperability with the reference implementation.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the protocol layers under test and [CONFIGURATION.md](CONFIGURATION.md) for the `Config` fields exercised by these tests. See [../CONTRIBUTING.md](../CONTRIBUTING.md) for how test results factor into the PR process.

## Test tiers at a glance

| Tier | Command | Docker required | Runtime |
|---|---|---|---|
| Fast (vet, build, race, golden) | `make test` | No | Seconds |
| Standing prohibition gates | `make gates` | No | Seconds |
| Interop (real OpenVPN 2.6 client) | `make interop` | Yes | Minutes |
| Golden-corpus regeneration | `make golden` | Yes | Minutes |
| Soak (20 connect/disconnect cycles) | `make soak` | Yes | Several minutes |

These map directly to the `Makefile` targets and to the `fast` and `interop` jobs in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## Fast tier: unit, race, and golden-vector tests

The default `make test` target (also `.DEFAULT_GOAL` in the `Makefile`) runs:

```bash
make gates
go vet ./...
go build ./...
go test -race ./...
```

`go test -race ./...` is run explicitly, not only through `make test` — CI's `fast` job runs both the bare command and `make test` as separate steps, per the project's convention (documented in `CLAUDE.md`) that the race detector runs on every CI run, not just occasionally. This matters most for the control-channel reliability layer (`internal/reliable`) and per-session state, which are exactly the kind of timer-driven, stateful code that hides data races.

No `.go` file in this tier carries a build tag, and none of it touches Docker — it is safe to run on every save.

Unit tests are spread throughout the module, mirroring package boundaries:

- Root package (`ovpn`): `ovpn_test.go`, `lifecycle_test.go`, `reneg_test.go`, `ippool_test.go`, `push_test.go`
- `internal/wire`: control-channel packet parsing/serialization (`wire_test.go`, `golden_test.go`)
- `internal/reliable`: retransmission and ACK bookkeeping (`reliable_test.go`)
- `internal/tlscrypt`: tls-crypt wrap/unwrap and static key parsing (`tlscrypt_test.go`, `keyfile_test.go`, `golden_test.go`)
- `internal/keyderiv`: Key Method 2 PRF and key expansion (`prf_test.go`, `keymethod2_test.go`, `keyexpansion_test.go`, `golden_test.go`)
- `internal/datachan`: AES-256-GCM data-channel wrap/unwrap, replay protection, ping keepalives (`datachan_test.go`, `replay_test.go`, `ping_test.go`, `golden_test.go`)
- `internal/ctrlconn`: the `net.Conn`-shaped control-channel framing layer that `crypto/tls` runs on top of (`conn_test.go`)
- `netstack`: the userspace UDP/TCP/ICMP stack (`stack_test.go`, `ipv4_test.go`, `udp_test.go`, `tcp_*_test.go`, `icmp_test.go`, `deadline_test.go`, `fakesession_test.go`, `tcpclient_test.go`, `udpaddr_test.go`)
- `examples/tunnelweb`: the bundled example server (`main_test.go`, `site/site_test.go`)

### Golden-vector tests

Every package's `golden_test.go` file (`internal/wire`, `internal/tlscrypt`, `internal/datachan`, `internal/keyderiv`) asserts against raw wire bytes captured from a real, unmodified OpenVPN 2.6 client's session — not hand-computed or self-generated vectors. These run in the fast tier with no Docker dependency: the corpus is pre-captured and committed under `testdata/golden/`, not regenerated on every run.

For control-channel vectors, the golden tests unwrap under the committed tls-crypt key, parse the recovered plaintext, re-serialize it, and re-wrap it — asserting the result is byte-identical to the original capture. For data-channel vectors, they open under the committed data-channel key using the direction-appropriate role, then re-seal using the vector's own recorded packet ID and the original sender's role — asserting byte-identical output. `internal/keyderiv/golden_test.go` additionally re-derives the data-channel key from the raw Key Method 2 seed material a real client exchanged, confirming `keyderiv.DeriveKeys` reproduces it independently of the reference PRF test vector.

See [`testdata/golden/README.md`](../testdata/golden/README.md) for the full provenance of this corpus (client image digest, OpenVPN package version, capture date) and exactly what "byte-exact" proves at each layer. All committed key material in that directory is throwaway, generated solely for the captured interop session — never used to protect real traffic.

To regenerate the corpus from a fresh interop run (a deliberate act, never a side effect of `make interop` or `make test`):

```bash
make golden
```

which runs `go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -update-golden -v`.

### Standing prohibition gates

`gates_test.go` (root package, no build tag) turns this project's own declared prohibitions — its `must_haves.prohibitions` entries — into executable assertions, so a regression fails a normal `go test` run instead of sitting undetected in a planning document. It walks the repository with `go/parser`/`go/ast` (not raw text matching) to check for forbidden constructs, such as use of `tls.ConnectionState().ExportKeyingMaterial()` for data-channel key derivation (see `CLAUDE.md`'s "What NOT to Use" table) or non-stdlib imports in the core library. Run it directly with:

```bash
make gates
```

which runs `go test -race -run 'TestPhase2|TestPhase3|TestPhase4' -v ./`. `make test` depends on `gates`, so a local `make test` run enforces these checks too, not only CI.

## Interop tier: real OpenVPN 2.6 client via Docker

The interop harness (`test/interop/`) is gated by the `interop` build tag and is excluded from `go test ./...` — it never runs as a side effect of the fast tier. It builds a version-pinned `debian:bookworm-slim`-based Docker image running the real, unmodified `openvpn` client package, starts a Go server process embedding this library, and drives the two through a real handshake and traffic exchange, asserting on packet captures throughout.

Run it with:

```bash
make interop
```

which:

1. Generates a fresh test PKI (`go run ./cmd/gentestpki -out test/interop/pki -profile large`).
2. Runs `go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -v`, which builds the pinned client image and the harness server image via Docker Compose and runs the full scenario table.

### Scenarios

`test/interop/interop_test.go` defines the scenario table (`var scenarios`) driving `TestInteropScenarios`:

| Scenario | Certificate profile | Synthetic loss | Extra behavior |
|---|---|---|---|
| `clean-small` | small | No | Baseline handshake and traffic exchange |
| `clean-large` | large | No | Certificate-fragmentation path (large cert forces control-channel fragmentation) |
| `lossy-large` | large | Yes (`docker-compose.lossy.yml`, `tc`/netem) | Retransmission and reliability-layer behavior under packet loss |
| `reneg` | small | No | `docker-compose.reneg.yml` overlay; short `reneg-sec 15` forces multiple renegotiations across 5 probe rounds, plus `explicit-exit-notify 2` graceful-disconnect verification |
| `auth-user-pass` | small | No | `docker-compose.auth.yml` overlay; `-no-client-cert -auth-user-pass voxio:s3cr3t` proves `Config.AuthUserPass` and certificate-less operation against a real client (no `cert`/`key` directives in `client.conf`, matching `-no-client-cert`/`-credentials` flags on `cmd/gentestpki`) |

A separate, non-default `TestSoak` (see below) exercises long-running connection lifecycle behavior and is not part of this table.

Each scenario run preserves its own packet capture, tls-crypt key, and (where applicable) derived data-channel keys before the next scenario overwrites the shared capture path — see `scenarioResult` in `test/interop/interop_test.go`.

### CI integration

`.github/workflows/ci.yml` defines two jobs:

- **`fast`** (`ubuntu-latest`): `go vet ./...`, `go build ./...`, `make gates`, `go test -race ./...`, then `make test` again as the same entry point a developer uses locally. Also runs `golangci-lint` (bundling `go vet`, `staticcheck`, `gosec`) as a non-blocking step.
- **`interop`** (`ubuntu-latest`, 25-minute timeout): verifies Docker is available, then runs `make interop`. This job fails outright — it never skips — if Docker is unavailable or an image build fails, because a silently skipped interop job would leave the project's central interop-verification claim unverified. On failure, packet captures and container output under `test/interop/captures/` are uploaded as a CI artifact for debugging.

GitHub-hosted `ubuntu-latest` runners are used for the interop job specifically because the lossy scenario needs `tc` (iproute2 netem) and `NET_ADMIN` inside the client container, which only a genuinely Linux Docker host provides reliably in CI.

## Soak testing

A separate, long-running soak test proves dead sessions do not accumulate across repeated connect/use/disconnect cycles from a real client:

```bash
make soak
```

which runs `go run ./cmd/gentestpki -out test/interop/pki -profile small` followed by `go test -tags interop -count=1 -timeout 1800s ./test/interop/ -run 'TestSoak' -v`. It drives one long-lived server process through 20 connect/use/clean-disconnect cycles via `docker-compose.soak.yml`, asserting that goroutine count and post-GC heap allocation return to their post-first-cycle baseline and that the tunnel IP pool is served from a stable address range rather than climbing.

`make soak` is deliberately not a dependency of `make test` or `make interop` — it takes several minutes, longer than either of those targets is meant to cost on a routine run.

## Writing new tests

- Standard Go test files: `*_test.go` alongside the code under test, using the standard `testing` package (`t.Run` subtests are used throughout for table-driven cases, e.g. `gates_test.go` and `internal/wire/wire_test.go`).
- Interop-tier files carry the `//go:build interop` build tag at the top of the file (see `test/interop/interop_test.go`) so they never run under a plain `go test ./...`.
- Golden-vector tests read their corpus from `testdata/golden/` via a package-relative `goldenDir` constant and `manifest.json` — follow the existing pattern in `internal/wire/golden_test.go` or `internal/keyderiv/golden_test.go` if adding a new golden-backed assertion rather than introducing a new corpus format.
- If a change introduces a new standing prohibition (a `must_haves.prohibitions` entry), add the corresponding assertion to `gates_test.go` using an AST walk (`go/parser` + `go/ast`), not raw text matching — a text search would also flag this project's own documentation of forbidden constructs.

## Coverage

No coverage threshold is configured in the `Makefile` or CI workflow — `go test -race ./...` runs without a `-cover` flag, and no `.github/workflows/ci.yml` step measures or gates on coverage percentage.

## Further reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — the protocol layers these tests exercise
- [CONFIGURATION.md](CONFIGURATION.md) — `Config` fields used to construct test servers
- [DEVELOPMENT.md](DEVELOPMENT.md) — local build and lint commands
- [`../test/interop/`](../test/interop/) — the interop harness source (Docker Compose files, PKI generation, packet decoding)
- [`../testdata/golden/README.md`](../testdata/golden/README.md) — golden-vector corpus provenance
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — how tests factor into the contribution and review process
