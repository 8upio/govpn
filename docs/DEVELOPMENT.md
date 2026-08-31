<!-- generated-by: gsd-doc-writer -->
[← Back to README](../README.md)

# Development

This document covers local development setup, build/test commands, code
style, and the contribution workflow for `govpn` (module
`github.com/8upio/govpn`, package `ovpn`). For first-run instructions and
prerequisites, see [GETTING-STARTED.md](GETTING-STARTED.md); for how the
test suite (unit, golden-vector, and Docker interop tiers) is organized,
see [TESTING.md](TESTING.md); for system design, see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Local setup

`govpn`'s core library and unit/golden tests have **no external
dependencies beyond the Go standard library and toolchain** — `go.mod`
declares no third-party requirements. Only the interop test tier
(`make interop`, `make golden`, `make soak`) additionally requires Docker.

1. Clone the repository and `cd` into it:

   ```bash
   git clone https://github.com/8upio/govpn.git
   cd govpn
   ```

2. Confirm your Go toolchain matches `go.mod`'s `go 1.24` directive:

   ```bash
   go version
   ```

3. Build and vet the module (no separate "install dependencies" step is
   needed — there are none to fetch):

   ```bash
   go build ./...
   go vet ./...
   ```

4. Run the fast test tier (see [Build commands](#build-commands) below):

   ```bash
   make test
   ```

If you plan to work on the interop harness (`test/interop/`) or regenerate
the golden-vector corpus (`testdata/golden/`), you additionally need a
working Docker + Docker Compose v2 installation. The interop harness builds
its own client image from a pinned `debian:bookworm-slim` digest
(`test/interop/Dockerfile`) rather than pulling a third-party OpenVPN
client image — no extra setup beyond having Docker running is required.

<!-- VERIFY: Docker Desktop version/edition requirements for local interop-harness development are not pinned anywhere in this repository beyond the CI job's own ubuntu-latest runner; see .github/workflows/ci.yml's own note that the harness was developed and manually verified on macOS with Docker Desktop's Linux VM. -->

## Build commands

All commands below are defined in the [`Makefile`](../Makefile). `make`
with no target runs `test` (`.DEFAULT_GOAL := test`).

| Command | Description |
|---|---|
| `make test` | Default target. Runs `make gates`, then `go vet ./...`, `go build ./...`, and `go test -race ./...`. Never touches Docker — the fast, reflexive tier, including the golden-vector tests (`internal/wire/golden_test.go`, `internal/tlscrypt/golden_test.go`, and other `internal/*/golden_test.go` files) that assert byte-exactness against real OpenVPN 2.6 client bytes committed in `testdata/golden/`. |
| `make gates` | Runs `gates_test.go`'s standing-prohibition assertions (`go test -race -run 'TestPhase2\|TestPhase3\|TestPhase4' -v ./`) — repository-wide checks such as "no code path calls `tls.ConnectionState().ExportKeyingMaterial()`" and "every `crypto/md5`/`crypto/sha1` import carries a `//nolint:gosec` rationale comment." A dependency of `make test`, so a plain `make test` run enforces it too. |
| `make interop` | Full interop tier. Generates a fresh test PKI (`go run ./cmd/gentestpki -out test/interop/pki -profile large`), then builds and runs the Docker Compose-based harness against a real, pinned OpenVPN 2.6 client across the scenario table (`clean-small`, `clean-large`, `lossy-large`) via `go test -tags interop ./test/interop/ -run TestInteropScenarios`. |
| `make golden` | Regenerates `testdata/golden/` from a fresh `clean-large` interop run (`go test -tags interop ... -run TestInteropScenarios -update-golden`). A deliberate act — never a side effect of `make test` or `make interop` — so a corpus change always shows up as an intentional diff. |
| `make soak` | Long-running (up to 30 minutes) soak test: one server process driven through 20 real connect/use/disconnect cycles from a real OpenVPN 2.6 client, checking for goroutine/memory leaks and tunnel-IP pool growth. Not a dependency of `test` or `interop` — run explicitly. |

Equivalent raw commands, if you want to run a step in isolation:

```bash
go vet ./...
go build ./...
go test -race ./...
```

## Code style

`govpn` uses standard Go tooling — there is no project-specific `.eslintrc`,
`.prettierrc`, or `.editorconfig` in the repository, and no `.golangci.yml`
configuration file; CI runs `golangci-lint-action@v6` with its default
ruleset (`--timeout=5m`), which bundles `go vet`, `staticcheck`, and `gosec`.

- Format code with `gofmt` (or `go fmt ./...`) before committing — standard
  Go convention, not project-specific tooling.
- `go vet ./...` and `go build ./...` are both part of `make test` and the
  CI `fast` job; a failing `vet` or build fails CI.
- The static-analysis step (`golangci-lint`) is currently
  **non-blocking** in CI (`continue-on-error: true` in
  `.github/workflows/ci.yml`) — findings are informational, not
  merge-blocking, but should still be addressed.
- **Expect `gosec` to flag every `crypto/md5` and `crypto/sha1` import** as
  weak crypto (G401/G505). These are real findings in general but false
  positives here: MD5/SHA1 are used only as label-mixing components of
  OpenVPN's mandated Key Method 2 PRF (`internal/keyderiv/prf.go`), not the
  actual security boundary (that's TLS + AES-256-GCM). Every such import
  must carry an explicit `//nolint:gosec` comment naming the specific rule
  (G401/G505) with a one-line rationale — see
  `internal/keyderiv/prf.go`'s import-site comments for the established
  pattern. `gates_test.go` (`make gates`) enforces that this annotation is
  present on every `crypto/md5`/`crypto/sha1` import in the repository, so
  a missing annotation fails the fast test tier, not just the lint step.
- `internal/` packages are split one-per-protocol-concern (see
  [ARCHITECTURE.md](ARCHITECTURE.md)'s directory structure rationale) —
  new protocol logic should generally land in the matching `internal/`
  package rather than in the top-level `ovpn` package, which is kept to
  the public surface (`Server`, `Session`, `Config`) and the glue that
  wires the internal packages together (`ovpn.go`, `push.go`,
  `ippool.go`).
- Protocol-level changes (wire format, cryptographic construction, key
  derivation) should be verified against the OpenVPN 2.6 C reference
  source (`ssl.c`, `crypto.c`, `tls_crypt.c`, `reliable.c`, `ssl_pkt.c`)
  rather than approximated from memory — this project's stated
  correctness source.

## Branch conventions

No branch-naming convention is documented in this repository — there is no
`CONTRIBUTING.md` or `.github/PULL_REQUEST_TEMPLATE.md` specifying one, and
the repository currently has only a single branch (`main`). `main` is the
default/trunk branch.

## PR process

There is no `.github/PULL_REQUEST_TEMPLATE.md` or `.github/ISSUE_TEMPLATE/`
in this repository, so the process below is inferred from what CI actually
enforces (`.github/workflows/ci.yml`):

- Every push and pull request triggers the CI workflow's two jobs: `fast`
  (vet, build, `make gates`, `go test -race ./...`, `make test`, and
  non-blocking `golangci-lint`) and `interop` (the full Docker-based
  real-OpenVPN-2.6-client harness, `make interop`).
- The `interop` job fails outright — it never skips — if Docker is
  unavailable or an image build fails, since a silently skipped interop
  run would leave this project's central compatibility claim unverified.
  On failure, it uploads packet captures and container output
  (`test/interop/captures/`) as a CI artifact for debugging.
- A change should pass `make test` locally before opening a PR; if the
  change touches control-channel framing, `tls-crypt`, key derivation, or
  data-channel crypto, also run `make interop` locally if Docker is
  available, since those are exactly the surfaces the interop tier exists
  to catch.
- Recent commit history uses a conventional-commit-style prefix
  (`feat:`, `fix:`, `docs:`, `chore:`, etc.) — follow that pattern for new
  commits and PR titles.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for further contribution
guidelines.

## Related documentation

- [README.md](../README.md) — project overview and quick start
- [GETTING-STARTED.md](GETTING-STARTED.md) — prerequisites and first run
- [TESTING.md](TESTING.md) — unit, golden-vector, and Docker interop test tiers
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design and directory structure rationale
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to contribute
