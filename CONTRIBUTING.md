<!-- generated-by: gsd-doc-writer -->
[← Back to README](README.md)

# Contributing to govpn

`govpn` is a pure-Go, standard-library-only implementation of the **server side of the OpenVPN protocol**. Every wire format and cryptographic construction is verified against the OpenVPN 2.6 C reference source and cross-checked against a real, unmodified OpenVPN 2.6 client. That verification bar shapes how contributions are made and reviewed — please read the constraints below before opening a PR.

## Before you start

- **See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the layered protocol stack (UDP triage → control-channel framing/reliability → `crypto/tls` → data-channel AEAD) and where each `internal/` package fits.
- **See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** for local setup, build commands, and code style.
- **See [docs/TESTING.md](docs/TESTING.md)** for the unit/golden-vector/interop test tiers described below.

## The standard-library-only constraint

The core library (everything outside `test/interop/`) depends on **Go standard library only** — `go.mod` declares no third-party requirements, and that is a deliberate, load-bearing project constraint, not an oversight.

- Do **not** add a third-party dependency to the root `go.mod` without first discussing it in an issue or PR description — explain what stdlib gap it fills and why a hand-written alternative isn't practical.
- The one exception already made in the project's own design notes is `golang.org/x/sys/unix` for OS-level TUN/utun syscalls, if that work is ever picked up — everything else (AES-GCM, AES-CTR, HMAC-SHA256, the legacy MD5/SHA1 PRF, X.509) has a direct stdlib home.
- Test-only tooling that lives in a separate module (e.g. `test/interop/` if it grows its own `go.mod`, such as for `gopacket`-based packet assertions) is a different story — those dependencies don't affect the core library's dependency graph and are fine.
- `go vet`, `staticcheck`, and `gosec` findings matter, but `gosec` will correctly-but-falsely flag `crypto/md5`/`crypto/sha1` imports used for OpenVPN's Key Method 2 PRF as weak crypto (G401/G505). Those are wire-format compatibility requirements, not the security boundary (that's TLS + AES-256-GCM) — suppress with an inline `//nolint:gosec` and a comment explaining why, never a blanket rule disable.

## Protocol correctness is verified, not assumed

Any change touching wire formats, framing, key derivation, or crypto must be checked against the OpenVPN reference source before it's considered correct — not approximated from memory or from a general understanding of how OpenVPN "usually" works. The project treats these C source files as the spec:

| Reference file | Subsystem |
|---|---|
| `ssl_pkt.c` | Control-channel packet format, opcode/session-ID/HMAC framing |
| `reliable.c` | Control-channel retransmission, ACK bookkeeping, packet-ID windows |
| `ssl.c` | `openvpn_PRF`, Key Method 2 key derivation, control-message format |
| `crypto.c` | Data-channel AEAD nonce construction, static-key file format |
| `tls_crypt.c` | tls-crypt wrap/unwrap (HMAC-SHA256 + AES-256-CTR) |

When you submit a PR that touches any of these areas, cite the reference file/function your implementation matches in the PR description or code comments. If you're not sure which reference behavior applies, open an issue to discuss before writing code.

## Interop verification

The project's core value claim — that a real, unmodified OpenVPN 2.6 client can connect and exchange traffic — is verified by a Docker-based interop harness in `test/interop/`, not asserted. It builds a version-pinned Debian `bookworm` OpenVPN client image and runs it against the library over Docker Compose, capturing packets for scenario assertions.

- If your change affects anything the interop harness exercises (handshake, data-channel crypto, control-channel framing, renegotiation, packet loss handling), run `make interop` locally before opening a PR, and mention the result in the PR description.
- If your change affects protocol behavior, consider whether `testdata/golden/` needs regenerating via `make golden` — this is a deliberate, explicit act (never a side effect of `make test` or `make interop`), so only run it when you mean to update the committed golden vectors, and call it out in your PR if you do.
- CI's `interop` job (`.github/workflows/ci.yml`) runs the same `make interop` target against the real client and fails the build outright (never skips) if Docker or the client image is unavailable.

## Running the test suite

```bash
make test      # go vet, go build, go test -race ./... (default target, no Docker)
make interop    # generates a test PKI and runs the full scenario table against a real OpenVPN 2.6 client (needs Docker)
make golden     # regenerates testdata/golden/ from a fresh interop capture (deliberate, not run automatically)
```

- **`go test -race` is mandatory**, not optional — CI runs it explicitly on every push and PR (`.github/workflows/ci.yml`, job `fast`), and `make test` runs it too. The control-channel reliability layer (retransmission timers, ACK bookkeeping) and per-session state are exactly the kind of stateful, timer-driven code that hides data races when tested without `-race`.
- `make test` also depends on `make gates` — the project's own standing prohibitions (`gates_test.go`), assertions derived from each shipped phase's `must_haves.prohibitions`. A gate failure means a regression against a constraint the project has already committed to, not a stylistic nitpick — treat it as a real test failure.
- The `interop` CI job only runs on `ubuntu-latest` (Docker Desktop on GitHub-hosted macOS runners doesn't expose a usable Docker daemon, and the lossy-loss scenario needs `iproute2`'s `tc netem` under `NET_ADMIN`, which only a genuine Linux Docker host provides reliably).

See [docs/TESTING.md](docs/TESTING.md) for the full breakdown of what each tier covers.

## Code style

- Run `go vet ./...` and `go build ./...` before opening a PR — both are checked in CI (`fast` job) and part of `make test`.
- `golangci-lint` (bundling `staticcheck` and `gosec`) runs in CI as a non-blocking, informational check — fix what it flags where reasonable, and document deliberate exceptions (like the `gosec` MD5/SHA1 case above) with an inline comment rather than silencing the rule everywhere.
- See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for further code style detail.

## Submitting a pull request

- Keep PRs scoped to one change — protocol/crypto changes, netstack changes, and doc-only changes are easier to review separately.
- Describe what reference source (if any) your change is verified against, and whether `make interop` and/or `make golden` were run.
- Ensure `make test` passes locally before requesting review; CI will also run `make test` and `make interop` on every push and pull request.
- There is no formal branch-naming or commit-message convention enforced yet — follow the existing git history's style (short, present-tense summary; `type(scope): description` is common but not required).
- <!-- VERIFY: no `.github/PULL_REQUEST_TEMPLATE.md` or `.github/ISSUE_TEMPLATE/` exists in the repository yet — confirm whether these should be added before external contributions are solicited -->

## Reporting issues

There is no issue template configured yet, so when filing a bug report or feature request, please include:

- What you expected to happen and what actually happened.
- Steps to reproduce, including relevant `ovpn.Config` fields (redact any real certificate/key material).
- The `govpn` commit or version, your Go version (`go version`), and, if relevant, the OpenVPN client version you tested against.
- For protocol/interop issues, a packet capture or the relevant `test/interop/captures/` output if you have one.

## License

<!-- VERIFY: no LICENSE file is present in the repository root; confirm the intended license before accepting external contributions -->
