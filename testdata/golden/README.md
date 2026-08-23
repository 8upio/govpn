# Golden vectors: real OpenVPN 2.6 client control-channel traffic

These files are raw wire bytes captured from a real, unmodified OpenVPN
client's session against this library, via the Docker interop harness
(`test/interop/`) — not hand-computed or self-generated. Every fast-tier
golden test (`internal/wire/golden_test.go`,
`internal/tlscrypt/golden_test.go`) asserts against these exact bytes, with
no Docker dependency (01-04-PLAN.md Task 2, closing 01-RESEARCH.md Open
Question 1).

## Provenance

| Field | Value |
|---|---|
| Client image | `debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241` (`test/interop/Dockerfile`) |
| OpenVPN client package | `openvpn 2.6.14-0+deb12u2` (Debian bookworm, resolved 2026-08-23 per `test/interop/Dockerfile`'s own comment) |
| Scenario | `clean-large` (`cmd/gentestpki -profile large`, no synthetic loss) |
| Capture date | 2026-08-23 |
| Regenerate with | `make golden` (`go test -tags interop -run TestInteropScenarios -update-golden ./test/interop/`) |

Regeneration is a deliberate act (`-update-golden` / `make golden`), never a
side effect of an ordinary `make interop` run — a corpus change always
appears as an intentional diff.

## Files

- `NNN-<direction>-<label>.bin` — one selected control datagram's raw wire
  bytes (tls-crypt wrapped), named by capture sequence and direction. See
  `manifest.json` for each vector's decoded direction, opcode, and
  reliability packet ID.
- `manifest.json` — the array `internal/wire/golden_test.go` and
  `internal/tlscrypt/golden_test.go` both read to know which wrapper
  direction and expected opcode/packet ID apply to each `.bin` file.
- `tls-crypt.key` — the exact tls-crypt static key (OpenVPN "Static key V1"
  PEM envelope) this session used.

## The committed key is throwaway material

**`tls-crypt.key` in this directory is a randomly generated key created
solely for this captured interop session. It has never protected, and must
never be used to protect, any real traffic.** Every CommonName in the
underlying certificate chain is namespaced `govpn-interop-*`
(`cmd/gentestpki`) for the same reason. Committing it is what makes these
vectors independently verifiable offline — without the exact key material,
nobody could confirm the golden tests' unwrap/re-wrap assertions actually
authenticate against real captured bytes rather than trusting the corpus on
faith.

## What "byte-exact" proves here

For every vector, the golden tests unwrap it under this key, parse the
recovered plaintext as a control packet, re-serialize that parse, and
re-wrap it using the vector's own recovered tls-crypt packet ID — asserting
the final bytes are identical to the original capture, byte for byte. That
chain (unwrap → parse → serialize → re-wrap) can only reproduce the
original if every layer (`internal/tlscrypt`, `internal/wire`) is byte-exact
against what a real client actually put on the wire, not merely
self-consistent against its own round trip.
