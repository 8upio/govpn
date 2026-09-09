# Golden vectors: real OpenVPN 2.6 client control- and data-channel traffic

These files are raw wire bytes captured from a real, unmodified OpenVPN
client's session against this library, via the Docker interop harness
(`test/interop/`) — not hand-computed or self-generated. Every fast-tier
golden test (`internal/wire/golden_test.go`,
`internal/tlscrypt/golden_test.go`, `internal/datachan/golden_test.go`,
`internal/keyderiv/golden_test.go`) asserts against these exact bytes, with
no Docker dependency (01-04-PLAN.md Task 2, closing 01-RESEARCH.md Open
Question 1; 02-04-PLAN.md Task 2 extended the corpus to the data channel;
05-05-PLAN.md Task 1 extended it to a second, AES-128-GCM data-channel
source).

## Provenance

| Field | Value |
|---|---|
| Client image | `debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241` (`test/interop/Dockerfile`) |
| OpenVPN client package | `openvpn 2.6.14-0+deb12u2` (Debian bookworm, resolved 2026-08-23 per `test/interop/Dockerfile`'s own comment) |
| Control-channel + AES-256-GCM data-channel source | `clean-large` (`cmd/gentestpki -profile large`, no synthetic loss) |
| AES-128-GCM data-channel source | `cipher-128` (client `data-ciphers AES-128-GCM`, server allow-list `AES-128-GCM`, 05-05-PLAN.md Task 2) |
| Capture date | 2026-08-23 (control-channel corpus); 2026-08-24 (data-channel corpus, 02-04-PLAN.md Task 2); 2026-09-09 (AES-128-GCM data-channel corpus, 05-05-PLAN.md Task 2) |
| Regenerate with | `make golden` (`go test -tags interop -run TestInteropScenarios -update-golden ./test/interop/`) |

Regeneration is a deliberate act (`-update-golden` / `make golden`), never a
side effect of an ordinary `make interop` or `make test` run — a corpus
change always appears as an intentional diff. One `make golden` run
regenerates the ENTIRE corpus from two source scenarios in a single pass:
`clean-large` for the control-channel vectors and the AES-256-GCM
data-channel vectors (both captured from the same session), and `cipher-128`
for the AES-128-GCM data-channel vectors — `-update-golden` refuses to write
anything unless BOTH scenarios passed, naming whichever one did not, so a
half-regenerated corpus can never be committed as if it were complete
(T-05-25).

## Files

- `001`-`005`, `<direction>-<label>.bin` — one selected control datagram's
  raw wire bytes (tls-crypt wrapped), named by capture sequence and
  direction, from the `clean-large` source. See `manifest.json` for each
  vector's decoded direction, opcode, and reliability packet ID.
- `006`-`008`, `<direction>-<label>.bin` — one selected AES-256-GCM
  data-channel (`P_DATA_V2`) datagram's raw wire bytes (never tls-crypt
  wrapped — RESEARCH Pitfall 3), from the `clean-large` source, covering a
  client-to-server ICMP echo request, a server-to-client echo reply, and a
  ping keepalive.
- `009`-`011`, `<direction>-<label>.bin` — the same three vector kinds, this
  time AES-128-GCM sealed, from the `cipher-128` source. File numbering
  continues after the `clean-large` source's own vectors rather than
  restarting, so no two sources' output files ever collide.
- See `manifest.json`'s `peer_id`/`data_packet_id`/`key_file`/`sender_slot`/
  `cipher` fields for each data-channel vector's decode/reseal parameters.
- `manifest.json` — the array `internal/wire/golden_test.go`,
  `internal/tlscrypt/golden_test.go`, and `internal/datachan/golden_test.go`
  all read. Control-channel entries carry `file`/`direction`/`opcode`/
  `packet_id` (Phase 1's original schema); data-channel entries additionally
  carry `peer_id`, `data_packet_id`, `key_file` (`data-channel.key` for the
  AES-256-GCM vectors, `data-channel-aes128.key` for the AES-128-GCM ones),
  `sender_slot` (0 or 1 — which `Key2.keys[]` slot the original sender
  encrypted with, recorded as data rather than left to inference, since
  RESEARCH Pitfall 1's mirror-opposite convention is exactly the thing this
  corpus exists to catch getting backwards), and `cipher` (the canonical
  cipher name the vector was captured under, e.g. `"AES-128-GCM"` — an
  absent value means `AES-256-GCM`, what every entry meant implicitly
  before Phase 5, so this corpus stays readable at an older revision). The
  golden tests build each vector's `Wrapper` from ITS OWN manifest-named
  cipher, never a package-wide assumption. `internal/wire` and
  `internal/tlscrypt`'s own tests filter data-channel entries out
  (`key_file != ""`) rather than trying to tls-crypt-unwrap a payload that
  was never tls-crypt wrapped — one manifest schema extended, not a second
  format introduced (01-04-SUMMARY.md's own established pattern).
- `tls-crypt.key` — the exact tls-crypt static key (OpenVPN "Static key V1"
  PEM envelope) the `clean-large` session used, for the control-channel
  corpus. Not re-captured from `cipher-128`: control-channel vectors and
  the tls-crypt key that protects them are cipher-independent, so capturing
  a second copy would only risk two committed keys silently diverging.
- `data-channel.key` — the `clean-large` session's derived AES-256-GCM
  data-channel key material, from the server's own perspective
  (`keyderiv.Key2.ServerSlots`), hex-encoded JSON:
  `encrypt_cipher`/`encrypt_implicit_iv`/`decrypt_cipher`/
  `decrypt_implicit_iv`/`cipher`/`cipher_key_len`. `internal/datachan/golden_test.go`
  builds both the server-perspective Wrapper (opens client-to-server traffic
  directly) and its mirror (opens server-to-client traffic) from this one
  file. `encrypt_cipher`/`decrypt_cipher` are always 32 bytes (64 hex chars)
  wide, regardless of cipher — they carry the full key-expansion slot, not
  the trimmed AEAD key; `cipher_key_len` (16 or 32) tells the reading side
  how many of those bytes the AEAD construction actually uses (RESEARCH
  Pitfall 5) — hexDecodeFixed's own fixed-width length check never changes.
- `data-channel-aes128.key` — the same shape as `data-channel.key`, from the
  `cipher-128` session instead: `cipher` is `"AES-128-GCM"` and
  `cipher_key_len` is `16`, while `encrypt_cipher`/`decrypt_cipher` still
  hex-encode the full 32-byte slot.
- `data-channel-km2.json` — the raw Key Method 2 seed material the
  `clean-large` session's real client and this library's own server
  actually exchanged (`client_pre_master`/`client_random1`/
  `client_random2`/`server_random1`/`server_random2`/`client_session_id`/
  `server_session_id`, hex-encoded), read by `internal/keyderiv/golden_test.go`'s
  `TestGoldenKeyExpansionFromCapture` to independently re-run
  `keyderiv.DeriveKeys` and confirm it reproduces `data-channel.key`
  byte-for-byte from live evidence, not only from the reference's own PRF
  test vector. There is no `cipher-128` equivalent: key expansion is
  cipher-independent, so a second copy would duplicate this proof rather
  than extend it.

## The committed key material is throwaway material

**`tls-crypt.key` and `data-channel.key`/`data-channel-aes128.key`/
`data-channel-km2.json` in this directory are randomly generated/derived for
a captured interop session. None of it has ever protected, and none of it
must ever be used to protect, any real traffic.** Every CommonName in the underlying certificate
chain is namespaced `govpn-interop-*` (`cmd/gentestpki`) for the same
reason, and the PKI itself (`test/interop/pki/`) is regenerated fresh by
`cmd/gentestpki` on every interop run — never reused, never committed.
Committing this key material is what makes these vectors independently
verifiable offline — without the exact key material, nobody could confirm
the golden tests' open/re-seal/re-derive assertions actually authenticate
against real captured bytes rather than trusting the corpus on faith.

## What "byte-exact" proves here

For every control-channel vector, the golden tests unwrap it under
`tls-crypt.key`, parse the recovered plaintext as a control packet,
re-serialize that parse, and re-wrap it using the vector's own recovered
tls-crypt packet ID — asserting the final bytes are identical to the
original capture, byte for byte. For every data-channel vector, the golden
tests open it under `data-channel.key` (choosing the direction-appropriate
Wrapper role, RESEARCH Pitfall 1), then re-seal the recovered plaintext
using the vector's own recorded `data_packet_id` and the ORIGINAL SENDER's
own role (`internal/datachan.Wrapper.SealWithPacketID`) — asserting the
result is identical to the original capture, byte for byte. Both chains can
only reproduce the original if every layer (`internal/tlscrypt`,
`internal/wire`, `internal/datachan`, `internal/keyderiv`) is byte-exact
against what a real client actually put on the wire, not merely
self-consistent against its own round trip — and, for the data channel
specifically, only if the key-direction convention is not silently
inverted, which is exactly the failure mode round-trip self-consistency
cannot catch on its own (RESEARCH Pitfall 1).
