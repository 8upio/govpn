# Pitfalls Research

**Domain:** Pure-Go reimplementation of the OpenVPN server protocol (control channel, tls-crypt, Key Method 2, AES-256-GCM data channel)
**Researched:** 2026-08-22
**Confidence:** MEDIUM-HIGH (official OpenVPN doxygen/source docs cross-checked for control-channel and data-channel wire formats; exact byte offsets for tls-crypt static key file layout and the full key_source2 struct are HIGH-confidence from well-established community reverse-engineering but should still be verified line-by-line against `crypto.c`/`ssl.c`/`tls_crypt.c` before coding, per the project's own stated principle — there is no RFC, the C source is the spec)

**Framing note:** Nearly every pitfall below reduces to one root cause: **a plausible-looking byte layout that is subtly wrong**, which produces one of exactly two symptoms against a real client — (a) a silent hang/retransmit loop with no error on either side, or (b) a 100%-reproducible "TLS/GCM authentication failed" error that looks like a key-derivation bug but is actually a framing/AAD/header bug. Both symptoms are indistinguishable from working code by reading it — they only surface against a real client with a packet capture. This is why the project already treats the Docker interop harness as a v1 requirement, not an afterthought; the pitfalls below exist specifically to reduce how many round trips through that harness are needed to find each bug class.

---

## Critical Pitfalls

### Pitfall 1: Using real TLS 1.2+ PRF or `ExportKeyingMaterial()` instead of OpenVPN's own TLS1-PRF

**What goes wrong:**
Data-channel keys come out wrong. The TLS handshake itself succeeds (control channel works fine), but every data-channel packet fails GCM tag verification against a real client, because the two sides derived different cipher/HMAC keys.

**Why it happens:**
OpenVPN's Key Method 2 key expansion looks like it should map onto `crypto/tls`'s `ConnectionState().ExportKeyingMaterial()` (RFC 5705) — both take a label and produce keying material from the TLS session. But OpenVPN implements its **own** PRF (`tls1_PRF` in `crypto.c`), which reproduces the *original TLS 1.0/SSL3* construction — `P_MD5(secret, seed) XOR P_SHA1(secret, seed)`, i.e. an HMAC-MD5-based P_hash XORed with an HMAC-SHA1-based P_hash, applied iteratively to produce arbitrary-length output. This is **not** the SHA-256-only PRF used by TLS 1.2, and it is **not** derived from the live TLS session's master secret via keying-material export — it runs entirely over application-level random material (`pre_master`, `random1`, `random2`) exchanged as an ordinary message *inside* the already-established TLS tunnel, independent of whatever TLS version/PRF `crypto/tls` negotiated for the control channel itself. RFC 5705 `EXPORTER-OpenVPN-datakeys` support was added later as an *alternative* key-derivation mode (opt-in, not the default Key Method 2 behavior) — do not assume it's what a stock OpenVPN 2.6 client does by default.

**How to avoid:**
- Implement `tls1_PRF` from scratch (MD5+SHA1 P_hash construction) as an isolated, independently unit-testable function — do not route it through `crypto/tls` in any way.
- Exchange the `key_source2` structure (client `pre_master[48]` + `random1[32]` + `random2[32]`; server `random1[32]` + `random2[32]`, no pre_master) as a plain message over the TLS control channel after the handshake completes — this is application data on top of TLS, not a TLS-layer operation.
- Derive `master_secret = tls1_PRF(pre_master, "OpenVPN master secret", client.random1 || server.random1, 48)`, then `key_expansion = tls1_PRF(master_secret, "OpenVPN key expansion", client.random2 || server.random2, 256)`.
- Write a standalone test vector (known input → known output) for `tls1_PRF` against a value captured from a real OpenVPN debug build or a documented test vector before wiring it into the handshake at all.

**Warning signs:**
- TLS handshake completes, PUSH_REPLY exchange appears to work, but the client immediately shows `"AEAD Decrypt error"` / auth failures on every data packet.
- Decryption "sometimes" works in one direction only (a sign that client-key/server-key assignment within the 256-byte `key_expansion` output was swapped, not that the PRF itself is wrong — see Pitfall 3).

**Phase to address:**
Key Method 2 / data-channel key derivation phase — must be verified byte-exact against `ssl.c`/`crypto.c` *before* any data-channel encryption code is written, exactly as the project's own briefing already flags.

---

### Pitfall 2: tls-crypt is MAC-then-encrypt with an SIV-style derived IV, not encrypt-then-MAC

**What goes wrong:**
Implementers reach for the "standard" modern pattern (encrypt with a random/counter IV, then MAC the ciphertext) because that's what most Go crypto tutorials teach. tls-crypt does the opposite, and doing it the "normal" way produces packets a real OpenVPN client will not decrypt.

**Why it happens:**
tls-crypt uses two independent 256-bit keys (Ka = authentication key, Ke = encryption key) derived from a static pre-shared key file, and computes:
`auth_tag = HMAC-SHA256(Ka, header || plaintext_payload)`, then uses the **top 128 bits of that auth_tag as the AES-256-CTR IV** to encrypt the payload with Ke. This is a synthetic-IV (SIV-like) construction: the MAC is computed over the *plaintext*, and its output doubles as the IV. Wire format: `opcode(1) || session_id(8) || packet_id(8) || auth_tag(32) || E(payload)`, where opcode+session_id+packet_id form the authenticated (not encrypted) header, and the payload is authenticated-and-encrypted. Getting the order backwards (encrypt first, then MAC the ciphertext) produces a completely different IV and different ciphertext than a real client/server pair expects — with no error message, just packets that fail to parse as valid TLS record data on the far end (looks like a TLS problem, is actually a tls-crypt bug).

**How to avoid:**
- Implement `auth_tag` computation and IV derivation as one atomic step, tested independently of the AES-CTR encryption step.
- Do not reuse the AAD/MAC-then-encrypt code path from tls-crypt for anything else (e.g. don't accidentally generalize it into a "standard AEAD wrapper" used elsewhere in the codebase — it's protocol-specific and non-standard by modern crypto conventions).
- Treat the **outer** tls-crypt `packet_id` (replay protection on the wrapped layer, no timestamp, purely a monotonic/window-checked counter per direction) as a completely separate counter from the **inner** reliability-layer packet-id that appears only after decryption, and again separate from the **data-channel** packet-id used in P_DATA_V2 (Pitfall 6). Three different packet-id concepts exist in this codebase; naming them identically in Go (e.g. all called `packetID uint32`) is a self-inflicted confusion risk — give them distinct types.

**Warning signs:**
- The very first `HARD_RESET_CLIENT_V2` packet from a real client never gets a reply, and the server has no visibility into why (because it can't authenticate/decrypt the wrapping to even see the inner opcode) — this manifests as the client retransmitting HARD_RESET forever with zero server-side log output, which is easy to misdiagnose as "the client isn't reaching the server at all" (a network problem) rather than a tls-crypt bug.

**Phase to address:**
tls-crypt implementation phase (should follow control-channel framing, precede/parallel with the TLS handshake integration phase, since tls-crypt wraps *every* control packet from the first byte — see Pitfall 5).

---

### Pitfall 3: Key expansion output layout — mixing up which 64-byte slot is cipher vs HMAC key, and which direction is "encrypt" on which side

**What goes wrong:**
The 256-byte `key_expansion` PRF output is a flat byte blob that must be sliced into 4 logical 64-byte key material slots (client-cipher, client-hmac, server-cipher, server-hmac in `struct key2`), each of which is itself only *partially* consumed (e.g. AES-256 uses the first 32 of 64 bytes; with AES-GCM the "hmac" slot isn't used for HMAC at all but its bytes are reused as GCM's implicit IV material — see Pitfall 6). Getting the slot order wrong, or getting which side's slot is "my encrypt key" vs "my decrypt key" wrong, produces the classic symmetric-crypto failure mode: **one direction of traffic decrypts fine, the other doesn't** (because you can accidentally use the same key for both directions on one side while the peer uses genuinely different keys, or you swap client/server assignment relative to the peer).

**Why it happens:**
The convention mirrors `--key-direction` semantics from `tls-auth`/static-key mode: whichever side is logically "0" uses slot A to encrypt and slot B to decrypt; the peer (logically "1") uses the *same two slots* but with encrypt/decrypt swapped. A server implementation that doesn't mirror this — e.g. always treating "slot 0 = my encrypt key" regardless of which side it is — will produce asymmetric behavior that's easy to miss in a quick loopback test where the bug happens to cancel out, but breaks against a real client.

**How to avoid:**
- Write the key-expansion output → `{encrypt: {cipher, hmac}, decrypt: {cipher, hmac}}` mapping as one explicit, well-commented function referencing the exact `key2`/`key_direction` logic in `ssl.c`/`crypto.c`, not scattered inline slicing at each call site.
- Test with a fixed, hardcoded `pre_master`/`random1`/`random2` input on both a mock "client" and mock "server" instance of your own code and assert the derived encrypt-key on one side equals the derived decrypt-key on the other, for both directions, before ever testing against a real client.

**Warning signs:**
Traffic flows one direction (e.g. server→client pings work) but the other direction fails GCM auth on every packet, or vice versa.

**Phase to address:**
Same phase as Pitfall 1 (Key Method 2 / data-channel key derivation) — this is the direct next step after the PRF itself is correct.

---

### Pitfall 4: `crypto/tls` over a custom `net.Conn` breaks unless the conn fully replicates TCP-stream semantics, including fragmenting large TLS records across multiple small control packets

**What goes wrong:**
The happy path — cert-based auth, which this project requires from day one — sends a server certificate (and likely a CA chain) as part of the handshake. That certificate message is commonly several KB, far larger than a single OpenVPN control-channel packet's safe payload (well under ~1250 bytes to avoid IP fragmentation — see Pitfall 5). `crypto/tls` has no concept of "control packets"; it just calls `Write([]byte)` on the underlying `net.Conn` with however many bytes make up a TLS record, and calls `Read([]byte)` expecting ordinary byte-stream semantics (partial reads allowed, but bytes must arrive in order, exactly once, with no gaps — exactly like a TCP socket). If the custom `net.Conn`'s `Write()` doesn't transparently fragment large writes into multiple reliability-layer control packets (and its `Read()` doesn't transparently reassemble them across multiple incoming control packets before returning bytes to the TLS stack), the handshake either corrupts silently or `crypto/tls` returns a low-level "unexpected EOF" / record-parsing error that gives no hint the real problem is packet-size handling one layer down.

**Why it happens:**
This is the single largest impedance mismatch in the whole "wrap OpenVPN's framing in `net.Conn` and put `crypto/tls` on top" design (which is otherwise the right call — it eliminates reimplementing TLS entirely). The custom `net.Conn` isn't just a thin adapter; it has to *be* a small reliable-byte-stream implementation (its own internal send buffer that chunks into packets, its own receive-side reassembly buffer that holds out-of-order/fragmented control packets until they can be delivered in order) — essentially a miniature TCP, built on top of the OpenVPN reliability layer's ACK/retransmit packet-id sequencing.

**How to avoid:**
- Design the framing `net.Conn`'s `Read`/`Write` as a proper reliable in-order byte-stream from the start — do not build it as "one `Write()` call = one control packet" (that assumption breaks the instant a TLS record exceeds one packet's capacity, which will happen on the very first real handshake).
- Test the framing `net.Conn` in isolation (without TLS at all) by writing a byte stream larger than one packet's payload and asserting it's received byte-for-byte, in order, on the other side, including with artificial reordering/duplication of the underlying "packets" to catch reassembly bugs early.
- Only once that passes, layer `tls.Server(conn, cfg)` on top and test the handshake against `crypto/tls`'s own client (`tls.Client`) before testing against a real OpenVPN binary — isolates "is my conn a correct byte stream" from "is my OpenVPN framing correct" as separate failure classes.

**Warning signs:**
Handshake works against tiny test certs (e.g. self-signed with no chain, small key) in dev, then fails or hangs once real Voxio-style CA chains or larger certs are used — a strong signal that record fragmentation wasn't actually exercised in earlier "success."

**Phase to address:**
Control-channel framing phase, verified specifically before or alongside the TLS handshake integration phase — this is exactly the project's own proposed step 2→3 boundary ("Framing als net.Conn bauen" → "crypto/tls darüberlegen"), and the fragmentation requirement should be an explicit acceptance criterion of the framing phase, not discovered later.

---

### Pitfall 5: No retransmission logic — works perfectly on Docker loopback, fails intermittently (or entirely) on any real network

**What goes wrong:**
UDP is unreliable by design; OpenVPN's control channel implements its own ACK+retransmit reliability layer specifically because of this. A from-scratch implementation, tested exclusively via a Docker bridge network (effectively zero packet loss, near-zero latency), can appear to work completely correctly while having **no retransmission logic at all** — every packet just happens to arrive. This is arguably the single most dangerous "looks done but isn't" trap in the whole project, because the interop harness itself (Docker-based, as specified) is exactly the environment least likely to expose it.

**Why it happens:**
Retransmission isn't visible in a quick functional test; it only matters when a packet is actually dropped, delayed, or reordered — conditions Docker's default bridge networking essentially never produces. Real clients (mobile networks, home NAT/firewalls, especially the Voxio Snom-phone use case which explicitly targets uncontrolled "plug into any internet connection" environments) will produce loss regularly.

**How to avoid:**
- Implement the ACK+retransmit model as specified (`reliable.c`): default `tls-timeout` ~2s retransmit interval, a small window of unacked outgoing buffers, ACKs either piggybacked on outgoing `P_CONTROL` packets when there's payload to send or sent standalone as `P_ACK` when idle.
- Add an artificial packet-loss/reorder layer to the interop harness (e.g. a `tc netem`-configured Docker network profile, or a proxy that randomly drops/delays/reorders UDP datagrams between client and server containers) as a *required* test scenario, not an optional one — this is the only way to actually exercise retransmission before it matters in production.
- Treat "handshake completes under 5% simulated packet loss" as an explicit phase acceptance criterion.

**Warning signs:**
Everything works in CI/Docker; field reports (or manual testing over real WiFi/mobile) show intermittent connection failures or hangs during handshake with no clear pattern.

**Phase to address:**
Control-channel framing / reliability-layer phase for the implementation; interop harness phase for the *verification* (packet-loss simulation must be added to the Docker harness, not left as a manual afterthought).

---

### Pitfall 6: P_DATA_V2 AAD, IV, and header layout — the "implicit IV" is derived key material, not zero and not random

**What goes wrong:**
AES-256-GCM needs a 96-bit nonce, unique per packet under a given key. OpenVPN's P_DATA_V2 format constructs it as: low 32 bits = the on-wire `packet_id` (a plain 4-byte big-endian counter, transmitted in cleartext, **not** the same format/counter as any control-channel packet-id), high 64 bits = an "implicit IV" that is **not sent on the wire at all** — it's derived from the same key-expansion output used for the (unused, in GCM mode) HMAC key slot, i.e. pre-shared during key negotiation and reused identically by both sides for every packet under that key. A common mistake is guessing this is all-zero, or random-per-packet (which would be non-reproducible and break decryption), or reusing the packet_id bytes twice. Separately: the P_DATA_V2 header itself (`opcode+key_id` byte + 24-bit peer_id, 4 bytes total) is passed to GCM as **additional authenticated data (AAD)** — it is not encrypted, but it must be authenticated exactly. Getting the AAD construction wrong (wrong byte count, wrong field order, or omitting peer_id) causes GCM tag verification to fail on literally every packet, which is easy to misdiagnose as a key-derivation bug (Pitfall 1/3) rather than an AAD-construction bug, since the symptom is identical.

**How to avoid:**
- Build nonce construction and AAD construction as two small, independently unit-tested functions with fixed test vectors, separate from the key-derivation code — this makes it possible to isolate "is my key wrong" from "is my AAD/nonce wrong" when debugging against a real client, instead of only having one giant "decryption fails" symptom to work from.
- Use `encoding/binary.BigEndian` explicitly and consistently for `packet_id`; note this out loud in code review / PR description, since it's easy to default to `LittleEndian` out of habit from other systems code.
- Confirm against `crypto.c` exactly which key-expansion slot and byte range supplies the implicit IV before implementing — this is a specific, checkable byte offset, not something to infer from general AEAD conventions.

**Warning signs:**
100% GCM auth failure rate immediately after PUSH_REPLY on the very first data packet (as opposed to Pitfall 1/3's partial-direction or intermittent failures) — a near-universal, immediate, symmetric failure is more likely an AAD/nonce bug than a key bug, since key bugs often still leave one direction accidentally working.

**Phase to address:**
Data-channel encryption phase (AES-256-GCM), after key derivation is independently verified correct via test vectors — do not debug key derivation and AAD/nonce construction against a real client simultaneously; verify each in isolation first.

---

### Pitfall 7: Session-ID handling — conditional header fields, and confusing "my session ID" with "peer's session ID"

**What goes wrong:**
Each side generates its own random 64-bit session_id at `HARD_RESET`. Every subsequent control packet header includes the *sender's own* session_id — not the peer's. A separate, **conditionally present** "remote session-id" field appears in the header only when the packet is also carrying a piggybacked ACK array (i.e., only if ack-array-length > 0), which shifts every subsequent byte offset in the header depending on that condition. Two distinct bugs are easy to introduce here: (1) treating the session_id field as always meaning "the peer's ID" (or always "mine") instead of "always the sender's own," which breaks packet routing/demux once both sides are established, and (2) parsing the header with a fixed offset that doesn't account for the optional remote-session-id + ACK-array block, corrupting parsing of every packet that happens to carry a piggybacked ACK (which, if piggybacking is implemented per Pitfall 5, is *most* packets during an active handshake).

**How to avoid:**
- Parse the control-channel header as a proper variable-length structure driven by the ack-array-length byte, not a fixed-offset struct overlay.
- Name fields explicitly `senderSessionID` (never just `sessionID`) in the Go struct to make the "always sender's own ID" convention impossible to misread at call sites.
- Never regenerate the server's session_id mid-session (e.g. due to accidentally treating each inbound UDP datagram as a fresh session in map-lookup logic) — a real client uses session-ID continuity to distinguish "normal handshake progress" from "stale/dead session, must reset," and a server-side ID that changes unexpectedly triggers the client to silently reset the connection.

**Warning signs:**
Handshake makes some initial progress (HARD_RESET exchange succeeds) then stalls exactly when the first ACK-carrying packet should appear; or client periodically full-resets mid-handshake for no visible reason.

**Phase to address:**
Control-channel framing phase — this is core wire-parsing logic that should be covered by unit tests using captured real-client byte sequences (from the interop harness, fed back into unit tests) before being trusted.

---

### Pitfall 8: Forgetting the server must explicitly push the fixed cipher, not just configure it locally

**What goes wrong:**
This project intentionally skips NCP (Negotiable Crypto Parameters) and hardcodes AES-256-GCM. A real OpenVPN 2.6 client, however, participates in NCP by default and will select its own default/negotiated cipher unless the server's `PUSH_REPLY` explicitly includes a `cipher AES-256-GCM` directive. NCP is fundamentally server-driven — the client generally defers to whatever cipher the server pushes — so a from-scratch server that has AES-256-GCM hardcoded *internally* but forgets to actually include `cipher AES-256-GCM` in the outgoing push-options string will still work with some client defaults by coincidence, but is fragile and version-dependent, and can silently produce a cipher mismatch (client assumes one cipher, server encrypts with another) with the exact same 100%-GCM-failure symptom as Pitfalls 1/3/6.

**How to avoid:**
Treat the push-options string content (not just the internal cipher selection) as part of the explicit spec to verify against a real client's log at verb 6+, and include `cipher AES-256-GCM` (and appropriate `auth`/`keysize` directives if applicable) in every PUSH_REPLY unconditionally, since NCP itself isn't implemented.

**Warning signs:**
Works against one client OS/version, fails against another with the same server binary — a strong sign the client's own cipher default (rather than an explicit server push) is what's actually in effect.

**Phase to address:**
Handshake sequencing / push-reply phase.

---

## Moderate Pitfalls

### Pitfall 9: Sinking implementation effort into perfecting the OCC string

**What goes wrong:**
Older OpenVPN tutorials and blog posts describe OCC (Options Compatibility/Consistency Check) mismatches as causing hard connection failures — true for pre-2.4-era OpenVPN. As of the 2.6 line, OCC mismatch warnings for key-method/keydir/tls-auth/cipher have been downgraded to debug-only logging (verb 7) and no longer disconnect the session. Implementers following outdated references sometimes spend real effort hand-crafting a byte-perfect OCC string, when it has no functional effect on a real 2.6 client.

**Prevention:**
Implement a best-effort OCC string for debug visibility (useful for your own `--verb 7`-equivalent logging and easier interop debugging), but do not treat OCC-string mismatch as a plausible root cause when a real 2.6 client silently disconnects — look at retransmission, session-ID, key-derivation, or AAD/nonce bugs first (Pitfalls 1–7).

---

### Pitfall 10: tls-crypt static key file format and key-direction handling

**What goes wrong:**
tls-crypt reuses the same 2048-bit static key file format historically used by `--secret`/`tls-auth` (`-----BEGIN OpenVPN Static key V1-----`, hex-encoded 256-byte blob), which splits into multiple 64-byte key slots with an optional `key-direction` (0/1) convention controlling which slots are used for which purpose on client vs server. Because this file format predates tls-crypt and is shared across three different features (`--secret` static-key mode, `tls-auth`, `tls-crypt`), it's easy to misapply the wrong slot-selection convention (e.g. tls-auth's HMAC-only slot usage vs tls-crypt's Ka/Ke split) when writing the parser.

**Prevention:**
Parse the key file generically (256 bytes → N fixed-size slots) but keep the *interpretation* of which slots are Ka/Ke strictly scoped to a tls-crypt-specific function, verified against `tls_crypt.c`'s exact slot-offset logic (not inferred from tls-auth's usage) before trusting it — this is exactly the kind of "no RFC, C source is the spec" detail the project already commits to verifying directly rather than guessing.

---

### Pitfall 11: Ping/keepalive omission causes disconnects only after idle periods

**What goes wrong:**
A real client expects periodic `ping` packets (interval set via server-pushed `ping`/`ping-restart` options) during idle periods; if the server never sends them and never pushes correct `ping-restart` values, the client's own idle-reconnect timer eventually fires and it tears down and reconnects — a bug that is invisible in short, active test sessions (constant traffic keeps timers happy) and only appears after minutes of idle time, which is easy to never hit in a quick manual test loop.

**Prevention:**
Implement server-side ping/keepalive sending and push appropriate `ping`/`ping-restart` values in PUSH_REPLY; add a long-idle-period scenario (several minutes of no application traffic) as an explicit interop test case, not just a "connect and immediately ping" happy path.

---

### Pitfall 12: 2.5 vs 2.6 client behavior drift undermines a single pinned interop target

**What goes wrong:**
The project correctly pins OpenVPN 2.6 as the interop target, but 2.6 changed several defaults relevant here: stricter default `--allow-compression no` (any compression-adjacent push becomes a hard error rather than a warning), `--data-ciphers` largely superseding `--cipher`/`--ncp-ciphers` semantics, and tls-crypt-v2 support existing alongside v1. If a contributor casually tests against whatever `openvpn` package their OS ships (which may be 2.5.x or older on some distros) instead of the pinned 2.6 Docker image, behavioral differences can produce confusing, non-reproducible bug reports.

**Prevention:**
Make the Docker interop harness the *only* sanctioned client version for bug triage; document the exact pinned client image tag; treat any bug report against an unpinned/local client install as "reproduce against the harness first."

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|-----------------|------------------|
| Skip retransmission logic, rely on Docker's near-zero packet loss | Faster to a working handshake demo | Silent failures on any real (lossy) network — directly undermines the Voxio "plug into any internet connection" use case | Never for anything beyond a throwaway spike; must be implemented before any field/interop-harness-with-loss testing |
| Hardcode fixed-offset header parsing instead of the conditional (ack-array-driven) layout | Simpler initial parser | Breaks the instant piggybacked ACKs appear, which is most packets during a real handshake | Only acceptable as a very first "no ACKs sent yet" milestone, must be replaced before Pitfall 5's retransmit/piggyback work lands |
| Reuse a single generic AEAD helper for both tls-crypt (MAC-then-encrypt/SIV) and data-channel GCM (standard AEAD) | Less code | Conflates two genuinely different, non-interchangeable constructions; a "fix" to one silently breaks the other | Never — keep them as separate, clearly-named functions even if there's some duplication |
| Test only against the project's own Docker-pinned 2.6 client during early development | Fast, reproducible iteration | Misses real-world network conditions (loss, reordering, NAT) and other client versions entirely until very late | Acceptable through early development phases, but packet-loss simulation and at least manual real-network testing must land before calling v1 done |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|-----------------|-------------------|
| `crypto/tls` (`tls.Server`) over custom framing `net.Conn` | Treating one `Write()`/`Read()` call as one control packet | Build the conn as a true reliable in-order byte stream that internally fragments/reassembles across many packets (Pitfall 4) |
| `crypto/tls` cert chain / client CA verification | Assuming small test certs represent real handshake message sizes | Test fragmentation with realistic (multi-KB, chained) certs from the start, not minimal self-signed test certs |
| Wireshark for protocol debugging | Expecting "Follow TLS Stream" to work directly on captured OpenVPN traffic | Control-channel bytes are wrapped in tls-crypt (opaque without the static key) and even once unwrapped are custom-framed, not raw TLS records Wireshark auto-detects; get further by (a) using `crypto/tls`'s `KeyLogWriter` to emit an SSLKEYLOGFILE from the Go server and correlating manually, and (b) logging decoded control-channel/handshake state directly from the Go binary rather than relying on Wireshark to parse OpenVPN's framing |
| Real OpenVPN client log verbosity | Debugging against default verbosity (verb 3–4), which hides per-packet opcode/size/negotiation detail | Run the reference client at verb 6–7 for any interop debugging session — many failure causes only appear in logs at that level |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|-----------------|
| Undersized UDP read buffer (e.g. 512–1024 bytes copied from a tutorial example) | Silent truncation of larger control/data packets — `net.PacketConn.ReadFrom` truncates without error on UDP | Size the read buffer comfortably above expected `tun-mtu` + all header overhead (2048–4096 bytes is a safe practical minimum); log/assert when a read returns exactly the buffer length | First cert-heavy TLS handshake message, or any data packet near MTU |
| Unsynchronized session map shared between the single UDP reader goroutine and per-session timer/expiry goroutines | Intermittent panics or corrupted routing under concurrent load, caught late (often only by `-race` or production load) | Guard the session map with a mutex or `sync.Map` from the initial design, not bolted on later | Any concurrent client churn (multiple simultaneous connects/reconnects) |
| Goroutines per session (handshake reader, retransmit timer, keepalive timer) not cancelled on `Session.Close()` | Goroutine count grows unbounded with connection churn; invisible until checked via `pprof`/goroutine metrics | Every long-lived per-session goroutine selects on a session-scoped `context.Context`; `Close()` is the single idempotent cancellation point; add a test asserting goroutine count returns to baseline after N connect/disconnect cycles | Flaky client populations reconnecting frequently (exactly the Snom-phone-on-arbitrary-networks use case) |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| No replay-window implementation on the data channel (only strict monotonic packet_id checking, or none at all) | Either constant false-rejects on ordinary UDP reordering (breaks usability), or full replay vulnerability if skipped entirely | Implement a proper sliding replay window (bitmask over a window of recent packet_ids, matching OpenVPN's default window semantics) per key/direction, not a strict-monotonic check |
| No replay protection on the tls-crypt-wrapped layer (separate from the data-channel replay window) | Wrapped control packets could be replayed to disrupt/desync a handshake | Implement replay checking on the tls-crypt outer packet_id as its own, separate check from the data-channel replay window — do not assume one covers the other |
| Treating GCM's "implicit IV" as something that can be re-derived or randomized per packet instead of exactly matching the pre-shared, key-expansion-derived value | Guaranteed decryption failure (if inconsistent with peer) or, in the worst misimplementation, actual nonce reuse (catastrophic for GCM) if the derivation is wrong in a way that repeats | Derive the implicit IV once per key negotiation from the exact key-expansion slot/offset specified in `crypto.c`, cache it, and never regenerate it per-packet |
| Never validating the server's own session_id continuity (accepting any inbound packet claiming to belong to any session without cross-checking sender's session_id against what was recorded at HARD_RESET) | Session confusion / potential for basic spoofing or cross-session interference before TLS-layer auth even kicks in | Bind session lookups to the (peer session_id, source address) pair established at HARD_RESET, and treat mismatches as a new/invalid session rather than silently reusing existing session state |

## "Looks Done But Isn't" Checklist

- [ ] **Handshake works in Docker:** Often missing real retransmission logic — verify by adding artificial packet loss/reorder (`tc netem` or an in-harness lossy proxy) and confirming the handshake still completes.
- [ ] **Data channel encrypts/decrypts correctly:** Often only tested in one direction, or only with a hardcoded/matching key on both "sides" of a self-test — verify with an actual real-client capture, both directions, and confirm the implicit IV / AAD are independently unit-tested, not just "it worked once."
- [ ] **Cert-based handshake succeeds:** Often only tested with a tiny self-signed test cert that fits in one packet — verify with a realistic multi-KB cert chain to exercise TLS record fragmentation across control packets.
- [ ] **Session cleanup on disconnect:** Often leaves goroutines/timers running — verify goroutine count returns to baseline after repeated connect/disconnect cycles under load, not just "the session object is dereferenced."
- [ ] **Tunnel "stays up":** Often only tested for a few seconds of active traffic — verify with several minutes of idle time to confirm ping/keepalive and `ping-restart` push values prevent client-side idle disconnects.
- [ ] **UDP packet reads never truncate:** Often uses an undersized fixed buffer copied from an example — verify the read buffer is sized well above worst-case packet size, and add an assertion/log for reads that hit the buffer boundary exactly.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|----------------|------------------|
| Wrong PRF / key layout (Pitfall 1, 3) | MEDIUM | Isolate with fixed test vectors against known-good output (from a debug OpenVPN build or documented vectors) before touching the data channel again; do not debug against a live client until vectors match |
| tls-crypt MAC/IV ordering wrong (Pitfall 2) | MEDIUM | Same approach — build fixed input/output test vectors for the tls-crypt wrap/unwrap functions in isolation, verify against `tls_crypt.c` logic directly rather than iterating against a live client |
| No fragmentation support in framing `net.Conn` (Pitfall 4) | HIGH | Requires redesigning the conn's internal buffering to be a true reliable byte stream; better to catch before this ships, since it's foundational to everything layered on top (TLS handshake, Key Method 2 exchange) |
| Missing retransmission (Pitfall 5) | MEDIUM-HIGH | Retrofittable without a full redesign if the reliability layer was built as a clean module, but requires adding the packet-loss test scenario to the harness and iterating against it — budget real time for this, it's easy to underestimate |
| AAD/nonce bugs in P_DATA_V2 (Pitfall 6) | LOW-MEDIUM | Isolated, testable functions (per the prevention strategy) make this a fast fix once identified — the expensive part is *identifying* it rather than fixing it, since the symptom is identical to a key-derivation bug |
| Session-ID / header offset bugs (Pitfall 7) | MEDIUM | Fix the parser to be driven by the ack-array-length field rather than fixed offsets; add unit tests from captured real-client byte sequences to prevent regression |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|-------------------|----------------|
| PRF / key derivation (1, 3) | Key Method 2 / data-channel key derivation phase | Standalone `tls1_PRF` test vectors; cross-check derived keys symmetrically between a mock client/server instance of your own code before testing against a real client |
| tls-crypt MAC-then-encrypt ordering, key file parsing (2, 10) | tls-crypt implementation phase | Fixed input/output test vectors for wrap/unwrap in isolation; separate replay-window test for the wrapped layer |
| Control-channel framing as a true reliable byte stream, TLS record fragmentation (4) | Control-channel framing phase (net.Conn) | Byte-stream reassembly test with artificial reordering/duplication; full TLS handshake test using a realistic (multi-KB, chained) cert before any real-client test |
| Retransmission / ACK piggybacking (5) | Control-channel framing phase (implementation) + interop harness phase (verification) | Docker harness extended with simulated packet loss/reorder as a required, not optional, test scenario |
| Session-ID conditional header parsing (7) | Control-channel framing phase | Unit tests built from captured real-client byte sequences (fed back from the interop harness) |
| Data-channel AAD/nonce/header (6) | Data-channel encryption phase (AES-256-GCM) | Independent unit tests for nonce/AAD construction, separate from key-derivation tests, so failures are diagnosable in isolation |
| Explicit cipher push in PUSH_REPLY despite no NCP (8) | Handshake sequencing / push-reply phase | Verify PUSH_REPLY content against real client's verb 6+ log, not just internal server config |
| OCC string over-investment (9) | Handshake sequencing phase | Confirm against 2.6 `Changes.rst` that OCC mismatches are debug-only before spending implementation time here |
| Ping/keepalive omission (11) | Handshake sequencing / push-reply phase | Long-idle-period interop test case (several minutes, no application traffic) |
| Pinned client version drift (12) | Interop harness phase | Harness documentation makes the pinned Docker image the sole source of truth for bug triage |
| Goroutine leaks, UDP buffer sizing, unsynchronized session map | Netstack / session-manager & Go concurrency concerns (cross-cutting, but concretely exercised once real session churn exists) | Goroutine-count-returns-to-baseline test after connect/disconnect cycles; `go test -race` in CI; buffer-size assertion/logging |

## Sources

- [OpenVPN: Data channel key generation (doxygen)](https://build.openvpn.net/doxygen/key_generation.html) — HIGH confidence (official OpenVPN project documentation), confirms `key_source2`/master-secret/key-expansion two-step process and the `generate_key_expansion_openvpn_prf()` entry point; exact PRF construction (MD5+SHA1 P_hash) and byte offsets confirmed via training-data knowledge of `crypto.c`/`ssl.c` — verify directly against source before implementation, as this file explicitly defers detail to source code
- [OpenVPN: OpenVPN's network protocol (doxygen)](https://build.openvpn.net/doxygen/network_protocol.html) — HIGH confidence (official), confirms control-channel header layout (opcode/key_id byte, session_id, conditional ACK-array + remote-session-id, packet-id, TLS payload) and P_DATA_V2's 1-byte opcode/key_id + 24-bit peer-id header
- [OpenVPN: Reliability Layer module (doxygen)](https://build.openvpn.net/doxygen/group__reliable.html) — HIGH confidence (official), confirms ACK+retransmit model, piggybacked vs standalone P_ACK, independent packet-id sequences for P_DATA vs P_CONTROL/P_ACK, default `tls-timeout`/window behavior
- [OpenVPN: Control channel encryption (tls-crypt, tls-crypt-v2) module (doxygen)](https://build.openvpn.net/doxygen/group__tls__crypt.html) and [`tls_crypt.h` source](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tls_crypt.h) — HIGH confidence (official source), confirms SIV-style MAC-then-encrypt construction, Ka/Ke split, wire format `opcode||session_id||packet_id||auth_tag||E(payload)`
- [OpenVPN: Data Channel Crypto module (doxygen)](https://build.openvpn.net/doxygen/group__data__crypto.html) — HIGH confidence (official), confirms P_DATA_V2 GCM nonce = 32-bit on-wire packet_id + 64-bit implicit IV (from the otherwise-unused HMAC key slot in GCM/CCM mode), and that opcode+peer-id are authenticated as AAD
- [OpenVPN Cryptographic Layer (community docs)](https://openvpn.net/community-docs/openvpn-cryptographic-layer.html) and [OpenVPN Protocol (community docs)](https://openvpn.net/community-docs/openvpn-protocol.html) — MEDIUM-HIGH confidence (official community documentation, cross-checks the doxygen sources above)
- [`openvpn/Changes.rst` (master, and v2.7.6 tag)](https://github.com/OpenVPN/openvpn/blob/master/Changes.rst) — HIGH confidence (official changelog), confirms OCC mismatch warnings downgraded to debug-only logging for key-method/keydir/tls-auth/cipher as of the 2.6-era codebase, and `--data-ciphers`/`--allow-compression` default changes relevant to 2.5 vs 2.6 interop drift
- [`cipher-negotiation.rst` (master)](https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/cipher-negotiation.rst) — MEDIUM-HIGH confidence (official docs), background on NCP/`data-ciphers` behavior relevant to the "explicit cipher push" pitfall
- Project's own `openvpn-go-briefing.md` and `.planning/PROJECT.md` — primary source for scope, stated known-hard-parts, and the project's own commitment to verifying byte-level details against `ssl.c`/`crypto.c` rather than training-data recall (the guiding principle this entire pitfalls file is built around)
- Training-data knowledge of the OpenVPN C reference (`ssl.c`, `crypto.c`, `reliable.c`, `tls_crypt.c`, `mtu.c`) — used to fill in exact byte-offset and struct-layout detail beyond what the doxygen prose pages state explicitly; flagged MEDIUM confidence where not independently cross-checked via search in this session, with explicit recommendation to re-verify against source before coding (consistent with the project's stated approach)

---
*Pitfalls research for: OpenVPN server protocol reimplementation in Go*
*Researched: 2026-08-22*
