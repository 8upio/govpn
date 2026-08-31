<!-- generated-by: gsd-doc-writer -->
[← Back to README](../README.md)

# Architecture

## System overview

`govpn` (module `github.com/8upio/govpn`, package `ovpn`) is a pure-Go implementation of the **server side of the OpenVPN protocol**, designed to be embedded directly inside a Go process — no wrapper around the `openvpn` binary, no separate process, and no third-party dependency beyond the Go standard library. An embedder constructs an `ovpn.Server` from a `Config`, hands it a `net.PacketConn` to `Serve`, and receives a `*Session` per connected client via `Config.OnSession` once that client has completed the full OpenVPN bring-up sequence (TLS handshake, Key Method 2 data-channel key derivation, and the `PUSH_REQUEST`/`PUSH_REPLY` exchange). Each `Session` then behaves as an `io.ReadWriteCloser` for the client's raw, decrypted IP packets.

Because the library never touches a TUN device or requires `CAP_NET_ADMIN`, it ships a companion privilege-free userspace netstack (package `netstack`) that can terminate tunnel traffic entirely in-process — UDP, a minimal server-side TCP, and ICMP echo — so an embedding process can, for example, serve HTTP over the tunnel with no OS-level networking privileges at all. See [NETSTACK.md](NETSTACK.md) for the netstack's own design.

The architectural style is a layered protocol stack: an untrusted-input triage layer at the UDP boundary, a control-channel framing/reliability layer that presents itself as an ordinary `net.Conn`, unmodified `crypto/tls` layered on top of that `net.Conn` for the handshake, and a data-channel AEAD layer keyed by material derived from the completed TLS session. Every wire format and cryptographic construction is verified against the OpenVPN 2.6 C reference source (`ssl.c`, `crypto.c`, `tls_crypt.c`, `reliable.c`, `ssl_pkt.c`) rather than approximated from memory, and cross-checked against a real OpenVPN 2.6 client via packet capture (`test/interop/`).

## Component diagram

```
                 UDP datagrams (client <-> server)
                              |
                              v
                    +-------------------+
                    |   ovpn.Server     |   ovpn.go: Serve/handleDatagram
                    |  (cheap triage,   |   - length/opcode sanity check
                    |   session demux)  |   - routes P_DATA_* by peer-id
                    +---------+---------+   - routes P_CONTROL_* by
                              |                (remote addr, session ID)
              +---------------+----------------+
              |                                 |
              v                                 v
   +----------------------+          +------------------------+
   | internal/tlscrypt     |          | internal/wire          |
   | Wrapper.Unwrap/Wrap   |          | ParseControlPacket /   |
   | (AES-256-CTR + HMAC-  |          | Header / ControlPacket |
   |  SHA256, SIV-style)   |          +-----------+------------+
   +----------------------+                       |
              |                                    v
              |                       +------------------------+
              |                       | internal/reliable       |
              |                       | ACK bookkeeping, packet-|
              |                       | ID windows, retransmit  |
              |                       +-----------+------------+
              |                                    |
              v                                    v
                    +----------------------------------+
                    | internal/ctrlconn.Conn            |
                    | (implements net.Conn)             |
                    +-----------------+------------------+
                                       |
                                       v
                        +------------------------------+
                        | crypto/tls (stdlib, unmodified)|
                        | tls.Server(conn, TLSConfig)    |
                        +---------------+-----------------+
                                       |
                                       v
                     +--------------------------------+
                     | internal/keyderiv                |
                     | Key Method 2: openvpn_PRF,        |
                     | master-secret + key-expansion,    |
                     | ClientOptions/PUSH_REQUEST layer   |
                     +-----------------+-----------------+
                                       |
                                       v
                +----------------------------------------+
                | ovpn.go: performPushExchange / push.go  |
                | ippool.go: tunnel-IP + peer-id allocator|
                +-----------------------+------------------+
                                        |
                                        v
                          +--------------------------+
                          | internal/datachan          |
                          | Wrapper.Seal/Open           |
                          | (AES-256-GCM P_DATA_V2)     |
                          +--------------+---------------+
                                        |
                                        v
                          +--------------------------+
                          |   ovpn.Session             |
                          | io.ReadWriteCloser of raw   |
                          | decrypted IP packets        |
                          +--------------+---------------+
                                        |
                            (embedder attaches, optionally)
                                        v
                          +--------------------------+
                          |   netstack.Stack           |
                          | userspace IPv4: UDP demux,  |
                          | minimal server-side TCP,    |
                          | ICMP echo                   |
                          +--------------------------+
```

See [API.md](API.md) for the full public surface these components expose, and [CONFIGURATION.md](CONFIGURATION.md) for how `Config` wires TLS, `tls-crypt`, and the tunnel network into this pipeline.

## Data flow

A typical client connection moves through the pipeline as follows:

1. **UDP triage** (`ovpn.go: Server.Serve` / `handleDatagram`) — every inbound datagram is read on the server's single UDP read loop, then dispatched to its own goroutine. Datagrams are rejected up front (mirroring `tls_pre_decrypt_lite`, `ssl_pkt.c:305-423`) if they are shorter than the `tls-crypt` prefix, longer than the `TLS_CHANNEL_BUF_SIZE` ceiling, or carry an out-of-range opcode — before any per-session state is allocated.
2. **Session routing** — `P_DATA_V1`/`P_DATA_V2` packets are routed by a 24-bit peer-id (no session ID field exists on data packets); all other control packets are routed by the pair `(remote UDP address, 8-byte session ID)`. An unrecognized `HARD_RESET_CLIENT_V2` from an unknown pair creates a brand-new `Session`; everything else with no match is dropped.
3. **`tls-crypt` unwrap** (`internal/tlscrypt`) — the datagram is authenticated and decrypted with the shared static key (`Config.TLSCryptKey`) before its contents are trusted at all.
4. **Control-channel framing and reliability** (`internal/wire`, `internal/reliable`, `internal/ctrlconn`) — the plaintext control packet's ack array and payload are parsed, fed into a per-session `reliable.Reliable` window for in-order delivery and retransmission, and made readable through `ctrlconn.Conn`, which implements `net.Conn`.
5. **TLS handshake** (`ovpn.go: runHandshake`) — `crypto/tls`, completely unmodified, is layered directly on `ctrlconn.Conn` via `tls.Server(conn, cfg)`. Success requires `Handshake()` to return `nil` and (with `Config.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert`) a verified client certificate, whose `CommonName` becomes `Session.PeerCN`.
6. **Key Method 2 exchange** (`internal/keyderiv`, `ovpn.go: performKeyMethod2Exchange`) — client and server random/pre-master material is exchanged over the now-established TLS channel and fed through the hand-rolled `openvpn_PRF` (RFC 2246 §5.6.4.1) to derive the data-channel key expansion (`keyderiv.Key2`), split into per-direction encrypt/decrypt/HMAC slots.
7. **`PUSH_REQUEST`/`PUSH_REPLY`** (`push.go`, `ovpn.go: performPushExchange`) — once the client sends the literal control string `"PUSH_REQUEST"`, the server allocates a tunnel IP and 24-bit peer-id from `ippool.go`, builds the data-channel `datachan.Wrapper`, and replies with the pushed `ifconfig`, `route-gateway`, `peer-id`, `cipher`, and `ping`/`ping-restart` values.
8. **Session handoff** (`ovpn.go: Config.OnSession`) — only after all of the above completes is the `*Session` handed to the embedder's `OnSession` callback; `Session.AssignedIP()` is already populated and the data channel is already live.
9. **Data channel** (`internal/datachan`) — subsequent `P_DATA_V2` packets are AES-256-GCM sealed/opened with a nonce assembled from the packet-id XORed against a per-key implicit IV (not Go's default random-nonce GCM convention). `Session.Read`/`Write` expose the decrypted/encrypted IP packets as an `io.ReadWriteCloser`.
10. **Optional netstack attachment** — an embedder may call `netstack.Stack.Attach(sess, ip)` to terminate that traffic entirely in-process (see [NETSTACK.md](NETSTACK.md)), or read/write raw IP packets itself.

Renegotiation (a `SOFT_RESET_V1`, client- or server-initiated on independent timers per `Config.RenegSec`) and idle-session reaping run as background per-session goroutines alongside this main flow; see Key abstractions below.

## Key abstractions

| Abstraction | Location | Description |
|---|---|---|
| `ovpn.Server` / `ovpn.Config` | `ovpn.go` | The public entry point: owns the UDP read loop, session table, and tunnel-IP pool; `Config` carries `TLSConfig`, `TLSCryptKey`, `Network`, `Cipher`, `OnSession`, `RenegSec`. |
| `ovpn.Session` | `session.go` | Per-client handle returned to the embedder via `OnSession`; implements `io.ReadWriteCloser` over decrypted IP packets and exposes `AssignedIP()`, `PeerID()`, `PeerCN`, `RenegotiationCount()`, `ConnectionState()`. |
| `wire.ControlPacket` / `wire.Header` | `internal/wire` | The control-channel wire format: opcode/key-id byte, 8-byte session ID, ack array, and payload — the plaintext layer that lives inside a `tls-crypt`-wrapped datagram. |
| `reliable.Reliable` | `internal/reliable` | A Go port of the OpenVPN control-channel reliability layer: packet-ID windows, ACK bookkeeping, and exponential-backoff retransmission on top of unreliable UDP. |
| `ctrlconn.Conn` | `internal/ctrlconn` | The architectural seam of the whole project: implements `net.Conn` by fragmenting outbound TLS ciphertext into `tls-crypt`-wrapped, reliably-delivered control packets, and reassembling inbound ciphertext from in-order delivery — letting stdlib `crypto/tls` run unmodified on top of it. |
| `tlscrypt.Wrapper` | `internal/tlscrypt` | Implements OpenVPN's `--tls-crypt`: a MAC-then-encrypt construction (AES-256-CTR + HMAC-SHA256, SIV-style synthetic IV) authenticating and encrypting every control-channel datagram, independent of and prior to the TLS handshake itself. |
| `keyderiv.Key2` / `keyderiv.PRF` | `internal/keyderiv` | Key Method 2 data-channel key derivation: the hand-rolled TLS 1.0 PRF (`openvpn_PRF`, RFC 2246 §5.6.4.1), the two-stage master-secret/key-expansion derivation, and per-direction key/implicit-IV slot assignment (`ServerSlots()`). |
| `datachan.Wrapper` | `internal/datachan` | The data channel itself: AES-256-GCM `Seal`/`Open` for `P_DATA_V2` packets, with the nonce assembled as `packetID XOR implicit_iv` rather than a random nonce; also absorbs keepalive pings and rejects replayed/out-of-window packets. |
| `ipPool` | `ippool.go` | Server-scoped, in-memory sequential allocator for tunnel IPs and 24-bit peer-ids from `Config.Network`; no persistence, no lease file. |
| `netstack.Stack` | `netstack/stack.go` | The privilege-free userspace IPv4 stack an embedder can attach a `Session` to; deliberately imports nothing from the `ovpn` package (structural `io.ReadWriteCloser` typing only). |

## Directory structure rationale

```
.
├── ovpn.go, session.go, push.go, ippool.go   Public package `ovpn`: Server, Session, PUSH exchange, IP pool
├── internal/
│   ├── wire/         Control-channel packet wire format (opcode, header, ack array)
│   ├── reliable/      Control-channel reliability layer (ACKs, retransmission, packet-ID windows)
│   ├── ctrlconn/       net.Conn implementation over wire+reliable+tlscrypt, hosting crypto/tls
│   ├── tlscrypt/       --tls-crypt wrap/unwrap (AES-256-CTR + HMAC-SHA256)
│   ├── keyderiv/       Key Method 2 PRF and data-channel key derivation
│   └── datachan/       AES-256-GCM data-channel Seal/Open, replay/ping handling
├── netstack/           Standalone, privilege-free userspace IPv4 stack (UDP, minimal TCP, ICMP)
├── examples/tunnelweb/ Reference embedder: real OpenVPN server + netstack + HTTP site through the tunnel
├── cmd/gentestpki/     Generates throwaway CA/server/client certs and tls-crypt keys for interop testing
├── test/interop/       Docker-based interop harness against a real, version-pinned OpenVPN 2.6 client
└── testdata/golden/    Golden byte-exact fixtures (e.g. key derivation vectors) checked against the reference
```

The `internal/` packages are split one-per-protocol-concern (framing, reliability, `tls-crypt`, key derivation, data channel) so each can be verified independently against its own section of the OpenVPN C reference source and carry its own byte-exact golden tests, while the top-level `ovpn` package is kept to the pieces that must be public (`Server`, `Session`, `Config`) or that wire those internal packages together (`ovpn.go`, `push.go`, `ippool.go`). `netstack` is a structurally independent package — it declares its own minimal `Session` interface and never imports `github.com/8upio/govpn` — so it can be tested and reasoned about (and reused) without any coupling to the OpenVPN protocol implementation itself.

## Related documentation

- [README.md](../README.md) — project overview and quick start
- [API.md](API.md) — public `Server`/`Session`/`Config` surface
- [NETSTACK.md](NETSTACK.md) — the userspace IPv4 stack in detail
- [CONFIGURATION.md](CONFIGURATION.md) — `Config` fields and PKI/`tls-crypt` setup
- [TESTING.md](TESTING.md) — unit, golden-vector, and Docker interop test tiers
- [GETTING-STARTED.md](GETTING-STARTED.md) — first steps embedding the library
- [DEVELOPMENT.md](DEVELOPMENT.md) — local development workflow
