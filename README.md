<!-- generated-by: gsd-doc-writer -->
# govpn

A pure-Go library implementing the **server side of the OpenVPN protocol** — embeddable directly in any Go program, with no wrapper around the `openvpn` binary and no separate process.

Per connected client, `govpn` hands your program a `Session` that behaves as an `io.ReadWriteCloser` for raw, decrypted IP packets. It ships with a privilege-free userspace netstack (UDP, minimal server-side TCP, and ICMP echo) so tunnel traffic can terminate entirely in-process — no TUN device, no `CAP_NET_ADMIN`, runnable in an ordinary unprivileged container.

- **Module:** `github.com/8upio/govpn`
- **Package:** `ovpn`
- **Dependencies:** Go standard library only — `go.mod` declares no third-party requirements.
- **Compatibility target:** a real, unmodified OpenVPN 2.6 client with `tls-crypt`, certificate auth, AES-256-GCM, and `topology subnet`.
- **Client authentication:** a client certificate, username/password via `Config.AuthUserPass`, or both — see [CONFIGURATION.md](docs/CONFIGURATION.md#authuserpass).

## Installation

```bash
go get github.com/8upio/govpn
```

Requires Go `1.24` or later (see `go.mod`).

## Quick start

The fastest way to see a real OpenVPN client talking to a `govpn`-embedded server is the bundled [`tunnelweb`](examples/tunnelweb/README.md) example, which serves a small web site reachable only through the tunnel:

```bash
# 1. Generate a test PKI (CA, server cert, tls-crypt key)
go run ./cmd/gentestpki -out /tmp/tunnelweb-pki -profile small

# 2. Start the server
go run ./examples/tunnelweb -pki /tmp/tunnelweb-pki
```

Then connect a real OpenVPN client using a client config built from the same PKI material, and open `http://10.8.0.1:8080/` from inside that client's network namespace. See [examples/tunnelweb/README.md](examples/tunnelweb/README.md) for the full walkthrough, including the exact `-listen`, `-network`, and `-http-port` flags.

## Usage

Embedding `govpn` means: build a `tls.Config` for mutual certificate auth, provide a `tls-crypt` static key, define the tunnel IP range, and hand the library an `ovpn.Config`. Each fully-established client session is delivered to `Config.OnSession` as a `*ovpn.Session`:

```go
srv := ovpn.NewServer(ovpn.Config{
    TLSConfig:   tlsCfg,       // mutual cert auth: ClientCAs, Certificates, MinVersion
    TLSCryptKey: tlsCryptKey,  // from ovpn.ParseStaticKeyV1
    Network:     tunnelNetwork, // *net.IPNet, e.g. 10.8.0.0/24 (topology subnet)
    Cipher:      "AES-256-GCM",
    // AuthUserPass: myAuthHook, // optional: authenticate by username/password
    //                           // instead of (or in addition to) a client cert
    Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)), // optional: nil is silent
    OnSession: func(sess *ovpn.Session) {
        // sess is an io.ReadWriteCloser of raw, decrypted IP packets.
        // sess.AssignedIP() and sess.PeerID() are already populated here.
        go io.Copy(sess, sess) // or attach it to your own packet handling
    },
    OnSessionClosed: func(sess *ovpn.Session, reason ovpn.CloseReason) {
        // fires once teardown completes, only for a session that reached
        // OnSession — reason distinguishes embedder Close, client
        // exit-notify, idle reap, or Server.Close.
        log.Printf("session for %s closed: %s", sess.RemoteAddress(), reason)
    },
})

pc, _ := net.ListenPacket("udp", "0.0.0.0:1194")
if err := srv.Serve(pc); err != nil {
    log.Fatal(err)
}
```

`ovpn.ParseStaticKeyV1` parses an OpenVPN "Static key V1" file into the raw bytes `Config.TLSCryptKey` expects. `sess.Stats()` returns a point-in-time snapshot of that session's traffic counters (bytes/packets in and out, inbound-queue drops, renegotiations, and established/last-authenticated-traffic timestamps) — useful for per-session observability without wrapping `Read`/`Write` yourself.

For traffic that needs to terminate entirely in-process (rather than being forwarded to a TUN device elsewhere), attach each session to the bundled userspace netstack instead of handling packets yourself:

```go
stack, _ := netstack.New(serverIP)
ln, _ := stack.ListenTCP(8080) // an http.Server can Serve(ln) directly

srv := ovpn.NewServer(ovpn.Config{
    // ...
    OnSession: func(sess *ovpn.Session) {
        _ = stack.Attach(sess, sess.AssignedIP())
    },
})
```

The `netstack` package imports nothing from `govpn` — `*ovpn.Session` satisfies its `Session` interface (`io.ReadWriteCloser`) structurally, with no coupling in either direction. See [docs/NETSTACK.md](docs/NETSTACK.md) for the full protocol coverage (IPv4, ICMP, UDP, TCP) and design.

For request/response shapes, the full `Config` surface, and `Session` methods (`AssignedIP`, `PeerID`, `ConnectionState`, `RenegotiationCount`, `Stats`, `CloseReason`, `Done`, and more), see [docs/API.md](docs/API.md).

## Documentation

| Doc | Covers |
|---|---|
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | Prerequisites, installation, and first run |
| [docs/API.md](docs/API.md) | `ovpn.Server`, `ovpn.Config`, `ovpn.Session` — the public API surface |
| [docs/NETSTACK.md](docs/NETSTACK.md) | The privilege-free userspace netstack (UDP, TCP, ICMP) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design: control channel, data channel, key derivation |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | `Config` fields, PKI/tls-crypt material, tunnel network setup |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Local dev setup, build commands, code style |
| [docs/TESTING.md](docs/TESTING.md) | Unit tests, golden vectors, and the Docker-based OpenVPN interop harness |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [examples/tunnelweb/README.md](examples/tunnelweb/README.md) | The canonical example: a web site reachable only through a real OpenVPN tunnel |

## License

<!-- VERIFY: no LICENSE file is present in the repository root; confirm the intended license before publishing -->
