<!-- generated-by: gsd-doc-writer -->
[← Back to README](../README.md)

# Getting Started

`govpn` (module `github.com/8upio/govpn`, package `ovpn`) is a pure-Go library — there is no
binary to install and no server to run in advance. "Getting started" means: pull the module,
generate a throwaway PKI, embed `ovpn.NewServer` in a small Go program (or just run the bundled
example), and connect a real OpenVPN 2.6 client to it.

## Prerequisites

- **Go 1.24 or later** — pinned in `go.mod` (`go 1.24`). Check your version with `go version`.
- **No third-party dependencies** — `go.mod` declares no requirements beyond the Go standard
  library, so `go get`/`go build` never reaches out to anything except the module itself.
- **A real OpenVPN 2.6 client**, if you want to verify an actual tunnel end to end (not required
  just to build or unit-test the library). On Debian/Ubuntu: `apt-get install openvpn`. This is
  optional for the quick start below, which only needs the Go toolchain.
- **Docker**, only if you want to run the project's own interop test harness (`make interop`)
  against a real, version-pinned OpenVPN 2.6 client instead of setting one up yourself. Not
  required for embedding the library or running the example.

## Installation

```bash
go get github.com/8upio/govpn
```

This adds `github.com/8upio/govpn` to your `go.mod`. No configuration files, environment
variables, or additional setup steps are required — see [CONFIGURATION.md](CONFIGURATION.md) for
the full `ovpn.Config` surface once you're ready to wire it into your own program.

## First run: the `tunnelweb` example

The fastest way to see a real OpenVPN client talking to a `govpn`-embedded server is the bundled
[`tunnelweb`](../examples/tunnelweb/README.md) example — a small web site reachable only through
the tunnel, with no TUN device and no OS TCP socket bound for HTTP.

1. **Clone the repository** (if you haven't already) and `cd` into it:

   ```bash
   git clone https://github.com/8upio/govpn.git
   cd govpn
   ```

2. **Generate a test PKI** — a throwaway CA, server certificate, and `tls-crypt` static key,
   using `cmd/gentestpki` (no `easy-rsa`, no shelling out to `openvpn --genkey`):

   ```bash
   go run ./cmd/gentestpki -out /tmp/tunnelweb-pki -profile small
   ```

   This writes `ca.crt`, `server.crt`, `server.key`, `client.crt`, `client.key`,
   `tls-crypt.key`, and a ready-to-use `client.conf` into `/tmp/tunnelweb-pki`.

3. **Start the server:**

   ```bash
   go run ./examples/tunnelweb -pki /tmp/tunnelweb-pki
   ```

   It prints the tunnel network, the server's tunnel IP, and the URL to open once a client is
   connected — by default:

   ```
   tunnelweb: network=10.8.0.0/24 server-tunnel-ip=10.8.0.1 — open http://10.8.0.1:8080/ from inside a connected client
   ```

4. **Connect a real OpenVPN client** using the generated `/tmp/tunnelweb-pki/client.conf` (built
   from the same PKI material — CA, client cert/key, and `tls-crypt` key), pointed at this
   server's UDP listener (`0.0.0.0:1194` by default):

   ```bash
   sudo openvpn --config /tmp/tunnelweb-pki/client.conf
   ```

5. **Open `http://10.8.0.1:8080/`** from inside that client's network namespace (the client
   machine or container, not the server) once the tunnel is up. You should see the tunnelweb
   landing page, served entirely through the tunnel.

See [../examples/tunnelweb/README.md](../examples/tunnelweb/README.md) for the full walkthrough,
including every page the example serves (`/status`, `/about`, `/echo`, `/headers`) and the
`-listen`, `-network`, and `-http-port` flags.

## Embedding `govpn` in your own program

Beyond running the example, embedding `govpn` directly means building a `tls.Config` for mutual
certificate auth, providing a `tls-crypt` static key, defining the tunnel network, and handing the
library an `ovpn.Config`:

```go
srv := ovpn.NewServer(ovpn.Config{
    TLSConfig:   tlsCfg,        // mutual cert auth: ClientCAs, Certificates, MinVersion
    TLSCryptKey: tlsCryptKey,   // from ovpn.ParseStaticKeyV1
    Network:     tunnelNetwork, // *net.IPNet, e.g. 10.8.0.0/24 (topology subnet)
    Cipher:      "AES-256-GCM",
    OnSession: func(sess *ovpn.Session) {
        // sess is an io.ReadWriteCloser of raw, decrypted IP packets.
    },
})

pc, _ := net.ListenPacket("udp", "0.0.0.0:1194")
if err := srv.Serve(pc); err != nil {
    log.Fatal(err)
}
```

For the full `Config` field reference and how each maps to an OpenVPN client-side directive, see
[CONFIGURATION.md](CONFIGURATION.md). For the `Server`/`Session` API surface, see
[API.md](API.md). For how to route decrypted packets into the bundled userspace netstack (no TUN
device, no `CAP_NET_ADMIN`) instead of handling them yourself, see [NETSTACK.md](NETSTACK.md).

## Common setup issues

- **`gentestpki: unknown -profile "..."`** — `-profile` only accepts `small` (default, ECDSA
  P-256, fast) or `large` (a three-level RSA-4096 chain used by the interop test harness to
  exercise TLS certificate fragmentation). For local experimentation, `small` is the right choice.
- **`tunnelweb: missing -pki`** — `tunnelweb` requires `-pki <dir>` pointing at a directory
  produced by `gentestpki`; it does not generate PKI material itself. Run step 2 above first.
- **Client fails to reach `http://10.8.0.1:8080/`** — that address only resolves from inside the
  connected client's own network namespace, not from the machine running the `tunnelweb` server.
  Confirm the OpenVPN client actually established the tunnel (check its log for `Initialization
  Sequence Completed`) before opening the URL.
- **Wrong Go version** — `go build` will fail with a `go.mod` version error on toolchains older
  than Go 1.24. Run `go version` and upgrade if needed.

## Next steps

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design: control channel, data channel, key
  derivation
- [CONFIGURATION.md](CONFIGURATION.md) — the full `ovpn.Config` field reference
- [API.md](API.md) — `ovpn.Server`, `ovpn.Config`, `ovpn.Session` — the public API surface
- [NETSTACK.md](NETSTACK.md) — the privilege-free userspace netstack (UDP, TCP, ICMP)
- [DEVELOPMENT.md](DEVELOPMENT.md) — local dev setup, build commands, code style
- [TESTING.md](TESTING.md) — unit tests, golden vectors, and the Docker-based OpenVPN interop
  harness
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — how to contribute
- [../examples/tunnelweb/README.md](../examples/tunnelweb/README.md) — the full `tunnelweb`
  walkthrough
