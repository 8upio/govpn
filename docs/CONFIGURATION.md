<!-- generated-by: gsd-doc-writer -->
[← Back to README](../README.md)

# Configuration

`govpn` (module `github.com/8upio/govpn`, package `ovpn`) has no config file, no
flags, and no environment variables of its own. Everything is set through a
single Go struct — `ovpn.Config` — that you build in code and pass to
`ovpn.NewServer`. This document covers every field on that struct, how it maps
to the matching OpenVPN 2.6 client-side config directives, and what is
deliberately fixed (not configurable) in the current implementation.

See also: [GETTING-STARTED.md](GETTING-STARTED.md) for a minimal end-to-end
setup, [API.md](API.md) for the `Server`/`Session` surface these fields feed,
[ARCHITECTURE.md](ARCHITECTURE.md) for how the control/data channel pieces fit
together, and [NETSTACK.md](NETSTACK.md) for the optional userspace netstack
that consumes a `Session` via `Config.OnSession`.

## `ovpn.Config`

Defined in `ovpn.go`:

```go
type Config struct {
    TLSConfig      *tls.Config
    TLSCryptKey    []byte
    Network        *net.IPNet
    Cipher         string
    OnSession      func(*Session)
    OnSessionPanic func(sess *Session, recovered any, stack []byte)
    RenegSec       time.Duration
}
```

| Field | Type | Required | Default when zero |
|---|---|---|---|
| `TLSConfig` | `*tls.Config` | Yes — `Serve` returns an error if nil | none |
| `TLSCryptKey` | `[]byte` | Yes — `Serve` returns an error if invalid | none |
| `Network` | `*net.IPNet` | No to start `Serve`; effectively required for any session to reach the data channel | sessions fail during `PUSH_REQUEST`/`PUSH_REPLY` if unset |
| `Cipher` | `string` | No | `"AES-256-GCM"` |
| `OnSession` | `func(*Session)` | No (but a server with no callback can't do anything useful with connected sessions) | no-op |
| `OnSessionPanic` | `func(sess *Session, recovered any, stack []byte)` | No | panic is not recovered — a panic inside `OnSession` propagates normally |
| `RenegSec` | `time.Duration` | No | `3600 * time.Second` (matches the OpenVPN reference's own `--reneg-sec` default, `options.c:878`) |

### `TLSConfig`

The control-channel TLS handshake — mutual certificate authentication,
the server's own certificate, and the minimum TLS version — is handed
unmodified to `tls.Server(conn, cfg)`. `govpn` does not enforce any particular
`tls.Config` field; you are responsible for configuring:

- `Certificates` — the server's own certificate/key pair (`tls.X509KeyPair`).
- `ClientCAs` — an `x509.CertPool` of CAs trusted to sign client certificates.
- `ClientAuth` — set to `tls.RequireAndVerifyClientCert` for cert-based client
  auth (matching a real OpenVPN client's `cert`/`key` directives). If this is
  left unset, no client certificate is required and `Session.PeerCN` (see
  [API.md](API.md)) will be empty.
- `MinVersion` — set explicitly to `tls.VersionTLS12` rather than relying on
  Go's own default floor, since that default has shifted upward across Go
  releases and an unannounced future bump could silently break interop with
  more conservative client configs.

Example, taken from `examples/tunnelweb/main.go`:

```go
tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    caPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
    MinVersion:   tls.VersionTLS12,
}
```

The matching client-side directives in a real OpenVPN 2.6 `.conf` are `cert`,
`key`, `ca`, and `remote-cert-tls server`.

### `TLSCryptKey`

The 256 raw bytes of an OpenVPN "Static key V1" tls-crypt key, shared with
every client connecting to this server (`govpn` does not support per-client
tls-crypt keys or tls-auth as a separate mode — only tls-crypt). Load a key
file with the package-level helper:

```go
data, err := os.ReadFile("tls-crypt.key")
if err != nil {
    // handle error
}
key, err := ovpn.ParseStaticKeyV1(data)
if err != nil {
    // handle error
}
cfg := ovpn.Config{TLSCryptKey: key, /* ... */}
```

`ParseStaticKeyV1` (declared in `ovpn.go`, implemented in
`internal/tlscrypt`) parses the standard
`-----BEGIN OpenVPN Static key V1-----` / `-----END OpenVPN Static key V1-----`
PEM-style envelope into its 256 raw bytes. `Serve` validates `TLSCryptKey`
up front (via a throwaway `tlscrypt.NewWrapper`) and returns an error before
it ever reads a datagram if the key is missing or malformed — a bad key never
surfaces only on the first inbound connection attempt.

The matching client-side directive is `tls-crypt <path-to-key-file>`. A real
OpenVPN client's static key file must contain the identical 256 bytes.

For generating a throwaway key/PKI for local testing (not for production
use), see [Generating test PKI material](#generating-test-pki-material-non-production)
below.

### `Network`

The virtual tunnel IPv4 network clients are assigned addresses from —
equivalent to `topology subnet` server-side configuration. Requirements,
enforced by the internal IP pool (`ippool.go`):

- Must be an IPv4 `*net.IPNet` (an IPv6 network or a non-IPv4-shaped mask is
  rejected).
- Must be at least a `/30` (4 addresses: network, server, one client,
  broadcast). Anything smaller returns an error from `Serve`.
- The server reserves the first host address (`network base + 1`) for
  itself — this is the address `stack.New(...)` / your own netstack or TUN
  code should bind as the server's own tunnel IP.
- Client addresses are allocated sequentially from the remaining host
  addresses (skipping the network, server, and broadcast addresses),
  first-free — a released address is reused before a never-used higher one.

```go
_, network, _ := net.ParseCIDR("10.8.0.0/24")
cfg := ovpn.Config{Network: network, /* ... */}
```

Unlike `TLSConfig`/`TLSCryptKey`, `Network` is **not** required for `Serve`
to start — a server without it can still complete the TLS handshake and
Key Method 2 (useful for control-channel-only testing). It is only required
once a session reaches the `PUSH_REQUEST`/`PUSH_REPLY` exchange: with no
`Network` configured, that exchange fails and the session is closed before
`OnSession` ever fires.

`govpn` always operates under `topology subnet` — every `PUSH_REPLY` includes
`topology subnet` and an `ifconfig <client-ip> <netmask>` pair (not a
point-to-point peer address). The matching client-side directives are
`topology subnet` (required — see the project's stated compatibility target)
and no server-side `ifconfig-pool`/`server` directive equivalent needs to be
set by hand on the client; addresses are pushed automatically.

### `Cipher`

The name pushed to clients as the `cipher <name>` option in `PUSH_REPLY` and
in the Key Method 2 options string (e.g. `cipher AES-256-GCM`). Defaults to
`"AES-256-GCM"` when left empty.

**This field only changes what string is negotiated/pushed — it does not
change what cipher is actually used.** The data-channel crypto implementation
(`internal/datachan`) hard-codes AES-256-GCM: encryption, decryption, and
nonce construction are all AES-256-GCM regardless of this field's value.
Setting `Cipher` to anything other than `"AES-256-GCM"` will advertise a
cipher name the server does not actually implement, which a real OpenVPN 2.6
client with NCP (cipher negotiation) enabled will accept at face value —
leave this field unset (or explicitly `"AES-256-GCM"`) unless you have
verified the client-side behavior you're relying on.

The matching client-side directive is `cipher AES-256-GCM` (also the default
a modern OpenVPN 2.6 client negotiates via NCP even without an explicit
`cipher` line).

### `OnSession`

Invoked exactly once per client, after Key Method 2 and the
`PUSH_REQUEST`/`PUSH_REPLY` exchange have both completed — not merely after
the TLS handshake returns. By the time `OnSession` fires, the `Session`
handed to it is fully usable: `Session.AssignedIP()` is populated and
`Session.PeerCN` holds the verified client CommonName. This is the
integration point for attaching a `Session` (which implements
`io.ReadWriteCloser` for decrypted IP packets) to your own packet-handling
code — e.g. the bundled userspace netstack (see
[NETSTACK.md](NETSTACK.md)) or a TUN device.

```go
cfg := ovpn.Config{
    OnSession: func(sess *ovpn.Session) {
        // sess.AssignedIP(), sess.PeerCN are already populated here.
    },
}
```

### `OnSessionPanic`

Optional. If set, it is invoked when `OnSession` panics, instead of letting
the panic take down the embedding process. It receives the `Session` that
was being handed to `OnSession`, the recovered panic value, and a captured
stack trace (`runtime/debug.Stack()`). `OnSessionPanic` itself runs inside
the recover path and must not panic. If left unset, a panic inside
`OnSession` is not recovered by `govpn` and propagates normally.

### `RenegSec`

The server's own renegotiation deadline: once a session's active key has
been established for at least this long, the server starts its own
soft-reset renegotiation on its own timer, independent of whatever
renegotiation interval the connecting client is configured with — whichever
side's timer fires first wins. `0` (the zero value) means the reference
implementation's own `reneg-sec` default of 3600 seconds
(`options.c:878`). This value is deliberately never pushed to the client as
a `reneg-sec` option — set the matching client-side `reneg-sec` value (if any)
independently in the client's own `.conf`.

```go
cfg := ovpn.Config{RenegSec: 900 * time.Second /* renegotiate every 15 min */}
```

## What is not configurable

`govpn`'s `PUSH_REPLY` (`push.go`) only ever sends: `ifconfig`,
`topology subnet`, `peer-id`, `cipher`, `ping`, and `ping-restart`. There is
currently no `Config` field for pushing routes, DNS (`dhcp-option`),
compression, or a custom keepalive interval/timeout — these are simply not
sent, matching no equivalent server-side directive. A connecting OpenVPN
client should not expect `redirect-gateway`, `route`, or `dhcp-option`
behavior from this server. The keepalive schedule (`ping 10`,
`ping-restart 60`) is currently fixed and not exposed as a `Config` field.

## Generating test PKI material (non-production)

For local development and interop testing, `cmd/gentestpki` generates a
throwaway CA, server certificate, client certificate, and tls-crypt key —
using `crypto/x509` + `crypto/rand`, no `easy-rsa`, no shelling out to the
`openvpn` binary:

```sh
go run ./cmd/gentestpki -out /tmp/my-pki -profile small
```

This produces `ca.crt`, `server.crt`, `server.key`, `client.crt`,
`client.key`, `tls-crypt.key`, and a matching `client.conf` in the output
directory. Every certificate's CommonName is namespaced with a
`govpn-interop-` prefix and validity is fixed at 24 hours from generation —
this tool is for local/interop testing only, never for production
credentials. `-profile large` generates a multi-level RSA-4096 chain instead
of the default ECDSA P-256 single-CA chain, for testing certificate
fragmentation across multiple control packets.

<!-- VERIFY: any production certificate issuance process, CA management, or key-rotation procedure — not discoverable from this repository, which only ships test/interop tooling. -->

## Minimal example

```go
tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    caPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
    MinVersion:   tls.VersionTLS12,
}

_, network, _ := net.ParseCIDR("10.8.0.0/24")

srv := ovpn.NewServer(ovpn.Config{
    TLSConfig:   tlsCfg,
    TLSCryptKey: tlsCryptKey, // from ovpn.ParseStaticKeyV1
    Network:     network,
    OnSession: func(sess *ovpn.Session) {
        // attach sess to your netstack/TUN here
    },
})

pc, _ := net.ListenPacket("udp", "0.0.0.0:1194")
if err := srv.Serve(pc); err != nil {
    log.Fatal(err)
}
```

The matching client-side `.conf` for this configuration:

```
client
dev tun
proto udp
remote <server-host> 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
ca ca.crt
cert client.crt
key client.key
tls-crypt tls-crypt.key
topology subnet
cipher AES-256-GCM
```

<!-- VERIFY: `<server-host>` — the actual hostname/IP a deployed server listens on is deployment-specific and not discoverable from this repository. -->
