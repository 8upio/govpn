# tunnelweb

The canonical example embedding `github.com/8upio/govpn`: a small web site
reachable **only** through a real OpenVPN tunnel, in one command.

`tunnelweb` starts a real OpenVPN server (via `ovpn.NewServer`/`Serve`), attaches
every connected client's session to a privilege-free userspace netstack
(`netstack.New`/`Attach`), and serves a landing page plus four subpages
(`/status`, `/about`, `/echo`, `/headers`) with stdlib `http.Serve` on the
netstack's own TCP listener — `stack.ListenTCP(port)`. There is no TUN device,
no `CAP_NET_ADMIN`, and no OS TCP socket bound for HTTP: the only way to reach
this site is through the tunnel itself.

## Run it

1. Generate a PKI (CA, server cert, tls-crypt key):

   ```sh
   go run ./cmd/gentestpki -out /tmp/tunnelweb-pki -profile small
   ```

2. Start the server:

   ```sh
   go run ./examples/tunnelweb -pki /tmp/tunnelweb-pki
   ```

   It prints the tunnel network, the server's tunnel IP, and the URL to open
   once a client is connected — by default:

   ```
   tunnelweb: network=10.8.0.0/24 server-tunnel-ip=10.8.0.1 — open http://10.8.0.1:8080/ from inside a connected client
   ```

3. Connect a real OpenVPN client using a client config built from the same
   `/tmp/tunnelweb-pki` material (client cert/key, the CA, and the tls-crypt
   key), pointed at this server's UDP listener (`0.0.0.0:1194` by default).

4. From inside that client's own network namespace — the client machine or
   container, not the server — open `http://10.8.0.1:8080/` in a browser.

Nothing here is reachable from outside the tunnel: `tunnelweb` never binds an
OS TCP socket for HTTP. The only listener that ever exists is
`stack.ListenTCP(port)`, which lives entirely inside the netstack's own
4-tuple routing table and only ever receives a packet that arrived through an
attached `Session`.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-pki` | *(required)* | Directory containing `ca.crt`, `server.crt`, `server.key`, `tls-crypt.key` |
| `-listen` | `0.0.0.0:1194` | UDP address the OpenVPN server listens on |
| `-network` | `10.8.0.0/24` | Tunnel IPv4 network clients are assigned from (`topology subnet`) |
| `-http-port` | `8080` | TCP port the web site listens on, over the netstack |

## What the pages prove

- **Landing (`/`)** — the first thing a browser sees once the tunnel comes
  up: proof the netstack TCP/HTTP path works at all.
- **Status (`/status`)** — live, per-session facts (assigned tunnel IP,
  server tunnel IP, cipher) derived from the request itself, proving this is
  really your session and not a static page.
- **About (`/about`)** — the "why": no TUN device, no `CAP_NET_ADMIN`,
  traffic terminates entirely in this Go process via the userspace netstack.
- **Echo test (`/echo`)** — the one interactive proof: a plain HTML form
  POST that round-trips a message through the tunnel and back, exercising
  the minimal server-side TCP path end to end.
- **Headers (`/headers`)** — echoes the raw HTTP headers this server
  actually received, proof the request genuinely transited the tunnel.

## Design

The pages themselves live in the importable `examples/tunnelweb/site`
package, which imports only the Go standard library — no `ovpn`, no
`netstack` — so it can be tested with `net/http/httptest` alone (see
`site/site_test.go`) and reused by other embedders (e.g. an interop test
harness) without pulling in a tunnel.
