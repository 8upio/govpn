# Phase 3: In-Process Termination — External API Coverage

**Assessed:** 2026-08-26 (planner, `/gsd-plan-phase 03`)

## Declaration

No external API integration: implements RFC-based IP/UDP/TCP/ICMP handling and an example
server against the local netstack; zero external services or SDKs.

## Reasoning

Every capability this phase delivers is a wire-format or interface behavior specified by a
public Internet Standard or by the Go standard library's own documented contracts — both
read directly during research, not summarized from memory:

| Capability | Specified by | External API? |
|---|---|---|
| IPv4 header parse/build, IHL, fragmentation flags | RFC 791 §3.1 | No — `encoding/binary` |
| Internet checksum (one's-complement, end-around carry) | RFC 1071 | No — ~15 lines, already live-verified in the Phase-2 harness |
| ICMP echo request/reply | RFC 792 | No |
| UDP header + IPv4 pseudo-header checksum, zero-checksum rule | RFC 768 | No |
| Minimal server-side TCP (header, MSS option, passive open, RST, TIME_WAIT) | RFC 9293 (obsoletes RFC 793) | No |
| `net.PacketConn` / `net.Listener` / `net.Conn` contracts | Go stdlib `net` (`/usr/local/go/src/net/net.go`) | No — stdlib interfaces implemented, not called |
| Deadline / `CloseWrite` / listener-wrapping behavior | Go stdlib `net/http` (`server.go`) | No — stdlib consumer, read to learn its expectations |
| Example web pages | `03-UI-SPEC.md` + stdlib `html/template`, `//go:embed` | No — no CDN, no font host, no analytics, no bundler |

`go.mod` remains at `module github.com/8upio/govpn` / `go 1.24` with **no `require`
directive** — the phase adds zero Go dependencies. RESEARCH.md's Package Legitimacy Audit
records zero packages proposed ("Not applicable this phase"), so the Package Legitimacy Gate
does not apply.

Two **Debian packages** are added to the interop client image in plan 03-06 — `curl` (for
the HTTP probes) and `netcat-openbsd` (for the UDP probe; the container's `/bin/sh` is dash,
which has no `/dev/udp`). Both are installed from the Debian bookworm repository against the
already digest-pinned base image, with resolved versions recorded in the Dockerfile's
existing comment block. They are test-fixture tooling in the *client* container — the
counterparty, not a dependency of the library — and are unreachable from the core module.

The only externally-produced software this phase interacts with remains the pinned
**OpenVPN 2.6.14 Debian client binary** from Phase 1's `test/interop/Dockerfile`. It is the
interop counterparty, not an API this library integrates against.

## Assumption Delta (recorded, not re-asked)

This phase introduces a **second consumer of `Session`** — the netstack, alongside direct
embedder use. `03-CONTEXT.md` already resolves the question, and it is not re-opened:

- **D-01/D-18** — the netstack declares its own minimal local session interface
  (`io.ReadWriteCloser`, satisfied structurally by `*ovpn.Session`) and never imports
  `github.com/8upio/govpn`. The core `ovpn` package stays independent of the netstack; an
  embedder imports both. The assigned tunnel IP is passed to `Attach(sess, ip)` rather than
  read off the session, which is what keeps the interface free of any `ovpn`-specific
  method and makes the fake-`Session` fast tier (D-12) possible.
- **D-02** — attachment is explicit: the embedder calls `stack.Attach(sess,
  sess.AssignedIP())` from `OnSession`. Detach is triggered solely by the stack's per-session
  read loop observing `Session.Read` return an error. Nothing in `ovpn.Config` knows the
  netstack exists.

Both are implemented as planned decisions in `03-01-PLAN.md` (the interface, the read loop,
the detach trigger) and demonstrated as the canonical embedder wiring in `03-05-PLAN.md`.
The dependency direction is enforced by standing gates
(`TestPhase3NetstackDoesNotImportCoreLibrary`, `TestPhase3CoreDoesNotImportNetstack`) added
in `03-01-PLAN.md` Task 3. No further discussion is required.

## Planner Assumption Surfaced (UI-SPEC unresolved row)

`03-UI-SPEC.md`'s UI Considerations table carried one ⚠ unresolved row — the status page's
exact field set, which could not be locked before the netstack API existed. It is resolved
in `03-05-PLAN.md`'s objective as an explicit, recorded planner assumption with its own risk
note: because the `site` package deliberately does not import `ovpn`, the assigned tunnel IP
comes from `*http.Request.RemoteAddr` and the server tunnel IP from
`http.LocalAddrContextKey`, both populated by the netstack's `*net.TCPAddr` handling, with an
em-dash fallback that never omits a row.
