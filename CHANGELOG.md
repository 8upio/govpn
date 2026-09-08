# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow Semantic Versioning strictly (pre-1.0), but
version numbers below still increase monotonically with each release.

## [Unreleased]

### Added

- `Config.AuthUserPass` — authenticates a client's Key Method 2
  username/password, on the initial handshake and on every renegotiation.
  `nil` (the default) leaves credentials parsed and ignored, matching
  every previous release's behavior exactly.
- `AuthClientReason` — an optional interface an `AuthUserPass` error may
  implement to send the client an `AUTH_FAILED,<reason>` rejection
  instead of the plain `AUTH_FAILED` form.
- `CloseReasonAuthFailed` — recorded when `Config.AuthUserPass` rejects a
  client's credentials; fires `Config.OnSessionClosed` only for a
  renegotiation-time rejection (an initial-handshake rejection never
  reaches `OnSession`, so it never reaches `OnSessionClosed` either).
- Supported certificate-less operation: a server can now authenticate
  clients by username/password alone (`tls.NoClientCert`/
  `tls.RequestClientCert` plus `Config.AuthUserPass`), matching a real
  OpenVPN client's `auth-user-pass` directive with no `cert`/`key`. Proven
  against a real, unmodified OpenVPN 2.6 client via the new
  `auth-user-pass` interop scenario.

### Changed

- **`Server.Serve` now returns an error for a configuration that would
  authenticate nobody** — `TLSConfig.ClientAuth` not mandating a client
  certificate (`tls.NoClientCert`, `tls.RequestClientCert`, or
  `tls.VerifyClientCertIfGiven`) AND `Config.AuthUserPass` left `nil`.
  **If you are already running with `ClientAuth: tls.NoClientCert` (or
  equivalent) and no `AuthUserPass`, `Serve` will now fail fast** where it
  previously started successfully and accepted every client
  unauthenticated — set `Config.AuthUserPass` or require a client
  certificate to keep starting.

## [0.1.0] - 2026-09-08

"Welle 1" of the Voxio requirements: observability and configuration,
all API-additive except one pushed-value change. Everything below is
new API surface unless noted under **Changed**.

### Added

- `netstack.WithReassemblyLimits(ReassemblyLimits)` — overrides the
  default per-attachment IPv4 fragment-reassembly bounds (datagram count,
  byte budget, timeout) instead of the fixed package constants. A zero
  field means "use the built-in default." Negative fields make `New`
  return the new `netstack.ErrInvalidReassemblyLimits`.
- `netstack.ListenUDPOptions(port, UDPOptions)` — opens a UDP listener
  with a caller-chosen queue depth (`UDPOptions.QueueDepth`) and overflow
  policy (`UDPOptions.DropPolicy`: `UDPDropNewest`, the unchanged
  default, or `UDPDropOldest`, which evicts the oldest queued datagram so
  a burst consumer always sees the freshest data — the right choice for
  real-time media). `netstack.ListenUDP` is now a thin wrapper over it.
  New sentinel errors `ErrInvalidUDPQueueDepth` and
  `ErrInvalidUDPDropPolicy`.
- `(*netstack.Stack).UDPStats()` — a new `UDPStats` snapshot
  (`QueueFullDropped`, `NoListenerDropped`, `BadChecksumDropped`),
  returning the zero value and registering no handler when no listener
  has ever been opened.
- `ovpn.CloseReason` and `Session.CloseReason()`/`Session.Done()` — every
  session teardown now records why it ended: `CloseReasonEmbedder`,
  `CloseReasonClientExitNotify`, `CloseReasonIdleReap`,
  `CloseReasonServerClose`, or `CloseReasonUnknown` (a session torn down
  before it was ever published to `OnSession`). `CloseReasonReplaced` is
  reserved for a future static-IP replace path and is never produced
  today.
- `Config.OnSessionClosed` — fires at most once per session, only for a
  session actually handed to `OnSession`, after teardown has fully
  completed, on its own goroutine, with panics recovered via
  `OnSessionPanic`. `Server.Close` now waits for every `OnSessionClosed`
  callback it triggered to return before `Close` itself returns.
- `Config.PingInterval` / `Config.ReapWindow` — make the pushed
  `ping`/`ping-restart` values and the idle-session reap window
  configurable (previously fixed at 10s/60s). `Serve` validates that
  `ReapWindow` is at least twice the resolved `PingInterval`, and rejects
  negative values.
- `Config.SessionInboundQueue` — overrides the per-session inbound
  raw-IP-packet queue depth (previously a fixed 32), useful for a bursty
  embedder (e.g. RTP/SIP) that can occasionally fall behind `Read`.
- `Session.Stats()` and `SessionStats` — per-session traffic counters:
  `BytesIn`/`BytesOut`, `PacketsIn`/`PacketsOut`, `InboundQueueDropped`,
  `Renegotiations`, `EstablishedAt`, and `LastAuthTrafficAt`. A ping
  keepalive (absorbed inside the decrypt path, or emitted via a path that
  bypasses `Write`) increments none of the byte/packet counters.
- `Session.RemoteAddress()` — an accessor alongside the existing exported
  `RemoteAddr` field, so a future storage-representation change doesn't
  break embedders using the method form.

### Changed

- The internal standing gate that previously asserted `Config` declares
  no `OnSessionClosed`-style field has been removed: that earlier
  deferral is superseded by this release's `Config.OnSessionClosed`. The
  `io.EOF`-from-`Read`/`Write` teardown observation it also protected is
  unchanged and still covered by test.
- The pushed `ping-restart` value is no longer the hardcoded literal
  `ping-restart 60` — it is now derived from `Config.ReapWindow` (default
  unchanged: 60 seconds). Likewise `ping N` is now derived from
  `Config.PingInterval` (default unchanged: 10 seconds). **This is the
  only wire-visible change in this release** — both values are identical
  to before at their (still the same) defaults.

### Not changed

`Config.TunMTU` was explicitly considered and NOT implemented: the Key
Method 2 options string stays fixed at `tun-mtu 1500`, and no `tun-mtu`
or `mssfix` directive is pushed in `PUSH_REPLY`. This server's own
netstack MTU remains independently configurable via `netstack.WithMTU`
and the two are not required to agree.
