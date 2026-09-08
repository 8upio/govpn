# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow Semantic Versioning strictly (pre-1.0), but
version numbers below still increase monotonically with each release.

## [Unreleased]

### Fixed

- An authenticated ping keepalive was treated as a decrypt failure, so a
  client that sent nothing but keepalives was idle-reaped after one
  `ReapWindow` despite being alive. The keepalive now refreshes the
  idle-reap timer, and it is logged with its own `keepalive`/
  `keepalive-lame-duck` reason token instead of sharing the auth-failure
  path.

### Added

- `SessionStats.KeepalivesIn` — counts inbound ping keepalives a session
  authenticated and absorbed. Excluded from `BytesIn`/`PacketsIn` (a ping
  is not tunnel payload) but counted here, and it refreshes
  `LastAuthTrafficAt`.

## [0.2.0] - 2026-09-08

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
- `Config.Logger *slog.Logger` — optional structured (`log/slog`) logging
  for handshake progress and failure, session lifecycle, authentication
  decisions, renegotiation, and every datagram the dispatch silently drops.
  `nil` (the default) is bit-for-bit today's previous silent behaviour: no
  output, no allocation. Every per-datagram drop is logged at Debug, never
  Info — an unauthenticated peer can trigger these without limit, so this
  keeps a forged-datagram flood from becoming a log-volume amplifier at
  the default level. Credentials, tls-crypt/data-channel key material, and
  packet payload bytes are never logged. See
  [docs/CONFIGURATION.md#logger](docs/CONFIGURATION.md#logger).
- `Config.AssignIP` — chooses a client's tunnel IP instead of the default
  dynamic pool. `nil` (the default) leaves every session's tunnel IP coming
  from the dynamic pool, byte-for-byte unchanged. Returning `(nil, nil)`
  falls back to the pool for that one session only. If the returned address
  is currently held by another live session, that session is evicted with
  the now-produced `CloseReasonReplaced` and the new session takes over the
  address — mirroring the OpenVPN reference's own default no-`--duplicate-cn`
  eviction behaviour, so a client reconnecting after a transient network
  flap is never locked out by its own still-live prior session. See
  [docs/CONFIGURATION.md#assignip](docs/CONFIGURATION.md#assignip).
- `Server.Sessions()` / `Server.Stats()` / `ServerStats` — a point-in-time,
  sorted-by-IP snapshot of established sessions, and eight counters
  covering handshake outcomes (which partition per settled handshake),
  `Config.AssignIP` rejections, pool exhaustion, and dispatch-level
  datagram drops. See [docs/API.md#serverstats](docs/API.md#serverstats).
- `(*netstack.Stack).IsAttached(ip)` / `Routes()` — the inventory
  counterpart to `Stack.Stats()`'s counters: which IPs are attached right
  now, as defensive copies sorted for deterministic output. See
  [docs/NETSTACK.md](docs/NETSTACK.md#attaching-a-session).
- `netstack/netstacktest` — an exported package of test helpers (frame
  builders for IPv4/UDP/ICMP-echo/fragment, plus `FakeSession`) for
  embedders driving a `netstack.Stack` from their own tests, with no
  `testing` dependency. `netstack`'s own test suite now uses this package
  exclusively — no private duplicate remains. See
  [docs/NETSTACK.md#test-helpers-netstacktest](docs/NETSTACK.md#test-helpers-netstacktest).

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
