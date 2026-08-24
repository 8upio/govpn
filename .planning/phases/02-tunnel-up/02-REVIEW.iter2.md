---
phase: 02-tunnel-up
reviewed: 2026-08-24T00:00:00Z
depth: standard
files_reviewed: 34
files_reviewed_list:
  - .github/workflows/ci.yml
  - Makefile
  - gates_test.go
  - internal/datachan/datachan.go
  - internal/datachan/datachan_test.go
  - internal/datachan/golden_test.go
  - internal/datachan/ping.go
  - internal/datachan/ping_test.go
  - internal/datachan/replay.go
  - internal/datachan/replay_test.go
  - internal/keyderiv/golden_test.go
  - internal/keyderiv/keyexpansion.go
  - internal/keyderiv/keyexpansion_test.go
  - internal/keyderiv/keymethod2.go
  - internal/keyderiv/keymethod2_test.go
  - internal/keyderiv/prf.go
  - internal/keyderiv/prf_test.go
  - internal/tlscrypt/golden_test.go
  - internal/wire/golden_test.go
  - ippool.go
  - ippool_test.go
  - ovpn.go
  - ovpn_test.go
  - push.go
  - push_test.go
  - session.go
  - test/interop/Dockerfile
  - test/interop/decode.go
  - test/interop/entrypoint.sh
  - test/interop/golden_export.go
  - test/interop/interop_test.go
  - test/interop/server/Dockerfile
  - test/interop/server/main.go
  - testdata/golden/README.md
  - testdata/golden/data-channel-km2.json
  - testdata/golden/manifest.json
findings:
  critical: 1
  warning: 4
  info: 0
  total: 5
status: issues_found
---

# Phase 02: Code Review Report

**Reviewed:** 2026-08-24T00:00:00Z
**Depth:** standard
**Files Reviewed:** 34
**Status:** issues_found

## Summary

Reviewed the Key Method 2 key derivation, AES-256-GCM data channel, PUSH
exchange, tunnel IP pool, and Session packet I/O introduced in this phase,
cross-checked against the pinned OpenVPN reference where the project's own
CLAUDE.md and code comments call out deliberate reference-faithful oddities
(tag-before-ciphertext AEAD order, inverted key-direction slots, frozen
packet-ID timestamps). Those specific oddities are correctly implemented and
well-tested (byte-exact golden vectors against a real captured OpenVPN 2.6.14
session, explicit "would catch an inversion" tests, etc.) — no findings
against them.

One protocol-correctness bug was found that would break real-world interop:
`Server.handleDatagram`'s length-based UDP triage applies a control-channel
minimum length (49 bytes, the tls-crypt prefix) uniformly to *all* incoming
datagrams, including data-channel (`P_DATA_V2`) packets — which can
legitimately be as short as 40 bytes (a ping keepalive). This silently drops
every client-to-server ping keepalive the library is supposed to support
(D-11), and it went unnoticed because every unit test that exercises ping
absorption calls `Session.handleDataPacket` directly, bypassing
`handleDatagram`'s gate entirely, and the interop golden corpus only captured
a *server*-to-client ping (the direction this bug doesn't affect).

The remaining findings are narrower: a netmask-normalization inconsistency
between `newIPPool` and `buildPushReply`, a data-hygiene gap in
`datachan.Wrapper.Open`'s replay-rejection path, and an unsynchronized
concurrent access to `Session` fields between the handshake goroutine and the
handshake-window timeout goroutine.

## Critical Issues

### CR-01: Data-channel ping keepalives from the client are silently dropped by an over-broad minimum-datagram-length gate

**File:** `ovpn.go:95-98, 296`
**Issue:**

`Server.handleDatagram` rejects every inbound UDP datagram shorter than
`minDatagramSize`:

```go
// minDatagramSize is the 49-byte tls-crypt prefix (tls_crypt.h
// TLS_CRYPT_OFF_CT) — nothing shorter than this can possibly be a valid
// tls-crypt-wrapped packet.
minDatagramSize = tlscrypt.OffCT   // = 49

...

func (s *Server) handleDatagram(pc net.PacketConn, addr net.Addr, packet []byte) {
	if len(packet) < minDatagramSize || len(packet) > maxDatagramSize {
		return
	}

	opcode, keyID := wire.ParseHeaderByte(packet[0])
	...
	if opcode == wire.OpDataV1 || opcode == wire.OpDataV2 {
		s.handleDataDatagram(opcode, packet)
		return
	}
	...
}
```

`minDatagramSize` is derived from `tlscrypt.OffCT` (49 bytes) — the minimum
size of a *tls-crypt-wrapped control-channel* packet — and the comment
explicitly reasons about tls-crypt only. But this check runs **before** the
opcode is even inspected, so it is applied uniformly to `P_DATA_V1`/
`P_DATA_V2` datagrams too, which are never tls-crypt wrapped and have a much
shorter wire layout (`internal/datachan/datachan.go`):

```
[opcode+keyid(1B)][peer-id(3B)][packet-id(4B)][tag(16B)][ciphertext(N)]
```

A minimal, structurally valid `P_DATA_V2` packet — the 16-byte OpenVPN ping
keepalive magic (`internal/datachan/ping.go`, D-11) — seals to exactly
`8 (header) + 16 (tag) + 16 (ping magic) = 40` bytes. Since `40 < 49`, every
client-to-server ping keepalive is dropped at this gate, before `handleDatagram`
ever branches into `handleDataDatagram` (which has its own, correctly-sized
4-byte minimum check) or reaches `datachan.Wrapper.Open` (whose own `ErrShort`
threshold, `offCiphertext = 24`, is also well below 49).

A real OpenVPN 2.6 client, once it receives this server's pushed
`ping 10, ping-restart 60` (`push.go`'s `buildPushReply`), begins sending its
own 16-byte ping keepalives to the server on that same schedule (the pushed
`ping`/`ping-restart` values govern both directions, matching
`helper_keepalive`, `helper.c:496-558`, cited in this project's own
`push.go` doc comment). Every one of those pings is silently discarded by
this server before authentication is even attempted. The client will
eventually treat the connection as dead (no server-observed traffic within
its `ping-restart` window) and tear down / reconnect the tunnel — defeating
the bidirectional keepalive `session.go`'s own `startKeepalive`/`runKeepalive`
were built to provide (D-11 explicitly frames this as bidirectional: "the
pushed schedule and the emitted schedule structurally unable to drift
apart").

This was not caught by the existing test suite because:
- Every `datachan` ping test (`TestPingIsAbsorbedNotDelivered`,
  `TestPingIsEncryptedLikeAnyPacket`) and every `Session`-level ping test
  (`TestPingNeverReachesSessionRead`, `TestServerEmitsPingOnSchedule`, etc.,
  `ovpn_test.go`) exercises `Wrapper.Open`/`Session.handleDataPacket`
  directly, never the full `Serve → handleDatagram` accept path.
- The committed golden corpus (`testdata/golden/manifest.json`) captured
  only a *server-to-client* ping-keepalive vector
  (`008-server-to-client-ping-keepalive.bin`); no client-to-server ping was
  captured (plausibly because this exact bug caused none to be observable
  in a form worth exporting), and `manifest.json`/`selectGoldenVectors`
  places no direction constraint on which side's ping gets selected.
- `TestInteropScenarios` asserts on ICMP echo round-trips (large payloads,
  unaffected — an ICMP echo request/reply is always well above 49 bytes
  sealed) but has no assertion on OpenVPN's own built-in ping mechanism
  arriving at the server from the client.

**Fix:** Apply the control-channel-specific minimum length only to
control-channel packets, after the data-channel branch has already been
taken (or use a data-channel-appropriate minimum, e.g.
`offCiphertext`/`headerSize+TagSize`, for that branch):

```go
func (s *Server) handleDatagram(pc net.PacketConn, addr net.Addr, packet []byte) {
	if len(packet) < 1 || len(packet) > maxDatagramSize {
		return
	}

	opcode, keyID := wire.ParseHeaderByte(packet[0])
	if !wire.ValidOpcode(opcode) {
		return
	}

	if opcode == wire.OpDataV1 || opcode == wire.OpDataV2 {
		// handleDataDatagram/datachan.Wrapper.Open already enforce their
		// own, much shorter, data-channel-appropriate minimum length.
		s.handleDataDatagram(opcode, packet)
		return
	}

	// minDatagramSize (the tls-crypt prefix) only applies to control-channel
	// packets, which are always tls-crypt wrapped.
	if len(packet) < minDatagramSize {
		return
	}
	...
}
```

Add a regression test that drives a synthetic client ping through the full
`srv.Serve()` accept path (not `sess.handleDataPacket` directly) and asserts
it is observed/absorbed, and extend the interop harness's data-channel
golden export to require at least one *client-to-server* ping vector.

## Warnings

### WR-01: `buildPushReply`'s netmask is not normalized the way `newIPPool` normalizes the same `Config.Network`

**File:** `push.go:84`, compare `ippool.go:63-69`
**Issue:**

`newIPPool` defensively normalizes `network.Mask` before using it, because
`net.IPNet.Mask` can be either a 4-byte or a 16-byte slice depending on how
the `*net.IPNet` was constructed (e.g. a CIDR string using IPv4-mapped IPv6
notation, or a manually-built `net.IPNet`):

```go
mask := network.Mask
if len(mask) == net.IPv6len {
	mask = mask[12:]
}
```

`buildPushReply`, which is also handed `s.cfg.Network` directly
(`ovpn.go:596`, `performPushExchange` → `buildPushReply(sess.assignedIP,
s.cfg.Network, sess.peerID, cipher)`), performs no equivalent normalization:

```go
netmask := net.IP(network.Mask).String()
```

If `network.Mask` is ever 16 bytes (the exact case `newIPPool` was written
to defend against), `net.IP(mask).String()` formats it as a 16-byte address
rather than a dotted-decimal IPv4 netmask, producing a malformed `ifconfig`
line in `PUSH_REPLY` and breaking the client's tunnel address configuration.
`net.ParseCIDR` on a plain dotted-decimal string never produces this shape,
so the bug is latent rather than reachable through the documented
`Config.Network` construction path in this codebase's own tests — but it is
a genuine inconsistency in defensive coding for a publicly settable `Config`
field, in the same file/function pair that already anticipated exactly this
edge case once.

**Fix:** Share one normalization path — e.g. have `buildPushReply` accept the
already-normalized mask ipPool computed (or call the same normalization
helper), rather than re-deriving the netmask string from `s.cfg.Network`
independently:

```go
func normalizeIPv4Mask(mask net.IPMask) net.IPMask {
	if len(mask) == net.IPv6len {
		return mask[12:]
	}
	return mask
}
```

### WR-02: `datachan.Wrapper.Open` can leave authenticated plaintext in the caller's `dst` buffer on a replay rejection

**File:** `internal/datachan/datachan.go:254-267`
**Issue:**

```go
prefixLen := len(dst)
plaintext, err := w.decryptAEAD.Open(dst, nonce[:], sealed, header)
if err != nil {
	return nil, ErrAuth
}

if !w.replay.accept(seq) {
	return nil, ErrReplay
}
```

On an `ErrAuth` failure, Go's `crypto/cipher` GCM implementation zeroes the
output region it wrote before returning, so `dst` is left clean. But on a
replay rejection, `AEAD.Open` has already **succeeded** — the tag verified,
and real decrypted plaintext bytes were written into (or appended onto)
`dst` — before `Open` decides to reject the packet and return `nil,
ErrReplay`. The caller's `dst` slice (if it had spare capacity, or if this
were later refactored to reuse a pooled buffer) is left holding successfully
decrypted attacker-controlled plaintext even though the function's return
value discards it. Every current call site passes `dst = nil`, so this has
no live impact today, but it's a footgun for a public API in a
security-sensitive package: a future caller that passes a reused/pooled
`dst` (a very natural thing to do to avoid per-packet allocation, which
`internal/datachan`'s own doc comments are otherwise careful about) would
silently leak replayed plaintext content into memory the function's contract
implies was left untouched.

**Fix:** Decrypt into a fresh/scratch buffer and only copy into the caller's
`dst` once the replay check has also passed, or document the caveat
explicitly on `Open`'s doc comment so future callers know not to reuse `dst`
across sessions/trust boundaries.

### WR-03: `Session.assignedIP`/`peerID`/`dataWrapper` are read and written without synchronization by two goroutines that can race

**File:** `session.go:423-444` (`Close`), `ovpn.go:563-594` (`performPushExchange`), `ovpn.go:678-685` (`enforceHandshakeWindow`)
**Issue:**

`performPushExchange` (running on the per-session `runHandshake` goroutine)
assigns `sess.assignedIP`, `sess.peerID`, and `sess.dataWrapper` with no
lock. `enforceHandshakeWindow` (running on its own goroutine, started
alongside `runHandshake` in `handleDatagram`'s `justCreated` branch) can call
`sess.Close()` concurrently if the handshake window elapses — and
`sess.doneCh` is deliberately *not* closed until `performPushExchange` has
already returned, so the window covers the entire bring-up sequence
including the moment those fields are being written:

```go
// performPushExchange:
sess.assignedIP = ip
sess.peerID = peerID
...
sess.dataWrapper = dataWrapper
```

```go
// Session.Close, potentially running concurrently on a different goroutine:
if s.assignedIP != nil && s.srv.pool != nil {
	s.srv.pool.release(s.assignedIP, s.peerID)
}
if s.dataWrapper != nil {
	...
}
```

If `enforceHandshakeWindow`'s timer fires at the exact moment
`performPushExchange` is assigning these fields (a narrow window in
practice — a default 60s handshake window against microsecond-scale field
assignment — but real under a short test-injected `handshakeWindow`, a
stalled/slow write to the client, or a future change that does more work in
that window), this is an unsynchronized concurrent read/write of the same
memory from two goroutines: undefined under the Go memory model, and capable
of manifesting as a stale/torn read of `assignedIP`/`peerID` that causes
`pool.release` to be skipped or to release the wrong/zero value, corrupting
the pool's bookkeeping. No existing test exercises this interleaving —
`TestOnSessionDoesNotFireWhenPushNeverArrives` shortens the handshake window
but only covers the case where the client never sends `PUSH_REQUEST` at all
(so `performPushExchange`'s field-assignment block is never entered
concurrently with the timeout).

**Fix:** Guard `assignedIP`/`peerID`/`dataWrapper` (and their use in `Close`)
with `Session`'s own mutex, or have `enforceHandshakeWindow`'s `Close` call
wait for/coordinate with `performPushExchange`'s critical section rather than
racing it — e.g. protect the assign-then-map-publish sequence in
`performPushExchange` and the release-on-close sequence in `Close` with the
same lock.

### WR-04: `Session.Close` releases pool state before removing the routing-table entry that still points at it

**File:** `session.go:423-439`
**Issue:**

```go
func (s *Session) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.srv != nil {
			if s.assignedIP != nil && s.srv.pool != nil {
				s.srv.pool.release(s.assignedIP, s.peerID)
			}
			if s.dataWrapper != nil {
				s.srv.mu.Lock()
				if existing, ok := s.srv.dataSessions[s.peerID]; ok && existing == s {
					delete(s.srv.dataSessions, s.peerID)
				}
				s.srv.mu.Unlock()
			}
			s.srv.removeSession(s)
		}
	})
	...
```

`pool.release` makes `s.peerID` immediately reusable by the *next*
`ipPool.allocate()` call, but `s.srv.dataSessions[s.peerID]` is only removed
(or, if already overwritten by a new session, left alone) afterward. Between
those two steps, a brand-new session can be allocated the exact same
peer-id and publish itself into `dataSessions` before the closing session's
own cleanup runs; the `existing == s` equality check happens to make this
safe today (the closing session's delete becomes a no-op once a new session
has already claimed the slot), but the correctness of that outcome depends
on a subtle, easy-to-break invariant rather than being structurally
guaranteed by the ordering itself. A stray decrypted packet destined for the
old peer-id in this window is routed to the old, already-`stopCh`-closed
session's `handleDataPacket` — harmless today only because AEAD
authentication under the old key material will reject it, not because the
routing itself was correct.

**Fix:** Reverse the order — remove the `dataSessions` entry (and any other
routing state) *before* releasing the address/peer-id back to the pool for
reuse, so a newly allocated session can never observe or be shadowed by a
routing-table entry that still belongs to the session being torn down.

---

_Reviewed: 2026-08-24T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
