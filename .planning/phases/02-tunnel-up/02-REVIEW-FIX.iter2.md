---
phase: 02-tunnel-up
fixed_at: 2026-08-24T21:45:32Z
review_path: .planning/phases/02-tunnel-up/02-REVIEW.md
iteration: 1
findings_in_scope: 5
fixed: 5
skipped: 0
status: all_fixed
---

# Phase 02: Code Review Fix Report

**Fixed at:** 2026-08-24T21:45:32Z
**Source review:** .planning/phases/02-tunnel-up/02-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 5 (1 critical, 4 warning)
- Fixed: 5
- Skipped: 0

Each fix was verified against the current source (all cited line numbers
matched the review's description exactly, no drift), given a dedicated
regression test that was confirmed to fail on the pre-fix code and pass
post-fix, and validated with `go build ./...`, `go vet ./...`, and
`go test -race -count=1 ./...` before being committed. The Docker-based
interop suite (`go test -tags interop -run TestInteropScenarios
./test/interop/...`) was also run to completion after every fix and again
after all five fixes were applied, confirming real client-to-server ping
delivery and the full handshake/PUSH_REQUEST/data-channel flow against an
unmodified OpenVPN 2.6 client remain intact.

## Fixed Issues

### CR-01: Data-channel ping keepalives from the client are silently dropped by an over-broad minimum-datagram-length gate

**Files modified:** `ovpn.go`, `ovpn_test.go`
**Commit:** `cf88d33`
**Applied fix:** Moved the tls-crypt-derived `minDatagramSize` (49-byte)
length check in `Server.handleDatagram` to run *after* the
`P_DATA_V1`/`P_DATA_V2` opcode branch instead of before it, so data-channel
packets are only gated by `handleDataDatagram`/`datachan.Wrapper.Open`'s
own, correctly-sized minimum (24 bytes: header + tag), not the
control-channel's tls-crypt prefix minimum. Added
`TestHandleDatagramAcceptsShortDataChannelPing`, which drives a real
40-byte sealed client ping through the full `Server.handleDatagram` accept
path and proves it reached `Wrapper.Open` (by asserting a second `Open` of
the identical bytes returns `ErrReplay`, only possible if the first
delivery already advanced the replay window). Confirmed this test fails
without the fix (`ErrPingAbsorbed` instead of `ErrReplay`, since the
gate silently dropped the packet) and passes with it. Also confirmed via
`go test -tags interop -run TestInteropScenarios ./test/interop/...`
(Docker-based, real OpenVPN 2.6 client) that all three scenarios
(clean-small, clean-large, lossy-large) pass with the fix applied — the one
`lossy-large` failure observed during an earlier interop run was confirmed
to be a pre-existing, unrelated flake in the Docker network-loss simulation
(reproduced identically on the pre-fix code, then passed on a rerun of both
pre-fix and post-fix code).

### WR-01: `buildPushReply`'s netmask is not normalized the way `newIPPool` normalizes the same `Config.Network`

**Files modified:** `ippool.go`, `push.go`, `push_test.go`
**Commit:** `de73298`
**Applied fix:** Extracted the existing 16-byte-mask normalization logic
out of `newIPPool` into a shared `normalizeIPv4Mask` helper in `ippool.go`,
and updated `buildPushReply` in `push.go` to call it before formatting the
netmask string, instead of re-deriving the netmask directly from
`network.Mask`. Added `TestPushReplyNormalizesSixteenByteMask`, which
constructs a `*net.IPNet` with a manually-forced 16-byte `Mask` (the exact
shape `newIPPool`'s own doc comment defends against) and asserts the
`PUSH_REPLY` `ifconfig` line contains the normalized dotted-decimal
netmask rather than the raw 16-byte IPv6-shaped mask. Confirmed this test
fails without the fix (`ifconfig 10.8.0.2 ::ffff:ff00` instead of
`255.255.255.0`) and passes with it.

### WR-02: `datachan.Wrapper.Open` can leave authenticated plaintext in the caller's `dst` buffer on a replay rejection

**Files modified:** `internal/datachan/datachan.go`, `internal/datachan/datachan_test.go`
**Commit:** `6bf164f`
**Applied fix:** Changed `Wrapper.Open` to decrypt into a fresh scratch
buffer (`w.decryptAEAD.Open(nil, ...)`) rather than directly into the
caller's `dst`, and to only `append` the decrypted plaintext onto `dst`
after both the AEAD tag check and the replay-window check have succeeded.
Added `TestOpenReplayRejectionDoesNotLeakPlaintextIntoDst`, which opens a
sealed packet once (to mark the replay window), then re-opens the
identical bytes with a `dst` slice that has spare backing capacity
pre-filled with a sentinel byte pattern, and asserts the backing array is
byte-for-byte unchanged after the (correctly rejected) replay attempt.
Confirmed this test fails without the fix (the backing array is
overwritten with the successfully-decrypted plaintext even though the
call returns `ErrReplay`) and passes with it.

### WR-03: `Session.assignedIP`/`peerID`/`dataWrapper` are read and written without synchronization by two goroutines that can race

**Files modified:** `session.go`, `ovpn.go`, `ovpn_test.go`
**Commit:** `31f27c0`
**Applied fix:** Added a `Session.mu sync.Mutex` field guarding
`assignedIP`, `peerID`, and `dataWrapper`, and updated every write
(`ovpn.go`'s `performPushExchange`) and read (`session.go`'s `Close`,
`AssignedIP`, `PeerID`) of those three fields to acquire it. Added
`TestPerformPushExchangeFieldWritesRaceSafeAgainstClose`, which mirrors
`performPushExchange`'s exact field-write sequence in a goroutine racing
directly against the real `Session.Close`, run under `go test -race`.
Confirmed this test reliably trips Go's race detector when `Close`'s reads
are reverted to be unguarded (manually verified by temporarily reverting
just that one function, running the test, observing the `WARNING: DATA
RACE` report pointing at the exact fields, then restoring the fix) and
passes cleanly with the fix in place.

**Status note:** this finding involves concurrency/lock-discipline
reasoning rather than a simple logic condition; the fix was verified with
`go test -race` (which is a strong, mechanical signal for this class of
bug, not just a syntax check) in addition to the standard build/vet/test
gates, but a human should still confirm the mutex's scope (guarding
exactly `assignedIP`/`peerID`/`dataWrapper` and their `Close`/`AssignedIP`/
`PeerID` use sites, per the review's own fix suggestion) is what was
intended before this phase proceeds to verification.

### WR-04: `Session.Close` releases pool state before removing the routing-table entry that still points at it

**Files modified:** `session.go`, `ovpn_test.go`
**Commit:** `26fbc5a`
**Applied fix:** Reversed the order of the two cleanup steps inside
`Session.Close`'s `stopOnce.Do` block: the `Server.dataSessions` routing
entry is now removed *before* the tunnel IP/peer-id is released back to
`Server.pool`, so a newly allocated session can never observe or be
shadowed by a routing-table entry that still belongs to the session being
torn down. Added `TestCloseRemovesRoutingEntryBeforeReleasingPeerID`,
which deterministically (not timing-dependent — see the test's own doc
comment for why holding `srv.mu` across the check window turns this into
a structural fact rather than a race) proves that a peer-id can never
become allocatable again while `dataSessions[peerID]` still points at the
closing session. Confirmed this test fails reliably (100% reproduction
across repeated runs) without the fix and passes reliably with it.

## Skipped Issues

None — all findings were fixed.

---

_Fixed: 2026-08-24T21:45:32Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
