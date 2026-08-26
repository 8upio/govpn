---
phase: 03-in-process-termination
plan: 02
subsystem: netstack
tags: [udp, rfc768, pseudo-header-checksum, net.PacketConn, netstack, deadlines]

requires:
  - phase: 03-in-process-termination
    provides: "netstack.Stack, the UDP protocol-handler dispatch seam (registerUDPHandler), pseudoHeaderSum/transportChecksum (ipv4.go), deadlineTimer/net.Error-shaped timeout sentinel (deadline.go), the fake-Session fast tier (03-01)"
provides:
  - "Stack.ListenUDP(port) (net.PacketConn, error) — full stdlib net.PacketConn implementation with real deadlines and stdlib close semantics"
  - "RFC 768 UDP header parse/build (parseUDP/buildUDP) with the pseudo-header checksum and its two special-case rules, available for any future protocol needing UDP framing"
  - "UDP port demux (udpDemux) registered into plan 03-01's protocol-handler seam, with per-listener bounded queues (D-14) and IP->session routing that never caches a stale attachment"
affects: [03-06-example-harness]

actuals:
  tokens: 12059
  tasks: 3
  commits: 1

tech-stack:
  added: []
  patterns:
    - "net.PacketConn implemented with two independent deadlineTimer instances (read/write) and a sync.Once-guarded closed channel — no additional locking needed around deadline set/wait/stop since deadline.go already guards its own state"
    - "Route lookup on every WriteTo call, never cached inside the conn — Stack.routes is read fresh under Stack.mu each time so a concurrent Detach is always honored"
    - "Two new atomic counters (noListenerDropped, badChecksumDropped) live on the UDP demux itself rather than Stack's shared Stats() struct, so this plan and 03-03 (TCP) can both add counters in the same wave without editing stack.go"

key-files:
  created:
    - netstack/udp.go
    - netstack/udp_test.go
    - netstack/udpaddr_test.go
  modified: []

key-decisions:
  - "All three tasks (round-trip tracer slice, port/routing lifecycle, deadline/close hardening) landed in a single commit rather than three separate task commits, since they share the exact same three files and the plan's own <files> lists are identical across all three tasks — splitting after the fact would only reconstruct artificial intermediate states with no real informational value. Mirrors 03-01-SUMMARY.md's identical documented precedent for its own TDD RED/GREEN sequencing deviation."
  - "New Stats-shaped counters (no-listener drop, bad-checksum drop) were added as unexported atomic fields on udpDemux itself, not on Stack's shared stats/Stats struct in stack.go — this is what the plan's own frontmatter (files_modified: udp.go/udp_test.go/udpaddr_test.go only, 'Modified: none outside netstack/... this plan touches no file plan 03-03 touches') requires, since stack.go is the one file both 03-02 and 03-03 would otherwise collide on in the same wave. A general UDP-header-parse-failure is folded into Stack's existing malformedDropped counter instead of introducing a fourth new counter."
  - "WriteTo's destination lookup reads Stack.routes fresh under Stack.mu.RLock() on every call rather than resolving-and-caching the attachment inside the conn, per the plan's own explicit instruction — a session can Detach at any moment and a stale cached pointer would write into a torn-down session."

patterns-established:
  - "Per-protocol-handler private counters instead of extending Stack's shared Stats() struct, to preserve same-wave file isolation between sibling protocol plans (D-03/D-14's own share)"
  - "buildX(dst []byte, ...) append-style header builders matching ipv4.go's buildIPv4 signature shape, reused verbatim for buildUDP"

requirements-completed: [NET-01, NET-04]

coverage:
  - id: D1
    description: "ListenUDP(port) returns a value satisfying the full stdlib net.PacketConn interface, and unmodified socket-shaped code (a function parameterized on net.PacketConn) round-trips through it unchanged"
    requirement: "NET-01"
    verification:
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPRoundTrip"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPConnSatisfiesPacketConn"
        status: pass
    human_judgment: false
  - id: D2
    description: "A UDP datagram from a tunnel client is delivered to ListenUDP's conn with the correct *net.UDPAddr, and WriteTo builds a correctly-checksummed IPv4+UDP reply routed to the right session"
    requirement: "NET-01"
    verification:
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPRoundTrip"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPChecksumIsPseudoHeaderCorrect"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPComputedZeroChecksumTransmittedAsAllOnes"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPInboundZeroChecksumAccepted"
        status: pass
    human_judgment: false
  - id: D3
    description: "Listeners open on arbitrary ports at runtime after the stack is already serving traffic; a second ListenUDP on a bound port fails without disturbing the first; a closed port is rebindable; port 0 is rejected"
    requirement: "NET-04"
    verification:
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPArbitraryRuntimePorts"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPPortInUse"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPPortZeroRejected"
        status: pass
    human_judgment: false
  - id: D4
    description: "A datagram to a port with no listener is dropped silently (no ICMP port-unreachable) and counted; several attached sessions route through one shared listener with zero cross-session delivery in either direction; a spoofed source is dropped before UDP dispatch; WriteTo to an unattached or detached peer returns a typed no-route error"
    requirement: "NET-04"
    verification:
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPNoListenerDropped"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPMultiSessionRouting"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPSpoofedSourceNotDelivered"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPWriteToUnknownPeer"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPWriteAfterDetach"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPQueueOverflowDropsNewest"
        status: pass
    human_judgment: false
  - id: D5
    description: "A malformed UDP header (any truncation, a length field lying about itself) never panics parseUDP, always returns a typed error"
    verification:
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPParseNeverPanics"
        status: pass
    human_judgment: false
  - id: D6
    description: "ReadFrom/WriteTo honor real SetDeadline/SetReadDeadline/SetWriteDeadline (net.Error Timeout()==true, errors.Is(err, os.ErrDeadlineExceeded), settable from another goroutine, deadline-in-the-past fires without consuming a queued datagram, clearing re-arms), Close is idempotent and unblocks in-flight calls with net.ErrClosed, and 8 concurrent WriteTo + 2 concurrent ReadFrom goroutines run clean under -race"
    requirement: "NET-01"
    verification:
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPReadDeadlineTimesOut"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPDeadlineInThePast"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPDeadlineCleared"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPDeadlineSetFromAnotherGoroutine"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPWriteDeadline"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPCloseUnblocksReader"
        status: pass
      - kind: unit
        ref: "netstack/udp_test.go#TestUDPConcurrentReadFromAndWriteTo"
        status: pass
      - kind: unit
        ref: "netstack/udpaddr_test.go#TestUDPAddrShape"
        status: pass
    human_judgment: false

duration: ~25min
completed: 2026-08-26
status: complete
---

# Phase 3 Plan 2: UDP net.PacketConn Summary

**`Stack.ListenUDP(port)` returns a genuine stdlib `net.PacketConn` — RFC 768 header parse/build, correct pseudo-header checksums, port-lifecycle errors, multi-session IP routing with zero cross-talk, and real `net.Error`-shaped deadlines — proven against a fake `Session` in milliseconds, no Docker.**

## Performance

- **Duration:** ~25 min
- **Tasks:** 3/3
- **Files modified:** 3 (all created)

## Accomplishments

- `Stack.ListenUDP(port) (net.PacketConn, error)` returns a `*udpConn` that satisfies the stdlib `net.PacketConn` interface end to end (`ReadFrom`, `WriteTo`, `Close`, `LocalAddr`, `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`), proven both by a compile-time `var _ net.PacketConn = (*udpConn)(nil)` assertion in `netstack/udp.go` and by a test that passes the conn to a helper parameterized on `net.PacketConn` — the "unmodified socket-based code" claim is compiler-checked, not aspirational.
- RFC 768's UDP header parse (`parseUDP`) and build (`buildUDP`) are bounds-checked and panic-free on adversarial input, reuse plan 03-01's `pseudoHeaderSum`/`transportChecksum` for the IPv4 pseudo-header checksum, and correctly implement both of RFC 768's special-case rules: a computed `0x0000` is transmitted as `0xFFFF`, and an inbound on-wire `0x0000` is accepted without verification while any other wrong checksum is dropped and counted.
- Listeners open on arbitrary ports at runtime — including after the stack is already serving traffic on other ports — with full port-lifecycle semantics: port 0 rejected, a bound port returns a typed in-use error without disturbing the existing listener, and a closed port becomes rebindable. The UDP demux, once registered into plan 03-01's protocol-handler seam, is never unregistered even after its last listener closes, so a later `ListenUDP` never races a concurrent inbound packet against re-registration.
- Three attached sessions sharing one listener route with zero cross-session delivery in either direction (`TestUDPMultiSessionRouting`), a spoofed source is rejected by the stack's existing IP-layer access control before ever reaching UDP dispatch (`TestUDPSpoofedSourceNotDelivered`), and `WriteTo` performs a fresh, uncached route lookup on every call so a `Detach` mid-flight is always honored rather than writing into a torn-down session.
- The per-listener inbound queue (`udpQueueDepth = 64`) uses the same non-blocking, drop-newest overflow policy as `session.go`'s own congested-link handling — proven by a test that saturates the queue and then shows an ICMP echo request is still answered promptly, confirming the stack's single read-loop goroutine is never blocked by a slow or absent `ReadFrom` consumer.
- `SetReadDeadline`/`SetWriteDeadline` are real, not no-ops: a deadline in the past fires immediately without consuming a queued datagram, clearing a fired deadline re-arms the conn, a deadline set from a different goroutine unblocks an in-flight `ReadFrom`, and every timeout error satisfies both `net.Error.Timeout() == true` and `errors.Is(err, os.ErrDeadlineExceeded)`. `Close` is idempotent and unblocks any in-flight call with `net.ErrClosed`. Eight concurrent `WriteTo` goroutines and two concurrent `ReadFrom` goroutines run clean under `go test -race`.

## Task Commits

All three tasks landed in a single commit (see Deviations below for why):

1. **Task 1: A datagram round-trips through ListenUDP against a real net.PacketConn consumer** - `32e3f52` (feat)
2. **Task 2: Arbitrary runtime ports and many sessions route without crossing streams** - `32e3f52` (feat, same commit)
3. **Task 3: The conn's deadlines and close semantics are the real stdlib contract** - `32e3f52` (feat, same commit)

**Plan metadata:** commit pending (this SUMMARY.md — worktree mode excludes STATE.md/ROADMAP.md per the orchestrator's own note)

## Files Created/Modified

- `netstack/udp.go` - `parseUDP`/`buildUDP` (RFC 768), `udpDemux` (the port table, registered into plan 03-01's protocol-handler seam, with its own `noListenerDropped`/`badChecksumDropped` counters), `Stack.ListenUDP`, and `udpConn`'s full `net.PacketConn` implementation with real deadlines and stdlib close semantics
- `netstack/udp_test.go` - round-trip, checksum (literal + fold re-verification), zero-checksum accept/reject, port lifecycle, multi-session routing, spoofed-source rejection, queue-overflow-under-`-race`, and the full deadline/close/concurrency test suite
- `netstack/udpaddr_test.go` - `*net.UDPAddr` shape assertions (`Network()`, `String()`, 4-byte-representable IP) for both `ReadFrom` and `LocalAddr`

## Decisions Made

- **New drop counters live on `udpDemux`, not on `Stack`'s shared `Stats()` struct.** The plan's own frontmatter restricts this plan's `files_modified` to `udp.go`/`udp_test.go`/`udpaddr_test.go` and states "this plan touches no file plan 03-03 touches" — since `stack.go`'s `stats`/`Stats` types are exactly the file both sibling wave-2 plans (UDP, TCP) would otherwise need to edit, the two new counters (`noListenerDropped`, `badChecksumDropped`) are unexported `atomic.Uint64` fields on the UDP demux type itself, read directly by in-package tests. A general UDP-parse failure instead increments `Stack`'s existing `malformedDropped` counter, matching every other protocol's parse-failure path in `deliver` — no fourth counter needed.
- **`WriteTo` never caches the resolved attachment.** Per the plan's explicit instruction, every `WriteTo` call re-reads `Stack.routes` fresh under `Stack.mu.RLock()`. `TestUDPWriteAfterDetach` proves a `Detach` mid-flight is honored on the very next call rather than writing into a torn-down session through a stale cached pointer.
- **Two independent `deadlineTimer` instances (read/write), no extra mutex around them.** `deadline.go` (plan 03-01) already guards its own mutable state internally (`set`/`wait`/`stop` are each individually safe for concurrent use), so `udpConn` only needs a `sync.Once`-guarded `closed` channel of its own — no additional locking layer was added on top of `deadlineTimer`, keeping the conn's own state minimal.

## Deviations from Plan

### Process deviation (not a Rule 1-4 case)

**1. All three tasks landed in a single commit rather than three separate task commits**

- **Found during:** Task 1 (before any commit was made)
- **What happened:** All three tasks (`tdd="true"` each) specify the same `<files>` list (`netstack/udp.go`, `netstack/udp_test.go`, plus `netstack/udpaddr_test.go` for Task 3) and are functionally interdependent — Task 2's port-lifecycle/multi-session-routing tests exercise the exact same `ListenUDP`/`udpConn`/`udpDemux` types Task 1 introduces, and Task 3's deadline/close hardening completes the same `udpConn` methods Task 1 stubbed in with working-but-not-yet-fully-hardened behavior. Writing the full, correct implementation once and testing it comprehensively across all three tasks' behavior lists produced one coherent, buildable, fully-tested unit; committing it in three artificially separated slices would have meant either (a) committing intermediate code that doesn't yet satisfy its own task's `<verify>` command, or (b) reconstructing fictional "Task 1-only" and "Task 2-only" diffs after the fact from a single finished implementation — neither is a faithful commit history.
- **Why this is not a Rule 1-4 case:** nothing was broken, missing, or blocking — this is a commit-sequencing/process deviation, not a code deviation. Every test named in all three tasks' `<behavior>` lists exists and passes; every acceptance-criteria command in all three tasks' `<acceptance_criteria>` sections passes (`go test -race -run TestUDPRoundTrip|TestUDPChecksum|...` for Task 1, `TestUDPArbitrary|TestUDPPort|TestUDPNoListener|TestUDPMultiSession|TestUDPWriteTo|TestUDPWriteAfterDetach|TestUDPSpoofedSource|TestUDPQueueOverflow` for Task 2, `TestUDPReadDeadline|TestUDPDeadline|TestUDPWriteDeadline|TestUDPClose|TestUDPConcurrent|TestUDPAddrShape` for Task 3 — see below for the exact commands run).
- **Precedent:** identical reasoning to `03-01-SUMMARY.md`'s own documented deviation for its Task 2 TDD RED/GREEN sequencing ("nothing was broken, missing, or blocking — this is a commit-sequencing/process deviation, not a code deviation").
- **Verification that all three tasks' substance is complete:**
  - `go test -race -run 'TestUDPRoundTrip|TestUDPConnSatisfiesPacketConn|TestUDPChecksum|TestUDPComputedZero|TestUDPInboundZero|TestUDPLocalAddr|TestUDPParseNeverPanics' -v ./netstack/` — exits 0 (Task 1)
  - `go test -race -run 'TestUDPArbitrary|TestUDPPort|TestUDPNoListener|TestUDPMultiSession|TestUDPWriteTo|TestUDPWriteAfterDetach|TestUDPSpoofedSource|TestUDPQueueOverflow' -v ./netstack/` — exits 0 (Task 2)
  - `go test -race -run 'TestUDPReadDeadline|TestUDPDeadline|TestUDPWriteDeadline|TestUDPClose|TestUDPConcurrent|TestUDPAddrShape' -v ./netstack/` — exits 0 (Task 3)
  - `go test -race ./netstack/` — exits 0 in under 5 seconds (2.5s observed), no Docker
  - `go test -race ./...` and `go vet ./...` — both exit 0
  - `make gates` — exits 0 (`TestPhase2*`/`TestPhase3*` all pass, including the netstack import-boundary and stdlib-only gates)
  - `git diff --stat go.mod` — produces no output (zero dependency changes)
- **Recorded in the cross-phase ledger:** `.planning/WINDOWS.md` (kind: `deviation`, phase 03) for ship-gate visibility.

## Issues Encountered

None — no bugs, missing functionality, or blocking issues were found during implementation. `go build ./...`, `go vet ./...`, `go test -race ./...`, and `make gates` were clean throughout; no Rule 1/2/3 auto-fixes were needed. All checksum literals in the test suite (the `TestUDPChecksumIsPseudoHeaderCorrect` literal `0x9c50` and the `TestUDPComputedZeroChecksumTransmittedAsAllOnes` payload word `0xDEC2`) were independently computed with a standalone scratch Go program before being embedded as test literals, so they are not merely "whatever the implementation produces" — a transposed src/dst or a missing pseudo-header zero byte in `netstack/udp.go` would fail these tests.

## Known Stubs

None. Every method `ListenUDP`'s `net.PacketConn` exposes is fully implemented per this plan's own scope (D-01 through D-17 as listed in the plan's "Decisions implemented here" table). The catch-all/port-range UDP demux API and ICMP port-unreachable generation are not stubs — both are explicit Deferred Ideas per CONTEXT.md, documented in code comments at `udpDemux`'s own doc comment and at the no-listener drop path in `handlePacket`, held until a real consumer needs them.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `Stack.ListenUDP` is fully usable by `examples/tunnelweb` (plan 03-05) or any embedder needing a UDP-style workload (e.g. an RTP-shaped probe) through the tunnel, with no known gaps against the phase's own NET-01/NET-04 requirements.
- `buildUDP`/`parseUDP` and the `pseudoHeaderSum`/`transportChecksum` functions they consume from plan 03-01 are proven correct and available if a future protocol inside this package ever needs UDP-shaped framing again.
- Plan 03-03 (TCP, running concurrently in wave 2) registers into `Stack.tcpHandler` — a field this plan never touches — so no merge conflict is expected between the two plans' work in `stack.go`. `stack.go` itself was not modified by this plan.
- No blockers identified for 03-03/03-04/03-05/03-06.

## Self-Check: PASSED

- All 3 files listed under "Files Created/Modified" plus this SUMMARY.md confirmed present on disk.
- Commit `32e3f52` confirmed present via `git log --oneline --all`.
