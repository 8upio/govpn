---
phase: quick-260908-fva
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - netstack/ipv4.go
  - netstack/reassembly.go
  - netstack/stack.go
  - netstack/tcp_timer.go
  - netstack/tcp_listener.go
  - netstack/udp.go
  - netstack/ipv4_test.go
  - netstack/reassembly_test.go
  - netstack/stack_test.go
  - netstack/fakesession_test.go
  - docs/NETSTACK.md
autonomous: true
requirements: [QUICK-260908-fva]

estimate:
  tokens: 240000
  raw_tokens: 120000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "A client that sends a large SIP/UDP datagram as 3 IPv4 fragments through the tunnel gets it delivered whole to the udpConn's ReadFrom, in any fragment arrival order."
    - "A reply larger than the configured MTU leaves the stack as correctly-offset, correctly-flagged, correctly-checksummed IPv4 fragments that a real IP stack reassembles."
    - "One session's fragment traffic can never consume more than 16 buffers / 256 KiB / 30 s of stack state, and a fragment whose source IP is not the sending session's own IP never allocates any."
    - "Detaching or closing a session with a half-filled reassembly buffer frees that state and never panics."
    - "The TCP MSS the stack advertises follows the configured MTU, so a full TCP segment never has to be fragmented."
  artifacts:
    - netstack/reassembly.go
    - netstack/reassembly_test.go
    - "netstack/ipv4.go: fragment fields on ipv4Header, geometry validation in parseIPv4, fragmentIPv4"
    - "netstack/stack.go: WithMTU/MTU()/ErrInvalidMTU, deliver/dispatch split, outbound fragmentation, 4 new Stats fields"
    - "docs/NETSTACK.md: Fragmentation and reassembly section"
  key_links:
    - "deliver -> reassembler.add: the source-IP ACL runs BEFORE add, so spoofed fragments never allocate buffer state."
    - "attachment.stop() -> reasm.discardAll(): the single teardown seam covering Detach, Close and detachAttachment."
    - "Stack.mtu -> maxSegmentSize() -> SYN-ACK/retransmit MSS: TCP stays unfragmented by construction."
    - "Stack.mtu -> writePacket -> fragmentIPv4 -> a.sess.Write: the only outbound fragmentation path."
---

<objective>
Replace the netstack's blanket "drop every IPv4 fragment" policy with RFC 815 hole-list
reassembly bounded per session, and add outbound fragmentation above a configurable MTU.

Purpose: the Voxio use case (Snom phones, SIP/RTP over UDP inside the tunnel) produces
exactly the traffic that fragments in practice — large SIP INVITEs over UDP. Today
`parseIPv4` returns `errFragmented` and `deliver` counts `FragmentsDropped`, so those
INVITEs are silently lost; outbound, `writePacket` writes every packet unchanged no matter
how large it is.

Scope is strictly **in-tunnel traffic** (the decrypted IP packets of a session). The outer
UDP transport and the control-channel fragmentation in `internal/ctrlconn` are untouched.

Output: `netstack/reassembly.go` (new), fragment support in `netstack/ipv4.go`, MTU option +
reassembly/fragmentation integration in `netstack/stack.go`, MTU-derived TCP MSS, and the
`docs/NETSTACK.md` updates.

This plan implements an already-approved design. Every constant value, the permissive RFC 815
overlap policy, the fixed 30 s timeout, the fixed per-session bounds, and the `WithMTU`
option shape are settled decisions — implement them as written, do not re-litigate them.
</objective>

<execution_context>
@$HOME/.claude/gsd-core/workflows/execute-plan.md
@$HOME/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.claude/CLAUDE.md

@netstack/ipv4.go
@netstack/stack.go
@netstack/clock.go
@netstack/udp.go
@netstack/fakesession_test.go
@docs/NETSTACK.md
</context>

<constraints>
Standing rules for every task below — violating one of these fails the task even if the tests pass:

- `netstack` stays stdlib-only and never imports the core module (`github.com/8upio/govpn`).
  `gates_test.go`'s `TestPhase3NetstackDoesNotImportCoreLibrary` enforces this; `make test`
  runs it.
- No direct `time.Now`, `time.NewTimer` or `time.Sleep` in new non-test code. Wall time
  enters the reassembler only as the `now time.Time` argument `deliver` passes from
  `s.clock.Now()` (`netstack/clock.go`). Importing `time` for the `time.Time`/`time.Duration`
  types is expected and fine.
- Every silent drop increments exactly one stats counter.
- Parsing checks lengths before every field access and must never panic on adversarial input
  (the discipline `parseIPv4`'s existing doc comment describes).
- `Stats` stays additively compatible: existing field names keep their names and positions.
- Each of the three tasks is independently committable: after each one, `make test` is green.
</constraints>

<tasks>

<task type="tracer" tdd="true">
  <name>Task 1: IPv4 fragment parsing, fragmentIPv4, and the RFC 815 reassembler</name>
  <files>netstack/ipv4.go, netstack/reassembly.go, netstack/stack.go, netstack/ipv4_test.go, netstack/reassembly_test.go, netstack/fakesession_test.go</files>

  <behavior>
    - parseIPv4 on a non-fragment: id/moreFragments/fragOffset populated, isFragment() false, existing callers unaffected.
    - parseIPv4 on a fragment: fragOffset reported in BYTES (field value x 8), isFragment() true.
    - parseIPv4 geometry: errBadFragment for a fragment with an empty payload, for MF=1 with payload length not a multiple of 8, and for fragOffset+payloadLen > 65535.
    - fragmentIPv4: a 4000-byte datagram at MTU 1500 becomes 3 fragments with offsets 0/1480/2960, MF 1/1/0, one shared ID, each <= MTU, each with a header checksum that folds to zero, non-final fragment payloads multiples of 8.
    - reassembler.add: in-order, reverse-order and interleaved fragment sets all produce the identical original datagram with flags/offset zeroed and Total Length rewritten.
    - reassembler.add: byte-identical duplicate -> reasmDuplicate and the datagram still completes afterwards.
    - reassembler.add: an overlapping fragment is accepted, its bytes win, the datagram completes.
    - reassembler.add: a second MF=0 fragment declaring a different total length, or data beyond a known end, -> reasmConflict, buffer dropped, accounted bytes back to zero.
    - reassembler.add: buffers past 16 keys -> reasmBoundExceeded; bytes past 256 KiB -> reasmBoundExceeded; add after discardAll -> reasmClosed; a buffer older than 30 s is expired lazily by the next add.
  </behavior>

  <action>
**1a. `netstack/ipv4.go` — fragment fields and geometry validation.**

Add to the constant block, each with a citation comment in the file's existing style:
`flagDontFragment = 0x4000` (the DF bit of RFC 791 §3.1's 3-bit Flags field, sharing the
16-bit word with MF and the fragment offset; this stack never sets it on packets it builds)
and `maxIPv4Datagram = 65535` (the largest value RFC 791 §3.1's 16-bit Total Length field can
express).

Delete the `errFragmented` sentinel. Add `errBadFragment = errors.New("netstack: IPv4
fragment geometry is invalid")` in its place.

Add three fields to `ipv4Header`: `id uint16`, `moreFragments bool`, `fragOffset int`.
Document on `fragOffset` that it is in BYTES — the on-wire 13-bit field value multiplied by 8
(RFC 791 §3.1 counts the offset in 8-byte units) — so no call site ever has to remember the
scaling. Add `func (h ipv4Header) isFragment() bool { return h.moreFragments || h.fragOffset != 0 }`.

Rewrite step 5 of `parseIPv4` (currently the `errFragmented` return) into: read
`id := binary.BigEndian.Uint16(pkt[4:6])`, read `flagsFragOffset := binary.BigEndian.Uint16(pkt[6:8])`,
derive `moreFragments := flagsFragOffset&flagMoreFragments != 0` and
`fragOffset := int(flagsFragOffset&fragOffsetMask) * 8`. If and only if the packet is a
fragment (MF set or offset non-zero), validate its geometry with `payloadLen := totalLen - ihl`
and return `errBadFragment` when: `payloadLen == 0`; or `moreFragments && payloadLen%8 != 0`
(RFC 791 §3.2 requires every non-final fragment's data length to be a multiple of 8); or
`fragOffset+payloadLen > maxIPv4Datagram`. Populate the three new header fields on every
parse, fragment or not. Update `parseIPv4`'s numbered doc comment so step 5 describes this
validation instead of the old blanket rejection, and note that because `writePacket` re-parses
what it is about to send, this same check also guarantees the stack can never emit a
geometrically invalid fragment.

Update `buildIPv4`'s doc comment: it still emits identification 0 and a zero flags/offset
word, and that is correct because identification only has to be unique per (src, dst,
protocol) within a reassembly window (RFC 6864 §4) — an ID is assigned only when
`writePacket` actually fragments. Do not carry forward the old claim about outbound
fragmentation being impossible.

**1b. `netstack/ipv4.go` — `fragmentIPv4`.**

Add the pure function `func fragmentIPv4(hdr ipv4Header, pkt []byte, mtu int, id uint16) [][]byte`.
It splits an already-parsed, already-valid datagram into MTU-sized fragments and allocates a
fresh slice per fragment (callers hand these straight to `Session.Write`). Procedure:

1. `maxData := (mtu - hdr.ihl) &^ 7` — the largest payload chunk that fits the MTU, rounded
   down to a multiple of 8 so every non-final fragment is automatically 8-aligned as RFC 791
   §3.2 requires. Defensively return `nil` if `maxData <= 0`; document that this is
   unreachable given `minMTU` 576 and `maxIPv4HeaderLen` 60 (worst case 516, floored to 512).
2. `payload := pkt[hdr.payloadOff:hdr.totalLen]`.
3. Walk `payload` in `maxData`-sized chunks, tracking the byte offset `off` of each chunk.
   For each chunk, allocate `hdr.ihl + len(chunk)` bytes, `copy` the FULL `hdr.ihl` header
   bytes from `pkt[:hdr.ihl]` (defensively including IP options — this stack generates none,
   but copying the parsed header length rather than a hardcoded 20 keeps the function honest
   if one ever appears), then `copy` the chunk after it.
4. Per fragment, patch the copied header: Total Length (bytes 2:4) = `ihl + len(chunk)`;
   Identification (bytes 4:6) = `id`; flags/fragment-offset (bytes 6:8) = `uint16(off/8)`,
   OR'd with `flagMoreFragments` for every chunk except the last (DF is deliberately never
   set — see `flagDontFragment`'s comment).
5. Zero the checksum field (bytes 10:12) and recompute it over the `ihl` header bytes with
   `internetChecksum`.

Document that the input's own header checksum is irrelevant here because every fragment gets
a freshly computed one.

**1c. `netstack/reassembly.go` (new file).**

Package `netstack`. File header comment in the citation style of `tcp_timer.go`: this file
implements RFC 815's hole-descriptor reassembly algorithm, bounded per attached session.
State it explicitly that the overlap policy is RFC 815 permissive — overlapping fragments are
accepted and newer bytes overwrite buffered ones — and why that is safe here: only the session
itself can write into its own buffer (the source-IP ACL in `deliver` runs before `add`), there
is no middlebox to smuggle a differing view past, and the geometry checks in `parseIPv4` plus
Go's own bounds checking rule out the Teardrop class of attack. Only genuine inconsistencies
(a second MF=0 fragment declaring a different total length; data beyond an already-known
total length) discard the datagram.

Constants, each with the citation comment its value comes from:

- `maxReassemblyBuffersPerSession = 16` — same order of magnitude as the existing per-session
  TCP caps `maxHalfOpenPerSession` / `maxLiveConnsPerSession`.
- `maxReassemblyBytesPerSession = 256 * 1024` — 4 maximum-size datagrams; per authenticated
  session, not system-wide.
- `reassemblyTimeout = 30 * time.Second` — Linux's own `ipfrag_time` default. Note in the
  comment that this is a deliberate deviation from RFC 1122 §3.3.2's 60-120 s guidance,
  chosen to bound state, and that it is fixed from the first fragment and NEVER extended by
  later fragments, so an attacker cannot keep a buffer alive indefinitely by dripping
  fragments into it.
- `holeOpenEnd = maxIPv4Datagram - 1` — the sentinel `last` value of the initial hole,
  meaning "end unknown", used until an MF=0 fragment reveals the real total length.

Types:

- `type reassemblyKey struct { src, dst netip.Addr; protocol uint8; id uint16 }` — RFC 791's
  own reassembly identity.
- `type hole struct { first, last int }` — inclusive byte offsets.
- `type reassemblyBuffer struct { header []byte; data []byte; holes []hole; totalLen int; expires time.Time }`
  where `header` is a copy of the offset-0 fragment's header (`ihl` bytes), nil until that
  fragment arrives; `data` has `len` equal to the highest byte end seen so far, and it is
  THAT length that is charged against the byte cap; `holes` is kept sorted and disjoint,
  starting as `[]hole{{0, holeOpenEnd}}`; `totalLen` is -1 until an MF=0 fragment arrives.
- `type reassembler struct { mu sync.Mutex; bufs map[reassemblyKey]*reassemblyBuffer; bytes int; closed bool }`
  with the map created lazily on first `add`, so an attachment that never sees a fragment
  allocates nothing.
- `type reasmOutcome int` with `reasmBuffered`, `reasmComplete`, `reasmDuplicate`,
  `reasmConflict`, `reasmBoundExceeded`, `reasmClosed`.

The reassembler knows nothing about `Stack` or `stats` — `deliver` maps outcomes to counters.
Its entire API is:

- `func (r *reassembler) add(now time.Time, hdr ipv4Header, pkt []byte) (datagram []byte, out reasmOutcome, expired int)`
- `func (r *reassembler) discardAll()` — sets `closed`, drops every buffer, zeroes `bytes`.

`add` runs entirely under `r.mu`, in exactly this order:

1. If `r.closed`, return `reasmClosed`.
2. Lazy expiry: delete every buffer whose `expires` is not after `now` (`!now.Before(b.expires)`),
   returning its bytes to the budget and incrementing `expired` once per DATAGRAM dropped.
   No goroutine and no timer: with at most 16 entries an O(n) sweep per fragment is cheaper
   than a timer would be. Document that this means a session that sends one fragment and then
   goes quiet holds its bytes until its next fragment or its detach — bounded, and accepted.
3. `payload := pkt[hdr.payloadOff:hdr.totalLen]`, `first := hdr.fragOffset`,
   `last := first + len(payload) - 1`.
4. Look up the buffer by key. If absent and `len(r.bufs) >= maxReassemblyBuffersPerSession`,
   return `reasmBoundExceeded`. Otherwise create it with `holes = []hole{{0, holeOpenEnd}}`,
   `totalLen = -1`, `expires = now.Add(reassemblyTimeout)` (set once, never extended).
5. Consistency, before touching any data. If `b.totalLen >= 0 && last >= b.totalLen` it is a
   conflict. If `!hdr.moreFragments`: when `b.totalLen >= 0 && b.totalLen != last+1` it is a
   conflict (an identical value is just a duplicate of the final fragment and is fine);
   otherwise set `b.totalLen = last + 1`. A conflict deletes the WHOLE buffer, returns its
   bytes to the budget, and returns `reasmConflict`.
6. Byte cap. `grow := max(0, last+1-len(b.data))`; if `r.bytes+grow > maxReassemblyBytesPerSession`,
   return `reasmBoundExceeded` — the fragment is discarded, the buffer survives and will
   expire on its own. Charging by REACHED BUFFER LENGTH rather than by bytes actually written
   is deliberate: an 8-byte fragment at offset 65000 costs 65 KiB, so a sparse-fragment
   attacker is capped by the same number as a dense one.
7. RFC 815 steps 1-8, permissive. Iterate over every hole that intersects `[first, last]`
   and replace each with up to two remainder holes: `{h.first, first-1}` when `first > h.first`,
   and `{last+1, h.last}` when `last < h.last` AND `hdr.moreFragments`; when `!hdr.moreFragments`
   drop every hole beyond `last`, since this fragment defines the end of the datagram. If the
   fragment intersects NO hole at all, it is a pure duplicate: return `reasmDuplicate`, leaving
   the buffer intact. Copy the payload unconditionally either way — grow `b.data` to `last+1`
   if needed, then `copy(b.data[first:], payload)`, so newer bytes overwrite older ones (this
   is the permissive overlap policy). Keep `r.bytes` in step with the growth. When `first == 0`,
   store `b.header = append([]byte(nil), pkt[:hdr.ihl]...)`.
8. The datagram is complete exactly when `len(b.holes) == 0 && b.totalLen >= 0 && b.header != nil`.
   If `len(b.header)+b.totalLen > maxIPv4Datagram`, treat it as a conflict (only reachable
   with IP options). Otherwise materialize: `out := append(append([]byte(nil), b.header...), b.data[:b.totalLen]...)`,
   rewrite Total Length (bytes 2:4) to `len(out)`, zero the flags/fragment-offset word (bytes
   6:8) so MF, DF and the offset are all cleared and the result can never be fed back into the
   reassembler, zero the checksum field and recompute it over `out[:len(b.header)]` with
   `internetChecksum`. Delete the buffer, return its bytes to the budget, return
   `(out, reasmComplete, expired)`.

Anything that neither completes nor errors returns `reasmBuffered`.

**1d. `netstack/stack.go` — the minimal change that keeps the build green.**

`errFragmented` no longer exists and `parseIPv4` now accepts fragments, so `deliver` must not
fall through to the protocol switch with one. Make exactly two edits, nothing more (Task 2
owns the real integration): drop the `errors.Is(err, errFragmented)` branch so any parse error
counts `malformedDropped`; and, immediately AFTER the two ACL checks and BEFORE the
`payload := ...` line, add a guard that counts `s.stats.fragmentsDropped.Add(1)` and returns
when `hdr.isFragment()`. Placing it after the ACL is intentional — that is where Task 2's
reassembly branch goes, so the ordering is already correct.

**1e. Test helper — `netstack/fakesession_test.go`.**

Add `func buildFragmentForTest(src, dst netip.Addr, proto uint8, id uint16, offsetBytes int, mf bool, payload []byte) []byte`:
build the packet with `buildIPv4`, then patch bytes 4:6 to `id` and bytes 6:8 to
`uint16(offsetBytes/8)` OR `flagMoreFragments` when `mf`, zero the checksum field and
recompute it over the 20 header bytes. Every fragment test in this plan builds its fragments
through this one helper so no test hand-assembles byte arithmetic. (The approved design filed
this helper under the later task; it moves here because Task 1's own tests need it and each
task must stand alone.)

**1f. Tests.**

Extend `netstack/ipv4_test.go`: assert `parseIPv4` reports id, MF and a byte-scaled
`fragOffset` for a fragment; table-drive `errBadFragment` for offset+length over 65535, for
MF with a payload length not divisible by 8, and for MF with an empty payload; extend
`TestParseIPv4NeverPanics` with mutated identification / flags / fragment-offset words
(including the maximum offset 0x1FFF) so the new field reads are covered by the
never-panic sweep. Add the `fragmentIPv4` test from the behavior block, including a
round-trip: feed all three fragments back through `reassembler.add` and assert the recovered
datagram's payload is byte-identical to the original.

Create `netstack/reassembly_test.go` driving `add` directly with no `Stack`: in-order,
reverse and interleaved 3-fragment sets (asserting the result's flags/offset word is zero,
Total Length is correct, and the header checksum folds to zero); the duplicate case; the
permissive overlap case (new bytes win, datagram completes); both conflict cases (asserting
`len(r.bufs) == 0` and `r.bytes == 0` afterwards); the timeout case (buffer one fragment, then
`add` a fragment for a DIFFERENT key at `now+31s` and assert `expired == 1`); the buffer cap
(17 distinct IDs, the 17th is `reasmBoundExceeded`); the byte cap (a fragment at offset 65520
costs about 65 KiB, so four fill 256 KiB and the fifth is refused); and `discardAll` followed
by `add` returning `reasmClosed`.
  </action>

  <verify>
    <automated>go vet ./netstack/ &amp;&amp; go build ./... &amp;&amp; go test -race -run 'Reassembl|Fragment|IPv4|Checksum' -v ./netstack/ &amp;&amp; make test</automated>
    <automated>grep -c 'errBadFragment' netstack/ipv4.go  # &gt;= 4: sentinel + three geometry checks</automated>
    <automated>grep -c 'now\.Add(reassemblyTimeout)' netstack/reassembly.go  # &gt;= 1 — the deadline comes from add's injected now, never from the wall clock</automated>
  </verify>

  <done>
`netstack/reassembly.go` and `netstack/reassembly_test.go` exist; `ipv4Header` carries
`id`/`moreFragments`/`fragOffset` with `isFragment()`; `parseIPv4` rejects invalid fragment
geometry with `errBadFragment` and accepts valid fragments; `fragmentIPv4` produces
RFC-791-conformant fragments; `reassembler.add` implements RFC 815 permissively with all
three bounds and lazy expiry; `errFragmented` is gone and `deliver` still counts
`FragmentsDropped` for fragments via the interim guard; `make test` is green.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Stack integration — WithMTU, reassembly in deliver, outbound fragmentation, MTU-derived MSS</name>
  <files>netstack/stack.go, netstack/tcp_timer.go, netstack/tcp_listener.go, netstack/udp.go, netstack/ipv4.go, netstack/stack_test.go</files>

  <behavior>
    - New() defaults to MTU 1500; WithMTU(575) and WithMTU(70000) both return ErrInvalidMTU; MTU() reports the configured value.
    - An ICMP echo request arriving as 3 fragments in reverse order produces exactly one echo reply, FragmentsReassembled == 1, PacketsReceived == 3.
    - A UDP datagram larger than the MTU, delivered as fragments, arrives whole at udpConn.ReadFrom.
    - A fragment whose source IP is not the sending session's IP increments SpoofedSourceDropped and leaves the reassembler empty.
    - A middle fragment whose payload length is not a multiple of 8 increments MalformedDropped.
    - A lone fragment left unreassembled is expired lazily: after Advance(31s) the next fragment yields ReassemblyTimeouts == 1.
    - WriteTo of 3000 bytes at WithMTU(1500) emits 3 packets with correct offsets/MF/shared ID/valid checksums, returns len(p), and sets OutboundFragmented == 1.
    - At WithMTU(1000) the SYN-ACK advertises MSS 960 and a full-window TCP response produces OutboundFragmented == 0.
    - Detaching a session with a half-filled reassembly buffer does not panic, and a re-attach starts with empty reassembly state.
  </behavior>

  <action>
**2a. MTU configuration.**

Add to `netstack/stack.go`'s constants, each with its citation: `defaultMTU = 1500` (the
`tun-mtu` this project pushes to clients, `ovpn.go`'s `serverKM2Options`), `minMTU = 576`
(RFC 1122 §3.3.3's EMTU_R — OpenVPN itself refuses a `tun-mtu` below this), and
`maxMTU = maxIPv4Datagram`.

Add `ErrInvalidMTU = errors.New("netstack: MTU must be between 576 and 65535")` to the typed
error block. Add `WithMTU(mtu int) Option` setting `s.mtu`, and `func (s *Stack) MTU() int`.
In `New`, initialize `s.mtu = defaultMTU` in the struct literal and validate AFTER the option
loop — `Option` has no error return, so `New` is the only place the range check can live —
returning `nil, ErrInvalidMTU` when `s.mtu < minMTU || s.mtu > maxMTU`.

Add fields `mtu int` and `ipID atomic.Uint32` to `Stack`, and `reasm reassembler` to
`attachment`. Extend `attachment.stop()` to call `a.reasm.discardAll()` after closing
`stopCh` — that single seam covers `Detach`, `Close` and `detachAttachment` alike. Document
that teardown deliberately bumps no counter: discarding buffers because the session went away
is not a drop worth alerting on.

**2b. Stats.**

Add four counters to `stats` and their exported twins to `Stats`, appended after the existing
fields so the struct stays additively compatible: `fragmentsReassembled`/`FragmentsReassembled`,
`reassemblyTimeouts`/`ReassemblyTimeouts` (counted in DATAGRAMS, incremented by `add`'s
`expired` return), `reassemblyBoundExceeded`/`ReassemblyBoundExceeded`, and
`outboundFragmented`/`OutboundFragmented` (counted in DATAGRAMS fragmented, not in fragments
emitted). Wire all four into `Stats()`. Narrow `FragmentsDropped`'s doc comment to its new
meaning: duplicate, conflict, or a fragment arriving after teardown. `errBadFragment` maps to
the existing `MalformedDropped`, not to `FragmentsDropped`.

**2c. `deliver` / `dispatch` split.**

Split the current `deliver` in two. `dispatch(a *attachment, hdr ipv4Header, pkt []byte)` gets
the existing protocol switch verbatim, including the `payload := pkt[hdr.payloadOff:hdr.totalLen]`
slice — move it, do not rewrite it. `deliver` keeps `packetsReceived.Add(1)`, `parseIPv4`, and
both ACL checks, and then, replacing Task 1's interim guard, handles the fragment branch:
when `hdr.isFragment()`, call `a.reasm.add(s.clock.Now(), hdr, pkt)`, add the returned
`expired` count to `reassemblyTimeouts`, and switch on the outcome — `reasmComplete` re-parses
the materialized datagram (counting `malformedDropped` and returning if that parse somehow
fails), increments `fragmentsReassembled` and calls `dispatch` with the re-parsed header;
`reasmBoundExceeded` increments `reassemblyBoundExceeded`; `reasmDuplicate`, `reasmConflict`
and `reasmClosed` increment `fragmentsDropped`; `reasmBuffered` falls through silently. Return
in every fragment case. A non-fragment calls `dispatch` directly.

Keeping the ACL strictly ahead of `add` is the security property this whole design rests on —
a spoofed fragment must never allocate buffer state. Say so in `deliver`'s doc comment, and
also document there that `packetsReceived` counts FRAGMENTS, not datagrams. Before you finish,
check `test/interop/server`'s PASS line for any assertion that assumes `PacketsReceived` equals
a reply count; if one exists, adjust that assertion rather than the counter semantics.

**2d. Outbound fragmentation in `writePacket`.**

After the existing source-IP check: when `hdr.totalLen <= s.mtu`, write `pkt` exactly as
today. Otherwise take `id := uint16(s.ipID.Add(1))` (starting at 1, wrapping naturally —
RFC 6864 §4 only requires uniqueness per (src, dst, protocol) within a reassembly window),
call `fragmentIPv4(hdr, pkt, s.mtu, id)`, return `errBadFragment` if it yields nothing,
increment `outboundFragmented` once for the datagram, then write each fragment in order via
`a.sess.Write`, returning the first error immediately. Document that fragments already sent
before an error are simply lost and time out at the peer, exactly as with any IP stack, and
that ordering within a datagram is guaranteed because the fragments are written from one
goroutine. `udpConn.WriteTo` is unchanged: it still returns `len(p)` on success, because from
the caller's perspective the whole datagram was accepted.

**2e. MTU-derived TCP MSS.**

Add `func (s *Stack) maxSegmentSize() uint16 { return uint16(s.mtu - minIPv4HeaderLen - tcpHeaderMinLen) }`
to `netstack/stack.go`, documenting that `minMTU` guarantees the result is at least 536 and
that deriving MSS from the MTU is what keeps TCP unfragmented by construction — at an MTU
below 1500 a full 1460-byte segment would otherwise split into two fragments on every send,
which is exactly the fragment-blackhole failure mode RFC 8900 warns about.

Replace the three live uses of `defaultMSS`: the clamp at `tcp_listener.go:322-323` and the
SYN-ACK at `:347` both become `d.stack.maxSegmentSize()`, and the SYN-ACK retransmit at
`tcp_timer.go:271` becomes `c.stack.maxSegmentSize()` (both structs already carry a `*Stack`).
KEEP the `defaultMSS = 1460` constant and reword its comment to describe it as the documented
default — the value `maxSegmentSize()` returns at `defaultMTU` — so
`tcp_segment_test.go:169`'s assertion keeps compiling and still holds for a default-MTU stack.

**2f. Comment corrections.**

Three comments now describe behavior that no longer exists. In `netstack/udp.go`'s
`maxUDPPayload` (around line 36-44), replace the claim that this bound is unreachable in
practice: a payload up to 65507 is now genuinely transmittable because `writePacket` fragments
anything above the MTU, so exceeding `maxUDPPayload` is a caller bug purely because of RFC
768's 16-bit Length field. In `netstack/stack.go`'s `readBufferSize` comment (around line
70-83), note that reassembled datagrams are materialized inside the reassembler and never
have to fit this read buffer — this buffer only ever has to hold one fragment as it arrives on
the wire. In `netstack/ipv4.go`'s `buildIPv4` comment, make sure it matches what Task 1 left
there (identification is assigned by `writePacket` when it fragments). After editing, verify
by grep that no comment in `netstack/` still asserts that this stack cannot fragment.

**2g. Tests in `netstack/stack_test.go`.**

Delete `TestFragmentDropped` and its `setFlagsFragOffsetForTest` helper if nothing else uses
it, and add, all built on `buildFragmentForTest` and `newTestStack`/`fakeClock`: the reverse
-order 3-fragment ICMP echo test; the oversized inbound UDP datagram test; the spoofed-fragment
test (asserting the reassembler is empty afterwards); the misaligned middle-fragment test;
`TestLoneFragmentTimesOut` (buffer one fragment, `Advance(31 * time.Second)`, feed a fragment
for another key, assert `ReassemblyTimeouts == 1`); the outbound `WriteTo(3000 bytes)` test at
`WithMTU(1500)` that drains 3 outbound packets, checks offsets/MF/shared ID/checksums, reassembles
them through a fresh `reassembler` and validates the result with `parseUDP`, and asserts both
`OutboundFragmented == 1` and the `len(p)` return; the `WithMTU(575)` / `WithMTU(70000)` /
default `MTU() == 1500` validation test; the `WithMTU(1000)` TCP test asserting a SYN-ACK MSS of
960 and `OutboundFragmented == 0` for a full response; and the detach-with-open-buffer test
proving no panic and a clean re-attach.
  </action>

  <verify>
    <automated>go vet ./... &amp;&amp; go build ./... &amp;&amp; go test -race -run 'Reassembl|Fragment|MTU' -v ./netstack/</automated>
    <automated>make test</automated>
    <automated>grep -c 'maxSegmentSize()' netstack/tcp_listener.go netstack/tcp_timer.go  # 2 and 1 respectively</automated>
    <automated>grep -c 'OutboundFragmented\|ReassemblyTimeouts\|ReassemblyBoundExceeded\|FragmentsReassembled' netstack/stack.go  # &gt;= 8: stats struct + Stats struct + Stats()</automated>
  </verify>

  <done>
`New` honors and validates `WithMTU`; `MTU()` reports it; `deliver` reassembles fragments
after the ACL and `dispatch` carries the unchanged protocol switch; `writePacket` fragments
above the MTU with a monotonically assigned IP ID; `attachment.stop()` discards reassembly
state; the four new `Stats` fields are populated; TCP MSS follows the MTU; every test listed
in the behavior block passes; `make test` is green.
  </done>
</task>

<task type="auto">
  <name>Task 3: Document fragmentation and reassembly in docs/NETSTACK.md</name>
  <files>docs/NETSTACK.md</files>

  <action>
Update `docs/NETSTACK.md` to match the shipped behavior. Verify every statement against the
code as you write it — this file is a contract for embedders, not a summary of intent.

1. **Scope section (around line 32-34).** The list of things this stack is not currently
   includes fragmentation/reassembly. Rewrite that item: bounded RFC 815 reassembly of
   in-tunnel IPv4 fragments and MTU-driven outbound fragmentation are now implemented; what
   remains out of scope is unchanged (no client-side TCP, no routing between sessions, no
   IPv6, no ICMP error generation). Add reassembly/fragmentation to the "what it does
   implement" list below it.

2. **Options section (around line 68-76).** Document `WithMTU(mtu int)` alongside
   `WithClock`: it sets the MTU used for outbound fragmentation and for deriving the TCP MSS,
   defaults to 1500, must be between 576 (RFC 1122 §3.3.3 EMTU_R) and 65535, and makes `New`
   return `ErrInvalidMTU` otherwise. Document `MTU() int` next to `ServerIP()`. Note the
   invariant that the `tun-mtu 1500` this project pushes to clients is fixed and independent
   of this setting — the netstack MTU is the embedder's own choice for what it emits.

3. **New section "Fragmentation and reassembly."** Cover: the three per-session bounds with
   their values and rationale (16 buffers, 256 KiB charged by reached buffer length so sparse
   fragments cost what dense ones cost, 30 s); that the timeout is fixed from the first
   fragment and never extended, with the RFC 1122 §3.3.2 deviation called out explicitly and
   justified by bounded state; the permissive RFC 815 overlap policy and the reasoning behind
   it (the source-IP ACL runs before any buffering, so only the session itself can write into
   its own buffer; no middlebox can smuggle a differing view past; geometry checks plus Go's
   bounds checking rule out the Teardrop class); the two consistency rules that DO discard a
   datagram (a second final fragment declaring a different total length; data beyond an
   already-known end); that expiry is lazy — swept on the next fragment or at detach, with no
   timer goroutine; that fragments are counted individually by `PacketsReceived`; and, on the
   outbound side, that any datagram larger than the MTU is fragmented with a monotonically
   assigned IP identification, and that the TCP MSS is derived from the MTU so TCP segments
   are unfragmented by construction.

4. **Statistics block (around line 240-255).** Add `FragmentsReassembled`,
   `ReassemblyTimeouts`, `ReassemblyBoundExceeded` and `OutboundFragmented` to the `Stats`
   struct listing in the same order the Go source declares them, and describe each in the
   prose around it. Narrow the `FragmentsDropped` description to duplicate / conflicting /
   post-teardown fragments, and note that a fragment with invalid geometry lands in
   `MalformedDropped`.

5. **TCP MSS sentence (around line 232).** Change the fixed "defaults to 1460" claim into the
   derived rule: the advertised MSS is the MTU minus 40 bytes (20 IPv4 + 20 TCP), i.e. 1460 at
   the default MTU, still capped so a peer requesting more does not raise it, with RFC 9293's
   default of 536 used when a SYN carries no MSS option.

6. **Threat-model note.** In the security/bounds discussion, record that Phase 3's T-03-03
   mitigation — which read "no reassembly buffer, no timer, no per-attacker state," asserted
   by the now-deleted `TestFragmentDropped` — is superseded. Its replacement is bounded
   per-session state: at most 16 buffers, 256 KiB and 30 s per authenticated session, with
   the source-IP ACL running before any allocation, and no ICMP fragmentation-needed error
   generated, so there is still no amplification path.

Do not touch any other section, and change no code in this task — the source is already
correct as of Task 2.
  </action>

  <verify>
    <automated>make test</automated>
    <automated>grep -c 'WithMTU' docs/NETSTACK.md  # &gt;= 2</automated>
    <automated>grep -c 'FragmentsReassembled\|ReassemblyTimeouts\|ReassemblyBoundExceeded\|OutboundFragmented' docs/NETSTACK.md  # &gt;= 4</automated>
    <automated>grep -c 'T-03-03' docs/NETSTACK.md  # &gt;= 1</automated>
    <automated>grep -ci 'RFC 815' docs/NETSTACK.md  # &gt;= 1</automated>
  </verify>

  <done>
`docs/NETSTACK.md` documents `WithMTU`/`MTU()`, carries a "Fragmentation and reassembly"
section covering the bounds, the timeout and its RFC 1122 deviation, the permissive overlap
policy with its rationale and the two discard rules, lists the four new `Stats` fields with
the narrowed `FragmentsDropped` semantics, states the MTU-derived MSS rule, and records that
T-03-03's original mitigation is superseded by bounded per-session state. `make test` is green.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| session -> netstack (in-tunnel IP packets) | Decrypted but attacker-controlled IPv4 packets from an authenticated client cross here into parsing and, now, into stateful reassembly buffers. |
| netstack -> session (outbound) | Packets the stack builds cross back out; fragmentation now rewrites headers on this path. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-FVA-01 | Denial of Service | `reassembler` buffer state | high | mitigate | Three fixed per-session bounds: `maxReassemblyBuffersPerSession` 16, `maxReassemblyBytesPerSession` 256 KiB charged by reached buffer length (a sparse fragment at offset 65000 costs 65 KiB, the same as a dense one), `reassemblyTimeout` 30 s fixed from the first fragment and never extended. Supersedes Phase 3's T-03-03. |
| T-FVA-02 | Spoofing | `deliver` fragment branch | high | mitigate | The source-IP ACL (`hdr.src == a.ip`) and destination check run strictly BEFORE `reasm.add`, so a spoofed fragment can never allocate or poison another session's buffer. Asserted by the spoofed-fragment test in Task 2. |
| T-FVA-03 | Tampering | overlapping fragments (Teardrop class) | medium | mitigate | `parseIPv4` validates fragment geometry before any buffering (non-empty payload, MF payloads multiple of 8, `fragOffset+payloadLen <= 65535`); all buffer writes are Go slice operations with bounds checking; overlap is permissive by design and safe because only the session itself can reach its own buffer. |
| T-FVA-04 | Denial of Service | inconsistent final fragments | medium | mitigate | A second MF=0 fragment declaring a different total length, or data beyond a known end, discards the whole buffer and frees its bytes (`reasmConflict`) rather than leaving ambiguous state. |
| T-FVA-05 | Information Disclosure | reassembly state surviving detach | low | mitigate | `attachment.stop()` calls `reasm.discardAll()`, covering `Detach`, `Close` and `detachAttachment`; a re-attach starts with empty state, asserted by the detach test in Task 2. |
| T-FVA-06 | Denial of Service | outbound fragmentation amplification | low | accept | Fragmentation is 1:N in packets but byte-for-byte bounded by the datagram the caller already handed in, and no ICMP fragmentation-needed error is generated, so there is no amplification path. |
</threat_model>

<verification>
1. `make test` (vet, build, `go test -race ./...`, gates) green after EACH of the three tasks.
2. `go test -race -run 'Reassembl|Fragment|MTU' -v ./netstack/` green after Task 2.
3. Optional interop (`make interop`): `ping -s 2000 10.8.0.1` from the OpenVPN client
   container must answer — ICMP over fragments in both directions — and the harness server's
   PASS line must stay consistent with the `PacketsReceived`-counts-fragments semantics.
</verification>

<success_criteria>
- A 3-fragment inbound datagram reassembles in any arrival order and reaches its UDP/ICMP handler whole.
- A reply larger than the configured MTU leaves as valid, correctly-offset IPv4 fragments.
- Per-session reassembly state is capped at 16 buffers / 256 KiB / 30 s, and spoofed fragments allocate nothing.
- `WithMTU` validates against 576..65535 and drives both fragmentation and the TCP MSS.
- `netstack` still imports nothing from the core module, and no new non-stdlib dependency appears.
- `docs/NETSTACK.md` matches the shipped behavior, including the superseded T-03-03 note.
- Three atomic commits, each leaving `make test` green.
</success_criteria>

<output>
Create `.planning/quick/260908-fva-ipv4-fragment-reassembly-rfc-815-mit-per/260908-fva-SUMMARY.md` when done.
</output>
