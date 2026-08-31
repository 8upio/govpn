# Phase 3: In-Process Termination - Pattern Map

**Mapped:** 2026-08-25
**Files analyzed:** 13
**Analogs found:** 11 / 13

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|-----------------|----------------|
| `netstack/stack.go` (Stack, Attach/Detach, per-session read loop) | service / event-driven | event-driven | `session.go` (Session pump/stopCh/stopOnce lifecycle) | role-match |
| `netstack/ipv4.go` (parseIPv4/buildIPv4, checksum) | utility / transform | transform | `internal/wire/wire.go` (bounds-checked binary parse/build) | exact |
| `netstack/icmp.go` (ICMP echo responder) | utility / event-driven | request-response | `test/interop/server/main.go:422-472` (`icmpEchoReply`/`startICMPResponder`) | exact |
| `netstack/udp.go` (UDP demux, `net.PacketConn`) | service / event-driven | request-response | `internal/wire/wire.go` (header parse) + stdlib `net.PacketConn` contract | role-match |
| `netstack/tcp/segment.go` (TCP header parse/build, MSS option) | utility / transform | transform | `internal/wire/wire.go` (bounds-checked binary parse/build) | exact |
| `netstack/tcp/state.go` (LISTEN/SYN_RCVD/ESTABLISHED transitions) | service / event-driven | event-driven | `internal/reliable/reliable.go` (stateful window/timer machinery, injected Clock) | role-match |
| `netstack/tcp/timer.go` (RTO doubling, TIME_WAIT) | utility / event-driven | event-driven | `internal/reliable/reliable.go` (Clock/SystemClock, backoff) | exact |
| `netstack/tcp/conn.go` (`net.Conn` impl: Read/Write/Close/deadlines) | service / streaming | streaming | `session.go` (`Session.Read`/`Write`/`Close`, stopCh discipline) | role-match |
| `netstack/tcp/listener.go` (`net.Listener` impl, accept queue) | service / event-driven | event-driven | `session.go` (Session lifecycle) + stdlib `net.Listener` contract | partial-match |
| `netstack/netstack_test.go` (fake-Session fast tier) | test | event-driven | `internal/reliable/reliable_test.go` pattern (injected Clock, no Docker) — see note below | role-match |
| `netstack/tcp/tcp_test.go` (state-machine tests, injected Clock) | test | event-driven | `internal/reliable/reliable.go`'s `Clock`/`SystemClock` (lines 81-89) | exact |
| `examples/tunnelweb/main.go` (embedder: ovpn + netstack + http.Serve) | config / request-response | request-response | `test/interop/server/main.go` (`run`, `OnSession` wiring, harness main) | role-match |
| `test/interop/entrypoint.sh` + `interop_test.go` extension (curl/UDP probes) | test | request-response | existing `entrypoint.sh` ping probe + `interop_test.go` assertions | exact |

## Pattern Assignments

### `netstack/stack.go` (service, event-driven)

**Analog:** `session.go` (Session struct, stopCh/stopOnce, single-reader Read contract)

**Lifecycle/teardown pattern** (session.go lines 95-106, 190-224):
```go
// stopCh is closed exactly once (guarded by stopOnce) to signal pump
// [...] other than Close's stopOnce.Do, and inbound itself is never closed
stopCh chan struct{}
stopOnce sync.Once

// closing reports whether Close has already started (or finished) tearing
// this session down, by checking whether stopCh is closed. Safe to call
// from any goroutine without additional synchronization — receiving from a
// closed channel is itself a synchronizing action.
func (s *Session) closing() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}
```
Apply this exact stopCh/stopOnce/select-based teardown discipline to `Stack.Attach`'s per-session read-loop goroutine: `Detach` should close a per-attachment stopCh (guarded by stopOnce), and the read loop selects on it alongside `sess.Read` returning an error. Per RESEARCH.md Pattern 4, **`sess.Read` returning an error is itself the sole detach trigger** — the read loop is the one place that discovers session death, mirroring `session.go`'s own pump goroutine discovering `Session.Close()`.

**Single-reader contract** (session.go lines 199-203, quoted verbatim in RESEARCH.md):
```go
// Assumes the single-reader-goroutine convention io.Reader implementations
// ordinarily rely on; concurrent Read calls on one Session are not
// supported (mirrors bufio.Reader's own contract).
```
`netstack.Stack.Attach` must start **exactly one** goroutine per attached session calling `sess.Read` — never call `Read` from two goroutines on the same session.

**Local session interface** (no `ovpn` import): declare `type session interface { io.ReadWriteCloser }` in `netstack`, matching `var _ io.ReadWriteCloser = (*Session)(nil)` already asserted at `session.go:521`. Do not import `github.com/8upio/govpn`.

**Write-side is lock-free from netstack's perspective:** `internal/datachan/datachan.go` lines 33-34 (`mu sync.Mutex` field) plus `Wrapper.Seal`'s own locking mean `Session.Write` is safe for concurrent multi-goroutine calls — the TCP retransmit-timer goroutine, TIME_WAIT timer, and `http.Handler` goroutines can all call `sess.Write` with zero additional locking in `netstack` itself.

---

### `netstack/ipv4.go`, `netstack/tcp/segment.go` (utility, transform)

**Analog:** `internal/wire/wire.go` (`ParseControlPacket`, lines 149-170+)

**Bounds-checked parse pattern** (wire.go lines 30-32, 149-170):
```go
// Every field read explicitly checks the remaining buffer length first and
// returns a typed sentinel error rather than ever indexing out of range —
// this function must never panic on arbitrary/adversarial input.
func ParseControlPacket(plaintext []byte, hdr Header) (ControlPacket, error) {
	buf := plaintext
	if len(buf) < 1 {
		return ControlPacket{}, ErrTooShort
	}
	ackCount := int(buf[0])
	buf = buf[1:]
	if ackCount > MaxAcks {
		return ControlPacket{}, ErrTooManyAcks
	}
	// ... continues checking len(buf) before every subsequent read
```
Apply identically to IPv4/ICMP/UDP/TCP header parsing: check `len(pkt) >= minHeaderLen` before reading any field, check `ihl*4 <= len(pkt)` and `totalLength <= len(pkt)` before slicing (per RESEARCH.md Anti-Patterns), return typed sentinel errors (e.g. `ErrTooShort`, `ErrBadVersion`) rather than panicking — this is the same discipline `internal/wire` already established and the codebase's own convention.

**Checksum function to copy verbatim** (already live and RFC-1071-verified in the harness — `test/interop/server/main.go:565-578` per RESEARCH.md Pattern 1):
```go
func internetChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
```
Move this function (byte-for-byte) from `test/interop/server/main.go` into `netstack/ipv4.go` (or a shared `checksum.go`); reuse it for IPv4 header, ICMP, and (with the pseudo-header sum added first) UDP/TCP checksums.

**Citation-header convention:** `internal/wire/wire.go` lines 1-19 open every wire-layout file with a package doc comment citing exact reference source file/line ranges (here, the OpenVPN C reference; for netstack, cite RFC 791/792/768/9293 section numbers instead — RESEARCH.md's own Sources section already has exact section/line citations to reuse).

---

### `netstack/icmp.go` (utility, request-response)

**Analog:** `test/interop/server/main.go` lines 396-472 (`startICMPResponder`, `icmpEchoReply`) — this is the exact logic Phase 3 is chartered to relocate (per 02-03-SUMMARY.md's own "Next Phase Readiness" note, and RESEARCH.md Pattern 1).

**Core pattern** (main.go lines 422-472, quoted in full above in Bash output — copy near-verbatim):
```go
func icmpEchoReply(pkt []byte) (reply []byte, ok bool) {
	const (
		minIPv4HeaderLen = 20
		minICMPHeaderLen = 8
		protocolICMP     = 1
		icmpTypeEchoReq  = 8
		icmpTypeEchoRepl = 0
	)
	if len(pkt) < minIPv4HeaderLen {
		return nil, false
	}
	version := pkt[0] >> 4
	ihl := int(pkt[0]&0x0F) * 4
	if version != 4 || ihl < minIPv4HeaderLen || len(pkt) < ihl+minICMPHeaderLen {
		return nil, false
	}
	if pkt[9] != protocolICMP {
		return nil, false
	}
	icmp := pkt[ihl:]
	if icmp[0] != icmpTypeEchoReq {
		return nil, false
	}
	out := append([]byte(nil), pkt...)
	var src, dst [4]byte
	copy(src[:], out[12:16])
	copy(dst[:], out[16:20])
	copy(out[12:16], dst[:])
	copy(out[16:20], src[:])
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], internetChecksum(out[:ihl]))
	outICMP := out[ihl:]
	outICMP[0] = icmpTypeEchoRepl
	outICMP[2], outICMP[3] = 0, 0
	binary.BigEndian.PutUint16(outICMP[2:4], internetChecksum(outICMP))
	return out, true
}
```
Deviation for the netstack version per CONTEXT.md: "echo responder for the server tunnel IP only... all other ICMP dropped silently" — add a destination-IP == server-tunnel-IP check before responding (the harness version didn't need this since it was single-session; the netstack version demuxes multiple attached sessions, so this becomes the netstack's V4-Access-Control boundary alongside source-IP-spoofing enforcement described in RESEARCH.md Security Domain).

**Dispatch wrapper pattern** (main.go lines 396-419, `startICMPResponder`): shows the "one goroutine, `sess.Read` loop, dispatch by packet type, `sess.Write` reply inline" shape — reuse this shape inside `Stack`'s per-session read loop's protocol switch (RESEARCH.md architecture diagram: `ICMP -> echo responder -> sess.Write() (reply, inline)`).

---

### `netstack/tcp/state.go`, `netstack/tcp/timer.go` (service/utility, event-driven)

**Analog:** `internal/reliable/reliable.go` (Clock injection, backoff, fixed capacity constants)

**Injected-Clock pattern** (reliable.go lines 81-89):
```go
type Clock interface {
    Now() time.Time
}

// SystemClock is the default Clock, backed by time.Now.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }
```
And the constructor default (reliable.go ~161-164):
```go
// nil, SystemClock is used. size must be in (0, Capacity].
func New(clock Clock, size int) *Reliable {
	if clock == nil {
		clock = SystemClock{}
	}
	...
```
Apply identically to `netstack/tcp`: a `Clock` interface + `SystemClock` default, injected into the TCP state machine's constructor, so `tcp_test.go` can drive retransmit/TIME_WAIT timing deterministically without real sleeps — this is the exact mechanism RESEARCH.md's Wave 0 Gaps section calls for ("state-machine transition tests using an injected Clock (mirroring internal/reliable's Clock/SystemClock pattern)").

**Named, fixed constants convention** (reliable.go lines 44-56, citation-header style): `AckSize = 8`, `Capacity = 12`, `NSendBuffers = 6`, `NRecBuffers = 12` — each with a doc comment citing its source and rationale. Apply the same style to TCP's own constants (MSS=1460, backlog depth, half-open cap, fixed RTO, receive window ~64KB) — RESEARCH.md Open Question #1 explicitly recommends this: "a specific number is less important than it existing and being named, matching this project's existing 'explicit typed constant, no magic number' convention."

**Backoff pattern:** reliable.go's retransmit backoff doubles `timeout` on every resend (`best->timeout *= 2` per its own citation header) — CONTEXT.md locks the identical "fixed RTO with doubling on retransmit" for TCP; reuse the same doubling-on-resend shape, not RFC 6298's SRTT/RTTVAR (explicitly out of scope per RESEARCH.md's Alternatives Considered).

---

### `netstack/tcp/conn.go` (service, streaming)

**Analog:** `session.go` `Read`/`Write`/`Close` (lines 305-521)

**Read pattern — retain-on-too-small-buffer** (session.go lines 305-320):
```go
// Read delivers exactly one raw, decrypted IP packet per call (D-05):
// datagram-shaped, never a stream. If p is too small to hold the next
// packet, Read returns a typed error and RETAINS the packet in
// pendingRead rather than truncating it or discarding it silently
func (s *Session) Read(p []byte) (int, error) {
	if s.pendingRead != nil {
		pkt := s.pendingRead
		if len(p) < len(pkt) {
			return 0, fmt.Errorf("ovpn: read buffer (%d bytes) too small for %d-byte packet; packet retained for a future Read", len(p), len(pkt))
		}
```
`net.Conn.Read` is stream-shaped (unlike `Session.Read`'s datagram shape), so this exact retain-pattern doesn't transfer directly — but the discipline "never silently truncate or drop, choose and document one policy" transfers: `tcp/conn.go`'s Read should deliver from a byte-stream reassembly buffer (in-order delivery per CONTEXT.md), returning as many bytes as fit in `p` and retaining the remainder for the next call (standard `io.Reader` streaming semantics — closer to `bufio.Reader` than to `Session.Read`, but the file's own reference to "mirrors bufio.Reader's own contract" at session.go:203 is directly applicable here too).

**Close/teardown discipline:** reuse `stopCh`/`stopOnce` shape from `session.go` (see stack.go section above) for `tcp/conn.go`'s Close — must be safe for concurrent/repeated Close calls, matching `Session.Close`'s `stopOnce.Do` wrapping (session.go:463-465).

**Deadline-aware Read (new pattern this phase, per RESEARCH.md Pitfall 1):** no existing codebase analog — `Session.Read` blocks on `stopCh`/`ipInbound` with no deadline concept. `tcp/conn.go` must add `SetReadDeadline`/`SetWriteDeadline` support via a `time.Timer`/`time.AfterFunc` unblocking a channel-select, returning a sentinel type satisfying `net.Error` (`Timeout() bool { return true }`) and wrapping `os.ErrDeadlineExceeded` via `Unwrap()` — required for `net/http`'s `readRequest` deadline calls (stdlib `net/http/server.go:992`, `net/net.go:158-159`, both cited in RESEARCH.md Pitfall 1). This is genuinely new code, not adapted from an existing analog.

---

### `examples/tunnelweb/main.go` (config, request-response)

**Analog:** `test/interop/server/main.go` (`run`, `OnSession` wiring — harness's own embedder-shaped main)

Read `test/interop/server/main.go`'s top-level `run`/config-construction/`OnSession` wiring (the file this session already read in full at lines 396-472, plus its surrounding `run` function) as the closest precedent for "one command, embeds `ovpn`, wires `OnSession`" — the harness IS an embedder example, just headless. `examples/tunnelweb/main.go` follows the same `ovpn.Config{OnSession: ...}` + `stack.Attach(sess, sess.AssignedIP())` wiring shape (per CONTEXT.md's own Integration Points), then layers `http.Serve(stack.ListenTCP(port), handler)` on top — new code for the HTTP handler/page content, but the harness main is the closest analog for the embedder skeleton itself.

---

### `test/interop/entrypoint.sh` + `interop_test.go` extension (test, request-response)

**Analog:** existing `entrypoint.sh` ping probe pattern + `interop_test.go`'s `assertDataChannelRoundTrip`/ping assertions (both cited in RESEARCH.md, already proven in Phase 2's harness).

Extend the existing probe-and-assert shape: add a `curl` invocation against the landing page + one subpage (assert content markers) and a UDP round-trip probe, following the same shell-probe-writes-marker-file → Go-test-parses-and-asserts pattern the ping probe already established. Add `curl` to `test/interop/Dockerfile`'s client image package list if absent (RESEARCH.md Environment Availability — flagged low-risk, trivial addition).

---

## Shared Patterns

### stopCh/stopOnce teardown discipline
**Source:** `session.go` lines 95-106, 190-224, 463-478
**Apply to:** `netstack.Stack`'s per-session attachment goroutine, `tcp/conn.go`, `tcp/listener.go` — any long-lived goroutine or resource in the netstack package needing exactly-once, panic-safe, concurrent-safe teardown.

### Injected Clock for deterministic timer tests
**Source:** `internal/reliable/reliable.go` lines 81-89, 161-164
**Apply to:** `netstack/tcp`'s retransmit timer, TIME_WAIT timer — enables `go test -race` fast-tier coverage of NET-02's handshake/close/retransmit behavior with no real Docker/real-time waits, matching RESEARCH.md's Wave 0 Gaps requirement.

### Bounds-checked, panic-free binary parsing with typed sentinel errors
**Source:** `internal/wire/wire.go` lines 30-32, `ParseControlPacket`
**Apply to:** every header parser in `netstack` (IPv4, ICMP, UDP, TCP) — check length before every field read, never trust length fields (IHL, total length) without validating against `len(buf)` first, return typed errors rather than panicking on adversarial input (RESEARCH.md Security Domain V5 explicitly calls this out).

### Named, documented, fixed constants (no magic numbers)
**Source:** `internal/reliable/reliable.go` lines 44-77 (citation-header style const block)
**Apply to:** all of netstack's tunable constants — MSS (1460), TCP backlog depth, half-open connection cap, fixed RTO value, advertised receive window (~64KB), TIME_WAIT duration — each with a doc comment citing the RFC or the "tunnel-quality link" scoping rationale from CONTEXT.md/RESEARCH.md.

### Internet checksum (RFC 1071) — single shared function
**Source:** `test/interop/server/main.go` lines 565-578 (`internetChecksum`)
**Apply to:** IPv4 header checksum, ICMP checksum, UDP/TCP checksum (with pseudo-header prepended) — one function, four call sites, moved verbatim into `netstack` per RESEARCH.md Pattern 1.

### Local structural interface, no upward import
**Source:** `session.go:521` (`var _ io.ReadWriteCloser = (*Session)(nil)`) + RESEARCH.md Pattern 5
**Apply to:** `netstack`'s local `session` interface — `netstack` must not import `github.com/8upio/govpn`; `*ovpn.Session` satisfies the local interface structurally, and fast-tier tests use an `io.Pipe`-backed fake satisfying the same interface.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `netstack/tcp/conn.go` deadline/timeout machinery (`SetReadDeadline`/`SetWriteDeadline` + `net.Error`-shaped timeout errors) | service | streaming | No existing type in the codebase implements deadline-aware I/O or a `net.Error`-compatible timeout sentinel — `Session.Read`/`Write` have no deadline concept at all. Build fresh per RESEARCH.md Pitfall 1's guidance (`time.AfterFunc` + channel-select + sentinel error wrapping `os.ErrDeadlineExceeded`). |
| `netstack/tcp/conn.go`'s `CloseWrite() error` half-close support | service | streaming | No existing half-close precedent in this codebase (`Session.Close` is a single full close). Build fresh per RESEARCH.md Pitfall 3, modeling TCP's own CLOSE-WAIT/FIN-WAIT states directly from RFC 9293 — no shortcut via an existing analog. |

## Metadata

**Analog search scope:** `session.go`, `internal/wire/wire.go`, `internal/reliable/reliable.go`, `internal/datachan/datachan.go`, `test/interop/server/main.go`, `gates_test.go`, `ovpn.go` (all read directly this session)
**Files scanned:** 7 core files + directory listing of `internal/` and repo root
**Pattern extraction date:** 2026-08-25
