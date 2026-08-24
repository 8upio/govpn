---
phase: 01-handshake
reviewed: 2026-08-23T00:00:00Z
depth: standard
files_reviewed: 33
files_reviewed_list:
  - .dockerignore
  - .github/workflows/ci.yml
  - .gitignore
  - Makefile
  - cmd/gentestpki/main.go
  - go.mod
  - internal/ctrlconn/conn.go
  - internal/ctrlconn/conn_test.go
  - internal/reliable/reliable.go
  - internal/reliable/reliable_test.go
  - internal/tlscrypt/golden_test.go
  - internal/tlscrypt/keyfile.go
  - internal/tlscrypt/keyfile_test.go
  - internal/tlscrypt/tlscrypt.go
  - internal/tlscrypt/tlscrypt_test.go
  - internal/wire/golden_test.go
  - internal/wire/wire.go
  - internal/wire/wire_test.go
  - ovpn.go
  - ovpn_test.go
  - session.go
  - test/interop/Dockerfile
  - test/interop/capture_test.go
  - test/interop/decode.go
  - test/interop/docker-compose.lossy.yml
  - test/interop/docker-compose.yml
  - test/interop/entrypoint.sh
  - test/interop/golden_export.go
  - test/interop/interop_test.go
  - test/interop/pcap.go
  - test/interop/server/Dockerfile
  - test/interop/server/main.go
  - testdata/golden/README.md
  - testdata/golden/manifest.json
findings:
  critical: 0
  warning: 4
  info: 4
  total: 8
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-23
**Depth:** standard
**Files Reviewed:** 33
**Status:** issues_found

## Summary

This is iteration 2 of the review loop, verifying commits a5b470e (CR-01), 0de8176 (WR-01), and be919ca (WR-02) against the findings from iteration 1.

**CR-01 (session/goroutine leak) — fixed correctly.** I traced `Session.Close()` → `stopOnce.Do` → `close(stopCh)` + `srv.removeSession(s)` → `conn.Close()` end to end against every call site (`Server.Close()`, `runHandshake`'s error path, `enforceHandshakeWindow`'s timeout path, and the new `pump()`/`handleDatagram` select-on-`stopCh` pairing). The fix correctly avoids the "close a channel others may still send on" hazard by never closing `inbound` itself, uses `sync.Once` to make teardown idempotent and race-safe across the three call sites that can now all reach `Close()` concurrently, and `ctrlconn.Conn.Close()` (the thing `Session.Close()` ultimately calls into) was already idempotent before this fix. `go test -race -count=1 ./...` passes. No deadlock: every call site releases `Server.mu` before calling into `Session.Close()`/`removeSession`. No new nil-pointer paths: `sess.conn` and `sess.stopCh` are always populated before any goroutine that could observe them is started, exactly as the original CR-01 fix suggestion specified. This is correct and complete.

**WR-01 (unrecovered panic in `Config.OnSession`) — fixed correctly, but the recover is a bare swallow.** `callOnSession`'s `defer func() { recover() }()` does stop a panicking callback from taking down the whole process — verified by reading the code and confirming `runHandshake` now routes through it. However, the panic value is discarded with no logging, no error surfaced to `Config`, and no way for the embedder to observe that a callback panicked at all. See WR-03 below — this doesn't invalidate the fix (a silent swallow is strictly better than a process crash) but it is a regression in observability worth tightening.

**WR-02 (tls-crypt packet-ID rollover) — the rollover gate itself is correct, but I found a separate, more concrete defect in the same function while verifying it.** The new gate in `Wrapper.Wrap` (`internal/tlscrypt/tlscrypt.go:190-208`) correctly mirrors `packet_id_send_update`'s fail-closed rollover check (`packet_id.c:323-344`) for the `sendSeq == 0xFFFFFFFF` case. But two lines later, `Wrap` still populates the wire packet-ID's timestamp field with `time.Now().Unix()` on *every single call* (`tlscrypt.go:215`), where the C reference writes a value that is frozen for the life of the key (`p->time`, set once and only ever touched again at a rollover). Cross-referencing `packet_id_test`'s `seq_backtrack` branch (`packet_id.c:214-269`) shows this isn't cosmetic: a genuine OpenVPN 2.6 client receiving this server's tls-crypt-wrapped traffic treats every packet whose `pin->time` exceeds its own stored `p->time` as an unconditional accept that resets its replay window — which, given this server increments the wire timestamp roughly once per wall-clock second, happens constantly. That defeats the reference's own sequence-based anti-replay backtrack window for traffic sent by this library. See WR-04 below.

I also confirmed the three Info items from iteration 1 (dead `rootCert`, string-concatenated paths instead of `filepath.Join`, `flushAckOnly`'s benign empty-ACK race) are all still present, unchanged — carried forward below as IN-01/IN-02/IN-03.

## Warnings

### WR-03: `callOnSession`'s panic recovery is a silent swallow — no observability into a caller callback that panicked

**File:** `ovpn.go:378-383`

**Issue:** The fix correctly prevents an `OnSession` panic from crashing the process:

```go
func (s *Server) callOnSession(sess *Session) {
	defer func() {
		recover() //nolint:errcheck // intentionally swallowed, see callOnSession's doc comment
	}()
	s.cfg.OnSession(sess)
}
```

But the recovered value is thrown away entirely. There is no logging, no counter, no callback the embedder can register to be told "your `OnSession` panicked for session X" — for a library with no logging story at all today, this means a caller who ships a nil-pointer bug in their `OnSession` callback will simply see that session silently vanish, with zero diagnostic trail, ever. This is a step better than the pre-fix behavior (crashing the whole process) but trades a loud, debuggable failure for a completely silent one, which is its own maintainability problem — especially for a library explicitly designed to be embedded in long-running production processes.

**Fix:** Either accept an optional error/panic hook on `Config` and call it with the recovered value, or at minimum log via `log.Printf`/`runtime/debug.Stack()` so the embedder isn't debugging a mysteriously-disappearing session with no trace at all:

```go
func (s *Server) callOnSession(sess *Session) {
	defer func() {
		if r := recover(); r != nil {
			if s.cfg.OnSessionPanic != nil {
				s.cfg.OnSessionPanic(sess, r, debug.Stack())
			}
		}
	}()
	s.cfg.OnSession(sess)
}
```

### WR-04: `Wrapper.Wrap` writes a live `time.Now()` into the tls-crypt long-form packet ID on every packet instead of the reference's frozen per-key timestamp, weakening a genuine OpenVPN client's anti-replay window against this server's own traffic

**File:** `internal/tlscrypt/tlscrypt.go:213-215`

**Issue:**

```go
var pid [PIDSize]byte
binary.BigEndian.PutUint32(pid[0:4], seq)
binary.BigEndian.PutUint32(pid[4:8], uint32(time.Now().Unix()))
```

The reference's `packet_id_send_update` (`packet_id.c:323-344`, called from `packet_id_write` at `tls_crypt.c:164`) sets `p->time` exactly once, the first time the sequence is ever used (`if (!p->time) { p->time = now; }`), and only touches it again on a rollover. That same `p->time` value — not a fresh `time.Now()` — is what gets written into *every* outgoing packet's long-form timestamp field for the rest of that key's lifetime. This project's `Wrap` instead calls `time.Now().Unix()` fresh on every single call, so the wire timestamp changes roughly once per wall-clock second regardless of how many packets are sent.

This matters because a real OpenVPN 2.6 client's `packet_id_test` (`packet_id.c:214-269`, `seq_backtrack` branch, which is the default mode used for control-channel/tls-crypt UDP traffic per `DEFAULT_SEQ_BACKTRACK`/`--replay-window`) branches on `pin->time` vs. its own stored `p->time`:
- `pin->time == p->time`: normal sequence-window backtrack check (the intended replay defense).
- `pin->time > p->time` ("time moved forward"): **unconditionally accepted**, and the window is reset to the new time/id baseline.

Since this server's outgoing timestamp increases roughly every second, a genuine OpenVPN client receiving this server's tls-crypt traffic spends most of its time in the "time moved forward → accept unconditionally, reset window" branch rather than the intended sequence-backtrack check — defeating the reference's own anti-replay window for packets this library sends, on every wall-clock-second boundary. This does not break interop (nothing gets wrongly rejected) and does not bypass the HMAC-SHA256 authentication that is the primary defense, but it is a real, provable divergence from the reference's documented anti-replay behavior, and it is currently untested: the golden-vector tests exercise `WrapWithPacketID` (which takes an explicit `pid` and bypasses this code path entirely — see its own doc comment acknowledging "Wrap's own auto-generated seq+time.Now() packet ID can never reproduce a specific historical capture's bytes"), so nothing in the test suite exercises live `Wrap`'s timestamp behavior against reference semantics.

**Fix:** Track a single frozen send-timestamp field (set once on first use, updated only at rollover — the direct Go equivalent of `p->time`), not `time.Now()` per call:

```go
type Wrapper struct {
	...
	sendSeq  uint32
	sendTime int64 // frozen at first Wrap call; only updated at rollover — mirrors packet_id_send.time

	sendRolloverAt int64
	replay replayWindow
}

func (w *Wrapper) Wrap(dst, header, plaintext []byte) ([]byte, error) {
	...
	w.mu.Lock()
	if w.sendTime == 0 {
		w.sendTime = time.Now().Unix()
	}
	if w.sendSeq == 0xFFFFFFFF {
		now := time.Now().Unix()
		if w.sendRolloverAt != 0 && now <= w.sendRolloverAt {
			w.mu.Unlock()
			return nil, errors.New("tlscrypt: packet ID roll over")
		}
		w.sendRolloverAt = now
		w.sendTime = now
		w.sendSeq = 0
	}
	w.sendSeq++
	seq, ts := w.sendSeq, w.sendTime
	w.mu.Unlock()

	var pid [PIDSize]byte
	binary.BigEndian.PutUint32(pid[0:4], seq)
	binary.BigEndian.PutUint32(pid[4:8], uint32(ts))
	...
}
```

### WR-05: CR-01/WR-01/WR-02 shipped without any regression test

**File:** `ovpn.go`, `session.go`, `internal/tlscrypt/tlscrypt.go` (fix commits a5b470e, 0de8176, be919ca)

**Issue:** None of the three fix commits touch a `_test.go` file. There is no test asserting `Session.Close()` actually removes the session from `Server.sessions` or stops the `pump()` goroutine (e.g. a goroutine-count assertion around `Close()`), no test asserting a panicking `OnSession` doesn't crash the test process, and no test driving `Wrapper.sendSeq` to `0xFFFFFFFF` to assert the rollover gate actually returns an error. `go test -race -count=1 ./...` still passes, but that's expected — it was never exercising any of this code before either. For a project whose own stated correctness bar is "verified... not approximated from memory" and whose CLAUDE.md calls out `go test -race` as mandatory specifically because this codebase's stateful, timer-driven code "hides data races," landing three non-trivial concurrency/lifecycle fixes with zero accompanying tests leaves all three regressable by a future refactor with no CI signal.

**Fix:** Add at minimum:
- A test that calls `Session.Close()` on an established session and asserts (via `runtime.NumGoroutine()` delta, or by injecting a way to observe `pump`'s exit, or simplest: asserting the session is gone from a testable view of `Server.sessions`) that the session is actually removed and the pump goroutine actually exits.
- A test that sets `Config.OnSession` to a function that panics and asserts `Serve`/the test process survives and returns normally.
- A test in `internal/tlscrypt` that constructs a `Wrapper`, forces `sendSeq` to `0xFFFFFFFF` (exported test hook or same-package white-box test), and asserts the next `Wrap` call returns the rollover error rather than a wrapped-around sequence number.

## Info

### IN-01: `cmd/gentestpki/main.go`'s `rootCert` variable is dead code

**File:** `cmd/gentestpki/main.go:100-171`

**Issue:** `rootCert` is declared, assigned in both the `profileSmall` and `profileLarge` branches, and only ever referenced via `_ = rootCert` (line 171) to satisfy the compiler. Still present, unchanged since iteration 1.

**Fix:** Remove the `rootCert` variable and its assignments entirely; nothing reads it.

### IN-02: `test/interop/server/main.go`'s `loadConfig` builds paths with string concatenation instead of `filepath.Join`

**File:** `test/interop/server/main.go:133-184`

**Issue:** Every path in `loadConfig` is built as `pkiDir + "/ca.crt"` etc. rather than `filepath.Join(pkiDir, "ca.crt")`, inconsistent with `cmd/gentestpki/main.go`'s use of `filepath.Join`. Still present, unchanged since iteration 1.

**Fix:** Use `filepath.Join(pkiDir, "ca.crt")` etc. throughout.

### IN-03: `internal/ctrlconn/conn.go`'s `flushAckOnly` can emit a spurious empty ACK-only packet under a benign race

**File:** `internal/ctrlconn/conn.go:196-205`

**Issue:** `flushAckOnly` checks `c.acks.Peek()` and then calls `buildControlPacket`, which internally calls `c.acks.Drain()`; a concurrent `Write` can drain the same pending ACKs first, leaving `flushAckOnly` to transmit a `P_ACK_V1` packet with a zero-length ack array. Low-impact, documented as acceptable in the surrounding comment. Still present, unchanged since iteration 1.

**Fix:** Have `buildControlPacket` report how many acks it actually drained and skip the transmit if zero.

### IN-04: `test/interop/decode.go` and `test/interop/pcap.go` are missing the `//go:build interop` tag their only callers carry

**File:** `test/interop/decode.go:1`, `test/interop/pcap.go:1`

**Issue:** Every file in `test/interop` that calls `decodeCapture`/`ReadUDPPayloads` (`capture_test.go`, `golden_export.go`, `interop_test.go`) is gated behind `//go:build interop`, but `decode.go` and `pcap.go` themselves are not. The result is that `go vet ./...` / `staticcheck ./...` (run without `-tags interop`, i.e. the default/fast tier) compile these two files with no callers in that build, and `staticcheck` correctly flags `tunnelPort`, `decodedPacket`, and `decodeCapture` as unused (`U1000`) — a false-positive-looking dead-code warning that will keep resurfacing in default-tier static analysis and obscure genuine dead-code findings in the same package.

**Fix:** Add `//go:build interop` to both files for consistency with the rest of the package, or intentionally document why they're meant to compile in both tiers if that's deliberate.

---

_Reviewed: 2026-08-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
