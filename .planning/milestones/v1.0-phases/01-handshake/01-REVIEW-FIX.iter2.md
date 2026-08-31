---
phase: 01-handshake
fixed_at: 2026-08-23T19:16:35Z
review_path: .planning/phases/01-handshake/01-REVIEW.md
iteration: 1
findings_in_scope: 3
fixed: 3
skipped: 0
status: all_fixed
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-08-23T19:16:35Z
**Source review:** .planning/phases/01-handshake/01-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 3 (fix_scope: critical_warning — CR-* and WR-*; IN-* findings out of scope)
- Fixed: 3
- Skipped: 0

**Verification environment:** All fixes were applied and verified (`go build ./...`, `go test -race ./...`) inside an isolated git worktree at `.claude/worktrees/rf-01-54620-1787512368` on temp branch `gsd-reviewfix/01-54620`, fast-forwarded onto `main` on cleanup. The numbers below are reproducible from `main` after the worktree teardown.

## Fixed Issues

### CR-01: `Session.Close()` does not remove the session from `Server.sessions` or stop the per-session `pump()` goroutine

**Files modified:** `session.go`, `ovpn.go`
**Commit:** `a5b470e`
**Applied fix:** Gave `Session` a `srv *Server` back-reference, a `stopCh chan struct{}`, and a `stopOnce sync.Once`. `Session.Close()` now idempotently closes `stopCh`, calls `srv.removeSession(s)`, and closes the underlying `ctrlconn.Conn`. `pump()` was changed from `for cp := range sess.inbound` to a `select` over `sess.inbound` and `stopCh` so it terminates on `Close()` without ever closing `inbound` itself (which other goroutines may still send on). `handleDatagram`'s enqueue `select` gained a `case <-sess.stopCh` branch so a send during teardown doesn't need to fall through to the queue-full `default`. `runHandshake`'s failure path and `enforceHandshakeWindow`'s timeout path were both switched from manually calling `sess.conn.Close()` + `s.removeSession(sess)` to calling `sess.Close()`, unifying all teardown paths (handshake failure, handshake-window timeout, application-initiated close, and `Server.Close()`) through the single `Session.Close()` implementation. `Server.Close()`'s session-teardown loop was also switched from `sess.conn.Close()` to `sess.Close()` for the same reason — otherwise full-server shutdown would still leak `pump()` goroutines via the same root cause this finding describes.

Adapted from the review's suggested patch: the review's snippet declared `stopOnce sync.Once` as a plain (non-pointer, non-embedded) field alongside `stopCh`/`srv`, which is exactly what was implemented; the actual diff additionally routes `Server.Close()` (not explicitly mentioned in the finding's Fix section, but sharing the identical bug pattern) through `sess.Close()` to avoid reintroducing the same goroutine leak via a second code path.

### WR-01: `Config.OnSession` is invoked without panic recovery

**Files modified:** `ovpn.go`
**Commit:** `0de8176`
**Applied fix:** Extracted the `s.cfg.OnSession(sess)` call into a new `Server.callOnSession` method that wraps the call in a `defer func() { recover() }()`, so a panic inside caller-supplied `OnSession` code is swallowed instead of propagating up through the per-session `runHandshake` goroutine and crashing the whole embedding process. `runHandshake` now calls `s.callOnSession(sess)` instead of `s.cfg.OnSession(sess)` directly, inside the existing `if s.cfg.OnSession != nil` guard.

### WR-02: `tlscrypt.Wrapper.Wrap`'s packet-ID sequence counter silently wraps around instead of erroring

**Files modified:** `internal/tlscrypt/tlscrypt.go`
**Commit:** `be919ca`
**Applied fix:** Adapted rather than applied verbatim. The review's suggested patch unconditionally errors the moment `sendSeq` would wrap past `0xFFFFFFFF`. Cross-checking `packet_id_send_update` in `/Users/svenloth/dev/openvpn-reference/src/openvpn/packet_id.c:323-344` (called by `tls_crypt_wrap` via `packet_id_write`, `tls_crypt.c:164-168`) shows the reference does **not** unconditionally fail on rollover: since `tls_crypt_wrap` always uses the long-form (sequence + timestamp) wire format, a rollover from `UINT32_MAX` back to `0` is *permitted* as long as wall-clock time has advanced since the previous rollover — the `"TLS-CRYPT ERROR: packet ID roll over."` failure only fires if a second rollover is attempted within the same wall-clock second as the first (i.e., only when the clock hasn't ticked forward). Blindly applying the review's literal patch would have made the Go port *less* faithful to the reference than the pre-fix code, by erroring in a case (a single, time-advanced rollover) that the reference actually permits.

Implemented instead: added a `sendRolloverAt int64` field to `Wrapper` recording the unix-second timestamp of the Wrapper's last rollover (0 = never rolled over). In `Wrap`, when `sendSeq == 0xFFFFFFFF`, the code now checks `time.Now().Unix()` against `sendRolloverAt`: if a rollover already happened at or after the current second, the wrap fails with `"tlscrypt: packet ID roll over"`; otherwise `sendRolloverAt` is updated and `sendSeq` is reset to `0` before the existing `sendSeq++`/`seq := sendSeq` logic runs. This preserves the reference's fail-closed behavior (never silently emits a non-monotonic sequence number) while still permitting the one legitimate rollover path the reference itself allows.

## Skipped Issues

None — all in-scope findings (CR-01, WR-01, WR-02) were fixed. IN-01, IN-02, and IN-03 were out of scope for this run (`fix_scope: critical_warning`) and were not attempted.

---

_Fixed: 2026-08-23T19:16:35Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
