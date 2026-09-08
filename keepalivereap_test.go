// keepalivereap_test.go is the B1/B2 regression suite for quick task
// 260908-sw5: an authenticated ping keepalive (datachan.ErrPingAbsorbed)
// must refresh the idle-reap timer and log its own keepalive reason token,
// never the auth-failure token — while a packet that genuinely fails to
// authenticate must still leave lastAuthTraffic untouched and still log an
// auth-failure reason token (T-04-07, unchanged). Built on
// newReapTestSession (lifecycle_test.go) and the syncBuffer/newTestLogger
// pair (logging_test.go).
package ovpn

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/datachan"
)

// TestKeepalivesOnlySessionIsNeverReaped is the B1 regression: a session
// receiving ONLY sealed pings, one every 10s, survives 9 rounds (90s of
// fake-clock time — well past a 60s reap window, i.e. a full window and a
// half) without runReap closing it.
func TestKeepalivesOnlySessionIsNeverReaped(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

	buf := &syncBuffer{}
	sess.log.Store(newTestLogger(buf, slog.LevelDebug))

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runReap(tick)
	}()
	defer func() {
		close(sess.stopCh)
		<-done
	}()

	// 9 rounds x 10s = 90s of fake-clock time against a 60s window: the
	// session outlives a full reap window and a half — the exact live-test
	// scenario (a silent SIP phone sending nothing but keepalives).
	for i := 0; i < 9; i++ {
		clock.Advance(10 * time.Second)

		pingSealed, err := sess.primary.wrapper.SealPing(nil)
		if err != nil {
			t.Fatalf("SealPing: %v", err)
		}
		sess.handleDataPacket(pingSealed)

		select {
		case tick <- time.Now():
		case <-done:
			t.Fatalf("session reaped after %d keepalives — the idle-reap timer was not refreshed", i+1)
		}
	}

	select {
	case <-done:
		t.Fatal("session was reaped even though every keepalive refreshed the timer")
	case <-time.After(200 * time.Millisecond):
	}

	stats := sess.Stats()
	if want := clock.Now(); !stats.LastAuthTrafficAt.Equal(want) {
		t.Errorf("Stats().LastAuthTrafficAt = %v, want %v (the last ping's clock reading)", stats.LastAuthTrafficAt, want)
	}
	if stats.KeepalivesIn != 9 {
		t.Errorf("Stats().KeepalivesIn = %d, want 9", stats.KeepalivesIn)
	}
	if stats.PacketsIn != 0 {
		t.Errorf("Stats().PacketsIn = %d after 9 absorbed keepalives, want 0", stats.PacketsIn)
	}

	logged := buf.String()
	if !strings.Contains(logged, "reason=keepalive") {
		t.Errorf("log output does not contain %q:\n%s", "reason=keepalive", logged)
	}
	// planner-discipline-allow: reason=data-auth
	if strings.Contains(logged, "reason=data-auth") {
		t.Errorf("log output contains an auth-failure reason token for authenticated keepalives:\n%s", logged)
	}
}

// TestForgedPacketStillLogsAuthFailure is the T-04-07 half of the guard
// that lives at the log layer: a packet that fails the AEAD tag check
// (rather than being recognized as a ping) leaves KeepalivesIn and
// LastAuthTrafficAt untouched and logs the primary auth-failure reason
// token.
func TestForgedPacketStillLogsAuthFailure(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Hour)

	buf := &syncBuffer{}
	sess.log.Store(newTestLogger(buf, slog.LevelDebug))

	wrapper := sess.primary.wrapper
	clock.Advance(5 * time.Second)
	wantTouch := clock.Now()

	sealed, err := wrapper.Seal(nil, bytes.Repeat([]byte{0x77}, 20))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sess.handleDataPacket(sealed)
	if got := sess.Stats().LastAuthTrafficAt; !got.Equal(wantTouch) {
		t.Fatalf("Stats().LastAuthTrafficAt = %v after authenticated traffic, want %v", got, wantTouch)
	}

	// Forge exactly as sessionstats_test.go's forged-packet test does: a
	// REAL sealed packet with its final ciphertext byte flipped, so the
	// packet fails the AEAD tag check rather than failing earlier for an
	// unrelated reason.
	clock.Advance(5 * time.Second)
	forged, err := wrapper.Seal(nil, bytes.Repeat([]byte{0x88}, 20))
	if err != nil {
		t.Fatalf("Seal (for forging): %v", err)
	}
	forged[len(forged)-1] ^= 0xFF
	sess.handleDataPacket(forged)

	stats := sess.Stats()
	if stats.KeepalivesIn != 0 {
		t.Errorf("Stats().KeepalivesIn = %d after a forged packet, want 0", stats.KeepalivesIn)
	}
	if !stats.LastAuthTrafficAt.Equal(wantTouch) {
		t.Errorf("Stats().LastAuthTrafficAt = %v after a forged packet, want unchanged %v", stats.LastAuthTrafficAt, wantTouch)
	}

	logged := buf.String()
	// planner-discipline-allow: reason=data-auth-failed
	if !strings.Contains(logged, "reason=data-auth-failed") {
		t.Errorf("log output does not contain the primary auth-failure reason token:\n%s", logged)
	}
}

// TestLameDuckKeepaliveRefreshesReapTimer is the lame-duck-slot half of the
// B1/B2 regression: a ping sealed under the lame-duck key (with a primary
// wrapper that cannot decrypt it) refreshes LastAuthTrafficAt, increments
// KeepalivesIn, and logs the lame-duck keepalive reason token — not the
// lame-duck auth-failure token.
func TestLameDuckKeepaliveRefreshesReapTimer(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

	buf := &syncBuffer{}
	sess.log.Store(newTestLogger(buf, slog.LevelDebug))

	// Make the primary slot fail to decrypt anything (distinct keys), and
	// give the lame-duck slot the wrapper that will actually succeed —
	// mirrors TestLameDuckDecryptResetsReapTimer's own setup
	// (lifecycle_test.go).
	failingWrapper, err := datachan.NewWrapper(lameDuckTestKeys(0x10), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper (failing primary): %v", err)
	}
	lameWrapper, err := datachan.NewWrapper(lameDuckTestKeys(0x50), 1, 1)
	if err != nil {
		t.Fatalf("NewWrapper (lame-duck): %v", err)
	}
	sess.mu.Lock()
	sess.primary = keySlot{keyID: 0, wrapper: failingWrapper}
	sess.lameDuck = keySlot{keyID: 1, wrapper: lameWrapper, mustDie: clock.Now().Add(time.Hour)}
	sess.mu.Unlock()

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runReap(tick)
	}()
	defer func() {
		close(sess.stopCh)
		<-done
	}()

	clock.Advance(50 * time.Second)
	wantTouch := clock.Now()

	pingSealed, err := lameWrapper.SealPing(nil)
	if err != nil {
		t.Fatalf("SealPing (lame-duck): %v", err)
	}
	sess.handleDataPacket(pingSealed)
	tick <- time.Now()

	select {
	case <-done:
		t.Fatal("session was reaped even though a lame-duck keepalive reset the timer")
	case <-time.After(200 * time.Millisecond):
	}

	stats := sess.Stats()
	if stats.KeepalivesIn != 1 {
		t.Errorf("Stats().KeepalivesIn = %d, want 1", stats.KeepalivesIn)
	}
	if !stats.LastAuthTrafficAt.Equal(wantTouch) {
		t.Errorf("Stats().LastAuthTrafficAt = %v, want %v", stats.LastAuthTrafficAt, wantTouch)
	}

	logged := buf.String()
	if !strings.Contains(logged, "reason=keepalive-lame-duck") {
		t.Errorf("log output does not contain %q:\n%s", "reason=keepalive-lame-duck", logged)
	}
	// planner-discipline-allow: reason=data-auth-failed-lame-duck
	if strings.Contains(logged, "reason=data-auth-failed-lame-duck") {
		t.Errorf("log output contains the lame-duck auth-failure token for an authenticated keepalive:\n%s", logged)
	}
}
