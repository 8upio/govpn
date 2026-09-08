// closereason_test.go exercises the Voxio Welle-1 M1 lifecycle surface:
// CloseReason, Session.Done/CloseReason, Config.OnSessionClosed, and
// Server.Close's wait-for-callbacks contract. Reuses this package's own
// existing live-tunnel-up harness (testPushClient, tunnelUpTestClient) for
// the end-to-end cases and the newReapTestSession/hand-built-Session style
// established by lifecycle_test.go for the synthetic ones — no second
// harness.
package ovpn

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/datachan"
)

// TestCloseReasonUnknownBeforeClose asserts CloseReason() returns
// CloseReasonUnknown for a still-live session.
func TestCloseReasonUnknownBeforeClose(t *testing.T) {
	sess := &Session{stopCh: make(chan struct{})}
	if got := sess.CloseReason(); got != CloseReasonUnknown {
		t.Fatalf("CloseReason() before any close = %v, want CloseReasonUnknown", got)
	}
}

// TestEmbedderCloseRecordsReasonAndFiresCallbackOnce is the embedder-Close
// half of M1's core proof: sess.Close() -> <-sess.Done() returns,
// sess.CloseReason() == CloseReasonEmbedder, and OnSessionClosed fires
// exactly once with that reason — driven against a live tunnel-up session
// so s.published is set the same way a real deployment sets it.
func TestEmbedderCloseRecordsReasonAndFiresCallbackOnce(t *testing.T) {
	_, network, err := net.ParseCIDR("10.61.0.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	tlsCfg, caPool := testHandshakeTLSConfig(t)

	sessions := make(chan *Session, 1)
	closed := make(chan CloseReason, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
		OnSessionClosed: func(sess *Session, r CloseReason) {
			closed <- r
		},
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client, replyReader := tunnelUpTestClient(t, key, serverPC.LocalAddr(), caPool)
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	if _, err := readControlString(replyReader, maxControlStringLen); err != nil {
		t.Fatalf("read push reply: %v", err)
	}

	var sess *Session
	select {
	case sess = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() never fired after Close")
	}

	if got := sess.CloseReason(); got != CloseReasonEmbedder {
		t.Fatalf("CloseReason() = %v, want CloseReasonEmbedder", got)
	}

	select {
	case r := <-closed:
		if r != CloseReasonEmbedder {
			t.Fatalf("OnSessionClosed reason = %v, want CloseReasonEmbedder", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnSessionClosed was never called")
	}

	select {
	case <-closed:
		t.Fatal("OnSessionClosed was called a second time")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestClientExitNotifyRecordsReasonAndFiresCallback mirrors
// TestExitNotifyClosesSessionImmediately's own live-tunnel-up harness
// (lifecycle_test.go), adding an OnSessionClosed assertion: an
// authenticated explicit-exit-notify records CloseReasonClientExitNotify
// and fires OnSessionClosed with that same reason.
func TestClientExitNotifyRecordsReasonAndFiresCallback(t *testing.T) {
	_, network, err := net.ParseCIDR("10.61.1.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	tlsCfg, caPool := testHandshakeTLSConfig(t)

	sessions := make(chan *Session, 1)
	closed := make(chan CloseReason, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
		OnSessionClosed: func(sess *Session, r CloseReason) {
			closed <- r
		},
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client, replyReader := tunnelUpTestClient(t, key, serverPC.LocalAddr(), caPool)
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	if _, err := readControlString(replyReader, maxControlStringLen); err != nil {
		t.Fatalf("read push reply: %v", err)
	}

	var sess *Session
	select {
	case sess = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}

	serverKeys, ok := sess.DebugDataKeys()
	if !ok {
		t.Fatal("DebugDataKeys() not ok")
	}
	clientWrapper, err := datachan.NewWrapper(mirrorDataKeys(serverKeys), sess.PeerID(), 0)
	if err != nil {
		t.Fatalf("build client wrapper: %v", err)
	}
	sealed, err := clientWrapper.Seal(nil, occExitPayload())
	if err != nil {
		t.Fatalf("seal exit-notify: %v", err)
	}
	if _, err := client.pc.WriteTo(sealed, serverPC.LocalAddr()); err != nil {
		t.Fatalf("write exit-notify: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() never fired after exit-notify")
	}
	if got := sess.CloseReason(); got != CloseReasonClientExitNotify {
		t.Fatalf("CloseReason() = %v, want CloseReasonClientExitNotify", got)
	}

	select {
	case r := <-closed:
		if r != CloseReasonClientExitNotify {
			t.Fatalf("OnSessionClosed reason = %v, want CloseReasonClientExitNotify", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnSessionClosed was never called")
	}
}

// TestIdleReapRecordsReasonAndFiresCallback drives runReap directly
// (newReapTestSession's own established pattern), with a manually-attached
// Server carrying OnSessionClosed and a manually-set published flag —
// mirroring how ovpn.go's runHandshake sets it right before OnSession
// fires — to prove the reaper's teardown records CloseReasonIdleReap and
// fires the callback with it.
func TestIdleReapRecordsReasonAndFiresCallback(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

	closed := make(chan CloseReason, 1)
	sess.srv.cfg.OnSessionClosed = func(s *Session, r CloseReason) { closed <- r }
	sess.published.Store(true)

	tick := make(chan time.Time)
	go sess.runReap(tick)

	clock.Advance(2 * time.Minute)
	tick <- time.Now()

	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() never fired after idle reap")
	}
	if got := sess.CloseReason(); got != CloseReasonIdleReap {
		t.Fatalf("CloseReason() = %v, want CloseReasonIdleReap", got)
	}

	select {
	case r := <-closed:
		if r != CloseReasonIdleReap {
			t.Fatalf("OnSessionClosed reason = %v, want CloseReasonIdleReap", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnSessionClosed was never called")
	}
}

// TestServerCloseRecordsReasonForEveryLiveSession asserts Server.Close's
// per-session teardown loop records CloseReasonServerClose for every
// session it tears down, and fires OnSessionClosed for each.
func TestServerCloseRecordsReasonForEveryLiveSession(t *testing.T) {
	srv := &Server{sessions: make(map[sessionKey]*Session)}

	var mu sync.Mutex
	var reasons []CloseReason
	srv.cfg.OnSessionClosed = func(sess *Session, r CloseReason) {
		mu.Lock()
		reasons = append(reasons, r)
		mu.Unlock()
	}

	var sessions []*Session
	for i := 0; i < 3; i++ {
		sess := &Session{srv: srv, stopCh: make(chan struct{})}
		sess.published.Store(true)
		sess.key = sessionKey{addr: string(rune('a' + i))}
		srv.sessions[sess.key] = sess
		sessions = append(sessions, sess)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for i, sess := range sessions {
		if got := sess.CloseReason(); got != CloseReasonServerClose {
			t.Errorf("session %d CloseReason() = %v, want CloseReasonServerClose", i, got)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reasons) != 3 {
		t.Fatalf("OnSessionClosed called %d times, want 3", len(reasons))
	}
	for i, r := range reasons {
		if r != CloseReasonServerClose {
			t.Errorf("reasons[%d] = %v, want CloseReasonServerClose", i, r)
		}
	}
}

// TestServerCloseWaitsForBlockingOnSessionClosed asserts Server.Close does
// not return until an OnSessionClosed callback it triggered — which
// deliberately blocks for a measurable interval — has itself returned.
// The assertion reads a flag the callback sets, checked immediately after
// Close() returns: no sleep-based polling loop.
func TestServerCloseWaitsForBlockingOnSessionClosed(t *testing.T) {
	srv := &Server{sessions: make(map[sessionKey]*Session)}

	var callbackFinished atomic.Bool
	srv.cfg.OnSessionClosed = func(sess *Session, r CloseReason) {
		time.Sleep(150 * time.Millisecond)
		callbackFinished.Store(true)
	}

	sess := &Session{srv: srv, stopCh: make(chan struct{})}
	sess.published.Store(true)
	sess.key = sessionKey{addr: "only"}
	srv.sessions[sess.key] = sess

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !callbackFinished.Load() {
		t.Fatal("Server.Close() returned before its blocking OnSessionClosed callback finished")
	}
}

// TestCloseIsIdempotentForCallback asserts calling Close twice, and
// calling it concurrently from N goroutines, yields exactly ONE
// OnSessionClosed invocation.
func TestCloseIsIdempotentForCallback(t *testing.T) {
	srv := &Server{sessions: make(map[sessionKey]*Session)}
	var callCount atomic.Int32
	closed := make(chan CloseReason, 1)
	srv.cfg.OnSessionClosed = func(sess *Session, r CloseReason) {
		callCount.Add(1)
		closed <- r
	}

	sess := &Session{srv: srv, stopCh: make(chan struct{})}
	sess.published.Store(true)

	// Sequential double-close.
	_ = sess.Close()
	_ = sess.Close()

	// Concurrent close from N goroutines.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sess.Close()
		}()
	}
	wg.Wait()

	var reason CloseReason
	select {
	case reason = <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("OnSessionClosed was never called")
	}
	select {
	case <-closed:
		t.Fatal("OnSessionClosed was called a second time")
	case <-time.After(200 * time.Millisecond):
	}
	if got := callCount.Load(); got != 1 {
		t.Fatalf("OnSessionClosed called %d times, want 1", got)
	}
	if reason != CloseReasonEmbedder {
		t.Fatalf("recorded reason = %v, want CloseReasonEmbedder", reason)
	}
	if got := sess.CloseReason(); got != CloseReasonEmbedder {
		t.Fatalf("CloseReason() = %v, want CloseReasonEmbedder", got)
	}
}

// TestConcurrentCloseWithReasonRecordsExactlyOneReason races two distinct
// CloseReasons against the same session's closeWithReason and asserts
// exactly one — whichever won stopOnce — is ever recorded, never a
// corrupted or mixed value, across many trials.
func TestConcurrentCloseWithReasonRecordsExactlyOneReason(t *testing.T) {
	for trial := 0; trial < 50; trial++ {
		sess := &Session{stopCh: make(chan struct{})}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = sess.closeWithReason(CloseReasonEmbedder)
		}()
		go func() {
			defer wg.Done()
			_ = sess.closeWithReason(CloseReasonIdleReap)
		}()
		wg.Wait()

		reason := sess.CloseReason()
		if reason != CloseReasonEmbedder && reason != CloseReasonIdleReap {
			t.Fatalf("trial %d: CloseReason() = %v, want CloseReasonEmbedder or CloseReasonIdleReap", trial, reason)
		}
	}
}

// TestOnSessionClosedPanicRecovered asserts a panicking OnSessionClosed is
// recovered (never crashes the process) and reaches Config.OnSessionPanic
// with a non-empty stack trace.
func TestOnSessionClosedPanicRecovered(t *testing.T) {
	srv := &Server{sessions: make(map[sessionKey]*Session)}
	srv.cfg.OnSessionClosed = func(sess *Session, r CloseReason) {
		panic("boom")
	}
	panicDone := make(chan struct{})
	var recovered atomic.Value
	var stackLen atomic.Int32
	srv.cfg.OnSessionPanic = func(sess *Session, rec any, stack []byte) {
		recovered.Store(rec)
		stackLen.Store(int32(len(stack)))
		close(panicDone)
	}

	sess := &Session{srv: srv, stopCh: make(chan struct{})}
	sess.published.Store(true)

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-panicDone:
	case <-time.After(2 * time.Second):
		t.Fatal("OnSessionPanic was never called")
	}
	if got, _ := recovered.Load().(string); got != "boom" {
		t.Fatalf("recovered value = %v, want %q", recovered.Load(), "boom")
	}
	if stackLen.Load() == 0 {
		t.Fatal("captured stack trace was empty")
	}
}

// TestSessionTornDownBeforePublishProducesNoCallback asserts a session
// closed before it was ever handed to OnSession (published never set —
// the handshake-failure/handshake-window-timeout case) records
// CloseReasonUnknown and never triggers OnSessionClosed at all.
func TestSessionTornDownBeforePublishProducesNoCallback(t *testing.T) {
	srv := &Server{sessions: make(map[sessionKey]*Session), handshakeWindow: time.Millisecond}
	called := make(chan struct{}, 1)
	srv.cfg.OnSessionClosed = func(sess *Session, r CloseReason) {
		called <- struct{}{}
	}

	sess := &Session{
		srv:    srv,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	// sess.published is deliberately never set — this session never
	// reached OnSession.
	srv.enforceHandshakeWindow(sess)

	if got := sess.CloseReason(); got != CloseReasonUnknown {
		t.Fatalf("CloseReason() = %v, want CloseReasonUnknown (never published)", got)
	}

	select {
	case <-called:
		t.Fatal("OnSessionClosed was called for a session that was never published to OnSession")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestPingIntervalAndReapWindowPushed is Welle-1 item 1e's live proof:
// non-default Config.PingInterval/Config.ReapWindow values reach the real
// PUSH_REPLY over a live tunnel-up exchange, and the package defaults
// (10s/60s) are what an unset Config still pushes.
func TestPingIntervalAndReapWindowPushed(t *testing.T) {
	cases := []struct {
		name        string
		pingInt     time.Duration
		reapWindow  time.Duration
		wantSegment string
		cidr        string
	}{
		{"custom", 5 * time.Second, 30 * time.Second, "ping 5,ping-restart 30", "10.62.0.0/24"},
		{"defaults", 0, 0, "ping 10,ping-restart 60", "10.62.1.0/24"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, network, err := net.ParseCIDR(c.cidr)
			if err != nil {
				t.Fatalf("parse network: %v", err)
			}
			key := testTLSCryptKey(t)

			serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("server listen: %v", err)
			}
			defer serverPC.Close()

			tlsCfg, caPool := testHandshakeTLSConfig(t)

			srv := NewServer(Config{
				TLSCryptKey:  key,
				TLSConfig:    tlsCfg,
				Network:      network,
				PingInterval: c.pingInt,
				ReapWindow:   c.reapWindow,
				AuthUserPass: testPermissiveAuthUserPass,
			})
			go func() { _ = srv.Serve(serverPC) }()
			defer srv.Close()

			client, replyReader := tunnelUpTestClient(t, key, serverPC.LocalAddr(), caPool)
			defer client.Close()

			if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
				t.Fatalf("write push request: %v", err)
			}
			reply, err := readControlString(replyReader, maxControlStringLen)
			if err != nil {
				t.Fatalf("read push reply: %v", err)
			}
			if !strings.Contains(reply, c.wantSegment) {
				t.Fatalf("push reply = %q, want it to contain %q", reply, c.wantSegment)
			}
		})
	}
}

// TestServeValidatesLifecycleConfig asserts Serve rejects negative
// PingInterval/ReapWindow/SessionInboundQueue, and a ReapWindow smaller
// than twice the resolved PingInterval, with a descriptive error.
func TestServeValidatesLifecycleConfig(t *testing.T) {
	key := testTLSCryptKey(t)

	cases := []struct {
		name string
		cfg  Config
	}{
		{"negative PingInterval", Config{PingInterval: -time.Second}},
		{"negative ReapWindow", Config{ReapWindow: -time.Second}},
		{"negative SessionInboundQueue", Config{SessionInboundQueue: -1}},
		{"ReapWindow less than 2x PingInterval", Config{PingInterval: 40 * time.Second, ReapWindow: 60 * time.Second}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.cfg
			cfg.TLSCryptKey = key
			cfg.TLSConfig = testTLSConfig(t)
			srv := NewServer(cfg)

			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer pc.Close()

			done := make(chan error, 1)
			go func() { done <- srv.Serve(pc) }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Serve() = nil, want a validation error")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Serve() did not return a validation error")
			}
		})
	}
}

// TestSessionInboundQueueSizing asserts Config.SessionInboundQueue sizes
// the session's ipInbound channel, and that it defaults to
// ipInboundQueueSize when unset.
func TestSessionInboundQueueSizing(t *testing.T) {
	cases := []struct {
		name  string
		queue int
		want  int
		cidr  string
	}{
		{"custom", 4, 4, "10.63.0.0/24"},
		{"default", 0, ipInboundQueueSize, "10.63.1.0/24"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, network, err := net.ParseCIDR(c.cidr)
			if err != nil {
				t.Fatalf("parse network: %v", err)
			}
			key := testTLSCryptKey(t)

			serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("server listen: %v", err)
			}
			defer serverPC.Close()

			tlsCfg, caPool := testHandshakeTLSConfig(t)

			sessions := make(chan *Session, 1)
			srv := NewServer(Config{
				TLSCryptKey:         key,
				TLSConfig:           tlsCfg,
				Network:             network,
				SessionInboundQueue: c.queue,
				AuthUserPass:        testPermissiveAuthUserPass,
				OnSession:           func(sess *Session) { sessions <- sess },
			})
			go func() { _ = srv.Serve(serverPC) }()
			defer srv.Close()

			client, replyReader := tunnelUpTestClient(t, key, serverPC.LocalAddr(), caPool)
			defer client.Close()

			if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
				t.Fatalf("write push request: %v", err)
			}
			if _, err := readControlString(replyReader, maxControlStringLen); err != nil {
				t.Fatalf("read push reply: %v", err)
			}

			var sess *Session
			select {
			case sess = <-sessions:
			case <-time.After(5 * time.Second):
				t.Fatal("OnSession was never called")
			}

			if got := cap(sess.ipInbound); got != c.want {
				t.Fatalf("cap(sess.ipInbound) = %d, want %d", got, c.want)
			}
		})
	}
}
