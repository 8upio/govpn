// lifecycle_test.go exercises Phase 4's session-teardown mechanics
// (SESS-05): explicit-exit-notify (OCC_EXIT) detection on the
// authenticated data channel, idle-session reaping on a
// server-authoritative clock, and the io.EOF/goroutine-teardown contract
// every teardown cause must uphold. Fast-tier only — no Docker, no real
// client — and, per this plan's must_haves prohibition, the reap window is
// crossed only through the injected clock, never a real wall-clock sleep.
package ovpn

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/datachan"
	"github.com/8upio/govpn/internal/wire"
)

// occExitPayload builds the 17-byte explicit-exit-notify payload (occMagic
// followed by occExit) a real client sends on the authenticated data
// channel (D-21).
func occExitPayload() []byte {
	return append(append([]byte{}, occMagic...), occExit)
}

// readWithTimeout calls sess.Read(buf) on its own goroutine and fails the
// test if it does not return within d — Session.Read has no deadline
// mechanism of its own (it blocks until a packet arrives or stopCh
// closes), so a bounded-wait helper is needed for any assertion that a
// packet was (or was not) delivered without risking a permanent hang.
func readWithTimeout(t testing.TB, sess *Session, buf []byte, d time.Duration) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := sess.Read(buf)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(d):
		t.Fatal("Read timed out")
		return 0, nil
	}
}

// TestExitNotifyClosesSessionImmediately is Task 1's D-21 proof, driven
// against a live srv.Serve loop with a real tunnel-up synthetic client: a
// 17-byte occMagic+occExit payload sealed under the client's own
// data-channel keys and sent as an ordinary P_DATA_V2 packet closes the
// session immediately — Session.Read returns io.EOF, the session leaves
// Server.sessions/Server.dataSessions, and its tunnel IP/peer-id return to
// the pool — while three negative cases (wrong opcode, truncated magic, an
// ordinary IP packet) leave the session open and functional.
func TestExitNotifyClosesSessionImmediately(t *testing.T) {
	_, network, err := net.ParseCIDR("10.60.0.0/24")
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
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
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

	sendSealed := func(payload []byte) {
		t.Helper()
		sealed, err := clientWrapper.Seal(nil, payload)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if _, err := client.pc.WriteTo(sealed, serverPC.LocalAddr()); err != nil {
			t.Fatalf("write data packet: %v", err)
		}
	}

	buf := make([]byte, 200)

	// Negative 1: magic matches but the opcode byte does not (OCC_REQUEST,
	// not OCC_EXIT) — must not close the session, and (since this plan
	// only special-cases OCC_EXIT) is delivered through like any other
	// payload.
	wrongOpcode := append(append([]byte{}, occMagic...), 0x00)
	sendSealed(wrongOpcode)
	n, err := readWithTimeout(t, sess, buf, 5*time.Second)
	if err != nil {
		t.Fatalf("Read after wrong-opcode payload: %v", err)
	}
	if !bytes.Equal(buf[:n], wrongOpcode) {
		t.Fatalf("Read = %x, want %x (wrong-opcode payload, session must stay open)", buf[:n], wrongOpcode)
	}

	// Negative 2: exactly the 16-byte magic with nothing after it — must
	// not close the session and must not panic.
	truncated := append([]byte{}, occMagic...)
	sendSealed(truncated)
	n, err = readWithTimeout(t, sess, buf, 5*time.Second)
	if err != nil {
		t.Fatalf("Read after truncated-magic payload: %v", err)
	}
	if !bytes.Equal(buf[:n], truncated) {
		t.Fatalf("Read = %x, want %x (truncated-magic payload, session must stay open)", buf[:n], truncated)
	}

	// Negative 3: an ordinary IP packet is unaffected.
	ordinary := bytes.Repeat([]byte{0x55}, 60)
	sendSealed(ordinary)
	n, err = readWithTimeout(t, sess, buf, 5*time.Second)
	if err != nil {
		t.Fatalf("Read after ordinary IP packet: %v", err)
	}
	if !bytes.Equal(buf[:n], ordinary) {
		t.Fatalf("Read = %x, want %x (ordinary IP packet)", buf[:n], ordinary)
	}

	// Positive: the real OCC_EXIT payload closes the session immediately.
	sendSealed(occExitPayload())

	if _, err := readWithTimeout(t, sess, buf, 5*time.Second); err != io.EOF {
		t.Fatalf("Read after OCC_EXIT = %v, want io.EOF", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		_, inSessions := srv.sessions[sess.key]
		_, inData := srv.dataSessions[sess.PeerID()]
		srv.mu.Unlock()
		if !inSessions && !inData {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session/dataSessions entry was never removed after OCC_EXIT")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, _, err := srv.pool.allocate(); err != nil {
		t.Fatalf("pool.allocate() after OCC_EXIT teardown: %v (tunnel IP/peer-id must be reusable)", err)
	}
}

// TestExitNotifyOnLameDuckKeyClosesSession is Task 1's proof that
// OCC_EXIT detection runs on ANY successfully-decrypted data packet, not
// only the primary slot's: after a renegotiation, an OCC_EXIT payload
// sealed under the now-demoted LAME-DUCK key, inside the transition
// window, still closes the session.
func TestExitNotifyOnLameDuckKeyClosesSession(t *testing.T) {
	_, network, err := net.ParseCIDR("10.60.1.0/24")
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
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
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

	oldServerKeys, ok := sess.DebugDataKeys()
	if !ok {
		t.Fatal("DebugDataKeys() not ok before renegotiation")
	}
	oldClientWrapper, err := datachan.NewWrapper(mirrorDataKeys(oldServerKeys), sess.PeerID(), 0)
	if err != nil {
		t.Fatalf("build old client wrapper: %v", err)
	}

	newConn := client.renegotiate(t, serverPC.LocalAddr(), 1)
	if err := newConn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set reneg deadline: %v", err)
	}
	renegTLSConn := tls.Client(newConn, &tls.Config{
		RootCAs:    caPool,
		ServerName: testHandshakeServerCN,
		MinVersion: tls.VersionTLS12,
	})
	if err := renegTLSConn.Handshake(); err != nil {
		t.Fatalf("reneg client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2(renegTLSConn); err != nil {
		t.Fatalf("write client Key Method 2 (reneg): %v", err)
	}
	if err := readTestServerKeyMethod2(renegTLSConn); err != nil {
		t.Fatalf("read server Key Method 2 (reneg): %v", err)
	}
	if err := newConn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear reneg deadline: %v", err)
	}
	waitForPrimaryKeyID(t, sess, 1)

	sealed, err := oldClientWrapper.Seal(nil, occExitPayload())
	if err != nil {
		t.Fatalf("seal OCC_EXIT under lame-duck key: %v", err)
	}
	if _, err := client.pc.WriteTo(sealed, serverPC.LocalAddr()); err != nil {
		t.Fatalf("write lame-duck OCC_EXIT packet: %v", err)
	}

	buf := make([]byte, 200)
	if _, err := readWithTimeout(t, sess, buf, 5*time.Second); err != io.EOF {
		t.Fatalf("Read after lame-duck OCC_EXIT = %v, want io.EOF", err)
	}
}

// newReapTestSession builds a minimal Session (mirroring
// TestPingNeverReachesSessionRead's own minimal-construction style) with a
// live, self-symmetric data-channel wrapper and an injected clock/reap
// window, so Task 2's tests can drive handleDataPacket/pump/runReap
// directly without a real network round trip.
func newReapTestSession(t testing.TB, clock *fakeClock, reapWindow time.Duration) *Session {
	t.Helper()
	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sess := &Session{
		primary:   keySlot{wrapper: wrapper},
		ipInbound: make(chan []byte, ipInboundQueueSize),
		stopCh:    make(chan struct{}),
		clock:     clock,
		srv:       &Server{reapWindow: reapWindow},
	}
	sess.lastAuthTraffic = clock.Now()
	return sess
}

// TestSilentSessionReaped is Task 2's core D-22 proof: with an injected
// clock and tick channel, a session with no authenticated traffic for the
// reap window is closed by runReap.
func TestSilentSessionReaped(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runReap(tick)
	}()

	clock.Advance(2 * time.Minute)
	tick <- time.Now()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runReap did not close the session once the reap window elapsed")
	}

	buf := make([]byte, 10)
	if _, err := readWithTimeout(t, sess, buf, 2*time.Second); err != io.EOF {
		t.Fatalf("Read after reap = %v, want io.EOF", err)
	}
}

// TestAuthenticatedDataResetsReapTimer is Task 2's proof that a
// successfully-decrypted data packet (primary slot) resets the reap timer:
// a session receiving one just under the window is not reaped.
func TestAuthenticatedDataResetsReapTimer(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

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

	sealed, err := sess.primary.wrapper.Seal(nil, bytes.Repeat([]byte{0x22}, 20))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sess.handleDataPacket(sealed)
	tick <- time.Now()

	select {
	case <-done:
		t.Fatal("session was reaped even though a data packet reset the timer")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestLameDuckDecryptResetsReapTimer is Task 2's proof that a data packet
// decrypting under the LAME-DUCK slot resets the reap timer exactly like
// one decrypting under the primary.
func TestLameDuckDecryptResetsReapTimer(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

	// Make the primary slot fail to decrypt anything (distinct keys), and
	// give the lame-duck slot the wrapper that will actually succeed.
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

	sealed, err := lameWrapper.Seal(nil, bytes.Repeat([]byte{0x33}, 20))
	if err != nil {
		t.Fatalf("Seal (lame-duck): %v", err)
	}
	sess.handleDataPacket(sealed)
	tick <- time.Now()

	select {
	case <-done:
		t.Fatal("session was reaped even though a lame-duck-key data packet reset the timer")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestForgedPacketDoesNotResetReapTimer is Task 2's T-04-07 proof: a
// packet that fails to authenticate on both slots does NOT reset the reap
// timer — an attacker cannot keep a dead session alive with garbage.
func TestForgedPacketDoesNotResetReapTimer(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runReap(tick)
	}()

	clock.Advance(50 * time.Second)

	// Garbage bytes: fails to authenticate on the only live (primary)
	// slot.
	sess.handleDataPacket(bytes.Repeat([]byte{0xFF}, 60))

	clock.Advance(20 * time.Second) // now 70s since the last REAL touch
	tick <- time.Now()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session was not reaped — the forged packet must not have reset the timer")
	}
}

// TestReapTimerStopsOnClose is Task 2's proof that the reaper goroutine
// exits on Close (via stopCh), like every other per-session goroutine.
func TestReapTimerStopsOnClose(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Minute)

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runReap(tick)
	}()

	close(sess.stopCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runReap did not exit after stopCh was closed")
	}
}

// TestDeliveredControlPacketResetsReapTimer is Task 2's proof that a
// delivered control packet alone resets the reap timer — a client
// mid-renegotiation with no data traffic is not reaped.
func TestDeliveredControlPacketResetsReapTimer(t *testing.T) {
	f := newRenegTestFixture(t)
	f.srv.reapWindow = time.Minute
	sess := f.newSession(t)
	sess.inbound = make(chan wire.ControlPacket, inboundQueueSize)
	sess.lastAuthTraffic = f.clock.Now()

	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		sess.pump()
	}()

	reapTick := make(chan time.Time)
	reapDone := make(chan struct{})
	go func() {
		defer close(reapDone)
		sess.runReap(reapTick)
	}()

	f.clock.Advance(50 * time.Second)

	sess.inbound <- wire.ControlPacket{
		Opcode:    wire.OpControlV1,
		KeyID:     0,
		SessionID: f.clientSID,
		PacketID:  0,
	}

	wantTouch := f.clock.Now()
	deadline := time.Now().Add(2 * time.Second)
	for {
		sess.mu.Lock()
		got := sess.lastAuthTraffic
		sess.mu.Unlock()
		if got.Equal(wantTouch) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lastAuthTraffic was never touched by the delivered control packet")
		}
		time.Sleep(2 * time.Millisecond)
	}

	reapTick <- time.Now()

	select {
	case <-reapDone:
		t.Fatal("session was reaped even though a delivered control packet reset the timer")
	case <-time.After(200 * time.Millisecond):
	}

	close(sess.stopCh)
	<-pumpDone
	<-reapDone
}

// TestReadWriteReturnEOFAfterEveryTeardownCause is Task 3's D-22 proof:
// Read and Write both return io.EOF after teardown from any of the four
// causes — embedder Close, exit-notify, reap, and handshake-window
// timeout.
func TestReadWriteReturnEOFAfterEveryTeardownCause(t *testing.T) {
	cases := []struct {
		name    string
		trigger func(t *testing.T) *Session
	}{
		{
			name: "embedder Close",
			trigger: func(t *testing.T) *Session {
				sess := &Session{stopCh: make(chan struct{})}
				_ = sess.Close()
				return sess
			},
		},
		{
			name: "exit-notify",
			trigger: func(t *testing.T) *Session {
				wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
				if err != nil {
					t.Fatalf("NewWrapper: %v", err)
				}
				sess := &Session{
					stopCh:    make(chan struct{}),
					primary:   keySlot{wrapper: wrapper},
					ipInbound: make(chan []byte, ipInboundQueueSize),
				}
				sealed, err := wrapper.Seal(nil, occExitPayload())
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				sess.handleDataPacket(sealed)
				return sess
			},
		},
		{
			name: "reap",
			trigger: func(t *testing.T) *Session {
				clock := newFakeClock()
				sess := newReapTestSession(t, clock, time.Minute)
				clock.Advance(2 * time.Minute)

				tick := make(chan time.Time)
				go sess.runReap(tick)
				tick <- time.Now()

				deadline := time.Now().Add(2 * time.Second)
				for !sess.closing() {
					if time.Now().After(deadline) {
						t.Fatal("runReap never closed the session")
					}
					time.Sleep(2 * time.Millisecond)
				}
				return sess
			},
		},
		{
			name: "handshake-window timeout",
			trigger: func(t *testing.T) *Session {
				sess := &Session{
					stopCh: make(chan struct{}),
					doneCh: make(chan struct{}),
				}
				srv := &Server{handshakeWindow: time.Millisecond}
				srv.enforceHandshakeWindow(sess)
				return sess
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := tc.trigger(t)

			buf := make([]byte, 10)
			if _, err := readWithTimeout(t, sess, buf, 2*time.Second); err != io.EOF {
				t.Errorf("Read after %s = %v, want io.EOF", tc.name, err)
			}
			if _, err := sess.Write(buf); err != io.EOF {
				t.Errorf("Write after %s = %v, want io.EOF", tc.name, err)
			}
		})
	}
}

// TestNoGoroutineLeakAcrossSessionLifecycle is Task 3's T-04-09 proof: a
// full tunnel-up plus one renegotiation plus a teardown leaves no
// goroutine behind — pump, keepalive, the reneg ticker, the reaper, and
// the lame-duck Conn's retransmit loop must all have exited once the
// session is closed and unreferenced. This is the fast-tier sentinel for
// the same property plan 04-04 measures against the real client.
func TestNoGoroutineLeakAcrossSessionLifecycle(t *testing.T) {
	_, network, err := net.ParseCIDR("10.60.2.0/24")
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
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	// Baseline is taken AFTER the Serve loop's own long-lived goroutine
	// already exists, but BEFORE any session exists — so the only
	// goroutines this test's own bring-up/renegotiation/teardown sequence
	// can be blamed for are session-scoped ones (pump, keepalive, the
	// reneg ticker, the reaper, and any renegotiation Conn's retransmit
	// loop), not the server's own always-running read loop.
	runtime.Gosched()
	time.Sleep(10 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	client, replyReader := tunnelUpTestClient(t, key, serverPC.LocalAddr(), caPool)

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

	newConn := client.renegotiate(t, serverPC.LocalAddr(), 1)
	if err := newConn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set reneg deadline: %v", err)
	}
	renegTLSConn := tls.Client(newConn, &tls.Config{
		RootCAs:    caPool,
		ServerName: testHandshakeServerCN,
		MinVersion: tls.VersionTLS12,
	})
	if err := renegTLSConn.Handshake(); err != nil {
		t.Fatalf("reneg client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2(renegTLSConn); err != nil {
		t.Fatalf("write client Key Method 2 (reneg): %v", err)
	}
	if err := readTestServerKeyMethod2(renegTLSConn); err != nil {
		t.Fatalf("read server Key Method 2 (reneg): %v", err)
	}
	if err := newConn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear reneg deadline: %v", err)
	}
	waitForPrimaryKeyID(t, sess, 1)

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	client.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.Gosched()
		n := runtime.NumGoroutine()
		if n <= baseline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count = %d, want <= baseline %d after full teardown", n, baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
