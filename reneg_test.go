// reneg_test.go exercises Phase 4's soft-reset renegotiation (SESS-04):
// fast-tier, synthetic-client tests driven against a live srv.Serve loop —
// no Docker, no real client, no real-wall-clock sleeps for any protocol
// deadline (04-01-PLAN.md's must_haves prohibition: "No test in this plan
// sleeps on real wall-clock time to advance a renegotiation or expiry
// deadline; all three new deadlines are driven through an injected
// clock").
package ovpn

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/datachan"
	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/reliable"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// fakeClock is an injectable Clock a test fully controls, mirroring
// internal/reliable's own unexported fakeClock test helper — so this
// package's timer tests (server-initiated reneg, lame-duck expiry) can be
// driven deterministically in milliseconds instead of real seconds/hours
// (must_haves prohibition: no test in this plan advances a renegotiation
// or expiry deadline via a real sleep).
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(0, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}


// mirrorDataKeys inverts encrypt/decrypt slots — the deliberate mirror
// opposite of the server's own key-direction assignment, so a client-side
// Wrapper decrypts what the server encrypts and vice versa (Pitfall 1),
// matching TestSessionReadWriteDatagramSemantics's own established pattern
// in ovpn_test.go.
func mirrorDataKeys(server keyderiv.DataKeys) keyderiv.DataKeys {
	return keyderiv.DataKeys{
		EncryptCipher:     server.DecryptCipher,
		EncryptImplicitIV: server.DecryptImplicitIV,
		DecryptCipher:     server.EncryptCipher,
		DecryptImplicitIV: server.EncryptImplicitIV,
	}
}

// waitForPrimaryKeyID polls sess's primary slot key-id until it equals
// want or the deadline elapses — never a fixed sleep. The server-side swap
// (runRenegotiation) happens on a goroutine independent of this test's own
// Key Method 2 read, so polling (not a synchronization primitive the
// server exposes) is the only option that doesn't require adding
// test-only hooks to production code.
func waitForPrimaryKeyID(t testing.TB, sess *Session, want uint8) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sess.mu.Lock()
		got := sess.primary.keyID
		sess.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sess.primary.keyID never reached %d (last seen %d)", want, got)
		}
		time.Sleep(5 * time.Millisecond) // polling only — not a protocol deadline wait
	}
}

// TestSoftResetRollover is 04-01-PLAN.md Task 1's end-to-end proof: a
// synthetic client that has reached tunnel-up opens a second
// control-channel Conn at key-id 1 over the SAME tls-crypt Wrapper and
// session IDs and sends SOFT_RESET_V1, completes a second TLS handshake
// and Key Method 2 exchange against the live server, and afterward: a data
// packet sealed under the NEW key-id-1 keys reaches Session.Read, a data
// packet sealed under the OLD key-id-0 keys ALSO reaches it (the lame-duck
// slot is still live), Session.Write's output opens only under the NEW
// keys (transmit switched), and AssignedIP/PeerID/the *Session pointer are
// all unchanged across the rollover with OnSession firing exactly once.
func TestSoftResetRollover(t *testing.T) {
	_, network, err := net.ParseCIDR("10.30.0.0/24")
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

	var onSessionCount int32
	sessions := make(chan *Session, 2)
	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		OnSession: func(sess *Session) {
			atomic.AddInt32(&onSessionCount, 1)
			sessions <- sess
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

	wantIP := sess.AssignedIP()
	wantPeerID := sess.PeerID()
	if wantIP == nil {
		t.Fatal("AssignedIP() is nil before renegotiation")
	}

	oldServerKeys, ok := sess.DebugDataKeys()
	if !ok {
		t.Fatal("DebugDataKeys() not ok before renegotiation")
	}
	oldClientWrapper, err := datachan.NewWrapper(mirrorDataKeys(oldServerKeys), wantPeerID, 0)
	if err != nil {
		t.Fatalf("build old client wrapper: %v", err)
	}

	// --- Renegotiate to key-id 1. ---
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

	if got := sess.AssignedIP(); !got.Equal(wantIP) {
		t.Errorf("AssignedIP() after reneg = %s, want %s (unchanged)", got, wantIP)
	}
	if got := sess.PeerID(); got != wantPeerID {
		t.Errorf("PeerID() after reneg = %d, want %d (unchanged)", got, wantPeerID)
	}
	select {
	case <-sessions:
		t.Fatal("OnSession fired a second time across a renegotiation")
	case <-time.After(200 * time.Millisecond):
	}
	if n := atomic.LoadInt32(&onSessionCount); n != 1 {
		t.Errorf("onSessionCount = %d, want exactly 1", n)
	}

	newServerKeys, ok := sess.DebugDataKeys()
	if !ok {
		t.Fatal("DebugDataKeys() not ok after renegotiation")
	}
	newClientWrapper, err := datachan.NewWrapper(mirrorDataKeys(newServerKeys), wantPeerID, 1)
	if err != nil {
		t.Fatalf("build new client wrapper: %v", err)
	}

	// New key decrypts.
	payloadNew := bytes.Repeat([]byte{0xAB}, 40)
	sealedNew, err := newClientWrapper.Seal(nil, payloadNew)
	if err != nil {
		t.Fatalf("seal under new key: %v", err)
	}
	sess.handleDataPacket(sealedNew)

	buf := make([]byte, 2048)
	n, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("Read after new-key packet: %v", err)
	}
	if !bytes.Equal(buf[:n], payloadNew) {
		t.Fatalf("Read = %x, want %x (new-key packet)", buf[:n], payloadNew)
	}

	// Old key STILL decrypts — the lame-duck slot is live during the
	// transition window (D-18).
	payloadOld := bytes.Repeat([]byte{0xCD}, 40)
	sealedOld, err := oldClientWrapper.Seal(nil, payloadOld)
	if err != nil {
		t.Fatalf("seal under old key: %v", err)
	}
	sess.handleDataPacket(sealedOld)

	n, err = sess.Read(buf)
	if err != nil {
		t.Fatalf("Read after old-key packet: %v", err)
	}
	if !bytes.Equal(buf[:n], payloadOld) {
		t.Fatalf("Read = %x, want %x (old-key packet, lame-duck window)", buf[:n], payloadOld)
	}

	// Session.Write's output opens only under the new key — transmit has
	// switched.
	writePayload := bytes.Repeat([]byte{0xEF}, 40)
	if _, err := sess.Write(writePayload); err != nil {
		t.Fatalf("Write after renegotiation: %v", err)
	}
	var wireBytes []byte
	select {
	case wireBytes = <-client.dataOut:
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe Write's output data packet")
	}
	if _, err := newClientWrapper.Open(nil, wireBytes); err != nil {
		t.Fatalf("new-key client Open of Write's output: %v", err)
	}
	if _, err := oldClientWrapper.Open(nil, wireBytes); err == nil {
		t.Fatal("old-key client Open of Write's output unexpectedly succeeded — transmit did not switch to the new key")
	}
}

// TestServerInitiatedRenegOnRenegSec is 04-01-PLAN.md Task 2's proof that
// the server's own reneg-sec timer fires with no inbound client packet:
// driving Session.runReneg from an injected tick channel, with an
// injected clock advanced past the server's resolved renegSec, produces a
// SOFT_RESET_V1 at the next key-id on the wire — before any datagram was
// ever sent from the (silent, in this test) client.
func TestServerInitiatedRenegOnRenegSec(t *testing.T) {
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()
	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	serverWrapper, err := tlscrypt.NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}
	clientWrapper, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	var clientSID, serverSID wire.SessionID
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}
	if _, err := rand.Read(serverSID[:]); err != nil {
		t.Fatalf("generate server session id: %v", err)
	}

	primaryConn := ctrlconn.New(serverSID, clientSID, serverWrapper, packetConnTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	defer primaryConn.Close()

	clock := newFakeClock()
	srv := &Server{
		pc:           serverPC,
		renegSec:     30 * time.Second,
		sessions:     make(map[sessionKey]*Session),
		dataSessions: make(map[uint32]*Session),
	}

	sess := &Session{
		SessionID:       serverSID,
		clientSessionID: clientSID,
		wrapper:         serverWrapper,
		conn:            primaryConn,
		RemoteAddr:      clientPC.LocalAddr(),
		srv:             srv,
		clock:           clock,
		stopCh:          make(chan struct{}),
		primary:         keySlot{keyID: 0, conn: primaryConn, established: clock.Now()},
	}

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runReneg(tick)
	}()
	defer func() {
		close(sess.stopCh)
		<-done
	}()

	clock.Advance(31 * time.Second)
	tick <- time.Now()

	if err := clientPC.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set client read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := clientPC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read server-initiated soft reset: %v", err)
	}

	header, _, err := clientWrapper.Unwrap(nil, buf[:n])
	if err != nil {
		t.Fatalf("client unwrap: %v", err)
	}
	opcode, keyID := wire.ParseHeaderByte(header[0])
	if opcode != wire.OpControlSoftResetV1 {
		t.Fatalf("opcode = %v, want OpControlSoftResetV1", opcode)
	}
	if keyID != 1 {
		t.Fatalf("keyID = %d, want 1", keyID)
	}
}

// TestRenegTimerRearmsAfterRollover is 04-01-PLAN.md Task 2's proof that
// the reneg-sec deadline is measured from the NEW primary slot's
// established timestamp after a rollover, not from session start: a
// client-initiated rollover to key-id 1 completes first, then advancing
// the injected clock past RenegSec again (measured from key-id 1's own
// established time) produces a SECOND, server-initiated renegotiation to
// key-id 2 — with no further real-time modeling of either deadline.
func TestRenegTimerRearmsAfterRollover(t *testing.T) {
	_, network, err := net.ParseCIDR("10.31.0.0/24")
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

	clock := newFakeClock()
	sessions := make(chan *Session, 2)
	srv := &Server{
		cfg: Config{
			TLSCryptKey: key,
			TLSConfig:   tlsCfg,
			Network:     network,
			RenegSec:    time.Hour,
			OnSession: func(sess *Session) {
				sessions <- sess
			},
		},
		handshakeWindow: reliable.HandshakeWindow,
		sessions:        make(map[sessionKey]*Session),
		dataSessions:    make(map[uint32]*Session),
		clock:           clock,
	}
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

	// --- Rollover 1: client-initiated, to key-id 1. ---
	newConn1 := client.renegotiate(t, serverPC.LocalAddr(), 1)
	if err := newConn1.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set reneg1 deadline: %v", err)
	}
	tlsConn1 := tls.Client(newConn1, &tls.Config{
		RootCAs:    caPool,
		ServerName: testHandshakeServerCN,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn1.Handshake(); err != nil {
		t.Fatalf("reneg1 client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2(tlsConn1); err != nil {
		t.Fatalf("write client Key Method 2 (reneg1): %v", err)
	}
	if err := readTestServerKeyMethod2(tlsConn1); err != nil {
		t.Fatalf("read server Key Method 2 (reneg1): %v", err)
	}
	if err := newConn1.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear reneg1 deadline: %v", err)
	}
	waitForPrimaryKeyID(t, sess, 1)

	// --- Rollover 2: server-initiated, driven by the reneg-sec timer
	// re-arming from key-id 1's own established timestamp. Advance the
	// injected clock well past RenegSec so the server's real
	// renegPollInterval poll ticker picks it up on its next tick — this
	// waits for the poller to OBSERVE an already-advanced deadline, never
	// a real-time model of the deadline itself. The client reacts only
	// once it actually receives the server's own SOFT_RESET_V1
	// (testPushClientDemux auto-registers the new Conn and reports it
	// here) — it never speculatively guesses the next key-id in advance. ---
	clock.Advance(2 * time.Hour)

	var conn2 *ctrlconn.Conn
	select {
	case conn2 = <-client.serverInitiatedReneg:
	case <-time.After(10 * time.Second):
		t.Fatal("server never initiated the second (server-triggered) renegotiation")
	}
	if err := conn2.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set reneg2 deadline: %v", err)
	}
	tlsConn2 := tls.Client(conn2, &tls.Config{
		RootCAs:    caPool,
		ServerName: testHandshakeServerCN,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn2.Handshake(); err != nil {
		t.Fatalf("server-initiated reneg client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2(tlsConn2); err != nil {
		t.Fatalf("write client Key Method 2 (reneg2): %v", err)
	}
	if err := readTestServerKeyMethod2(tlsConn2); err != nil {
		t.Fatalf("read server Key Method 2 (reneg2): %v", err)
	}
	if err := conn2.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear reneg2 deadline: %v", err)
	}

	waitForPrimaryKeyID(t, sess, 2)
}

// TestRenegTimerStopsOnClose mirrors TestPingTimerStopsOnClose
// (ovpn_test.go): after stopCh closes, runReneg's own goroutine exits
// (asserted via a done channel, not a sleep), and it no longer accepts
// further ticks.
func TestRenegTimerStopsOnClose(t *testing.T) {
	sess := &Session{
		srv:    &Server{},
		stopCh: make(chan struct{}),
	}

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runReneg(tick)
	}()

	close(sess.stopCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reneg timer goroutine did not exit after stopCh closed")
	}

	select {
	case tick <- time.Now():
		t.Fatal("reneg timer goroutine accepted a tick after it should have already exited")
	case <-time.After(100 * time.Millisecond):
		// Expected: nobody is receiving on tick anymore.
	}
}
