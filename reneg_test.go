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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
		CipherKeyLen:      server.CipherKeyLen,
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
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
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
			TLSCryptKey:  key,
			TLSConfig:    tlsCfg,
			Network:      network,
			RenegSec:     time.Hour,
			AuthUserPass: testPermissiveAuthUserPass,
			OnSession: func(sess *Session) {
				sessions <- sess
			},
		},
		handshakeWindow: reliable.HandshakeWindow,
		// This test jumps the injected clock forward 2 hours (below) to
		// make the reneg-sec poller observe an already-elapsed deadline —
		// it doesn't exercise 04-02's idle-reap mechanism at all, so
		// reapWindow must be set well past that jump (a hand-built Server
		// bypasses NewServer's own defaultReapWindow default, mirroring
		// handshakeWindow's identical explicit-set-required precedent
		// above): without this, runReap would observe the same 2-hour
		// clock jump against a zero-value reapWindow and reap the session
		// before this test's own server-initiated renegotiation ever
		// completes.
		reapWindow:   24 * time.Hour,
		sessions:     make(map[sessionKey]*Session),
		dataSessions: make(map[uint32]*Session),
		clock:        clock,
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

// renegTestFixture is the shared plumbing every Task 3 white-box test
// below needs: a live server-side control-channel Conn (primaryConn), a
// throwaway *Server with no dependency on a full srv.Serve loop, and the
// raw session IDs/wrapper a hand-built wire.ControlPacket needs to look
// authentic to beginRenegotiation. Mirrors TestServerInitiatedRenegOnRenegSec's
// own direct-construction style.
type renegTestFixture struct {
	serverPC, clientPC   net.PacketConn
	serverWrapper        *tlscrypt.Wrapper
	clientSID, serverSID wire.SessionID
	primaryConn          *ctrlconn.Conn
	srv                  *Server
	clock                *fakeClock
}

func newRenegTestFixture(t testing.TB) *renegTestFixture {
	t.Helper()
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { _ = serverPC.Close() })
	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	t.Cleanup(func() { _ = clientPC.Close() })

	serverWrapper, err := tlscrypt.NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}

	var clientSID, serverSID wire.SessionID
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}
	if _, err := rand.Read(serverSID[:]); err != nil {
		t.Fatalf("generate server session id: %v", err)
	}

	primaryConn := ctrlconn.New(serverSID, clientSID, serverWrapper, packetConnTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	t.Cleanup(func() { _ = primaryConn.Close() })

	clock := newFakeClock()
	srv := &Server{
		pc: serverPC,
		// A large renegSec keeps checkReneg's own server-initiated-timer
		// trigger (Task 2) from firing spuriously in these Task 3 tests,
		// which target the receive-side rejection/expiry mechanisms only.
		renegSec: time.Hour,
		// renegMinInterval is normally resolved in Serve as
		// renegSec/renegMinIntervalDivisor (04-03-PLAN.md Task 2 bug fix);
		// this hand-built Server bypasses that resolution and must set it
		// explicitly — mirroring handshakeWindow/reapWindow's own
		// established precedent — to preserve TestRenegFloodRateLimited's
		// exact original 60s rate-limit window.
		renegMinInterval: time.Hour / renegMinIntervalDivisor,
		sessions:         make(map[sessionKey]*Session),
		dataSessions:     make(map[uint32]*Session),
	}

	return &renegTestFixture{
		serverPC:      serverPC,
		clientPC:      clientPC,
		serverWrapper: serverWrapper,
		clientSID:     clientSID,
		serverSID:     serverSID,
		primaryConn:   primaryConn,
		srv:           srv,
		clock:         clock,
	}
}

// newSession builds a Session at established key-id 0 over the fixture's
// primaryConn, ready for beginRenegotiation/startRenegotiation tests.
func (f *renegTestFixture) newSession(t testing.TB) *Session {
	t.Helper()
	return &Session{
		SessionID:       f.serverSID,
		clientSessionID: f.clientSID,
		wrapper:         f.serverWrapper,
		conn:            f.primaryConn,
		RemoteAddr:      f.clientPC.LocalAddr(),
		srv:             f.srv,
		clock:           f.clock,
		stopCh:          make(chan struct{}),
		primary:         keySlot{keyID: 0, conn: f.primaryConn, established: f.clock.Now()},
	}
}

// softReset builds a hand-crafted P_CONTROL_SOFT_RESET_V1 wire.ControlPacket
// at keyID, matching what handleDatagram would have parsed from an inbound
// datagram, for directly exercising beginRenegotiation.
func (f *renegTestFixture) softReset(keyID uint8) wire.ControlPacket {
	return wire.ControlPacket{
		Opcode:    wire.OpControlSoftResetV1,
		KeyID:     keyID,
		SessionID: f.clientSID,
	}
}

// TestForgedKeyIDRenegRejected is 04-01-PLAN.md Task 3's T-04-02 proof: a
// SOFT_RESET_V1 at a key-id other than the locally-computed next one
// (here, 5 instead of 1) is refused — no new Conn is constructed, no
// pending slot is published, and the session's primary key-id is
// unchanged.
func TestForgedKeyIDRenegRejected(t *testing.T) {
	f := newRenegTestFixture(t)
	sess := f.newSession(t)

	f.srv.beginRenegotiation(sess, f.softReset(5), f.clientPC.LocalAddr(), f.serverPC)

	sess.mu.Lock()
	gotKeyID := sess.primary.keyID
	gotPending := sess.pendingReneg
	sess.mu.Unlock()

	if gotKeyID != 0 {
		t.Errorf("primary.keyID = %d, want 0 (unchanged)", gotKeyID)
	}
	if gotPending != nil {
		t.Error("pendingReneg is set — a forged key-id must not construct any new Conn")
	}
}

// TestRenegRejectedBeforePrimaryEstablished is 04-01-PLAN.md Task 3's
// proof that a SOFT_RESET_V1 arriving while the primary slot is not yet
// established (ssl.c:3882-3900's S_GENERATED_KEYS gate) is refused.
func TestRenegRejectedBeforePrimaryEstablished(t *testing.T) {
	f := newRenegTestFixture(t)
	sess := f.newSession(t)
	sess.mu.Lock()
	sess.primary = keySlot{conn: f.primaryConn} // established left zero
	sess.mu.Unlock()

	f.srv.beginRenegotiation(sess, f.softReset(1), f.clientPC.LocalAddr(), f.serverPC)

	sess.mu.Lock()
	gotPending := sess.pendingReneg
	sess.mu.Unlock()
	if gotPending != nil {
		t.Error("renegotiation was accepted before the primary slot was established")
	}
}

// TestRenegFloodRateLimited is 04-01-PLAN.md Task 3's T-04-01 proof: once
// one renegotiation has been accepted, a burst of further SOFT_RESET_V1
// requests at the (now correct) next key-id, all arriving within
// renegMinInterval of the first, are every one refused — at most one
// renegotiation total.
func TestRenegFloodRateLimited(t *testing.T) {
	f := newRenegTestFixture(t)
	sess := f.newSession(t)

	// First SOFT_RESET_V1, at the correct next key-id (1): accepted.
	f.srv.beginRenegotiation(sess, f.softReset(1), f.clientPC.LocalAddr(), f.serverPC)
	sess.mu.Lock()
	firstConn := sess.pendingReneg
	sess.mu.Unlock()
	if firstConn == nil {
		t.Fatal("first SOFT_RESET_V1 was not accepted")
	}
	t.Cleanup(func() { _ = firstConn.Close() })

	// Simulate that renegotiation having already completed — exactly the
	// state runRenegotiation's own atomic swap leaves — WITHOUT advancing
	// the clock, so lastRenegAccepted (set by the accepted request above)
	// is still within renegMinInterval of now.
	sess.mu.Lock()
	sess.pendingReneg = nil
	sess.primary = keySlot{keyID: 1, conn: firstConn, established: sess.now()}
	sess.mu.Unlock()

	// A burst of further SOFT_RESET_V1 requests at the new correct next
	// key-id (2), all within renegMinInterval of the first: every one is
	// refused.
	for i := 0; i < 3; i++ {
		f.srv.beginRenegotiation(sess, f.softReset(2), f.clientPC.LocalAddr(), f.serverPC)
	}

	sess.mu.Lock()
	gotKeyID := sess.primary.keyID
	gotPending := sess.pendingReneg
	sess.mu.Unlock()
	if gotKeyID != 1 {
		t.Errorf("primary.keyID = %d, want 1 (unchanged — the rate-limited burst must not have advanced it)", gotKeyID)
	}
	if gotPending != nil {
		t.Error("pendingReneg is set — the rate-limited burst must not have published anything")
	}
}

// lameDuckTestKeys returns a deterministic, self-symmetric
// keyderiv.DataKeys distinct from testSymmetricDataKeys's own pattern, so
// a single test can build two independent Wrappers (old/new) that never
// accidentally share key material.
func lameDuckTestKeys(seed byte) keyderiv.DataKeys {
	var keys keyderiv.DataKeys
	for i := range keys.EncryptCipher {
		keys.EncryptCipher[i] = seed + byte(i)
	}
	for i := range keys.EncryptImplicitIV {
		keys.EncryptImplicitIV[i] = seed + 0x10 + byte(i)
	}
	keys.DecryptCipher = keys.EncryptCipher
	keys.DecryptImplicitIV = keys.EncryptImplicitIV
	keys.CipherKeyLen = 32
	return keys
}

// TestLameDuckKeyRefusedAfterTransitionWindow is 04-01-PLAN.md Task 3's
// T-04-03 proof (decrypt side): with an injected clock, a data packet
// sealed under the lame-duck key still decrypts before its mustDie
// deadline, and no longer decrypts once the clock advances past it.
func TestLameDuckKeyRefusedAfterTransitionWindow(t *testing.T) {
	newWrapper, err := datachan.NewWrapper(lameDuckTestKeys(0x30), 1, 1)
	if err != nil {
		t.Fatalf("NewWrapper (new): %v", err)
	}
	oldWrapper, err := datachan.NewWrapper(lameDuckTestKeys(0x70), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper (old): %v", err)
	}

	clock := newFakeClock()
	sess := &Session{
		clock:     clock,
		primary:   keySlot{keyID: 1, wrapper: newWrapper},
		lameDuck:  keySlot{keyID: 0, wrapper: oldWrapper, mustDie: clock.Now().Add(time.Minute)},
		ipInbound: make(chan []byte, ipInboundQueueSize),
		stopCh:    make(chan struct{}),
	}

	payload := bytes.Repeat([]byte{0x11}, 40)

	// Before mustDie: the old key still decrypts (D-18).
	sealed, err := oldWrapper.Seal(nil, payload)
	if err != nil {
		t.Fatalf("seal (before expiry): %v", err)
	}
	sess.handleDataPacket(sealed)

	buf := make([]byte, 200)
	n, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("Read (before expiry): %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("Read = %x, want %x", buf[:n], payload)
	}

	// Advance the clock past mustDie.
	clock.Advance(2 * time.Minute)

	sealed2, err := oldWrapper.Seal(nil, payload)
	if err != nil {
		t.Fatalf("seal (after expiry): %v", err)
	}
	sess.handleDataPacket(sealed2)

	select {
	case leaked := <-sess.ipInbound:
		t.Fatalf("old-key packet was delivered after mustDie: %x", leaked)
	default:
	}
}

// TestLameDuckConnClosedOnExpiry is 04-01-PLAN.md Task 3's T-04-03 proof
// (resource side): the lame-duck slot's expiry sweep (runReneg's own
// ticker) closes its Conn once mustDie passes, freeing its retransmit
// goroutine — asserted via a bounded runtime.NumGoroutine poll, never a
// fixed sleep.
func TestLameDuckConnClosedOnExpiry(t *testing.T) {
	f := newRenegTestFixture(t)
	sess := f.newSession(t)
	sess.primary = keySlot{keyID: 1, conn: f.primaryConn, established: f.clock.Now()}

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

	// Baseline is taken AFTER the fixture's own primaryConn and this
	// test's runReneg goroutine both already exist (neither is expected
	// to exit during this test — only lameDuckConn's own retransmit
	// goroutine, created next, should).
	runtime.Gosched()
	baseline := runtime.NumGoroutine()

	lameWrapper, err := datachan.NewWrapper(lameDuckTestKeys(0x90), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	lameDuckConn := ctrlconn.NewWithKeyID(f.serverSID, f.clientSID, f.serverWrapper, packetConnTransport{pc: f.serverPC}, f.clientPC.LocalAddr(), nil, 0)

	sess.mu.Lock()
	sess.lameDuck = keySlot{keyID: 0, conn: lameDuckConn, wrapper: lameWrapper, mustDie: f.clock.Now().Add(time.Minute)}
	sess.mu.Unlock()

	f.clock.Advance(2 * time.Minute)
	tick <- time.Now()

	// Poll for the goroutine count to return to baseline — lameDuckConn's
	// own retransmitLoop should exit once Close() propagates through its
	// closeCh. Bounded poll, not a fixed sleep (04-01-PLAN.md Task 3).
	deadline := time.Now().Add(3 * time.Second)
	for {
		if runtime.NumGoroutine() <= baseline {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lame-duck Conn's retransmit goroutine did not exit after the expiry sweep (goroutines = %d, baseline = %d)", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(5 * time.Millisecond) // polling only — waiting for a goroutine to exit, not a protocol deadline
	}

	sess.mu.Lock()
	gotConn := sess.lameDuck.conn
	gotWrapper := sess.lameDuck.wrapper
	sess.mu.Unlock()
	if gotConn != nil {
		t.Error("lameDuck.conn was not cleared after the expiry sweep")
	}
	if gotWrapper != nil {
		t.Error("lameDuck.wrapper was not cleared after the expiry sweep")
	}
}

// TestStalledRenegotiationRecoversAfterWindow is 04-REVIEW.md CR-01's
// regression test: a renegotiation whose peer never completes the TLS
// handshake must not (a) leak runRenegotiation's own goroutine and
// newConn's retransmit goroutine forever, nor (b) permanently disable all
// future renegotiation for the session. Before CR-01's fix,
// runRenegotiation had no watchdog of its own (unlike the initial
// handshake's enforceHandshakeWindow) — tlsConn.Handshake() blocked
// forever on a peer that never responds, sess.pendingReneg never cleared,
// and every subsequent startRenegotiation call was refused by its own
// in-flight check for the remaining lifetime of the session.
//
// This mirrors lifecycle_test.go's own "handshake-window timeout" case
// (a direct, synchronous call against a tiny srv.handshakeWindow rather
// than a real production-sized wait) since enforceRenegotiationWindow, like
// enforceHandshakeWindow, is built on time.After rather than the injected
// fake Clock — internal/reliable.Clock only abstracts Now(), not timers —
// so a short real duration is this codebase's existing, established
// pattern for deterministically exercising this class of watchdog.
func TestStalledRenegotiationRecoversAfterWindow(t *testing.T) {
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

	var clientSID, serverSID wire.SessionID
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}
	if _, err := rand.Read(serverSID[:]); err != nil {
		t.Fatalf("generate server session id: %v", err)
	}

	primaryConn := ctrlconn.New(serverSID, clientSID, serverWrapper, packetConnTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	defer primaryConn.Close()

	tlsCfg, _ := testHandshakeTLSConfig(t)

	srv := &Server{
		pc: serverPC,
		cfg: Config{
			TLSConfig: tlsCfg,
		},
		sessions:        make(map[sessionKey]*Session),
		dataSessions:    make(map[uint32]*Session),
		handshakeWindow: 30 * time.Millisecond,
	}

	sess := &Session{
		SessionID:       serverSID,
		clientSessionID: clientSID,
		wrapper:         serverWrapper,
		conn:            primaryConn,
		RemoteAddr:      clientPC.LocalAddr(),
		srv:             srv,
		stopCh:          make(chan struct{}),
		primary:         keySlot{keyID: 0, conn: primaryConn, established: time.Now()},
	}

	newConn, keyID, ok := srv.startRenegotiation(sess, serverPC, clientPC.LocalAddr(), 0, false)
	if !ok {
		t.Fatalf("startRenegotiation: not ok")
	}

	// No peer ever drives this reneg's TLS handshake to completion —
	// simulating the stalled/abandoned-peer scenario CR-01 describes.
	// Before the fix, this goroutine never returns.
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		srv.runRenegotiation(sess, newConn, keyID)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		sess.mu.Lock()
		pending := sess.pendingReneg
		sess.mu.Unlock()
		if pending == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sess.pendingReneg never cleared after the stalled renegotiation's handshake window elapsed (CR-01 regression)")
		}
		time.Sleep(2 * time.Millisecond) // polling only — not a protocol deadline wait
	}

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runRenegotiation goroutine never returned after its watchdog abandoned the stalled handshake (leaked goroutine, CR-01 regression)")
	}

	// The actual regression CR-01 identified: without the fix, EVERY
	// subsequent renegotiation attempt is refused forever once one stalls.
	// Confirm a fresh attempt re-arms now that pendingReneg has cleared.
	if _, _, ok := srv.startRenegotiation(sess, serverPC, clientPC.LocalAddr(), 0, false); !ok {
		t.Fatal("startRenegotiation refused after the stalled renegotiation was abandoned — pendingReneg did not re-arm (CR-01 regression)")
	}
}

// TestDebugDataKeysConcurrentWithWrite is 04-REVIEW.md WR-01's regression
// test: DebugDataKeys is a public, documented-as-safe-to-call-from-a-
// harness accessor, but before this fix it read s.dataKeys with no lock at
// all while runRenegotiation/performKeyMethod2Exchange write it under
// sess.mu — an unsynchronized concurrent read/write of the same memory
// from two goroutines, exactly the pattern `go test -race` is designed to
// catch. This drives the same write/read pattern those two call sites use
// (mu-guarded write, DebugDataKeys read) concurrently and in a tight loop,
// with no other synchronization point between them (deliberately NOT
// polling under mu first, which is what let every other test in this
// phase's suite pass under -race even before this fix — see WR-01's own
// finding text).
func TestDebugDataKeysConcurrentWithWrite(t *testing.T) {
	sess := &Session{stopCh: make(chan struct{})}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			dk := &keyderiv.Key2{}
			sess.mu.Lock()
			sess.dataKeys = dk
			sess.mu.Unlock()
			i++
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(deadline) {
			_, _ = sess.DebugDataKeys()
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestPumpDoesNotDeliverAfterClose is 04-REVIEW.md WR-02's regression test:
// pump()'s select has no priority between sess.inbound and sess.stopCh, so
// a packet already sitting in sess.inbound when Close() closes stopCh can
// still be selected on that same iteration and routed to a Conn Close() is
// tearing down. This test pre-loads exactly one packet into sess.inbound
// and closes stopCh BEFORE pump ever runs, so pump's very first select call
// sees both channels ready simultaneously — reproducing the race window
// WR-02 describes on every trial. Go's select picks pseudo-randomly
// between multiple ready cases, so which case fires is not itself
// deterministic, but the OUTCOME is: with the fix, the closing() check
// inside the inbound case deterministically skips delivery every time that
// case is chosen, so touchAuthTraffic (delivery's own observable side
// effect, ovpn.go:661) must never fire — checked across many trials
// instead of relying on a single lucky/unlucky select outcome.
func TestPumpDoesNotDeliverAfterClose(t *testing.T) {
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

	var clientSID, serverSID wire.SessionID
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}
	if _, err := rand.Read(serverSID[:]); err != nil {
		t.Fatalf("generate server session id: %v", err)
	}

	conn := ctrlconn.New(serverSID, clientSID, serverWrapper, packetConnTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	defer conn.Close()

	const trials = 200
	for i := 0; i < trials; i++ {
		sess := &Session{
			inbound: make(chan wire.ControlPacket, 1),
			stopCh:  make(chan struct{}),
			primary: keySlot{keyID: 0, conn: conn},
		}
		// Ack-only, empty-payload packet: absorb() takes the no-op path
		// for both its Ack-window update and its receive-window Put/Get
		// (no bytes ever cross the wire), so this only exercises whether
		// delivery is attempted at all — not any other absorb behavior.
		sess.inbound <- wire.ControlPacket{Opcode: wire.OpAckV1}
		close(sess.stopCh)

		done := make(chan struct{})
		go func() {
			defer close(done)
			sess.pump()
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("trial %d: pump() never returned", i)
		}

		sess.mu.Lock()
		delivered := !sess.lastAuthTraffic.IsZero()
		sess.mu.Unlock()
		if delivered {
			t.Fatalf("trial %d: pump() delivered a packet to a Conn after stopCh was already closed (WR-02 regression)", i)
		}
	}
}

// TestEnforceRenegotiationWindowDoesNotCloseSwappedConn is 04-REVIEW.md
// CR-02's regression test: enforceRenegotiationWindow's timeout branch must
// only close newConn if THIS call actually is the one that cleared
// sess.pendingReneg (i.e. the renegotiation was still in flight when the
// watchdog fired) — never unconditionally. Before the fix, the timer
// branch unconditionally called newConn.Close() regardless of whether the
// pendingReneg check matched, so a timer that fires in the narrow window
// between runRenegotiation's atomic-swap unlock and its deferred
// close(done) would tear down the just-promoted, live primary Conn for a
// renegotiation that had already succeeded.
//
// This drives that exact post-swap, pre-done window directly and
// deterministically: sess is constructed already in the state
// runRenegotiation's own swap leaves it in (pendingReneg == nil,
// primary.conn == newConn), and done is deliberately never closed —
// reproducing "the timer is the select's only ready case even though the
// reneg already succeeded" without any goroutine race or real sleep. A
// handshakeWindow of 1ms makes enforceRenegotiationWindow's time.After
// fire almost immediately when called synchronously.
func TestEnforceRenegotiationWindowDoesNotCloseSwappedConn(t *testing.T) {
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

	var clientSID, serverSID wire.SessionID
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}
	if _, err := rand.Read(serverSID[:]); err != nil {
		t.Fatalf("generate server session id: %v", err)
	}

	newConn := ctrlconn.New(serverSID, clientSID, serverWrapper, packetConnTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	defer newConn.Close()

	srv := &Server{handshakeWindow: time.Millisecond}

	sess := &Session{
		stopCh:  make(chan struct{}),
		primary: keySlot{keyID: 1, conn: newConn, established: time.Now()},
		// pendingReneg is nil — simulating runRenegotiation's own atomic
		// swap having ALREADY cleared it and published newConn as primary,
		// exactly the state between ovpn.go's post-swap sess.mu.Unlock()
		// and its deferred close(done) actually running.
		pendingReneg: nil,
	}

	// done is deliberately never closed, so the select inside
	// enforceRenegotiationWindow has only the timer as a ready case —
	// reproducing the race window even though the renegotiation already
	// succeeded.
	done := make(chan struct{})
	srv.enforceRenegotiationWindow(sess, newConn, done)

	sess.mu.Lock()
	gotPending := sess.pendingReneg
	sess.mu.Unlock()
	if gotPending != nil {
		t.Errorf("pendingReneg = %v, want nil (unchanged — it was already clear, so the watchdog must not touch it)", gotPending)
	}

	// newConn must NOT have been closed: give it a short read deadline and
	// confirm Read reports a timeout, not io.EOF. ctrlconn.Conn.Read only
	// returns io.EOF once c.closed is true and its read buffer is empty
	// (internal/ctrlconn/conn.go) — a live Conn with no data delivered and
	// an elapsed read deadline instead returns a timeout error.
	if err := newConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := newConn.Read(buf); err == nil {
		t.Fatal("Read unexpectedly succeeded with no data ever delivered")
	} else if err == io.EOF {
		t.Fatal("enforceRenegotiationWindow closed newConn even though the renegotiation had already succeeded (CR-02 regression): Read returned io.EOF instead of timing out")
	}
}

// TestRunRenegotiationAbandonsSwapWhenPendingRenegAlreadyCleared is
// 04-REVIEW.md CR-03's regression test: runRenegotiation's swap section
// must re-check sess.pendingReneg == newConn (symmetric with
// enforceRenegotiationWindow's own compare-and-clear) at the same point it
// already checks sess.closing(), before committing the primary/lame-duck
// swap under sess.mu. Without this check, if enforceRenegotiationWindow
// wins the race — observing sess.pendingReneg == newConn, clearing it, and
// closing newConn — in the window between Handshake()/deriveKeyMethod2
// succeeding and runRenegotiation's own sess.mu.Lock() (ovpn.go:1129),
// sess.closing() alone doesn't catch it (the session itself isn't
// closing, only this one renegotiation attempt was invalidated), so the
// swap would unconditionally publish the now-closed newConn as
// sess.primary.conn — permanently and silently breaking the session's
// control channel for that key-id.
//
// This drives that exact scenario deterministically, without depending on
// any real timing race: sess is constructed with pendingReneg already
// nil — simulating "the watchdog already got here first and cleared it" —
// while a real client goroutine drives an actual TLS handshake and Key
// Method 2 exchange to completion over newConn, so runRenegotiation's own
// Handshake()/deriveKeyMethod2 calls genuinely succeed (this exercises the
// swap-lock gate itself, not a failed-handshake early return). Because
// sess.pendingReneg never equals newConn at any point in this test — not
// just transiently — the fix's re-check is guaranteed to observe the
// mismatch on every run, regardless of scheduler timing.
func TestRunRenegotiationAbandonsSwapWhenPendingRenegAlreadyCleared(t *testing.T) {
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

	oldPrimaryConn := ctrlconn.New(serverSID, clientSID, serverWrapper, packetConnTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	defer oldPrimaryConn.Close()

	newConn := ctrlconn.NewWithKeyID(serverSID, clientSID, serverWrapper, packetConnTransport{pc: serverPC}, clientPC.LocalAddr(), nil, 1)
	defer newConn.Close()

	tlsCfg, caPool := testHandshakeTLSConfig(t)

	srv := &Server{
		pc: serverPC,
		cfg: Config{
			TLSConfig: tlsCfg,
		},
		sessions:        make(map[sessionKey]*Session),
		dataSessions:    make(map[uint32]*Session),
		handshakeWindow: 5 * time.Second,
	}

	sess := &Session{
		SessionID:       serverSID,
		clientSessionID: clientSID,
		wrapper:         serverWrapper,
		conn:            oldPrimaryConn,
		RemoteAddr:      clientPC.LocalAddr(),
		srv:             srv,
		stopCh:          make(chan struct{}),
		primary:         keySlot{keyID: 0, conn: oldPrimaryConn, established: time.Now()},
		// cipher simulates the cipher already negotiated at this session's
		// (never-driven-here) initial handshake — CIPH-06: runRenegotiation
		// must reuse it, never re-select, so it has to be non-empty for
		// datachan.NewWrapper's own CipherKeyLen validation to succeed on
		// the rollover this test drives.
		cipher: "AES-256-GCM",
		// pendingReneg is deliberately left nil — simulating
		// enforceRenegotiationWindow having ALREADY observed
		// sess.pendingReneg == newConn, cleared it, and closed newConn,
		// exactly the state runRenegotiation's swap-lock section must
		// detect (CR-03) rather than trusting sess.closing() alone.
		pendingReneg: nil,
	}

	// Manual server-side dispatch: this test deliberately runs without a
	// live srv.Serve(serverPC) loop (so it can hold pendingReneg nil for
	// the whole test), but session.go's own routeControlPacket — which a
	// live Serve loop would use to demux inbound datagrams to a Conn —
	// routes to sess.pendingReneg by definition (session.go:643-645), so
	// it would never deliver anything to newConn while pendingReneg is
	// nil. Route straight to newConn instead, independent of
	// sess.pendingReneg, mirroring ovpn.go's own unwrap-and-parse step
	// (readAndParseReply's client-side counterpart) so the client's real
	// TLS handshake bytes actually reach newConn's reassembly buffer.
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		buf := make([]byte, maxDatagramSize)
		for {
			n, _, err := serverPC.ReadFrom(buf)
			if err != nil {
				return
			}
			header, plaintext, err := serverWrapper.Unwrap(nil, buf[:n])
			if err != nil {
				continue
			}
			opcode, keyID := wire.ParseHeaderByte(header[0])
			if keyID != 1 {
				continue
			}
			var csid wire.SessionID
			copy(csid[:], header[1:1+wire.SessionIDSize])
			cp, err := wire.ParseControlPacket(plaintext, wire.Header{Opcode: opcode, KeyID: keyID, SessionID: csid})
			if err != nil {
				continue
			}
			newConn.Deliver(cp)
		}
	}()

	// Real client goroutine: completes an actual TLS handshake and Key
	// Method 2 exchange over newConn's peer socket, so runRenegotiation's
	// own Handshake()/deriveKeyMethod2 calls genuinely succeed.
	clientConn := ctrlconn.NewWithKeyID(clientSID, serverSID, clientWrapper, packetConnTransport{pc: clientPC}, serverPC.LocalAddr(), nil, 1)
	defer clientConn.Close()

	// Symmetric manual dispatch for the client side: ctrlconn.Conn never
	// reads its own transport (only writes to it — see conn.go's Transport
	// interface), so something must read clientPC and call
	// clientConn.Deliver for the server's handshake/Key-Method-2 replies
	// to ever reach the client's tls.Conn, exactly like the server-side
	// dispatch loop above.
	clientDispatchDone := make(chan struct{})
	go func() {
		defer close(clientDispatchDone)
		buf := make([]byte, maxDatagramSize)
		for {
			n, _, err := clientPC.ReadFrom(buf)
			if err != nil {
				return
			}
			header, plaintext, err := clientWrapper.Unwrap(nil, buf[:n])
			if err != nil {
				continue
			}
			opcode, keyID := wire.ParseHeaderByte(header[0])
			if keyID != 1 {
				continue
			}
			var ssid wire.SessionID
			copy(ssid[:], header[1:1+wire.SessionIDSize])
			cp, err := wire.ParseControlPacket(plaintext, wire.Header{Opcode: opcode, KeyID: keyID, SessionID: ssid})
			if err != nil {
				continue
			}
			clientConn.Deliver(cp)
		}
	}()

	clientDone := make(chan error, 1)
	go func() {
		clientTLSConn := tls.Client(clientConn, &tls.Config{
			RootCAs:    caPool,
			ServerName: testHandshakeServerCN,
			MinVersion: tls.VersionTLS12,
		})
		if err := clientTLSConn.Handshake(); err != nil {
			clientDone <- err
			return
		}
		if err := writeTestClientKeyMethod2(clientTLSConn); err != nil {
			clientDone <- err
			return
		}
		clientDone <- readTestServerKeyMethod2(clientTLSConn)
	}()

	srv.runRenegotiation(sess, newConn, 1)

	if err := <-clientDone; err != nil {
		t.Fatalf("client handshake/Key Method 2: %v", err)
	}

	sess.mu.Lock()
	gotKeyID := sess.primary.keyID
	gotConn := sess.primary.conn
	gotRenegotiations := sess.renegotiations
	gotPending := sess.pendingReneg
	sess.mu.Unlock()

	if gotKeyID != 0 || gotConn != oldPrimaryConn {
		t.Fatalf("sess.primary = {keyID: %d, conn: %p}, want unchanged {keyID: 0, conn: %p} (CR-03 regression: swap committed despite pendingReneg already cleared)", gotKeyID, gotConn, oldPrimaryConn)
	}
	if gotRenegotiations != 0 {
		t.Errorf("sess.renegotiations = %d, want 0 (swap must not have run)", gotRenegotiations)
	}
	if gotPending != nil {
		t.Errorf("sess.pendingReneg = %v, want nil (unchanged)", gotPending)
	}

	// newConn must have been closed by the abandoned swap (CR-03's fix
	// path), not left live and not promoted to primary.
	if err := newConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := newConn.Read(buf); err != io.EOF {
		t.Fatalf("newConn.Read = %v, want io.EOF (runRenegotiation must close newConn when abandoning the swap, CR-03)", err)
	}
}

// TestRunRenegotiationClearsPendingRenegOnWrapperFailure is 04-REVIEW.md
// WR-03's regression test. datachan.NewWrapper cannot actually be made to
// fail from runRenegotiation's call site today — DataKeys' cipher fields
// are fixed-size [32]byte arrays, so aes.NewCipher/cipher.NewGCM never
// error for it (internal/keyderiv/keyexpansion.go) — so there is no
// runtime failure seam to inject without changing DataKeys' shape, which
// is out of scope for this fix. This is therefore a structural assertion
// against runRenegotiation's own source (ovpn.go): its
// datachan.NewWrapper error-handling block must clear sess.pendingReneg
// before closing newConn and returning, mirroring the function's other
// early-return paths (abandon()) — exactly the omission WR-03 found. If a
// future edit to this call site drops the pendingReneg guard again, this
// test fails immediately, rather than waiting for a future
// variable-length-cipher change (e.g. an NCP/cipher-negotiation phase) to
// make the bug reachable in production with no coverage to catch it.
func TestRunRenegotiationClearsPendingRenegOnWrapperFailure(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "ovpn.go")
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read ovpn.go: %v", err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, src, 0)
	if err != nil {
		t.Fatalf("parse ovpn.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "runRenegotiation" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("runRenegotiation not found in ovpn.go")
	}

	// Find the `newWrapper, err := datachan.NewWrapper(...)` statement and
	// the `if err != nil { ... }` block immediately following it — this is
	// WR-03's exact call site.
	var wrapperErrBlock *ast.BlockStmt
	for i, stmt := range fn.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		isWrapperCall := false
		for _, rhs := range assign.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewWrapper" {
				isWrapperCall = true
			}
		}
		if !isWrapperCall {
			continue
		}
		if i+1 >= len(fn.Body.List) {
			t.Fatal("datachan.NewWrapper call has no following statement in runRenegotiation")
		}
		ifStmt, ok := fn.Body.List[i+1].(*ast.IfStmt)
		if !ok {
			t.Fatal("statement following datachan.NewWrapper call in runRenegotiation is not an if statement")
		}
		wrapperErrBlock = ifStmt.Body
		break
	}
	if wrapperErrBlock == nil {
		t.Fatal("could not locate datachan.NewWrapper's error-handling block in runRenegotiation")
	}

	clearsPendingReneg := false
	ast.Inspect(wrapperErrBlock, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "pendingReneg" {
				clearsPendingReneg = true
			}
		}
		return true
	})

	if !clearsPendingReneg {
		t.Fatal("runRenegotiation's datachan.NewWrapper failure branch no longer clears sess.pendingReneg (WR-03 regression) — every subsequent renegotiation attempt would be refused forever by startRenegotiation's in-flight guard")
	}
}
