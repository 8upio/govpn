// sessionstats_test.go exercises Welle-1 item 1d: SessionStats,
// Session.Stats(), and Session.RemoteAddress(). Reuses the hand-built-
// Session-plus-real-wrapper scaffolding TestPingNeverReachesSessionRead
// and TestServerEmitsPingOnSchedule already establish (ovpn_test.go) for
// the data-path counter tests, and the live tunnel-up harness
// (testPushClient/tunnelUpTestClient) for the EstablishedAt/
// LastAuthTrafficAt proof, which needs a real OnSession publish point and
// a real authenticated round trip.
package ovpn

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/datachan"
)

// TestSessionStatsCountsAuthenticatedInboundPackets asserts
// Stats().PacketsIn/BytesIn count exactly the authenticated inbound IP
// packets handleDataPacket delivers, summing their plaintext lengths.
func TestSessionStatsCountsAuthenticatedInboundPackets(t *testing.T) {
	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sess := &Session{
		primary:   keySlot{wrapper: wrapper},
		ipInbound: make(chan []byte, ipInboundQueueSize),
		stopCh:    make(chan struct{}),
	}

	sizes := []int{10, 25, 60}
	var wantBytes uint64
	for i, n := range sizes {
		payload := bytes.Repeat([]byte{byte(0x10 + i)}, n)
		sealed, err := wrapper.Seal(nil, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		sess.handleDataPacket(sealed)
		wantBytes += uint64(n)
	}

	stats := sess.Stats()
	if stats.PacketsIn != uint64(len(sizes)) {
		t.Errorf("Stats().PacketsIn = %d, want %d", stats.PacketsIn, len(sizes))
	}
	if stats.BytesIn != wantBytes {
		t.Errorf("Stats().BytesIn = %d, want %d", stats.BytesIn, wantBytes)
	}
}

// TestSessionStatsPingAbsorbedNotCounted asserts a ping keepalive absorbed
// inside Wrapper.Open increments neither PacketsIn nor BytesIn.
func TestSessionStatsPingAbsorbedNotCounted(t *testing.T) {
	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sess := &Session{
		primary:   keySlot{wrapper: wrapper},
		ipInbound: make(chan []byte, ipInboundQueueSize),
		stopCh:    make(chan struct{}),
	}

	pingSealed, err := wrapper.SealPing(nil)
	if err != nil {
		t.Fatalf("SealPing: %v", err)
	}
	sess.handleDataPacket(pingSealed)

	stats := sess.Stats()
	if stats.PacketsIn != 0 {
		t.Errorf("Stats().PacketsIn = %d after an absorbed ping, want 0", stats.PacketsIn)
	}
	if stats.BytesIn != 0 {
		t.Errorf("Stats().BytesIn = %d after an absorbed ping, want 0", stats.BytesIn)
	}
	if stats.KeepalivesIn != 1 {
		t.Errorf("Stats().KeepalivesIn = %d after an absorbed ping, want 1", stats.KeepalivesIn)
	}
}

// TestSessionStatsForgedPacketIncrementsNothing asserts a packet that
// fails to authenticate leaves every SessionStats counter at zero.
func TestSessionStatsForgedPacketIncrementsNothing(t *testing.T) {
	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sess := &Session{
		primary:   keySlot{wrapper: wrapper},
		ipInbound: make(chan []byte, ipInboundQueueSize),
		stopCh:    make(chan struct{}),
	}

	sess.handleDataPacket(bytes.Repeat([]byte{0xFF}, 60))

	stats := sess.Stats()
	if stats != (SessionStats{}) {
		t.Errorf("Stats() after a forged packet = %+v, want the zero value", stats)
	}
}

// TestSessionStatsCountsOutboundWrites asserts Stats().PacketsOut/BytesOut
// count exactly the successful Session.Write calls, summing their payload
// lengths, and that emitPing (which deliberately bypasses Write) never
// increments either.
func TestSessionStatsCountsOutboundWrites(t *testing.T) {
	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
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

	sess := &Session{
		srv:        &Server{pc: serverPC},
		RemoteAddr: clientPC.LocalAddr(),
		primary:    keySlot{wrapper: wrapper},
		stopCh:     make(chan struct{}),
	}

	payloads := [][]byte{
		bytes.Repeat([]byte{0x21}, 10),
		bytes.Repeat([]byte{0x22}, 40),
		bytes.Repeat([]byte{0x23}, 5),
	}
	var wantBytes uint64
	for _, p := range payloads {
		n, err := sess.Write(p)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(p) {
			t.Fatalf("Write = %d, want %d", n, len(p))
		}
		wantBytes += uint64(len(p))
	}

	// emitPing bypasses Write entirely — must not affect PacketsOut/BytesOut.
	sess.emitPing()

	stats := sess.Stats()
	if stats.PacketsOut != uint64(len(payloads)) {
		t.Errorf("Stats().PacketsOut = %d, want %d", stats.PacketsOut, len(payloads))
	}
	if stats.BytesOut != wantBytes {
		t.Errorf("Stats().BytesOut = %d, want %d", stats.BytesOut, wantBytes)
	}
}

// TestSessionStatsInboundQueueDropped asserts filling ipInbound past
// capacity increments InboundQueueDropped by exactly the number of
// dropped packets, while PacketsIn/BytesIn still count every
// authenticated packet handleDataPacket decrypted (counted before the
// queue-full check, which is a separate, additional counter — not a
// replacement for PacketsIn/BytesIn).
func TestSessionStatsInboundQueueDropped(t *testing.T) {
	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sess := &Session{
		primary:   keySlot{wrapper: wrapper},
		ipInbound: make(chan []byte, 1), // capacity 1, never drained below
		stopCh:    make(chan struct{}),
	}

	const total = 4
	for i := 0; i < total; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 8)
		sealed, err := wrapper.Seal(nil, payload)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		sess.handleDataPacket(sealed)
	}

	stats := sess.Stats()
	if stats.PacketsIn != total {
		t.Errorf("Stats().PacketsIn = %d, want %d (every decrypted packet is counted)", stats.PacketsIn, total)
	}
	if want := uint64(total - 1); stats.InboundQueueDropped != want {
		t.Errorf("Stats().InboundQueueDropped = %d, want %d (queue capacity 1, %d packets sent)", stats.InboundQueueDropped, want, total)
	}
}

// TestSessionStatsRenegotiationsMatchesAccessor asserts
// Stats().Renegotiations equals RenegotiationCount().
func TestSessionStatsRenegotiationsMatchesAccessor(t *testing.T) {
	sess := &Session{stopCh: make(chan struct{})}
	sess.mu.Lock()
	sess.renegotiations = 3
	sess.mu.Unlock()

	stats := sess.Stats()
	if stats.Renegotiations != sess.RenegotiationCount() {
		t.Fatalf("Stats().Renegotiations = %d, RenegotiationCount() = %d, want equal", stats.Renegotiations, sess.RenegotiationCount())
	}
	if stats.Renegotiations != 3 {
		t.Fatalf("Stats().Renegotiations = %d, want 3", stats.Renegotiations)
	}
}

// TestSessionRemoteAddressMatchesField asserts RemoteAddress() returns the
// same net.Addr as the exported RemoteAddr field.
func TestSessionRemoteAddressMatchesField(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 8, 0, 2), Port: 1234}
	sess := &Session{RemoteAddr: addr, stopCh: make(chan struct{})}
	if sess.RemoteAddress() != sess.RemoteAddr {
		t.Fatalf("RemoteAddress() = %v, RemoteAddr = %v, want equal", sess.RemoteAddress(), sess.RemoteAddr)
	}
}

// TestSessionStatsEstablishedAt is the live-tunnel-up half of this plan's
// SessionStats behavior: EstablishedAt is non-zero once OnSession has
// fired and equals the injected session clock's reading at the publish
// point. (LastAuthTrafficAt's own advances-on-auth/never-on-forged
// behavior is asserted separately, at the Session level, by
// TestSessionStatsLastAuthTrafficAtAdvancesOnAuthOnly below — driving it
// over this same live control channel would risk a background
// control-channel ACK independently touching lastAuthTraffic via
// ovpn.go's pump, which is a correct but confounding second touch source
// for a negative assertion.)
func TestSessionStatsEstablishedAt(t *testing.T) {
	_, network, err := net.ParseCIDR("10.64.0.0/24")
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
	sessions := make(chan *Session, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
	})
	srv.clock = clock
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

	// clock has never been advanced: the publish-point reading is still
	// exactly its start value.
	wantEstablished := clock.Now()
	stats := sess.Stats()
	if stats.EstablishedAt.IsZero() {
		t.Fatal("Stats().EstablishedAt is zero after OnSession fired")
	}
	if !stats.EstablishedAt.Equal(wantEstablished) {
		t.Fatalf("Stats().EstablishedAt = %v, want %v (the session clock's reading at publish)", stats.EstablishedAt, wantEstablished)
	}
}

// TestSessionStatsLastAuthTrafficAtAdvancesOnAuthOnly is the Session-level
// half of this plan's SessionStats behavior: LastAuthTrafficAt advances on
// authenticated data-channel traffic and does not advance on forged
// traffic — driven directly via handleDataPacket, mirroring
// TestForgedPacketDoesNotResetReapTimer's own established pattern
// (lifecycle_test.go), deliberately NOT over a live control channel: a
// live tls.Conn can independently touch lastAuthTraffic via ovpn.go's pump
// on an ordinary background ACK, which would confound a negative
// assertion made against real wall-clock timing.
func TestSessionStatsLastAuthTrafficAtAdvancesOnAuthOnly(t *testing.T) {
	clock := newFakeClock()
	sess := newReapTestSession(t, clock, time.Hour)
	wrapper := sess.primary.wrapper

	clock.Advance(5 * time.Second)
	wantTouch := clock.Now()

	sealed, err := wrapper.Seal(nil, bytes.Repeat([]byte{0x55}, 20))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sess.handleDataPacket(sealed)

	if got := sess.Stats().LastAuthTrafficAt; !got.Equal(wantTouch) {
		t.Fatalf("Stats().LastAuthTrafficAt = %v after authenticated traffic, want %v", got, wantTouch)
	}

	// Forged traffic must not advance LastAuthTrafficAt further, even
	// though the clock keeps moving. Built as a REAL sealed packet with
	// its final byte (part of the ciphertext) flipped: the opcode/peer-id
	// header stays intact, but Open() fails authentication
	// (TestOpenRejectsTamperedTag's own property, internal/datachan) — a
	// raw garbage datagram would risk failing earlier for an unrelated
	// reason, which would prove nothing about the counter this test
	// targets.
	clock.Advance(5 * time.Second)
	forged, err := wrapper.Seal(nil, bytes.Repeat([]byte{0x66}, 20))
	if err != nil {
		t.Fatalf("seal (for forging): %v", err)
	}
	forged[len(forged)-1] ^= 0xFF
	sess.handleDataPacket(forged)

	if got := sess.Stats().LastAuthTrafficAt; !got.Equal(wantTouch) {
		t.Fatalf("Stats().LastAuthTrafficAt = %v after forged traffic, want unchanged %v", got, wantTouch)
	}
}
