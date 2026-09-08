// assignip_test.go exercises Welle 2's Config.AssignIP surface: the nil
// default, the (nil, nil) pool fallback, every reserve validation
// rejection, the hook error/panic paths, and the replace (no-`--duplicate-
// cn`-eviction) semantics. Reuses this package's own live-tunnel-up harness
// (tunnelUpTestClient, testHandshakeTLSConfig) exactly as closereason_test.go
// does — no second harness — plus a distinct 10.6x.y.0/24 network per test,
// matching closereason_test.go's own convention.
package ovpn

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// errAssignIPTestHookError is a fixed sentinel a test's AssignIP hook
// returns to exercise the hook-error rejection path.
var errAssignIPTestHookError = errors.New("assignip_test: synthetic hook error")

// newAssignIPTestServer builds and starts a live Server on cidr with cfg's
// AssignIP/OnSession/OnSessionClosed already merged in, returning the
// server, its listening PacketConn, and the CA pool a synthetic client
// verifies the server certificate against. The caller is responsible for
// closing serverPC and srv (via t.Cleanup or defer, matching this package's
// existing test convention).
func newAssignIPTestServer(t *testing.T, cidr string, cfg Config) (*Server, net.PacketConn, *x509.CertPool) {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}

	tlsCfg, caPool := testHandshakeTLSConfig(t)

	cfg.TLSCryptKey = key
	cfg.TLSConfig = tlsCfg
	cfg.Network = network
	if cfg.AuthUserPass == nil {
		cfg.AuthUserPass = testPermissiveAuthUserPass
	}
	srv := NewServer(cfg)
	go func() { _ = srv.Serve(serverPC) }()

	return srv, serverPC, caPool
}

// doPushRequest sends PUSH_REQUEST over client and returns the raw
// PUSH_REPLY string.
func doPushRequest(t *testing.T, client *testPushClient, replyReader *bufio.Reader) string {
	t.Helper()
	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reply, err := readControlString(replyReader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read push reply: %v", err)
	}
	return reply
}

// doPushRequestExpectNoReply sends PUSH_REQUEST and asserts the server
// never answers with a PUSH_REPLY within the given bound — the observable
// shape of a session rejected before PUSH_REPLY (AssignIP validation
// failure, hook error, or hook panic).
func doPushRequestExpectNoReply(t *testing.T, client *testPushClient, replyReader *bufio.Reader) {
	t.Helper()
	if err := client.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	if reply, err := readControlString(replyReader, maxControlStringLen); err == nil {
		t.Fatalf("expected no push reply (session rejected before PUSH_REPLY), got %q", reply)
	}
	_ = client.conn.SetDeadline(time.Time{})
}

// TestAssignIPNilBehavesAsToday asserts a nil Config.AssignIP (the default)
// still assigns from the dynamic pool exactly as before this hook existed.
func TestAssignIPNilBehavesAsToday(t *testing.T) {
	srv, serverPC, caPool := newAssignIPTestServer(t, "10.64.0.0/24", Config{})
	defer serverPC.Close()
	defer srv.Close()

	client, replyReader := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client.Close()

	reply := doPushRequest(t, client, replyReader)
	if !strings.Contains(reply, "ifconfig 10.64.0.2 ") {
		t.Fatalf("push reply = %q, want it to contain the first dynamic pool address", reply)
	}
}

// TestAssignIPStaticAddress asserts a Config.AssignIP returning a valid
// in-network address gives the session exactly that tunnel IP.
func TestAssignIPStaticAddress(t *testing.T) {
	want := net.IPv4(10, 64, 1, 42).To4()
	srv, serverPC, caPool := newAssignIPTestServer(t, "10.64.1.0/24", Config{
		AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
			return want, nil
		},
	})
	defer serverPC.Close()
	defer srv.Close()

	client, replyReader := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client.Close()

	reply := doPushRequest(t, client, replyReader)
	if !strings.Contains(reply, "ifconfig "+want.String()+" ") {
		t.Fatalf("push reply = %q, want it to contain ifconfig %s", reply, want)
	}
}

// TestAssignIPNilNilFallsBackToPool asserts a (nil, nil) hook return falls
// back to the dynamic pool for that one session, and does not disable the
// hook for a later session that returns a static address.
func TestAssignIPNilNilFallsBackToPool(t *testing.T) {
	want := net.IPv4(10, 64, 2, 77).To4()
	var calls atomic.Int32
	srv, serverPC, caPool := newAssignIPTestServer(t, "10.64.2.0/24", Config{
		AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
			if calls.Add(1) == 1 {
				return nil, nil
			}
			return want, nil
		},
	})
	defer serverPC.Close()
	defer srv.Close()

	client1, reply1 := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client1.Close()
	firstReply := doPushRequest(t, client1, reply1)
	if strings.Contains(firstReply, "ifconfig "+want.String()+" ") {
		t.Fatalf("first session (nil,nil) fallback got the static address %s, want a dynamic pool address", want)
	}
	if !strings.Contains(firstReply, "ifconfig 10.64.2.2 ") {
		t.Fatalf("first session reply = %q, want the first dynamic pool address", firstReply)
	}

	client2, reply2 := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client2.Close()
	secondReply := doPushRequest(t, client2, reply2)
	if !strings.Contains(secondReply, "ifconfig "+want.String()+" ") {
		t.Fatalf("second session reply = %q, want it to contain the static address %s", secondReply, want)
	}
}

// TestAssignIPRejectsInvalidAddress covers every reserve validation
// rejection reachable through the live handshake: the handshake fails
// before PUSH_REPLY, OnSession never fires, OnSessionClosed never fires,
// and Server.Stats().AssignIPRejected increments by exactly one.
func TestAssignIPRejectsInvalidAddress(t *testing.T) {
	cases := []struct {
		name string
		cidr string
		ip   net.IP
	}{
		{"not ipv4", "10.64.10.0/24", net.ParseIP("2001:db8::1")},
		{"outside network", "10.64.11.0/24", net.IPv4(10, 99, 0, 5).To4()},
		{"network address", "10.64.12.0/24", net.IPv4(10, 64, 12, 0).To4()},
		{"server address", "10.64.13.0/24", net.IPv4(10, 64, 13, 1).To4()},
		{"broadcast address", "10.64.14.0/24", net.IPv4(10, 64, 14, 255).To4()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			onSessionCalled := make(chan struct{}, 1)
			onClosedCalled := make(chan struct{}, 1)
			srv, serverPC, caPool := newAssignIPTestServer(t, c.cidr, Config{
				AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
					return c.ip, nil
				},
				OnSession:       func(sess *Session) { onSessionCalled <- struct{}{} },
				OnSessionClosed: func(sess *Session, r CloseReason) { onClosedCalled <- struct{}{} },
			})
			defer serverPC.Close()
			defer srv.Close()

			before := srv.stats.assignIPRejected.Load()

			client, replyReader := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
			defer client.Close()

			doPushRequestExpectNoReply(t, client, replyReader)

			select {
			case <-onSessionCalled:
				t.Fatal("OnSession fired for a rejected AssignIP address")
			case <-time.After(200 * time.Millisecond):
			}
			select {
			case <-onClosedCalled:
				t.Fatal("OnSessionClosed fired for a session never published to OnSession")
			case <-time.After(50 * time.Millisecond):
			}

			if got := srv.stats.assignIPRejected.Load(); got != before+1 {
				t.Fatalf("stats.assignIPRejected = %d, want %d", got, before+1)
			}
		})
	}
}

// TestAssignIPHookErrorRejectsHandshake asserts a non-nil error from
// Config.AssignIP fails the handshake before PUSH_REPLY and increments
// AssignIPRejected.
func TestAssignIPHookErrorRejectsHandshake(t *testing.T) {
	onSessionCalled := make(chan struct{}, 1)
	srv, serverPC, caPool := newAssignIPTestServer(t, "10.64.20.0/24", Config{
		AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
			return nil, errAssignIPTestHookError
		},
		OnSession: func(sess *Session) { onSessionCalled <- struct{}{} },
	})
	defer serverPC.Close()
	defer srv.Close()

	before := srv.stats.assignIPRejected.Load()

	client, replyReader := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client.Close()

	doPushRequestExpectNoReply(t, client, replyReader)

	select {
	case <-onSessionCalled:
		t.Fatal("OnSession fired for a hook error")
	case <-time.After(200 * time.Millisecond):
	}
	if got := srv.stats.assignIPRejected.Load(); got != before+1 {
		t.Fatalf("stats.assignIPRejected = %d, want %d", got, before+1)
	}
}

// TestAssignIPHookPanicRejectsHandshake asserts a panicking Config.AssignIP
// is recovered, routed to Config.OnSessionPanic (fail closed, never a
// crash), fails the handshake before PUSH_REPLY, and increments
// AssignIPRejected.
func TestAssignIPHookPanicRejectsHandshake(t *testing.T) {
	onSessionCalled := make(chan struct{}, 1)
	panicked := make(chan string, 1)
	srv, serverPC, caPool := newAssignIPTestServer(t, "10.64.21.0/24", Config{
		AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
			panic("assignip boom")
		},
		OnSession: func(sess *Session) { onSessionCalled <- struct{}{} },
		OnSessionPanic: func(sess *Session, recovered any, stack []byte) {
			s, _ := recovered.(string)
			panicked <- s
		},
	})
	defer serverPC.Close()
	defer srv.Close()

	before := srv.stats.assignIPRejected.Load()

	client, replyReader := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client.Close()

	doPushRequestExpectNoReply(t, client, replyReader)

	select {
	case <-onSessionCalled:
		t.Fatal("OnSession fired for a panicking hook")
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case got := <-panicked:
		if got != "assignip boom" {
			t.Fatalf("OnSessionPanic recovered = %q, want %q", got, "assignip boom")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnSessionPanic was never called")
	}
	if got := srv.stats.assignIPRejected.Load(); got != before+1 {
		t.Fatalf("stats.assignIPRejected = %d, want %d", got, before+1)
	}
}

// TestAssignIPReplace is the core replace-semantics proof: two sequential
// clients whose hook returns the same IP. The first session is evicted with
// CloseReasonReplaced (both via OnSessionClosed and CloseReason()), the
// second session ends up holding the address, a concurrent dynamic
// (fallback) session gets a different address while the second session
// lives, and after the second session closes the address becomes
// allocatable/reservable again — the pool holds exactly one holder for the
// offset at every point in between.
func TestAssignIPReplace(t *testing.T) {
	staticIP := net.IPv4(10, 64, 30, 50).To4()
	var calls atomic.Int32

	sessions := make(chan *Session, 4)
	type closedEvent struct {
		sess   *Session
		reason CloseReason
	}
	closed := make(chan closedEvent, 4)

	srv, serverPC, caPool := newAssignIPTestServer(t, "10.64.30.0/24", Config{
		AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
			if calls.Add(1) <= 2 {
				return staticIP, nil
			}
			return nil, nil
		},
		OnSession:       func(sess *Session) { sessions <- sess },
		OnSessionClosed: func(sess *Session, r CloseReason) { closed <- closedEvent{sess, r} },
	})
	defer serverPC.Close()
	defer srv.Close()

	// First client: gets the static address.
	client1, reply1 := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client1.Close()
	firstReply := doPushRequest(t, client1, reply1)
	if !strings.Contains(firstReply, "ifconfig "+staticIP.String()+" ") {
		t.Fatalf("first session reply = %q, want ifconfig %s", firstReply, staticIP)
	}
	var sess1 *Session
	select {
	case sess1 = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession (session 1) was never called")
	}

	// Second client: same hook return -> evicts session 1, takes over the
	// address.
	client2, reply2 := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client2.Close()
	secondReply := doPushRequest(t, client2, reply2)
	if !strings.Contains(secondReply, "ifconfig "+staticIP.String()+" ") {
		t.Fatalf("second session reply = %q, want ifconfig %s", secondReply, staticIP)
	}
	var sess2 *Session
	select {
	case sess2 = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession (session 2) was never called")
	}

	// session 1's eviction: OnSessionClosed(CloseReasonReplaced) and
	// CloseReason() both report it.
	var gotClosedEvent closedEvent
	select {
	case gotClosedEvent = <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSessionClosed for the evicted session was never called")
	}
	if gotClosedEvent.sess != sess1 {
		t.Fatalf("OnSessionClosed fired for the wrong session")
	}
	if gotClosedEvent.reason != CloseReasonReplaced {
		t.Fatalf("OnSessionClosed reason = %v, want CloseReasonReplaced", gotClosedEvent.reason)
	}
	if got := sess1.CloseReason(); got != CloseReasonReplaced {
		t.Fatalf("sess1.CloseReason() = %v, want CloseReasonReplaced", got)
	}
	if got := sess2.AssignedIP(); !got.Equal(staticIP) {
		t.Fatalf("sess2.AssignedIP() = %v, want %v", got, staticIP)
	}

	// A third, dynamic-fallback session gets a DIFFERENT address while
	// session 2 still holds the static one.
	client3, reply3 := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client3.Close()
	thirdReply := doPushRequest(t, client3, reply3)
	if strings.Contains(thirdReply, "ifconfig "+staticIP.String()+" ") {
		t.Fatalf("third (dynamic) session got the still-live static address %s", staticIP)
	}
	select {
	case <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession (session 3) was never called")
	}

	// Exactly one pool holder for the offset: reserve fails while session
	// 2 is alive, succeeds once it is closed.
	if _, err := srv.pool.reserve(staticIP); err == nil {
		t.Fatal("pool.reserve(staticIP) succeeded while session 2 still holds it, want an error")
	}

	if err := sess2.Close(); err != nil {
		t.Fatalf("sess2.Close(): %v", err)
	}
	select {
	case <-sess2.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("sess2.Done() never fired")
	}

	peerID, err := srv.pool.reserve(staticIP)
	if err != nil {
		t.Fatalf("pool.reserve(staticIP) after sess2 closed: %v", err)
	}
	srv.pool.release(staticIP, peerID)
}

// TestAssignIPReplaceAgainstClosingOldSession asserts the replace path's
// sync.Once-blocking property: a concurrent closeWithReason on the old
// session (racing the replace path's own eviction) still lets the new
// client's handshake succeed deterministically — the second, no-op-looking
// closeWithReason call blocks until the first one's stopOnce.Do body
// (which contains pool.release) has fully returned, so the retried
// reserve is guaranteed to see the released entry.
func TestAssignIPReplaceAgainstClosingOldSession(t *testing.T) {
	staticIP := net.IPv4(10, 64, 31, 60).To4()
	var calls atomic.Int32

	sessions := make(chan *Session, 4)
	closed := make(chan CloseReason, 4)

	srv, serverPC, caPool := newAssignIPTestServer(t, "10.64.31.0/24", Config{
		AssignIP: func(peerCN string, cs tls.ConnectionState) (net.IP, error) {
			if calls.Add(1) <= 2 {
				return staticIP, nil
			}
			return nil, nil
		},
		OnSession:       func(sess *Session) { sessions <- sess },
		OnSessionClosed: func(sess *Session, r CloseReason) { closed <- r },
	})
	defer serverPC.Close()
	defer srv.Close()

	client1, reply1 := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client1.Close()
	doPushRequest(t, client1, reply1)

	var sess1 *Session
	select {
	case sess1 = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession (session 1) was never called")
	}

	client2, reply2 := tunnelUpTestClient(t, srv.cfg.TLSCryptKey, serverPC.LocalAddr(), caPool)
	defer client2.Close()

	// Race a concurrent, redundant closeWithReason on session 1 against
	// the second client's own handshake — assignTunnelIP's internal
	// eviction call will race this one for stopOnce, but sync.Once
	// guarantees only one body ever runs and the other blocks until it
	// finishes.
	go func() { _ = sess1.closeWithReason(CloseReasonEmbedder) }()

	secondReply := doPushRequest(t, client2, reply2)
	if !strings.Contains(secondReply, "ifconfig "+staticIP.String()+" ") {
		t.Fatalf("second session reply = %q, want ifconfig %s (replace must still succeed against a racing close)", secondReply, staticIP)
	}

	select {
	case <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession (session 2) was never called")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSessionClosed for session 1 was never called")
	}
}
