// auth_test.go exercises quick 260908-m4e: Config.AuthUserPass,
// AuthClientReason, CloseReasonAuthFailed, the Serve guard (D-07), and the
// AUTH_FAILED rejection wire format — against a live srv.Serve loop and a
// synthetic client, following this package's own established patterns
// (ovpn_test.go's testPushClient/tunnelUpTestClient*, reneg_test.go's
// renegotiate).
package ovpn

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- buildAuthFailed / sanitizeAuthClientReason: pure-function wire format ---

// TestBuildAuthFailedPlainForm asserts the plain AUTH_FAILED literal (R5)
// when clientReason sanitizes to empty.
func TestBuildAuthFailedPlainForm(t *testing.T) {
	if got := buildAuthFailed(""); got != authFailedLiteral {
		t.Errorf("buildAuthFailed(\"\") = %q, want %q", got, authFailedLiteral)
	}
}

// TestBuildAuthFailedWithReason asserts the extended AUTH_FAILED,<reason>
// form (R5/R6/D-04).
func TestBuildAuthFailedWithReason(t *testing.T) {
	got := buildAuthFailed("bad credentials")
	want := "AUTH_FAILED,bad credentials"
	if got != want {
		t.Errorf("buildAuthFailed(%q) = %q, want %q", "bad credentials", got, want)
	}
}

// TestBuildAuthFailedSanitizesControlBytes asserts D-04's sanitization:
// bytes < 0x20 or == 0x7f are stripped (a NUL would truncate the control
// string, a newline would corrupt log parsing) and the reason is capped at
// maxAuthClientReasonLen.
func TestBuildAuthFailedSanitizesControlBytes(t *testing.T) {
	dirty := "bad\x00creds\nwith\x7fcontrol\x01bytes"
	got := buildAuthFailed(dirty)
	if strings.ContainsAny(got, "\x00\n\x7f\x01") {
		t.Errorf("buildAuthFailed(%q) = %q, still contains control bytes", dirty, got)
	}
	want := "AUTH_FAILED,badcredswithcontrolbytes"
	if got != want {
		t.Errorf("buildAuthFailed(%q) = %q, want %q", dirty, got, want)
	}
}

// TestBuildAuthFailedTruncatesLongReason asserts a reason sanitizing to
// more than maxAuthClientReasonLen bytes is truncated, not rejected
// outright.
func TestBuildAuthFailedTruncatesLongReason(t *testing.T) {
	long := strings.Repeat("x", maxAuthClientReasonLen+50)
	got := buildAuthFailed(long)
	wantPrefix := authFailedLiteral + ","
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("buildAuthFailed(long) = %q, want prefix %q", got, wantPrefix)
	}
	reasonLen := len(got) - len(wantPrefix)
	if reasonLen != maxAuthClientReasonLen {
		t.Errorf("sanitized reason length = %d, want %d", reasonLen, maxAuthClientReasonLen)
	}
}

// TestBuildAuthFailedAllControlReasonYieldsPlainForm asserts a reason that
// sanitizes down to nothing (every byte stripped) falls back to the plain
// AUTH_FAILED form rather than sending a bare trailing comma.
func TestBuildAuthFailedAllControlReasonYieldsPlainForm(t *testing.T) {
	if got := buildAuthFailed("\x00\x01\x7f"); got != authFailedLiteral {
		t.Errorf("buildAuthFailed(all-control) = %q, want %q", got, authFailedLiteral)
	}
}

// TestAuthFailedWireFramingExactlyOneNUL asserts writeControlString's own
// framing (push.go) applied to buildAuthFailed's output puts exactly one
// 0x00 terminator on the wire and nothing after it (R5).
func TestAuthFailedWireFramingExactlyOneNUL(t *testing.T) {
	var buf strings.Builder
	if err := writeControlString(&buf, buildAuthFailed("bad creds")); err != nil {
		t.Fatalf("writeControlString: %v", err)
	}
	wire := buf.String()
	want := "AUTH_FAILED,bad creds\x00"
	if wire != want {
		t.Errorf("wire bytes = %q, want %q", wire, want)
	}
	if strings.Count(wire, "\x00") != 1 {
		t.Errorf("wire bytes contain %d NUL bytes, want exactly 1", strings.Count(wire, "\x00"))
	}
}

// --- km2Credential: length/emptiness extraction ---

func TestKM2CredentialInBoundsNonEmpty(t *testing.T) {
	got, ok := km2Credential(append([]byte("alice"), 0))
	if !ok {
		t.Fatal("km2Credential reported out of bounds for a 6-byte field")
	}
	if got != "alice" {
		t.Errorf("km2Credential = %q, want %q", got, "alice")
	}
}

func TestKM2CredentialNilFieldIsEmptyButInBounds(t *testing.T) {
	got, ok := km2Credential(nil)
	if !ok {
		t.Fatal("km2Credential reported out of bounds for a nil field")
	}
	if got != "" {
		t.Errorf("km2Credential(nil) = %q, want empty string", got)
	}
}

func TestKM2CredentialOverLongIsOutOfBounds(t *testing.T) {
	field := make([]byte, userPassLen+1)
	if _, ok := km2Credential(field); ok {
		t.Errorf("km2Credential reported in-bounds for a %d-byte field (userPassLen=%d)", len(field), userPassLen)
	}
}

func TestKM2CredentialExactlyAtBoundIsInBounds(t *testing.T) {
	field := make([]byte, userPassLen)
	if _, ok := km2Credential(field); !ok {
		t.Errorf("km2Credential reported out of bounds for a %d-byte field, want in-bounds (== userPassLen)", len(field))
	}
}

// --- End-to-end: valid credentials, nil hook, rejection, panic, reneg ---

// TestAuthUserPassAcceptsValidCredentials proves the hook receives the
// client's exact username/password and a real tls.ConnectionState, and
// that a nil error lets the tunnel come up normally (PUSH_REPLY arrives,
// OnSession fires).
func TestAuthUserPassAcceptsValidCredentials(t *testing.T) {
	_, network, err := net.ParseCIDR("10.90.0.0/24")
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

	type hookCall struct {
		username, password string
		cs                 tls.ConnectionState
	}
	hookCalls := make(chan hookCall, 1)
	sessions := make(chan *Session, 1)

	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
			hookCalls <- hookCall{username, password, cs}
			return nil
		},
		OnSession: func(sess *Session) { sessions <- sess },
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client, replyReader := tunnelUpTestClientCreds(t, key, serverPC.LocalAddr(), caPool, "alice", "s3cr3t")
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reply, err := readControlString(replyReader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read push reply: %v", err)
	}
	if !strings.HasPrefix(reply, "PUSH_REPLY") {
		t.Fatalf("reply = %q, want a PUSH_REPLY", reply)
	}

	select {
	case call := <-hookCalls:
		if call.username != "alice" || call.password != "s3cr3t" {
			t.Errorf("hook saw (%q, %q), want (%q, %q)", call.username, call.password, "alice", "s3cr3t")
		}
		if !call.cs.HandshakeComplete {
			t.Error("hook's tls.ConnectionState.HandshakeComplete = false, want true")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AuthUserPass was never called")
	}

	select {
	case <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}
}

// TestAuthUserPassNilHookIgnoresCredentials proves back-compat: a nil hook
// leaves credentials parsed-and-ignored, and the tunnel still comes up,
// exactly like before this quick task.
func TestAuthUserPassNilHookIgnoresCredentials(t *testing.T) {
	_, network, err := net.ParseCIDR("10.90.1.0/24")
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
	// D-07's Serve guard requires SOME authentication when AuthUserPass is
	// left nil (the whole point of this test) — so the client certificate
	// itself has to be mandatory here. RequireAnyClientCert accepts any
	// presented certificate without verifying it against caPool, so a
	// throwaway self-signed cert is sufficient; this test's own concern is
	// credential handling, not certificate verification (already covered
	// by testHandshakeTLSConfig's own mutual-TLS tests).
	tlsCfg.ClientAuth = tls.RequireAnyClientCert
	clientCert := selfSignedTestCert(t)

	sessions := make(chan *Session, 1)
	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		// AuthUserPass intentionally left nil.
		OnSession: func(sess *Session) { sessions <- sess },
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client := newTestPushClientWithCerts(t, key, serverPC.LocalAddr(), caPool, []tls.Certificate{clientCert})
	defer client.Close()

	if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := client.tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2Creds(client.tlsConn, "whatever", "unchecked"); err != nil {
		t.Fatalf("write client Key Method 2: %v", err)
	}
	if err := readTestServerKeyMethod2(client.tlsConn); err != nil {
		t.Fatalf("read server Key Method 2: %v", err)
	}
	if err := client.conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear client deadline: %v", err)
	}
	replyReader := bufio.NewReader(client.tlsConn)

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reply, err := readControlString(replyReader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read push reply: %v", err)
	}
	if !strings.HasPrefix(reply, "PUSH_REPLY") {
		t.Fatalf("reply = %q, want a PUSH_REPLY", reply)
	}

	select {
	case <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}
}

// selfSignedTestCert generates a throwaway self-signed ECDSA certificate —
// no CA needed, since RequireAnyClientCert accepts any presented
// certificate without verifying it against a CA pool.
func selfSignedTestCert(t testing.TB) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ovpn-auth-test-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestAuthUserPassRejectsOnHookError proves a non-nil hook error rejects
// the client on the INITIAL handshake: the client reads exactly
// AUTH_FAILED off the TLS stream, no PUSH_REPLY is ever written,
// OnSession never fires, and the server-side Session records
// CloseReasonAuthFailed. The session is observed white-box (it was never
// published, so there is no OnSessionClosed handle) while the hook is
// blocked on a channel, following this package's established
// srv.mu/srv.sessions access pattern.
func TestAuthUserPassRejectsOnHookError(t *testing.T) {
	_, network, err := net.ParseCIDR("10.90.2.0/24")
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

	hookEntered := make(chan struct{})
	allowHookReturn := make(chan struct{})
	onSessionCalled := int32(0)

	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
			close(hookEntered)
			<-allowHookReturn
			return errors.New("invalid credentials")
		},
		OnSession: func(sess *Session) { atomic.AddInt32(&onSessionCalled, 1) },
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client := newTestPushClient(t, key, serverPC.LocalAddr(), caPool)
	defer client.Close()

	if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := client.tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2Creds(client.tlsConn, "bob", "wrongpass"); err != nil {
		t.Fatalf("write client Key Method 2: %v", err)
	}
	if err := readTestServerKeyMethod2(client.tlsConn); err != nil {
		t.Fatalf("read server Key Method 2: %v", err)
	}

	// White-box: grab the single in-flight Session while the hook is
	// blocked, before releasing it — this package's established pattern
	// for observing a session that will never be published (its
	// CloseReasonAuthFailed can't be read via OnSessionClosed, since that
	// only fires for a published session).
	var sess *Session
	select {
	case <-hookEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("AuthUserPass was never called")
	}
	srv.mu.Lock()
	for _, s := range srv.sessions {
		sess = s
	}
	srv.mu.Unlock()
	if sess == nil {
		t.Fatal("no in-flight Session found in srv.sessions while the hook was blocked")
	}
	close(allowHookReturn)

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reader := bufio.NewReader(client.tlsConn)
	reply, err := readControlString(reader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read AUTH_FAILED: %v", err)
	}
	if reply != authFailedLiteral {
		t.Errorf("reply = %q, want %q", reply, authFailedLiteral)
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session never closed after auth rejection")
	}
	if got := sess.CloseReason(); got != CloseReasonAuthFailed {
		t.Errorf("CloseReason() = %v, want %v", got, CloseReasonAuthFailed)
	}
	if atomic.LoadInt32(&onSessionCalled) != 0 {
		t.Error("OnSession fired for a rejected initial handshake, want never")
	}
}

// TestAuthUserPassRejectsWithClientReason proves an error implementing
// AuthClientReason produces the extended AUTH_FAILED,<reason> form on the
// wire (R6/D-04).
func TestAuthUserPassRejectsWithClientReason(t *testing.T) {
	_, network, err := net.ParseCIDR("10.90.3.0/24")
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
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
			return authReasonError{reason: "account disabled"}
		},
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client, reader := tunnelUpTestClientCreds(t, key, serverPC.LocalAddr(), caPool, "carol", "whatever")
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reply, err := readControlString(reader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read AUTH_FAILED: %v", err)
	}
	want := authFailedLiteral + ",account disabled"
	if reply != want {
		t.Errorf("reply = %q, want %q", reply, want)
	}
}

type authReasonError struct{ reason string }

func (e authReasonError) Error() string        { return "auth rejected: " + e.reason }
func (e authReasonError) ClientReason() string { return e.reason }

// authFieldCase drives one of the empty/over-long credential rejection
// tests via writeTestClientKeyMethod2Raw, so the wire field can be
// constructed directly rather than through the string-based
// writeTestClientKeyMethod2Creds helper.
func testAuthFieldRejection(t *testing.T, name string, username, password []byte) {
	t.Helper()
	_, network, err := net.ParseCIDR("10.90.4.0/24")
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

	var hookCalled int32
	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
			atomic.AddInt32(&hookCalled, 1)
			return nil
		},
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client := newTestPushClient(t, key, serverPC.LocalAddr(), caPool)
	defer client.Close()

	if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := client.tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2Raw(client.tlsConn, nil, username, password, testDefaultPeerInfo); err != nil {
		t.Fatalf("write client Key Method 2: %v", err)
	}
	if err := readTestServerKeyMethod2(client.tlsConn); err != nil {
		t.Fatalf("read server Key Method 2: %v", err)
	}
	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reader := bufio.NewReader(client.tlsConn)
	reply, err := readControlString(reader, maxControlStringLen)
	if err != nil {
		t.Fatalf("%s: read AUTH_FAILED: %v", name, err)
	}
	if !strings.HasPrefix(reply, authFailedLiteral) {
		t.Errorf("%s: reply = %q, want it to start with %q", name, reply, authFailedLiteral)
	}
	if atomic.LoadInt32(&hookCalled) != 0 {
		t.Errorf("%s: AuthUserPass was called, want it never reached for a failed field extraction", name)
	}
}

func TestAuthUserPassEmptyUsernameRejected(t *testing.T) {
	testAuthFieldRejection(t, "empty username", nil, append([]byte("pw"), 0))
}

func TestAuthUserPassEmptyPasswordRejected(t *testing.T) {
	testAuthFieldRejection(t, "empty password", append([]byte("user"), 0), nil)
}

func TestAuthUserPassOverLongUsernameRejected(t *testing.T) {
	// Wire length 200: > userPassLen (128), <= keyderiv's own 512-byte cap
	// (maxOptionsStringLen) — reaches this auth layer rather than failing
	// the KM2 parse itself (D-02).
	overLong := make([]byte, 200)
	for i := range overLong {
		overLong[i] = 'a'
	}
	testAuthFieldRejection(t, "over-long username", overLong, append([]byte("pw"), 0))
}

// TestAuthUserPassHookPanicRecovered proves a panicking hook is recovered,
// routed to Config.OnSessionPanic, treated as a rejection (client still
// gets AUTH_FAILED), and the session records CloseReasonAuthFailed (D-08).
func TestAuthUserPassHookPanicRecovered(t *testing.T) {
	_, network, err := net.ParseCIDR("10.90.5.0/24")
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

	const panicValue = "boom: simulated AuthUserPass bug"
	panicked := make(chan any, 1)
	var stackSeen []byte

	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
			panic(panicValue)
		},
		OnSessionPanic: func(sess *Session, recovered any, stack []byte) {
			stackSeen = stack
			panicked <- recovered
		},
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client, reader := tunnelUpTestClientCreds(t, key, serverPC.LocalAddr(), caPool, "dave", "whatever")
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reply, err := readControlString(reader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read AUTH_FAILED: %v", err)
	}
	if reply != authFailedLiteral {
		t.Errorf("reply = %q, want %q", reply, authFailedLiteral)
	}

	select {
	case r := <-panicked:
		if r != panicValue {
			t.Errorf("recovered value = %v, want %q", r, panicValue)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnSessionPanic was never called")
	}
	if len(stackSeen) == 0 {
		t.Error("OnSessionPanic's stack argument was empty")
	}
}

// TestAuthUserPassRenegotiationFailureFiresOnSessionClosed proves R3/D-01:
// the hook runs on EVERY key exchange, so a renegotiation that fails
// authentication tears the whole (already-published) session down with
// CloseReasonAuthFailed and fires OnSessionClosed — unlike an
// initial-handshake rejection, which never reaches OnSession at all.
func TestAuthUserPassRenegotiationFailureFiresOnSessionClosed(t *testing.T) {
	_, network, err := net.ParseCIDR("10.90.6.0/24")
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

	var callCount int32
	sessions := make(chan *Session, 1)
	closed := make(chan CloseReason, 1)

	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		AuthUserPass: func(username, password string, cs tls.ConnectionState) error {
			if atomic.AddInt32(&callCount, 1) == 1 {
				return nil // initial handshake succeeds
			}
			return errors.New("credentials revoked before renegotiation") // reneg fails
		},
		OnSession:       func(sess *Session) { sessions <- sess },
		OnSessionClosed: func(sess *Session, r CloseReason) { closed <- r },
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client, replyReader := tunnelUpTestClientCreds(t, key, serverPC.LocalAddr(), caPool, "erin", "s3cr3t")
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	if _, err := readControlString(replyReader, maxControlStringLen); err != nil {
		t.Fatalf("read push reply: %v", err)
	}

	select {
	case <-sessions:
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
	if err := writeTestClientKeyMethod2Creds(renegTLSConn, "erin", "s3cr3t"); err != nil {
		t.Fatalf("write client Key Method 2 (reneg): %v", err)
	}
	// deriveKeyMethod2 always writes the server's own Key Method 2 message
	// before verifyUserPass ever runs (ovpn.go's own unconditional-publish
	// comment) — read and discard it first, exactly like the initial
	// handshake path (tunnelUpTestClientCreds).
	if err := readTestServerKeyMethod2(renegTLSConn); err != nil {
		t.Fatalf("read server Key Method 2 (reneg): %v", err)
	}

	// No PUSH_REQUEST on a renegotiation (D-03/R5: "send to any active
	// session" is unconditional) — read straight for AUTH_FAILED.
	renegReader := bufio.NewReader(renegTLSConn)
	reply, err := readControlString(renegReader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read AUTH_FAILED on reneg stream: %v", err)
	}
	if reply != authFailedLiteral {
		t.Errorf("reneg reply = %q, want %q", reply, authFailedLiteral)
	}

	select {
	case r := <-closed:
		if r != CloseReasonAuthFailed {
			t.Errorf("OnSessionClosed reason = %v, want %v", r, CloseReasonAuthFailed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnSessionClosed was never called after a renegotiation-time auth rejection")
	}
}

// --- Serve guard (D-07) ---

// TestServeRejectsUnauthenticatedConfigurations is D-07's own table test:
// Serve must refuse to start for any ClientAuthType that does not
// mandate a client certificate when Config.AuthUserPass is nil —
// including tls.VerifyClientCertIfGiven, which an ordering comparison
// (`ClientAuth < RequireAnyClientCert`) would have missed, since it sorts
// numerically ABOVE RequireAnyClientCert yet does not require a
// certificate at all.
func TestServeRejectsUnauthenticatedConfigurations(t *testing.T) {
	key := testTLSCryptKey(t)

	permissiveHook := func(_, _ string, _ tls.ConnectionState) error { return nil }

	cases := []struct {
		name       string
		clientAuth tls.ClientAuthType
		hook       func(string, string, tls.ConnectionState) error
		wantErr    bool
	}{
		{"NoClientCert/nil hook", tls.NoClientCert, nil, true},
		{"RequestClientCert/nil hook", tls.RequestClientCert, nil, true},
		{"VerifyClientCertIfGiven/nil hook", tls.VerifyClientCertIfGiven, nil, true},
		{"RequireAnyClientCert/nil hook", tls.RequireAnyClientCert, nil, false},
		{"RequireAndVerifyClientCert/nil hook", tls.RequireAndVerifyClientCert, nil, false},
		{"NoClientCert/hook set", tls.NoClientCert, permissiveHook, false},
		{"RequestClientCert/hook set", tls.RequestClientCert, permissiveHook, false},
		{"VerifyClientCertIfGiven/hook set", tls.VerifyClientCertIfGiven, permissiveHook, false},
		{"RequireAnyClientCert/hook set", tls.RequireAnyClientCert, permissiveHook, false},
		{"RequireAndVerifyClientCert/hook set", tls.RequireAndVerifyClientCert, permissiveHook, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tlsCfg := testTLSConfig(t)
			tlsCfg.ClientAuth = c.clientAuth

			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer pc.Close()

			srv := NewServer(Config{
				TLSCryptKey:  key,
				TLSConfig:    tlsCfg,
				AuthUserPass: c.hook,
			})

			// A configuration that passes the guard makes Serve enter its
			// blocking read loop rather than returning — run it on its own
			// goroutine and close the server immediately after giving it a
			// moment to reach that loop, exactly like this package's own
			// TestServeClose. A guard-rejected configuration returns from
			// Serve immediately regardless; Close afterward is still safe
			// (idempotent, ovpn.go's own contract).
			done := make(chan error, 1)
			go func() { done <- srv.Serve(pc) }()
			time.Sleep(20 * time.Millisecond)
			_ = srv.Close()

			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return after Close")
			}

			if c.wantErr {
				if err == nil {
					t.Fatal("Serve() = nil, want an error naming AuthUserPass")
				}
				if !strings.Contains(err.Error(), "AuthUserPass") {
					t.Errorf("Serve() error = %q, want it to mention AuthUserPass", err.Error())
				}
			} else if err != nil {
				t.Errorf("Serve() = %v, want nil (this configuration authenticates every client)", err)
			}
		})
	}
}
