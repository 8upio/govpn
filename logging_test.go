// logging_test.go proves Config.Logger's contract (quick 260908-na1): a nil
// Logger is bit-for-bit silent and never panics; a configured Logger emits
// the session established/closed lifecycle records with the expected
// attributes; an AuthUserPass rejection logs the username and never the
// password; a garbage datagram produces exactly one Debug-only record
// (never Info/Warn/Error, so a forged-datagram flood cannot amplify log
// volume at the default level); and no log record ever contains the
// tls-crypt key. Reuses this package's own live-tunnel-up harness
// (testHandshakeTLSConfig, tunnelUpTestClient(Creds), testPushClient,
// writeControlString/readControlString/pushRequestLiteral) rather than
// building a second one.
package ovpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a mutex-guarded io.Writer so a test goroutine can read the
// rendered log output while a handler goroutine is still writing to it —
// slog.Handler implementations do not otherwise guarantee a happens-before
// edge visible to a concurrent, unrelated reader.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// newTestLogger builds a *slog.Logger over buf at level lvl, rendering
// plain text so With-carried attrs (e.g. the per-session logger's
// remote/session_id/peer_cn/ip/peer_id, D-03) are visible in the output
// without reimplementing slog.Handler.
func newTestLogger(buf *syncBuffer, lvl slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: lvl}))
}

// waitForLogContains polls buf (bounded by timeout, never an unbounded
// wait) until its rendered content contains substr, returning that content.
// Fails the test on timeout.
func waitForLogContains(t testing.TB, buf *syncBuffer, substr string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if s := buf.String(); strings.Contains(s, substr) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for log output to contain %q; got:\n%s", timeout, substr, buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLoggerNilIsSilentAndSafe proves a Server built with a nil
// Config.Logger resolves a non-nil discard logger (Enabled reports false
// for every level) and that a full tunnel-up + Close against such a server
// produces no panic — the test completing at all is the assertion.
func TestLoggerNilIsSilentAndSafe(t *testing.T) {
	bare := NewServer(Config{})
	lg := bare.logger()
	if lg == nil {
		t.Fatal("srv.logger() returned nil for a Server built with no Config.Logger")
	}
	if lg.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("nil-Logger server's resolved logger reports Enabled(Error) == true, want false")
	}

	_, network, err := net.ParseCIDR("10.91.0.0/24")
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

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() never fired after Close")
	}
}

// TestLoggerSessionEstablishedAndClosedRecords is the tracer's own proof
// (E6/J6): a live bring-up emits "session established" at INFO carrying
// peer_cn= and ip=, and the following sess.Close() emits "session closed"
// with reason=embedder.
func TestLoggerSessionEstablishedAndClosedRecords(t *testing.T) {
	_, network, err := net.ParseCIDR("10.92.0.0/24")
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

	buf := &syncBuffer{}
	lg := newTestLogger(buf, slog.LevelDebug)

	sessions := make(chan *Session, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
		Logger:       lg,
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

	established := waitForLogContains(t, buf, `msg="session established"`, 5*time.Second)
	if !strings.Contains(established, "peer_cn=") {
		t.Errorf("session established record missing peer_cn=: %s", established)
	}
	if !strings.Contains(established, "ip=") {
		t.Errorf("session established record missing ip=: %s", established)
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	closed := waitForLogContains(t, buf, `msg="session closed"`, 5*time.Second)
	if !strings.Contains(closed, "reason=embedder") {
		t.Errorf("session closed record missing reason=embedder: %s", closed)
	}
}

// TestLoggerAuthRejectionLogsUsernameNeverPassword proves F3 (verifyUserPass
// -> callAuthUserPass): an "auth rejected" record carries the username and
// the rendered output NEVER contains the password (T-na1-02).
func TestLoggerAuthRejectionLogsUsernameNeverPassword(t *testing.T) {
	_, network, err := net.ParseCIDR("10.93.0.0/24")
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

	buf := &syncBuffer{}
	lg := newTestLogger(buf, slog.LevelDebug)

	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
		AuthUserPass: func(_, _ string, _ tls.ConnectionState) error {
			return errors.New("invalid credentials")
		},
		Logger: lg,
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	const testUsername = "logtest-user"
	const testPassword = "logtest-pa55word-never-logged"

	client, replyReader := tunnelUpTestClientCreds(t, key, serverPC.LocalAddr(), caPool, testUsername, testPassword)
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	if _, err := readControlString(replyReader, maxControlStringLen); err != nil {
		t.Fatalf("read AUTH_FAILED: %v", err)
	}

	rendered := waitForLogContains(t, buf, `msg="auth rejected"`, 5*time.Second)
	if !strings.Contains(rendered, testUsername) {
		t.Errorf("auth rejected record missing username %q: %s", testUsername, rendered)
	}
	if strings.Contains(buf.String(), testPassword) {
		t.Fatalf("rendered log output contains the password: %s", buf.String())
	}
}

// TestLoggerGarbageDatagramIsDebugOnly is the tracer's other half (B2,
// T-na1-01): a garbage datagram (an out-of-range opcode byte) produces
// exactly one level=DEBUG record with reason=bad-opcode and nothing at
// INFO or above — the property that keeps an unauthenticated flood from
// amplifying log volume at the library's default log level.
func TestLoggerGarbageDatagramIsDebugOnly(t *testing.T) {
	_, network, err := net.ParseCIDR("10.94.0.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	tlsCfg, _ := testHandshakeTLSConfig(t)

	buf := &syncBuffer{}
	lg := newTestLogger(buf, slog.LevelDebug)

	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		Logger:       lg,
	})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	waitForLogContains(t, buf, "server listening", 5*time.Second)
	buf.Reset()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	// opcode 0xff>>3 (P_OPCODE_SHIFT) is out of wire.ValidOpcode's range ->
	// B2 (bad-opcode). If the observed reason token ever differs, the fix
	// is to this test, never to the log_sites table (260908-na1-PLAN.md
	// Task 1 action 6).
	if _, err := clientPC.WriteTo([]byte{0xff, 0x00, 0x00}, serverPC.LocalAddr()); err != nil {
		t.Fatalf("write garbage datagram: %v", err)
	}

	rendered := waitForLogContains(t, buf, "reason=bad-opcode", 5*time.Second)
	if strings.Contains(rendered, "level=INFO") || strings.Contains(rendered, "level=WARN") || strings.Contains(rendered, "level=ERROR") {
		t.Fatalf("garbage datagram produced a record above Debug: %s", rendered)
	}
}

// TestLoggerNeverLeaksKeyMaterial reuses the established+closed flow (D-08)
// and asserts the rendered output never contains the tls-crypt key's hex
// encoding (T-na1-03).
func TestLoggerNeverLeaksKeyMaterial(t *testing.T) {
	_, network, err := net.ParseCIDR("10.95.0.0/24")
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

	buf := &syncBuffer{}
	lg := newTestLogger(buf, slog.LevelDebug)

	sessions := make(chan *Session, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession:    func(sess *Session) { sessions <- sess },
		Logger:       lg,
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
	waitForLogContains(t, buf, `msg="session closed"`, 5*time.Second)

	keyHex := hex.EncodeToString(key[:16])
	if strings.Contains(buf.String(), keyHex) {
		t.Fatalf("rendered log output contains the tls-crypt key hex: %s", buf.String())
	}
}
