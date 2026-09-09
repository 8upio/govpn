package ovpn

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/datachan"
	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

func testTLSCryptKey(t testing.TB) []byte {
	t.Helper()
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test tls-crypt key: %v", err)
	}
	return key
}

// testTLSConfig builds a throwaway self-signed server TLS config, just
// enough for Serve's own up-front validation (Config.TLSConfig must be
// set) and to give a background handshake goroutine a real certificate to
// serve. These wire-level tests never drive an actual TLS handshake — that
// is exercised end-to-end by internal/ctrlconn's TestTLSHandshakeOverCtrlConn
// and this package's own interop harness (test/interop) — so the cert
// needs no CA chain or client-auth configuration.
func testTLSConfig(t testing.TB) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ovpn-test-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
}

// testPermissiveAuthUserPass satisfies Serve's D-07 guard (quick
// 260908-m4e) for this package's many pre-existing tests that use a
// certificate-less TLSConfig (testTLSConfig/testHandshakeTLSConfig both
// leave ClientAuth at its zero value, tls.NoClientCert) without
// themselves testing authentication — it accepts every credential
// unconditionally, reproducing the pre-AuthUserPass behaviour these tests
// were already written against.
func testPermissiveAuthUserPass(_, _ string, _ tls.ConnectionState) error { return nil }

// clientHardReset builds and wraps a synthetic P_CONTROL_HARD_RESET_CLIENT_V2
// using the client tls-crypt key direction (encrypt with keys[1], decrypt
// with keys[0]).
func clientHardReset(t testing.TB, clientWrap *tlscrypt.Wrapper, clientSID wire.SessionID) []byte {
	t.Helper()

	cp := wire.ControlPacket{
		Opcode:    wire.OpControlHardResetClientV2,
		KeyID:     0,
		SessionID: clientSID,
		PacketID:  0,
	}
	plaintext := cp.AppendPlaintext(nil)

	header := wire.AppendHeaderByte(make([]byte, 0, 1+wire.SessionIDSize), cp.Opcode, cp.KeyID)
	header = append(header, clientSID[:]...)

	packet, err := clientWrap.Wrap(nil, header, plaintext)
	if err != nil {
		t.Fatalf("client wrap: %v", err)
	}
	return packet
}

// readAndParseReply reads one datagram from clientPC, unwraps it under the
// client key direction, and parses it as a control packet.
func readAndParseReply(t testing.TB, clientPC net.PacketConn, clientWrap *tlscrypt.Wrapper) wire.ControlPacket {
	t.Helper()

	buf := make([]byte, maxDatagramSize)
	if err := clientPC.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, _, err := clientPC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	header, plaintext, err := clientWrap.Unwrap(nil, buf[:n])
	if err != nil {
		t.Fatalf("client unwrap reply: %v", err)
	}

	opcode, keyID := wire.ParseHeaderByte(header[0])
	var serverSID wire.SessionID
	copy(serverSID[:], header[1:1+wire.SessionIDSize])

	cp, err := wire.ParseControlPacket(plaintext, wire.Header{Opcode: opcode, KeyID: keyID, SessionID: serverSID})
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	return cp
}

// testHandshakeServerCN is the CommonName/DNSName testHandshakeTLSConfig
// issues its server certificate for, and the ServerName a synthetic client
// verifies against.
const testHandshakeServerCN = "ovpn-test-handshake-server"

// testHandshakeTLSConfig builds a throwaway CA and a CA-issued server
// certificate (unlike testTLSConfig's bare self-signed cert, which none of
// this package's earlier tests ever actually verify — they never complete
// a real handshake). It returns the server's *tls.Config plus the CA pool
// a synthetic client uses for real certificate verification: these
// push-exchange tests (02-02-PLAN.md Task 3) are this package's first to
// drive an actual tls.Client(...).Handshake() against a live srv.Serve
// loop, so — unlike the earlier hard-reset-only tests — skipping
// verification here would be a real, avoidable weakening rather than a
// harmless test shortcut.
func testHandshakeTLSConfig(t testing.TB) (*tls.Config, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ovpn-test-handshake-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: testHandshakeServerCN},
		// DNSNames is required: Go's x509 verifier has ignored the legacy
		// Subject.CommonName fallback for hostname matching since Go 1.15
		// (see internal/ctrlconn/conn_test.go's genTestCerts, the same
		// precedent this helper follows).
		DNSNames:              []string{testHandshakeServerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
		MinVersion:   tls.VersionTLS12,
	}
	return serverCfg, pool
}

// testPushClient drives a synthetic OpenVPN client through hard reset, a
// real TLS handshake, Key Method 2, and PUSH_REQUEST/PUSH_REPLY against a
// live srv.Serve loop — enough to exercise runHandshake's full tunnel-up
// path end to end without Docker, for 02-02-PLAN.md Task 3's OnSession-
// timing tests. It reuses this package's own PUSH_REQUEST/PUSH_REPLY
// framing helpers (readControlString/writeControlString/
// pushRequestLiteral, push.go) since this file lives in package ovpn.
type testPushClient struct {
	pc        net.PacketConn
	wrapper   *tlscrypt.Wrapper
	clientSID wire.SessionID
	conn      *ctrlconn.Conn
	tlsConn   *tls.Conn
	stop      chan struct{}

	// mu guards conns: testPushClientDemux routes an inbound packet to the
	// Conn matching its key-id, so a renegotiating test can register a
	// second, key-id-1 Conn (via renegotiate below) without racing the
	// demux goroutine that is already reading (04-01-PLAN.md Task 1
	// action 8).
	mu    sync.Mutex
	conns map[uint8]*ctrlconn.Conn

	// dataOut receives a copy of any inbound datagram testPushClientDemux
	// cannot tls-crypt-unwrap — i.e. every P_DATA_V2 packet the server
	// sends this client, since the data channel is never tls-crypt wrapped
	// (04-01-PLAN.md Task 1's rollover test needs to observe the raw bytes
	// Session.Write sends, but the demux goroutine is the only reader of
	// client.pc). Buffered so a slow test consumer never blocks the demux
	// loop; a full buffer drops the newest datagram, mirroring this
	// package's own non-blocking-queue drop discipline elsewhere.
	dataOut chan []byte

	// serverInitiatedReneg receives the newly auto-registered Conn
	// whenever testPushClientDemux sees a SOFT_RESET_V1 for a key-id it
	// has no registered Conn for yet — mirroring how a real client
	// reacts to an unprompted, server-initiated soft reset (it does not
	// speculatively guess the next key-id and start sending before
	// observing the server's own reset marker; sending prematurely would
	// permanently trip the server's tls-crypt replay window on every
	// retransmission of that same packet-id, 04-01-PLAN.md Task 2). A
	// test drives its own tls.Client(...).Handshake() over the Conn
	// received here.
	serverInitiatedReneg chan *ctrlconn.Conn
}

// newTestPushClient performs the client's hard reset against serverAddr
// under key, builds a client-side ctrlconn.Conn over the same UDP socket,
// and starts demuxing further server datagrams into it. The caller drives
// the TLS handshake itself (via c.tlsConn.Handshake()) and everything
// after it — this constructor only gets as far as a live control-channel
// Conn ready for tls.Client to run on top of. caPool is the CA pool the
// client verifies the server's certificate against (testHandshakeTLSConfig
// issues both from the same throwaway CA).
func newTestPushClient(t testing.TB, key []byte, serverAddr net.Addr, caPool *x509.CertPool) *testPushClient {
	t.Helper()
	return newTestPushClientWithCerts(t, key, serverAddr, caPool, nil)
}

// newTestPushClientWithCerts is newTestPushClient's own delegate, extended
// with an optional client certificate (quick 260908-m4e's
// TestAuthUserPassNilHookIgnoresCredentials needs a client cert to satisfy
// Serve's D-07 guard while still proving a nil AuthUserPass hook ignores
// credentials — RequireAnyClientCert accepts any presented certificate
// without verifying it against caPool, so a throwaway self-signed cert is
// sufficient). A nil/empty certs leaves every existing call site's
// behavior unchanged (no client certificate presented at all).
func newTestPushClientWithCerts(t testing.TB, key []byte, serverAddr net.Addr, caPool *x509.CertPool, certs []tls.Certificate) *testPushClient {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}

	wrapper, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	var clientSID wire.SessionID
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}

	// remoteSID is left zero: the client cannot know the server's session
	// ID before any packet has arrived, and no receiver in this codebase
	// (confirmed by grep) ever validates an incoming packet's
	// RemoteSessionID field — it is write-only, purely for the reference
	// protocol's own bookkeeping, not enforced on the receive side here.
	// An unlearned zero value never causes a packet to be misrouted or
	// rejected.
	conn := ctrlconn.New(clientSID, wire.SessionID{}, wrapper, packetConnTransport{pc: pc}, serverAddr, nil)

	client := &testPushClient{
		pc:                   pc,
		wrapper:              wrapper,
		clientSID:            clientSID,
		conn:                 conn,
		stop:                 make(chan struct{}),
		conns:                map[uint8]*ctrlconn.Conn{0: conn},
		dataOut:              make(chan []byte, 8),
		serverInitiatedReneg: make(chan *ctrlconn.Conn, 4),
	}
	go testPushClientDemux(client)

	// SendReset transmits the initial hard reset through conn's OWN
	// send-side reliability window (packet ID 0) — unlike a hand-crafted
	// raw packet sent outside conn's own bookkeeping (as clientHardReset
	// does for this package's earlier, hard-reset-only tests), which would
	// leave conn's packet-ID counter starting over at 0 for its first REAL
	// write (the TLS ClientHello), duplicating — from the server's
	// recvRel's perspective — the packet ID the server already consumed
	// for the hard reset itself, silently corrupting the reassembled TLS
	// byte stream ("tls: first record does not look like a TLS
	// handshake").
	if err := conn.SendReset(wire.OpControlHardResetClientV2); err != nil {
		t.Fatalf("send hard reset: %v", err)
	}

	client.tlsConn = tls.Client(conn, &tls.Config{
		RootCAs:      caPool,
		ServerName:   testHandshakeServerCN,
		MinVersion:   tls.VersionTLS12,
		Certificates: certs,
	})

	return client
}

// renegotiate opens a second client-side Conn at keyID over the SAME
// client tls-crypt wrapper and session ID (mirroring the server's own
// runRenegotiation reusing sess.wrapper — 04-RESEARCH.md Pattern 3),
// registers it in the demux's per-key-id map so inbound packets at that
// key-id reach it, and sends the triggering SOFT_RESET_V1 — mirroring a
// real client's own soft-reset request. The caller drives the resulting
// *tls.Client handshake and Key Method 2 exchange itself, exactly like
// newTestPushClient's own conn (04-01-PLAN.md Task 1 action 8).
func (c *testPushClient) renegotiate(t testing.TB, serverAddr net.Addr, keyID uint8) *ctrlconn.Conn {
	t.Helper()

	newConn := ctrlconn.NewWithKeyID(c.clientSID, wire.SessionID{}, c.wrapper, packetConnTransport{pc: c.pc}, serverAddr, nil, keyID)

	c.mu.Lock()
	c.conns[keyID] = newConn
	c.mu.Unlock()

	if err := newConn.SendReset(wire.OpControlSoftResetV1); err != nil {
		t.Fatalf("send soft reset: %v", err)
	}
	return newConn
}

// Close stops the demux goroutine and tears down every Conn this client
// ever registered (the initial key-id-0 Conn plus any renegotiated Conn)
// and its UDP socket.
func (c *testPushClient) Close() {
	close(c.stop)
	c.mu.Lock()
	conns := make([]*ctrlconn.Conn, 0, len(c.conns))
	for _, conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	_ = c.pc.Close()
}

// testPushClientDemux mirrors internal/ctrlconn's own conn_test.go demux
// helper: unwrap under the client's own tls-crypt Wrapper, parse the
// plaintext body, and route the result by key-id to the matching
// registered Conn (client.conns) — extended from a single fixed conn so a
// renegotiating test's second, key-id-1 Conn also receives its own control
// traffic (04-01-PLAN.md Task 1 action 8). A key-id with no registered Conn
// is silently dropped, mirroring the server's own pump/routeControlPacket
// drop discipline.
func testPushClientDemux(client *testPushClient) {
	buf := make([]byte, maxDatagramSize)
	for {
		select {
		case <-client.stop:
			return
		default:
		}
		if err := client.pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return
		}
		n, _, err := client.pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		header, plaintext, err := client.wrapper.Unwrap(nil, buf[:n])
		if err != nil {
			// Not a tls-crypt-wrapped control packet — the data channel is
			// never tls-crypt wrapped, so this is exactly what every
			// P_DATA_V2 packet looks like from here. Forward a copy to
			// dataOut for any test that needs to observe raw data-channel
			// bytes (e.g. Session.Write's output) rather than dropping it.
			raw := make([]byte, n)
			copy(raw, buf[:n])
			select {
			case client.dataOut <- raw:
			default:
			}
			continue
		}
		opcode, keyID := wire.ParseHeaderByte(header[0])
		var sid wire.SessionID
		copy(sid[:], header[1:1+wire.SessionIDSize])
		cp, err := wire.ParseControlPacket(plaintext, wire.Header{Opcode: opcode, KeyID: keyID, SessionID: sid})
		if err != nil {
			continue
		}
		client.mu.Lock()
		target := client.conns[keyID]
		if target == nil && opcode == wire.OpControlSoftResetV1 {
			// A server-initiated soft reset for a key-id this client has
			// never seen: react exactly like a real client would — open a
			// new Conn for it now, over the SAME client wrapper and
			// session ID, and report it so a test can drive its own
			// tls.Client(...).Handshake() (04-01-PLAN.md Task 2). Building
			// this Conn any earlier (e.g. speculatively, before the server
			// ever sent anything) would have nowhere to route on the
			// server side yet, and every retransmission of that same
			// packet-id would then be permanently rejected by the
			// server's tls-crypt replay window once the first one had
			// already been seen and dropped.
			newConn := ctrlconn.NewWithKeyID(client.clientSID, wire.SessionID{}, client.wrapper, packetConnTransport{pc: client.pc}, client.conn.RemoteAddr(), nil, keyID)
			client.conns[keyID] = newConn
			target = newConn
			select {
			case client.serverInitiatedReneg <- newConn:
			default:
			}
		}
		client.mu.Unlock()
		if target != nil {
			target.Deliver(cp)
		}
	}
}

// writeTestClientKeyMethod2Raw writes a well-formed client Key Method 2
// message matching keyderiv.ReadClientKeyMethod2's expected layout: 4
// reserved bytes, KEY_METHOD_2, 48-byte pre_master, 32-byte random1,
// 32-byte random2, then the four given fields, each as its own
// 2-byte-big-endian-length-prefixed byte string (readLengthPrefixedString's
// counterpart) — allowing a test to construct a field of any length,
// including one deliberately over keyderiv's own 512-byte cap or this
// package's 128-byte userPassLen. This is the single place the fixed
// reserved/key-method/random prefix is built; writeTestClientKeyMethod2Creds
// and the legacy writeTestClientKeyMethod2 both delegate here.
func writeTestClientKeyMethod2Raw(w io.Writer, options, username, password, peerInfo []byte) error {
	buf := make([]byte, 0, 4+1+48+32+32+8+len(options)+len(username)+len(password)+len(peerInfo))
	buf = append(buf, 0, 0, 0, 0) // reserved
	buf = append(buf, 2)          // KEY_METHOD_2

	random := make([]byte, 48+32+32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	buf = append(buf, random...)

	for _, field := range [][]byte{options, username, password, peerInfo} {
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(field)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, field...)
	}

	_, err := w.Write(buf)
	return err
}

// testDefaultPeerInfo is the peer_info payload writeTestClientKeyMethod2Creds
// (and therefore writeTestClientKeyMethod2/tunnelUpTestClient and every
// test built on them) sends by default: "IV_NCP=2", the same NCP-support
// signal a real OpenVPN 2.6 client always sends (tls_peer_info_ncp_ver,
// ssl_ncp.c:55-70), implying the capability list [AES-256-GCM,
// AES-128-GCM] (peerCipherList, cipher.go). Phase 5's selectCipher
// requires the peer to actually advertise SOME capability (or a matching
// OCC cipher) before it negotiates anything — without this default, every
// one of this package's many pre-existing handshake/push/renegotiation
// tests, which never set peer_info themselves, would fail cipher
// negotiation outright. Advertising IV_NCP=2 rather than an explicit
// IV_CIPHERS= list keeps the server's own default allow-list order
// deciding the outcome (AES-256-GCM first, since selectCipher iterates the
// server's list outermost) — preserving every pre-existing test's implicit
// assumption of a fixed AES-256-GCM session (05-01-PLAN.md "the
// AES-256-GCM path is provably unchanged").
var testDefaultPeerInfo = []byte("IV_NCP=2\n")

// writeTestClientKeyMethod2Creds writes a client Key Method 2 message
// carrying username/password (options left empty, peer_info set to
// testDefaultPeerInfo above), encoding each non-empty credential as
// append([]byte(s), 0) — write_string's own convention (R2: the wire
// length includes the trailing NUL) — and an empty string as a genuinely
// zero-length field (the "not provided by peer" case, distinct from a
// present-but-empty string).
func writeTestClientKeyMethod2Creds(w io.Writer, username, password string) error {
	encode := func(s string) []byte {
		if s == "" {
			return nil
		}
		return append([]byte(s), 0)
	}
	return writeTestClientKeyMethod2Raw(w, nil, encode(username), encode(password), testDefaultPeerInfo)
}

// testPlaceholderUsername/testPlaceholderPassword are content-arbitrary
// (this project doesn't validate the username/password strings when
// Config.AuthUserPass is nil, RESEARCH.md Pitfall 4) but deliberately
// non-empty (quick 260908-m4e): an EMPTY credential is an auth failure
// regardless of whether a hook is set (R3/D-02), so every one of this
// package's many pre-existing tests that reuse a permissive
// testPermissiveAuthUserPass hook to satisfy Serve's D-07 guard needs a
// non-empty placeholder here, not an empty one — otherwise the emptiness
// check would reject them before the (accepting) hook is ever reached.
const (
	testPlaceholderUsername = "testuser"
	testPlaceholderPassword = "testpass"
)

// writeTestClientKeyMethod2 writes a well-formed (but content-arbitrary)
// client Key Method 2 message carrying testPlaceholderUsername/
// testPlaceholderPassword. Delegates to writeTestClientKeyMethod2Creds so
// there is one prefix-building path, not two.
func writeTestClientKeyMethod2(w io.Writer) error {
	return writeTestClientKeyMethod2Creds(w, testPlaceholderUsername, testPlaceholderPassword)
}

// readTestServerKeyMethod2 reads and discards the server's own Key Method
// 2 message (keyderiv.WriteServerKeyMethod2's layout: 4 reserved bytes,
// key-method byte, 32-byte random1, 32-byte random2, then four
// length-prefixed strings) without needing to know serverKM2Options'
// exact content in advance.
func readTestServerKeyMethod2(r io.Reader) error {
	var fixed [4 + 1 + 32 + 32]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return err
		}
		if n := binary.BigEndian.Uint16(lenBuf[:]); n > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
				return err
			}
		}
	}
	return nil
}

// tunnelUpTestClientCreds drives client all the way through hard reset, TLS
// handshake, and Key Method 2 (carrying username/password, quick
// 260908-m4e), returning a reader positioned right after the server's own
// Key Method 2 reply. It fails the test on any error along the way.
func tunnelUpTestClientCreds(t testing.TB, key []byte, serverAddr net.Addr, caPool *x509.CertPool, username, password string) (*testPushClient, *bufio.Reader) {
	t.Helper()

	client := newTestPushClient(t, key, serverAddr, caPool)

	// A bounded deadline through handshake+KM2 turns a protocol bug in this
	// test harness into a fast, diagnosable failure instead of a silent
	// hang up to go test's own default 10-minute timeout.
	if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	if err := client.tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2Creds(client.tlsConn, username, password); err != nil {
		t.Fatalf("write client Key Method 2: %v", err)
	}
	if err := readTestServerKeyMethod2(client.tlsConn); err != nil {
		t.Fatalf("read server Key Method 2: %v", err)
	}

	if err := client.conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear client deadline: %v", err)
	}

	return client, bufio.NewReader(client.tlsConn)
}

// tunnelUpTestClient drives client all the way through hard reset, TLS
// handshake, and Key Method 2 carrying testPlaceholderUsername/
// testPlaceholderPassword (quick 260908-m4e — see those constants' own
// doc comment for why these must be non-empty, not the empty defaults this
// function used before AuthUserPass existed), returning a reader
// positioned right after the server's own Key Method 2 reply. It fails the
// test on any error along the way. Delegates to tunnelUpTestClientCreds so
// there is one bring-up path, not two.
func tunnelUpTestClient(t testing.TB, key []byte, serverAddr net.Addr, caPool *x509.CertPool) (*testPushClient, *bufio.Reader) {
	t.Helper()
	return tunnelUpTestClientCreds(t, key, serverAddr, caPool, testPlaceholderUsername, testPlaceholderPassword)
}

// TestOnSessionFiresAfterPushReply is 02-02-PLAN.md Task 3's D-08 proof: a
// real client's OnSession callback observes a fully populated
// Session.AssignedIP() inside Config.Network, and — via the
// onSessionEntered/allowOnSessionReturn gate below — cannot have been
// entered until this test has ALREADY read the full PUSH_REPLY off the
// wire, proving the reply write happens-before the callback (not merely
// "usually does" by timing coincidence).
func TestOnSessionFiresAfterPushReply(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.0.0/24")
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

	onSessionEntered := make(chan struct{})
	allowOnSessionReturn := make(chan struct{})
	sessions := make(chan *Session, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession: func(sess *Session) {
			close(onSessionEntered)
			<-allowOnSessionReturn
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

	reply, err := readControlString(replyReader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read push reply: %v", err)
	}
	if !strings.HasPrefix(reply, "PUSH_REPLY,") {
		t.Fatalf("push reply = %q, want a PUSH_REPLY prefix", reply)
	}

	// The reply has now been fully read off the wire. OnSession must not
	// have been entered before this point was reachable — check it here,
	// AFTER the read, so a regression that fired OnSession before writing
	// the reply would instead show onSessionEntered already closed before
	// our read above even returned (which this ordering can't detect
	// after the fact), or — the case this really guards — a regression
	// that never writes the reply at all would hang the read above
	// forever rather than let a stale OnSession fire un-observed.
	select {
	case <-onSessionEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was not entered even though the PUSH_REPLY already arrived")
	}
	close(allowOnSessionReturn)

	select {
	case sess := <-sessions:
		ip := sess.AssignedIP()
		if ip == nil {
			t.Fatal("OnSession fired with a nil AssignedIP()")
		}
		if !network.Contains(ip) {
			t.Errorf("AssignedIP() = %s, not inside %s", ip, network)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}
}

// TestOnSessionFiresExactlyOnce is 02-02-PLAN.md Task 3's proof that a
// normal single-PUSH_REQUEST exchange over a live, real handshake causes
// exactly one allocation and exactly one OnSession invocation — the
// control-flow guarantee (runHandshake has exactly one callOnSession
// callsite, called once per goroutine) that every session, including a
// retransmitted one, relies on. TestPerformPushExchangeAnswersBuffered
// RetransmitWithSameIP below covers the retransmit-specific claim (T-02-06:
// a buffered second PUSH_REQUEST is answered with the SAME assigned IP,
// not a fresh allocation) deterministically, without depending on live
// network timing to land two records in one read.
func TestOnSessionFiresExactlyOnce(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.1.0/24")
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

	select {
	case sess := <-sessions:
		if sess.AssignedIP() == nil {
			t.Fatal("OnSession fired with a nil AssignedIP()")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}

	// Give a second (incorrect) OnSession invocation a brief window to
	// show up before asserting there wasn't one.
	select {
	case <-sessions:
		t.Fatal("OnSession was called a second time for the same session")
	case <-time.After(200 * time.Millisecond):
	}

	if got := atomic.LoadInt32(&onSessionCount); got != 1 {
		t.Errorf("OnSession called %d times, want exactly 1", got)
	}
}

// TestPerformPushExchangeAnswersBufferedRetransmitWithSameIP is
// 02-02-PLAN.md Task 3's deterministic T-02-06 proof: it calls
// performPushExchange directly with BOTH "PUSH_REQUEST\x00" occurrences
// already sitting in sess.tlsReader's buffer before the call ever reads
// from it — deterministically reproducing "the client's retransmit already
// arrived by the time the first reply goes out" without depending on live
// network timing to land two TLS records in one read (which
// TestOnSessionFiresExactlyOnce's earlier, flakier design attempted and
// which lost the race under go test -race on this machine).
func TestPerformPushExchangeAnswersBufferedRetransmitWithSameIP(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.7.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	srv := &Server{pool: pool, cfg: Config{Network: network}, dataSessions: make(map[uint32]*Session)}

	input := pushRequestLiteral + "\x00" + pushRequestLiteral + "\x00"
	dataKeys, err := keyderiv.NewKey2(make([]byte, 256))
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}
	sess := &Session{tlsReader: bufio.NewReader(strings.NewReader(input)), dataKeys: dataKeys, cipher: "AES-256-GCM"}

	var out strings.Builder
	if err := srv.performPushExchange(sess, &out); err != nil {
		t.Fatalf("performPushExchange: %v", err)
	}

	if sess.assignedIP == nil {
		t.Fatal("performPushExchange did not assign an IP")
	}
	assignedIP := sess.assignedIP.String()

	replies := strings.Split(strings.TrimSuffix(out.String(), "\x00"), "\x00")
	if len(replies) != 2 {
		t.Fatalf("got %d replies, want 2 (one per buffered PUSH_REQUEST): %q", len(replies), out.String())
	}
	if replies[0] != replies[1] {
		t.Errorf("retransmitted push request answered differently:\n  1: %q\n  2: %q", replies[0], replies[1])
	}
	wantSegment := "ifconfig " + assignedIP + " "
	if !strings.Contains(replies[0], wantSegment) {
		t.Errorf("reply does not contain the assigned IP %s: %q", assignedIP, replies[0])
	}

	// Confirm only ONE address was actually taken from the pool: a second
	// allocation should return the pool's NEXT free address, not the same
	// one (which it would if performPushExchange had mistakenly allocated
	// twice and then only used one of the two results).
	next, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate after performPushExchange: %v", err)
	}
	if next.Equal(sess.assignedIP) {
		t.Errorf("second pool.allocate() returned the same address %s performPushExchange already assigned — it must have allocated only once", next)
	}
}

// TestPerformPushExchangeReleasesAllocationWhenSessionAlreadyClosing is
// WR-05's regression test: enforceHandshakeWindow's timeout goroutine can
// call sess.Close() concurrently with performPushExchange at any point up
// to sess.doneCh closing. This forces Close to have already run to
// completion by the time performPushExchange reaches the point where it
// would otherwise publish sess.assignedIP/peerID/dataWrapper and the
// srv.dataSessions routing entry — the same outcome enforceHandshakeWindow
// landing "anywhere before w.Write(reply) returns" produces, made
// deterministic here by calling the real, idempotent sess.Close() before
// performPushExchange ever runs rather than depending on goroutine
// scheduling. Before the fix, performPushExchange never consulted
// sess.stopCh at all: it would allocate, publish every field, publish the
// dataSessions routing entry, start the keepalive goroutine, and return nil
// regardless — permanently leaking the pool IP/peer-id (nothing else would
// ever release it, since Close's own stopOnce.Do already ran) and leaving a
// permanently stale srv.dataSessions entry. This test fails against that
// code: performPushExchange returns nil, sess.assignedIP/dataWrapper end up
// non-nil, srv.dataSessions gains an entry, and the network's sole
// allocatable address never becomes allocatable again.
func TestPerformPushExchangeReleasesAllocationWhenSessionAlreadyClosing(t *testing.T) {
	_, network, err := net.ParseCIDR("10.60.0.0/30") // exactly one allocatable client address/peer-id
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	srv := &Server{
		pool:         pool,
		cfg:          Config{Network: network},
		sessions:     make(map[sessionKey]*Session),
		dataSessions: make(map[uint32]*Session),
	}

	dataKeys, err := keyderiv.NewKey2(make([]byte, 256))
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}
	sess := &Session{
		tlsReader: bufio.NewReader(strings.NewReader(pushRequestLiteral + "\x00")),
		dataKeys:  dataKeys,
		cipher:    "AES-256-GCM",
		srv:       srv,
		stopCh:    make(chan struct{}),
	}

	// Simulates enforceHandshakeWindow's timeout goroutine winning the
	// race entirely: sess.assignedIP/peerID/dataWrapper are all still
	// unset, so this Close call's own cleanup is a no-op (nothing to
	// release yet) — exactly the state a real timeout-triggered Close
	// would find if it ran before performPushExchange even called
	// s.pool.allocate(). What's under test is what performPushExchange
	// does AFTER this, once its own allocate() call succeeds and it
	// checks sess.closing() before publishing anything.
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var out strings.Builder
	if err := srv.performPushExchange(sess, &out); err == nil {
		t.Fatal("performPushExchange succeeded for an already-closing session; want an error")
	}

	if sess.assignedIP != nil {
		t.Errorf("sess.assignedIP = %v, want nil — must not publish state for an already-closing session", sess.assignedIP)
	}
	if sess.primary.wrapper != nil {
		t.Error("sess.primary.wrapper is set — must not publish state for an already-closing session")
	}

	srv.mu.Lock()
	n := len(srv.dataSessions)
	srv.mu.Unlock()
	if n != 0 {
		t.Errorf("srv.dataSessions has %d entries, want 0 — must not leak a routing entry for an already-closing session", n)
	}

	// The core WR-05 assertion: the IP/peer-id s.pool.allocate() handed out
	// inside performPushExchange must have been released back to the pool,
	// not permanently leaked — a second allocate() on this exactly-one-slot
	// network must still succeed.
	if _, _, err := pool.allocate(); err != nil {
		t.Fatalf("pool.allocate() after performPushExchange: %v (the allocation performPushExchange made was never released back to the pool)", err)
	}
}

// TestPushExchangeFailsWithoutNegotiatedCipher is T-05-05's fail-loud
// guard (05-03-PLAN.md Task 2): performPushExchange must never substitute a
// default cipher for a session whose negotiation never ran (sess.cipher ==
// "") — a hand-built *Session with no cipher set, exactly like a wiring bug
// that skipped performKeyMethod2Exchange's publish would produce, must
// error out before writing anything, not silently push AES-256-GCM.
func TestPushExchangeFailsWithoutNegotiatedCipher(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.8.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	srv := &Server{pool: pool, cfg: Config{Network: network}, dataSessions: make(map[uint32]*Session)}

	dataKeys, err := keyderiv.NewKey2(make([]byte, 256))
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}
	// cipher is deliberately left unset (the zero value, "").
	sess := &Session{tlsReader: bufio.NewReader(strings.NewReader(pushRequestLiteral + "\x00")), dataKeys: dataKeys}

	var out strings.Builder
	if err := srv.performPushExchange(sess, &out); err == nil {
		t.Fatal("performPushExchange succeeded for a session with no negotiated cipher; want an error")
	}
	if out.Len() != 0 {
		t.Errorf("performPushExchange wrote %q, want nothing written when it fails before ever reading the push request", out.String())
	}
	if sess.assignedIP != nil {
		t.Error("sess.assignedIP is set — must not allocate a tunnel IP when the cipher guard fails")
	}
}

// TestOnSessionDoesNotFireWhenPushNeverArrives is 02-02-PLAN.md Task 3's
// proof that runHandshake's doneCh close now covers the whole bring-up
// sequence, not merely tls.Conn.Handshake() returning nil: a client that
// completes TLS and Key Method 2 but never sends PUSH_REQUEST is still
// reaped by enforceHandshakeWindow, and OnSession never fires for it. Uses
// the test-injectable Server.handshakeWindow field rather than waiting a
// real 60 seconds.
func TestOnSessionDoesNotFireWhenPushNeverArrives(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.2.0/24")
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

	var onSessionCalled int32
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession: func(sess *Session) {
			atomic.AddInt32(&onSessionCalled, 1)
		},
	})
	srv.handshakeWindow = 150 * time.Millisecond
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	client := newTestPushClient(t, key, serverPC.LocalAddr(), caPool)
	defer client.Close()

	// Bounded, same rationale as tunnelUpTestClient: a protocol bug here
	// must fail fast, not hang up to go test's default 10-minute timeout.
	if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := client.tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2(client.tlsConn); err != nil {
		t.Fatalf("write client Key Method 2: %v", err)
	}
	if err := readTestServerKeyMethod2(client.tlsConn); err != nil {
		t.Fatalf("read server Key Method 2: %v", err)
	}
	if err := client.conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear client deadline: %v", err)
	}
	// Deliberately never send PUSH_REQUEST.

	var sess *Session
	deadline := time.Now().Add(2 * time.Second)
	for sess == nil && time.Now().Before(deadline) {
		srv.mu.Lock()
		for _, s := range srv.sessions {
			sess = s
		}
		srv.mu.Unlock()
		if sess == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sess == nil {
		t.Fatal("expected a session to exist before the handshake window elapses")
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		_, present := srv.sessions[sess.key]
		srv.mu.Unlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session still present in Server.sessions after the handshake window elapsed")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := atomic.LoadInt32(&onSessionCalled); got != 0 {
		t.Errorf("OnSession called %d times, want 0 (client never sent PUSH_REQUEST)", got)
	}
}

// TestAssignedIPIsZeroBeforeTunnelUp mirrors ConnectionState's documented
// zero-value behavior (D-07): AssignedIP() on a Session whose exchange has
// not completed returns nil.
func TestAssignedIPIsZeroBeforeTunnelUp(t *testing.T) {
	sess := &Session{}
	if ip := sess.AssignedIP(); ip != nil {
		t.Errorf("AssignedIP() on a fresh session = %v, want nil", ip)
	}
}

// TestAssignedIPReleasedOnClose is 02-02-PLAN.md Task 3's D-02 proof at
// the Session/Server level (ippool_test.go already covers it at the pool
// level): closing a session that reached tunnel-up releases its address
// back to Server.pool for immediate reuse.
func TestAssignedIPReleasedOnClose(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.3.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	srv := &Server{pool: pool, sessions: make(map[sessionKey]*Session)}

	ip, peerID, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	sess := &Session{srv: srv, assignedIP: ip, peerID: peerID, stopCh: make(chan struct{})}

	if err := sess.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ip2, _, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate after close: %v", err)
	}
	if !ip2.Equal(ip) {
		t.Errorf("allocate after close = %s, want the released address %s", ip2, ip)
	}
}

// TestOnSessionPanicStillRecovered is 02-02-PLAN.md Task 3's proof that a
// panicking OnSession at the NEW callsite (after the push exchange, D-08)
// is still recovered and still reaches Config.OnSessionPanic, exactly like
// TestOnSessionPanicRecovered already proves for callOnSession in
// isolation — this test drives it through the real runHandshake path.
func TestOnSessionPanicStillRecovered(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.4.0/24")
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

	const panicValue = "boom: simulated OnSession bug in the tunnel-up path"
	panicked := make(chan any, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		OnSession: func(sess *Session) {
			panic(panicValue)
		},
		OnSessionPanic: func(sess *Session, recovered any, stack []byte) {
			panicked <- recovered
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

	select {
	case r := <-panicked:
		if r != panicValue {
			t.Errorf("recovered value = %v, want %q", r, panicValue)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnSessionPanic was never called")
	}
}

// TestCloseIsIdempotentAfterTunnelUp is 02-02-PLAN.md Task 3's proof that
// calling Close twice on a tunnel-up session releases its address exactly
// once (the same guarantee TestSessionCloseStopsPumpAndRemovesFromSessions
// already proves for a pre-tunnel-up session).
func TestCloseIsIdempotentAfterTunnelUp(t *testing.T) {
	_, network, err := net.ParseCIDR("10.20.5.0/24")
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
		OnSession: func(sess *Session) {
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

	assignedIP := sess.AssignedIP()
	if assignedIP == nil {
		t.Fatal("session reached OnSession with a nil AssignedIP()")
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	ip2, _, err := srv.pool.allocate()
	if err != nil {
		t.Fatalf("allocate after double close: %v", err)
	}
	if !ip2.Equal(assignedIP) {
		t.Errorf("allocate after double close = %s, want the released address %s (double release must not corrupt pool state)", ip2, assignedIP)
	}
}

// TestDuplicateCNGetsDistinctIPs is 02-02-PLAN.md Task 2's D-04 proof: two
// sessions whose verified CommonName is identical (the reference's own
// --duplicate-cn semantics — duplicate connections from the same client
// identity are allowed, each getting its own tunnel address) still receive
// distinct addresses and peer-ids. ipPool.allocate takes no identity
// parameter at all, so it cannot special-case a CommonName even if it
// wanted to — this test drives that property directly against two Session
// values sharing the same PeerCN, exactly mirroring how ovpn.go's
// performPushExchange calls s.pool.allocate() with no knowledge of
// sess.PeerCN.
func TestDuplicateCNGetsDistinctIPs(t *testing.T) {
	_, network, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}

	const duplicateCN = "duplicate-client"
	sess1 := &Session{PeerCN: duplicateCN}
	sess2 := &Session{PeerCN: duplicateCN}

	ip1, peerID1, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate for sess1: %v", err)
	}
	sess1.assignedIP, sess1.peerID = ip1, peerID1

	ip2, peerID2, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate for sess2: %v", err)
	}
	sess2.assignedIP, sess2.peerID = ip2, peerID2

	if sess1.PeerCN != sess2.PeerCN {
		t.Fatalf("test setup bug: sessions do not share a CommonName (%q vs %q)", sess1.PeerCN, sess2.PeerCN)
	}
	if sess1.assignedIP.Equal(sess2.assignedIP) {
		t.Errorf("two sessions with identical PeerCN %q got the same tunnel address %s", duplicateCN, sess1.assignedIP)
	}
	if sess1.peerID == sess2.peerID {
		t.Errorf("two sessions with identical PeerCN %q got the same peer-id %d", duplicateCN, sess1.peerID)
	}
}

func TestHardResetRoundTrip(t *testing.T) {
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t), AuthUserPass: testPermissiveAuthUserPass})
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(serverPC) }()
	defer srv.Close()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	clientWrap, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	clientSID := wire.SessionID{1, 2, 3, 4, 5, 6, 7, 8}

	packet := clientHardReset(t, clientWrap, clientSID)
	if _, err := clientPC.WriteTo(packet, serverPC.LocalAddr()); err != nil {
		t.Fatalf("write hard reset: %v", err)
	}

	cp := readAndParseReply(t, clientPC, clientWrap)

	if cp.Opcode != wire.OpControlHardResetServerV2 {
		t.Errorf("opcode = %d, want %d (OpControlHardResetServerV2)", cp.Opcode, wire.OpControlHardResetServerV2)
	}
	var zero wire.SessionID
	if cp.SessionID == zero {
		t.Error("server session ID is zero, want a freshly generated non-zero value")
	}
	if cp.PacketID != 0 {
		t.Errorf("server packet ID = %d, want 0", cp.PacketID)
	}
	if len(cp.Acks) != 1 || cp.Acks[0] != 0 {
		t.Errorf("acks = %v, want [0] (acking the client's packet ID 0)", cp.Acks)
	}
	if cp.RemoteSessionID != clientSID {
		t.Errorf("remote session id = %x, want %x (the client's own session id)", cp.RemoteSessionID, clientSID)
	}
}

func TestConcurrentSessions(t *testing.T) {
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t), AuthUserPass: testPermissiveAuthUserPass})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	type result struct {
		serverSID wire.SessionID
		err       error
	}

	run := func(fill byte) result {
		clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return result{err: err}
		}
		defer clientPC.Close()

		clientWrap, err := tlscrypt.NewWrapper(key, false)
		if err != nil {
			return result{err: err}
		}

		var sid wire.SessionID
		for i := range sid {
			sid[i] = fill
		}

		buf := make([]byte, 0, 1+wire.SessionIDSize)
		cp := wire.ControlPacket{Opcode: wire.OpControlHardResetClientV2, SessionID: sid}
		plaintext := cp.AppendPlaintext(nil)
		header := wire.AppendHeaderByte(buf, cp.Opcode, cp.KeyID)
		header = append(header, sid[:]...)
		packet, err := clientWrap.Wrap(nil, header, plaintext)
		if err != nil {
			return result{err: err}
		}

		if _, err := clientPC.WriteTo(packet, serverPC.LocalAddr()); err != nil {
			return result{err: err}
		}

		readBuf := make([]byte, maxDatagramSize)
		if err := clientPC.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return result{err: err}
		}
		n, _, err := clientPC.ReadFrom(readBuf)
		if err != nil {
			return result{err: err}
		}
		rHeader, rPlaintext, err := clientWrap.Unwrap(nil, readBuf[:n])
		if err != nil {
			return result{err: err}
		}
		opcode, keyID := wire.ParseHeaderByte(rHeader[0])
		var serverSID wire.SessionID
		copy(serverSID[:], rHeader[1:1+wire.SessionIDSize])
		rcp, err := wire.ParseControlPacket(rPlaintext, wire.Header{Opcode: opcode, KeyID: keyID, SessionID: serverSID})
		if err != nil {
			return result{err: err}
		}
		if rcp.RemoteSessionID != sid {
			return result{err: err}
		}
		return result{serverSID: serverSID}
	}

	const n = 2
	fills := [n]byte{0xAA, 0xBB}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = run(fills[i])
		}()
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			t.Fatalf("client %d: %v", i, r.err)
		}
	}
	if results[0].serverSID == results[1].serverSID {
		t.Errorf("expected distinct server session IDs, both clients got %x", results[0].serverSID)
	}
}

func TestServeClose(t *testing.T) {
	key := testTLSCryptKey(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t), AuthUserPass: testPermissiveAuthUserPass})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(pc) }()

	// Give Serve a moment to reach its blocking ReadFrom call.
	time.Sleep(50 * time.Millisecond)

	if err := srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned error after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

// TestSessionCloseStopsPumpAndRemovesFromSessions is a regression test for
// CR-01 (01-REVIEW.md): Session.Close() must remove the session from
// Server.sessions and must stop the per-session pump/runHandshake/
// enforceHandshakeWindow goroutines, not merely close the underlying
// control-channel Conn.
func TestSessionCloseStopsPumpAndRemovesFromSessions(t *testing.T) {
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t), AuthUserPass: testPermissiveAuthUserPass})
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	clientWrap, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	runtime.GC()
	baseline := runtime.NumGoroutine()

	clientSID := wire.SessionID{9, 9, 9, 9, 9, 9, 9, 9}
	packet := clientHardReset(t, clientWrap, clientSID)
	if _, err := clientPC.WriteTo(packet, serverPC.LocalAddr()); err != nil {
		t.Fatalf("write hard reset: %v", err)
	}
	readAndParseReply(t, clientPC, clientWrap)

	// The hard reset above has already caused handleDatagram to create the
	// session and start its pump/runHandshake/enforceHandshakeWindow
	// goroutines (ovpn.go's "if justCreated" branch). The TLS handshake
	// itself never completes in this test — there is no real TLS client on
	// the other end, exactly as in TestHardResetRoundTrip — so
	// Config.OnSession is never invoked; grab the *Session straight from
	// the server's session table instead.
	var sess *Session
	deadline := time.Now().Add(2 * time.Second)
	for sess == nil && time.Now().Before(deadline) {
		srv.mu.Lock()
		for _, s := range srv.sessions {
			sess = s
		}
		srv.mu.Unlock()
		if sess == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sess == nil {
		t.Fatal("expected a session to have been created in Server.sessions")
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("session close: %v", err)
	}

	srv.mu.Lock()
	_, stillPresent := srv.sessions[sess.key]
	srv.mu.Unlock()
	if stillPresent {
		t.Error("session still present in Server.sessions after Close()")
	}

	// pump, runHandshake, and enforceHandshakeWindow should all exit
	// shortly after Close() (Close's stopCh close unblocks pump directly;
	// closing sess.conn unblocks the in-flight Handshake() call, which in
	// turn closes doneCh and unblocks enforceHandshakeWindow). Poll for
	// goroutine count to return to its pre-session baseline rather than
	// asserting instantaneously, since goroutine teardown is asynchronous.
	deadline = time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= baseline {
			break
		} else if time.Now().After(deadline) {
			t.Errorf("goroutine count did not return to baseline after Close(): got %d, want <= %d", n, baseline)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestHandshakeWindowTearsDownStalledSession verifies the
// timeout-triggered teardown path of enforceHandshakeWindow: a client that
// sends its hard reset but never progresses the TLS handshake must be torn
// down once the handshake window elapses — removed from Server.sessions
// with all three per-session goroutines (pump, runHandshake,
// enforceHandshakeWindow) exiting. Unlike
// TestSessionCloseStopsPumpAndRemovesFromSessions, nothing here ever calls
// Close explicitly; the window expiry alone must do the whole teardown.
// The window is shortened via the test-injectable Server.handshakeWindow
// field (production default: reliable.HandshakeWindow, 60s).
func TestHandshakeWindowTearsDownStalledSession(t *testing.T) {
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t), AuthUserPass: testPermissiveAuthUserPass})
	srv.handshakeWindow = 150 * time.Millisecond
	go func() { _ = srv.Serve(serverPC) }()
	defer srv.Close()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	clientWrap, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	runtime.GC()
	baseline := runtime.NumGoroutine()

	clientSID := wire.SessionID{7, 7, 7, 7, 7, 7, 7, 7}
	packet := clientHardReset(t, clientWrap, clientSID)
	if _, err := clientPC.WriteTo(packet, serverPC.LocalAddr()); err != nil {
		t.Fatalf("write hard reset: %v", err)
	}
	readAndParseReply(t, clientPC, clientWrap)

	// The session must exist before the window elapses.
	var sess *Session
	deadline := time.Now().Add(2 * time.Second)
	for sess == nil && time.Now().Before(deadline) {
		srv.mu.Lock()
		for _, s := range srv.sessions {
			sess = s
		}
		srv.mu.Unlock()
		if sess == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sess == nil {
		t.Fatal("expected a session to have been created in Server.sessions")
	}

	// Stall: never speak TLS. The window expiry alone must remove the
	// session and wind down its goroutines.
	deadline = time.Now().Add(5 * time.Second)
	for {
		srv.mu.Lock()
		_, stillPresent := srv.sessions[sess.key]
		srv.mu.Unlock()
		if !stillPresent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session still present in Server.sessions after handshake window elapsed")
		}
		time.Sleep(10 * time.Millisecond)
	}

	deadline = time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= baseline {
			break
		} else if time.Now().After(deadline) {
			t.Errorf("goroutine count did not return to baseline after window teardown: got %d, want <= %d", n, baseline)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestOnSessionPanicRecovered is a regression test for WR-01/WR-03
// (01-REVIEW.md): a panicking Config.OnSession callback must not crash the
// process, and — since WR-03's fix — the recovered panic value must be
// surfaced to Config.OnSessionPanic rather than silently swallowed.
func TestOnSessionPanicRecovered(t *testing.T) {
	key := testTLSCryptKey(t)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	panicked := make(chan any, 1)
	srv := NewServer(Config{
		TLSCryptKey: key,
		TLSConfig:   testTLSConfig(t),
		OnSession: func(sess *Session) {
			panic("boom: simulated OnSession bug")
		},
		OnSessionPanic: func(sess *Session, recovered any, stack []byte) {
			panicked <- recovered
		},
	})
	// Directly exercise callOnSession rather than driving a full TLS
	// handshake: OnSession only fires post-handshake, and this test's only
	// concern is that a panic inside it is recovered and routed to
	// OnSessionPanic, not the handshake machinery itself (covered by
	// TestHardResetRoundTrip and the interop suite).
	sess := &Session{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.callOnSession(sess)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callOnSession did not return — panic was not recovered")
	}

	select {
	case r := <-panicked:
		if r != "boom: simulated OnSession bug" {
			t.Errorf("recovered value = %v, want %q", r, "boom: simulated OnSession bug")
		}
	case <-time.After(time.Second):
		t.Fatal("OnSessionPanic was never called")
	}
}

// TestSessionReadWriteDatagramSemantics is 02-03-PLAN.md Task 1's D-05
// proof: Session.Write seals exactly one full IP packet per call (the peer
// decrypts it to the exact bytes given to Write, not a stream fragment),
// and Session.Read delivers exactly one full IP packet per call — a
// too-small buffer returns an error and RETAINS the packet (this
// Session's own documented D-05 choice, session.go's pendingRead doc
// comment) rather than truncating it or silently losing it, and a
// subsequent Read with a large-enough buffer still receives it, in full.
func TestSessionReadWriteDatagramSemantics(t *testing.T) {
	var raw [256]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	key2, err := keyderiv.NewKey2(raw[:])
	if err != nil {
		t.Fatalf("NewKey2: %v", err)
	}
	serverKeys := key2.ServerSlots(32)
	// clientKeys is the mirror image of serverKeys (matching how a real
	// peer's own key-direction assignment inverts the server's, Pitfall
	// 1) — this test's own encrypt/decrypt pairing, not
	// keyderiv.keyDirection(false) itself, since that's internal/keyderiv's
	// own already-tested concern.
	clientKeys := keyderiv.DataKeys{
		EncryptCipher:     serverKeys.DecryptCipher,
		EncryptImplicitIV: serverKeys.DecryptImplicitIV,
		DecryptCipher:     serverKeys.EncryptCipher,
		DecryptImplicitIV: serverKeys.EncryptImplicitIV,
		CipherKeyLen:      serverKeys.CipherKeyLen,
	}

	const peerID = 7
	serverWrapper, err := datachan.NewWrapper(serverKeys, peerID, 0)
	if err != nil {
		t.Fatalf("NewWrapper (server): %v", err)
	}
	clientWrapper, err := datachan.NewWrapper(clientKeys, peerID, 0)
	if err != nil {
		t.Fatalf("NewWrapper (client): %v", err)
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
		primary:    keySlot{wrapper: serverWrapper},
		ipInbound:  make(chan []byte, ipInboundQueueSize),
		stopCh:     make(chan struct{}),
	}

	// --- Write: seals exactly one packet per call, sent to RemoteAddr. ---
	writePayload := bytes.Repeat([]byte{0x99}, 500)
	n, err := sess.Write(writePayload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(writePayload) {
		t.Fatalf("Write returned %d, want %d", n, len(writePayload))
	}

	buf := make([]byte, 2048)
	if err := clientPC.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	rn, _, err := clientPC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	clientDecoded, err := clientWrapper.Open(nil, buf[:rn])
	if err != nil {
		t.Fatalf("client Open of the packet Write sent: %v", err)
	}
	if !bytes.Equal(clientDecoded, writePayload) {
		t.Error("client did not decrypt Write's exact payload")
	}

	// --- Read: the client seals a 500-byte packet, sess's own decrypt
	// path (handleDataPacket) delivers it whole in one Read. ---
	sealedFromClient, err := clientWrapper.Seal(nil, writePayload)
	if err != nil {
		t.Fatalf("client Seal: %v", err)
	}
	sess.handleDataPacket(sealedFromClient)

	small := make([]byte, 100)
	if _, err := sess.Read(small); err == nil {
		t.Fatal("Read into a too-small buffer succeeded, want an error")
	}

	big := make([]byte, 500)
	rcount, err := sess.Read(big)
	if err != nil {
		t.Fatalf("Read after a too-small Read retained the packet: %v", err)
	}
	if rcount != 500 {
		t.Fatalf("Read returned %d bytes, want exactly 500", rcount)
	}
	if !bytes.Equal(big[:rcount], writePayload) {
		t.Error("retained packet was not delivered intact by the next Read")
	}
}

// testSymmetricDataKeys builds a deterministic keyderiv.DataKeys whose
// encrypt and decrypt slots are identical, so a single datachan.Wrapper
// can Seal and Open its own traffic — sufficient for these Session-level
// keepalive/ping-plumbing tests, which are not about
// internal/datachan's own key-direction correctness (already proven
// there and in internal/keyderiv's own tests).
func testSymmetricDataKeys(t testing.TB) keyderiv.DataKeys {
	t.Helper()
	var keys keyderiv.DataKeys
	for i := range keys.EncryptCipher {
		keys.EncryptCipher[i] = byte(0x30 + i)
	}
	for i := range keys.EncryptImplicitIV {
		keys.EncryptImplicitIV[i] = byte(0x40 + i)
	}
	keys.DecryptCipher = keys.EncryptCipher
	keys.DecryptImplicitIV = keys.EncryptImplicitIV
	keys.CipherKeyLen = 32
	return keys
}

// TestPingNeverReachesSessionRead is 02-03-PLAN.md Task 3's DATA-03 proof
// at the Session level: driving handleDataPacket with a ping followed by a
// real 60-byte IP packet, Read's first and only returned value is the
// 60-byte packet — the ping is never returned, never returned as a
// zero-length read, and does not consume the queue slot the real packet
// needs.
func TestPingNeverReachesSessionRead(t *testing.T) {
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

	real := bytes.Repeat([]byte{0x77}, 60)
	realSealed, err := wrapper.Seal(nil, real)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sess.handleDataPacket(realSealed)

	buf := make([]byte, 200)
	n, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 60 {
		t.Fatalf("Read returned %d bytes, want 60 (the ping must not be delivered, not even as a zero-length read)", n)
	}
	if !bytes.Equal(buf[:n], real) {
		t.Errorf("Read = %x, want %x", buf[:n], real)
	}

	select {
	case extra := <-sess.ipInbound:
		t.Errorf("unexpected extra queued packet after the real one: %x — the ping must not have consumed a queue slot", extra)
	default:
	}
}

// TestServerEmitsPingOnSchedule is 02-03-PLAN.md Task 3's D-11 proof: with
// an injected tick channel standing in for a real pingInterval ticker
// (internal/reliable's own injected-Clock precedent), advancing one tick
// produces exactly one emitted ping, and three more ticks (standing in for
// "35 seconds" at a 10-second period) produce exactly three more — no ping
// is emitted before the first tick.
func TestServerEmitsPingOnSchedule(t *testing.T) {
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

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runKeepalive(tick)
	}()
	defer func() {
		close(sess.stopCh)
		<-done
	}()

	// No ping before the first tick.
	if err := clientPC.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	if _, _, err := clientPC.ReadFrom(buf); err == nil {
		t.Fatal("received a packet before any tick was sent, want none")
	}

	readOnePing := func() {
		t.Helper()
		if err := clientPC.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		n, _, err := clientPC.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if _, err := wrapper.Open(nil, buf[:n]); !errors.Is(err, datachan.ErrPingAbsorbed) {
			t.Fatalf("Open(received packet) = %v, want ErrPingAbsorbed", err)
		}
	}

	// One tick (standing in for the first 10-second interval) -> one ping.
	tick <- time.Now()
	readOnePing()

	// Three more ticks (standing in for the remaining time within a
	// 35-second window at a 10-second period) -> three more pings.
	for i := 0; i < 3; i++ {
		tick <- time.Now()
		readOnePing()
	}
}

// TestPingTimerStopsOnClose is 02-03-PLAN.md Task 3's proof that the
// keepalive goroutine exits cleanly on Close: after stopCh closes,
// runKeepalive's own goroutine exits (asserted via a done channel, not a
// sleep), and it no longer accepts further ticks.
func TestPingTimerStopsOnClose(t *testing.T) {
	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}
	sess := &Session{primary: keySlot{wrapper: wrapper}, stopCh: make(chan struct{})}

	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runKeepalive(tick)
	}()

	close(sess.stopCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive goroutine did not exit after stopCh closed")
	}

	select {
	case tick <- time.Now():
		t.Fatal("keepalive goroutine accepted a tick after it should have already exited")
	case <-time.After(100 * time.Millisecond):
		// Expected: nobody is receiving on tick anymore.
	}
}

// TestPingEmissionDoesNotConsumeSessionWriteQuota is 02-03-PLAN.md Task 3's
// proof that server-emitted pings never go through the public
// Session.Write path: a real embedder Write and an independently-timer-
// triggered ping both reach the client as two separate packets, and the
// Write call's own return value is unaffected by the concurrently-emitted
// ping — proving the ping used primary.wrapper/srv.pc directly (emitPing),
// never Session.Write itself.
func TestPingEmissionDoesNotConsumeSessionWriteQuota(t *testing.T) {
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

	payload := bytes.Repeat([]byte{0x11}, 60)
	n, err := sess.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write returned %d, want %d — a concurrently-emitted ping must not affect Write's own return value", n, len(payload))
	}

	tick := make(chan time.Time, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.runKeepalive(tick)
	}()
	tick <- time.Now()
	defer func() {
		close(sess.stopCh)
		<-done
	}()

	// Two independent packets must arrive: Write's own payload and the
	// timer's own ping — order is not guaranteed between two independent
	// goroutines, so accept either arrival order.
	var sawPayload, sawPing bool
	buf := make([]byte, 2048)
	for i := 0; i < 2; i++ {
		if err := clientPC.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		rn, _, err := clientPC.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read packet %d: %v", i, err)
		}
		got, openErr := wrapper.Open(nil, buf[:rn])
		switch {
		case errors.Is(openErr, datachan.ErrPingAbsorbed):
			sawPing = true
		case openErr == nil && bytes.Equal(got, payload):
			sawPayload = true
		default:
			t.Fatalf("packet %d: Open = (%x, %v), want either the ping (ErrPingAbsorbed) or Write's exact payload", i, got, openErr)
		}
	}
	if !sawPayload {
		t.Error("Write's own payload never arrived on the wire")
	}
	if !sawPing {
		t.Error("the timer-triggered ping never arrived on the wire")
	}
}

// TestHandleDatagramAcceptsShortDataChannelPing is CR-01's regression test:
// handleDatagram used to apply the control-channel's tls-crypt-derived
// minDatagramSize (49 bytes) uniformly to every inbound datagram, including
// P_DATA_V2 packets — which are never tls-crypt wrapped and can legitimately
// be far shorter. A real client-to-server ping keepalive (D-11) seals to
// exactly 40 bytes, so it used to be silently dropped by that gate before
// handleDatagram ever inspected the opcode. This test drives a synthetic
// 40-byte sealed client ping through the full Server.handleDatagram accept
// path (not Session.handleDataPacket directly, which every other ping test
// in this file exercises and which never touched the buggy gate) and proves
// the packet actually reached Wrapper.Open server-side: a ping is absorbed
// (D-11) and never observable via ipInbound, so the proof is indirect —
// re-opening the identical bytes a second time must now be rejected as a
// replay, which is only possible if the first delivery already advanced the
// server's replay window.
func TestHandleDatagramAcceptsShortDataChannelPing(t *testing.T) {
	const peerID = 7

	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), peerID, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	pingSealed, err := wrapper.SealPing(nil)
	if err != nil {
		t.Fatalf("SealPing: %v", err)
	}
	if len(pingSealed) != 40 {
		t.Fatalf("sealed ping is %d bytes, want 40 (CR-01's reproduction size)", len(pingSealed))
	}
	if len(pingSealed) >= minDatagramSize {
		t.Fatalf("test fixture no longer reproduces CR-01: sealed ping (%d bytes) is not shorter than minDatagramSize (%d)", len(pingSealed), minDatagramSize)
	}

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer serverPC.Close()

	sess := &Session{
		primary:   keySlot{wrapper: wrapper},
		ipInbound: make(chan []byte, ipInboundQueueSize),
		stopCh:    make(chan struct{}),
	}
	s := &Server{
		pc:           serverPC,
		sessions:     make(map[sessionKey]*Session),
		dataSessions: map[uint32]*Session{peerID: sess},
	}

	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("resolve addr: %v", err)
	}

	// Drive the full accept path.
	s.handleDatagram(serverPC, clientAddr, pingSealed)

	// The ping itself must never surface on ipInbound (D-11) — assert that
	// separately from the replay proof below, so a future regression that
	// starts delivering pings as ordinary payloads is also caught.
	select {
	case leaked := <-sess.ipInbound:
		t.Fatalf("ping keepalive was delivered as an IP packet: %x", leaked)
	default:
	}

	// Re-open the identical bytes directly against the same Wrapper this
	// session used. If handleDatagram's length gate had swallowed the
	// packet before it ever reached Wrapper.Open, the replay window would
	// still be empty and this would succeed (ErrPingAbsorbed again) instead
	// of failing with ErrReplay.
	if _, err := wrapper.Open(nil, pingSealed); !errors.Is(err, datachan.ErrReplay) {
		t.Fatalf("re-Open of the same sealed ping = %v, want ErrReplay (proves handleDatagram actually delivered the first one to Wrapper.Open instead of dropping it at the pre-opcode length gate)", err)
	}
}

// TestPerformPushExchangeFieldWritesRaceSafeAgainstClose is WR-03's
// regression test. ovpn.go's performPushExchange (on this session's own
// runHandshake goroutine) writes assignedIP/peerID/dataWrapper, while
// enforceHandshakeWindow's timeout goroutine can call Session.Close —
// which reads those same fields — concurrently at any point until
// sess.doneCh closes (deliberately not closed until performPushExchange's
// whole bring-up sequence returns). The real interleaving is a
// millisecond-scale timing race not reliably reproducible through the full
// TLS/Key-Method-2/PUSH_REQUEST protocol machinery, so this test drives the
// exact same field-write sequence performPushExchange uses (same lock
// discipline under test) directly against the real Close, forced to
// overlap via a barrier, repeated to make any regression in either side's
// locking reliably caught by `go test -race`.
func TestPerformPushExchangeFieldWritesRaceSafeAgainstClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		sess := &Session{
			stopCh: make(chan struct{}),
			srv: &Server{
				sessions:     make(map[sessionKey]*Session),
				dataSessions: make(map[uint32]*Session),
			},
		}

		wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), 1, 0)
		if err != nil {
			t.Fatalf("NewWrapper: %v", err)
		}

		start := make(chan struct{})
		writerDone := make(chan struct{})

		// Mirrors performPushExchange's own assign-then-publish sequence
		// (ovpn.go) byte-for-byte: same fields, same lock discipline.
		go func() {
			<-start
			ip, peerID := net.ParseIP("10.8.0.2"), uint32(1)
			sess.mu.Lock()
			sess.assignedIP = ip
			sess.peerID = peerID
			sess.mu.Unlock()

			sess.mu.Lock()
			sess.primary = keySlot{wrapper: wrapper}
			sess.mu.Unlock()
			close(writerDone)
		}()

		close(start)
		// Race the timeout-triggered Close directly against the writer
		// goroutine above, exactly as enforceHandshakeWindow can.
		_ = sess.Close()
		<-writerDone
	}
}

// TestCloseRemovesRoutingEntryBeforeReleasingPeerID is WR-04's regression
// test: Close must remove the srv.dataSessions routing entry before
// releasing peerID back to the pool, not after — releasing first makes
// peerID immediately reusable by the next ipPool.allocate() call, opening a
// window where a brand-new session could claim peerID and publish itself
// into dataSessions before the closing session's own routing entry is
// removed.
//
// This is made deterministic (not a timing-dependent race) by holding
// srv.mu ourselves before starting Close on another goroutine: whichever
// order Close's release-vs-delete steps run in, the delete step needs
// srv.mu, so Close necessarily blocks trying to acquire it while we hold
// it. On the FIXED order (delete before release), that block happens
// *before* Close ever calls release — so peerID can never become
// allocatable while we hold srv.mu, for any wait duration, structurally,
// not probabilistically. On the buggy order (release before delete),
// release only needs the pool's own mutex, entirely independent of srv.mu,
// so it completes almost immediately regardless of whether we hold srv.mu
// — making peerID allocatable while dataSessions[peerID] still routes to
// the closing session.
func TestCloseRemovesRoutingEntryBeforeReleasingPeerID(t *testing.T) {
	_, network, err := net.ParseCIDR("10.50.0.0/30") // exactly one allocatable client address/peer-id
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	pool, err := newIPPool(network)
	if err != nil {
		t.Fatalf("newIPPool: %v", err)
	}
	ip, peerID, err := pool.allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), peerID, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	srv := &Server{
		pool:         pool,
		sessions:     make(map[sessionKey]*Session),
		dataSessions: make(map[uint32]*Session),
	}
	sess := &Session{
		srv:        srv,
		stopCh:     make(chan struct{}),
		assignedIP: ip,
		peerID:     peerID,
		primary:    keySlot{wrapper: wrapper},
	}
	srv.mu.Lock()
	srv.dataSessions[peerID] = sess
	srv.mu.Unlock()

	// Hold srv.mu across the whole check window (see doc comment above for
	// why this makes the assertion structural rather than timing-luck
	// based).
	srv.mu.Lock()

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		sess.Close()
	}()

	violation := false
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, gotPeerID, err := pool.allocate()
		if err != nil {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if gotPeerID != peerID {
			t.Fatalf("attacker allocate() returned peer-id %d, want %d (test setup bug)", gotPeerID, peerID)
		}
		// Read directly (not through srv.mu) — safe here specifically
		// because we are the one holding srv.mu, so Close's own
		// dataSessions write cannot be concurrently in flight.
		if existing, ok := srv.dataSessions[peerID]; ok && existing == sess {
			violation = true
		}
		pool.release(ip, peerID) // restore pool state; Close's own release below is idempotent either way
		break
	}

	srv.mu.Unlock()
	<-closeDone

	if violation {
		t.Fatal("peerID became allocatable while dataSessions[peerID] still routed to the closing session — the routing entry must be removed before peerID is released back to the pool")
	}
}
