package ovpn

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	pc      net.PacketConn
	wrapper *tlscrypt.Wrapper
	conn    *ctrlconn.Conn
	tlsConn *tls.Conn
	stop    chan struct{}
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

	stop := make(chan struct{})
	go testPushClientDemux(pc, wrapper, conn, stop)

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

	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    caPool,
		ServerName: testHandshakeServerCN,
		MinVersion: tls.VersionTLS12,
	})

	return &testPushClient{pc: pc, wrapper: wrapper, conn: conn, tlsConn: tlsConn, stop: stop}
}

// Close stops the demux goroutine and tears down the client's control
// channel and UDP socket.
func (c *testPushClient) Close() {
	close(c.stop)
	_ = c.conn.Close()
	_ = c.pc.Close()
}

// testPushClientDemux mirrors internal/ctrlconn's own conn_test.go demux
// helper: unwrap under the client's own tls-crypt Wrapper, parse the
// plaintext body, and hand the result to conn.Deliver.
func testPushClientDemux(pc net.PacketConn, wrapper *tlscrypt.Wrapper, conn *ctrlconn.Conn, stop <-chan struct{}) {
	buf := make([]byte, maxDatagramSize)
	for {
		select {
		case <-stop:
			return
		default:
		}
		if err := pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		header, plaintext, err := wrapper.Unwrap(nil, buf[:n])
		if err != nil {
			continue
		}
		opcode, keyID := wire.ParseHeaderByte(header[0])
		var sid wire.SessionID
		copy(sid[:], header[1:1+wire.SessionIDSize])
		cp, err := wire.ParseControlPacket(plaintext, wire.Header{Opcode: opcode, KeyID: keyID, SessionID: sid})
		if err != nil {
			continue
		}
		conn.Deliver(cp)
	}
}

// writeTestClientKeyMethod2 writes a well-formed (but content-arbitrary —
// this project doesn't validate the options/username/password/peer_info
// strings, RESEARCH.md Pitfall 4) client Key Method 2 message matching
// keyderiv.ReadClientKeyMethod2's expected layout: 4 reserved bytes,
// KEY_METHOD_2, 48-byte pre_master, 32-byte random1, 32-byte random2, then
// four empty length-prefixed strings (options/username/password/
// peer_info).
func writeTestClientKeyMethod2(w io.Writer) error {
	buf := make([]byte, 0, 4+1+48+32+32+8)
	buf = append(buf, 0, 0, 0, 0) // reserved
	buf = append(buf, 2)          // KEY_METHOD_2

	random := make([]byte, 48+32+32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	buf = append(buf, random...)

	// options, username, password, peer_info: four empty (0x0000-prefixed)
	// strings — this server only warns, never fails, on an empty/mismatched
	// options string (RESEARCH.md Pitfall 4).
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0)

	_, err := w.Write(buf)
	return err
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

// tunnelUpTestClient drives client all the way through hard reset, TLS
// handshake, Key Method 2, and one PUSH_REQUEST, returning a reader
// positioned to read the PUSH_REPLY response(s). It fails the test on any
// error along the way.
func tunnelUpTestClient(t testing.TB, key []byte, serverAddr net.Addr, caPool *x509.CertPool) (*testPushClient, *bufio.Reader) {
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
	if err := writeTestClientKeyMethod2(client.tlsConn); err != nil {
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
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
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

	srv := &Server{pool: pool, cfg: Config{Network: network}}

	input := pushRequestLiteral + "\x00" + pushRequestLiteral + "\x00"
	sess := &Session{tlsReader: bufio.NewReader(strings.NewReader(input))}

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
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
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
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
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
		TLSCryptKey: key,
		TLSConfig:   tlsCfg,
		Network:     network,
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

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t)})
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

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t)})
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

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t)})
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

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t)})
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

	srv := NewServer(Config{TLSCryptKey: key, TLSConfig: testTLSConfig(t)})
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
