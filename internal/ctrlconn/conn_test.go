package ctrlconn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// var _ net.Conn = (*Conn)(nil) is asserted in conn.go itself; acceptance
// criteria greps for that line there.

// udpTransport adapts a real net.PacketConn to ctrlconn.Transport for this
// test — Conn always calls WriteTo with the peer address it was
// constructed with, so no address translation is needed here.
type udpTransport struct{ pc net.PacketConn }

func (t udpTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	return t.pc.WriteTo(p, addr)
}

// demux is the loopback UDP read loop each side of the test runs: unwrap
// under this side's own tls-crypt Wrapper, parse the plaintext body, and
// hand the result to Conn.Deliver — exactly the job internal/wire +
// internal/tlscrypt + ovpn.go's handleDatagram play together in the real
// server, reduced to its essential shape for exercising real framing and
// reliability code on both ends of a real loopback socket.
func demux(pc net.PacketConn, wrapper *tlscrypt.Wrapper, conn *Conn, stop <-chan struct{}) {
	buf := make([]byte, 2048)
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

// testCerts holds a freshly-generated, in-test-only CA and a server/client
// cert pair issued from it, for exercising real mutual TLS 1.2 certificate
// verification over Conn.
type testCerts struct {
	caPool *x509.CertPool
	server tls.Certificate
	client tls.Certificate
}

func genTestCerts(t testing.TB) testCerts {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ctrlconn-test-ca"},
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

	serial := int64(2)
	mk := func(cn string, eku x509.ExtKeyUsage) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate %s key: %v", cn, err)
		}
		serial++
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			// DNSNames is required: Go's x509 verifier has ignored the
			// legacy Subject.CommonName fallback for hostname matching
			// since Go 1.15 (crypto/x509 changelog) — a cert with only a
			// CommonName and no SAN fails ServerName verification.
			DNSNames:              []string{cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{eku},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create %s cert: %v", cn, err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return testCerts{
		caPool: pool,
		server: mk("ctrlconn-test-server", x509.ExtKeyUsageServerAuth),
		client: mk("ctrlconn-test-client", x509.ExtKeyUsageClientAuth),
	}
}

// TestTLSHandshakeOverCtrlConn stands up two Conn instances over a real
// loopback UDP pair — one running tls.Server, one running tls.Client, both
// with a real generated CA and cert pair, the server requiring and
// verifying the client certificate, MinVersion pinned to TLS 1.2 — and
// proves the architectural bet this phase rests on: crypto/tls sits on top
// of Conn completely unmodified. Both handshakes must return nil, each
// side must report the other's verified CommonName, and a payload written
// after the handshake must arrive intact. This exercises the real framing
// and reliability code on BOTH ends, because the reliability layer is
// symmetric in the reference (01-RESEARCH.md).
func TestTLSHandshakeOverCtrlConn(t *testing.T) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate tls-crypt key: %v", err)
	}
	serverWrapper, err := tlscrypt.NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}
	clientWrapper, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
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

	var serverSID, clientSID wire.SessionID
	if _, err := rand.Read(serverSID[:]); err != nil {
		t.Fatalf("generate server session id: %v", err)
	}
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}

	serverConn := New(serverSID, clientSID, serverWrapper, udpTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	clientConn := New(clientSID, serverSID, clientWrapper, udpTransport{pc: clientPC}, serverPC.LocalAddr(), nil)
	defer serverConn.Close()
	defer clientConn.Close()

	var _ net.Conn = serverConn // both instances satisfy net.Conn

	stop := make(chan struct{})
	defer close(stop)
	go demux(serverPC, serverWrapper, serverConn, stop)
	go demux(clientPC, clientWrapper, clientConn, stop)

	certs := genTestCerts(t)
	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{certs.server},
		ClientCAs:    certs.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	clientTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{certs.client},
		RootCAs:      certs.caPool,
		ServerName:   "ctrlconn-test-server",
		MinVersion:   tls.VersionTLS12,
	}

	serverTLS := tls.Server(serverConn, serverTLSCfg)
	clientTLS := tls.Client(clientConn, clientTLSCfg)

	var wg sync.WaitGroup
	var serverErr, clientErr error
	wg.Add(2)
	go func() { defer wg.Done(); serverErr = serverTLS.Handshake() }()
	go func() { defer wg.Done(); clientErr = clientTLS.Handshake() }()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("handshake did not complete within 15s")
	}

	if serverErr != nil {
		t.Fatalf("server Handshake(): %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("client Handshake(): %v", clientErr)
	}

	serverState := serverTLS.ConnectionState()
	if len(serverState.PeerCertificates) == 0 {
		t.Fatal("server: no peer certificates after handshake")
	}
	if got, want := serverState.PeerCertificates[0].Subject.CommonName, "ctrlconn-test-client"; got != want {
		t.Errorf("server sees peer CN = %q, want %q", got, want)
	}

	clientState := clientTLS.ConnectionState()
	if len(clientState.PeerCertificates) == 0 {
		t.Fatal("client: no peer certificates after handshake")
	}
	if got, want := clientState.PeerCertificates[0].Subject.CommonName, "ctrlconn-test-server"; got != want {
		t.Errorf("client sees peer CN = %q, want %q", got, want)
	}

	// Post-handshake payload delivery: the client writes application data
	// after its own handshake completes (exactly like the real client's
	// Key Method 2 payload, RESEARCH Pitfall 5) and the server reads it
	// back intact through crypto/tls's own record layer over Conn.
	msg := []byte("post-handshake application data over ctrlconn")
	writeDone := make(chan error, 1)
	go func() {
		_, werr := clientTLS.Write(msg)
		writeDone <- werr
	}()

	if err := serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(serverTLS, got); err != nil {
		t.Fatalf("server read post-handshake payload: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write post-handshake payload: %v", err)
	}
	if string(got) != string(msg) {
		t.Errorf("post-handshake payload = %q, want %q", got, msg)
	}
}

// newWaitDrainedPair builds a loopback UDP pair of Conns (no TLS needed —
// WaitDrained only cares about the send-side reliability window, not any
// payload's content) for TestWaitDrained*'s two scenarios.
func newWaitDrainedPair(t testing.TB) (serverConn, clientConn *Conn, serverPC, clientPC net.PacketConn) {
	t.Helper()

	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate tls-crypt key: %v", err)
	}
	serverWrapper, err := tlscrypt.NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}
	clientWrapper, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	serverPC, err = net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	clientPC, err = net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}

	var serverSID, clientSID wire.SessionID
	if _, err := rand.Read(serverSID[:]); err != nil {
		t.Fatalf("generate server session id: %v", err)
	}
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatalf("generate client session id: %v", err)
	}

	serverConn = New(serverSID, clientSID, serverWrapper, udpTransport{pc: serverPC}, clientPC.LocalAddr(), nil)
	clientConn = New(clientSID, serverSID, clientWrapper, udpTransport{pc: clientPC}, serverPC.LocalAddr(), nil)

	return serverConn, clientConn, serverPC, clientPC
}

// TestWaitDrainedReturnsTrueOnceAcked proves WaitDrained reports true once
// the peer has ACKed everything this Conn transmitted: with demux running
// on BOTH ends (so the peer's Deliver-triggered ACK — flushAckOnly,
// conn.go:157-160 — can make its way back), a Write followed by
// WaitDrained must observe the send window empty well within the given
// timeout.
func TestWaitDrainedReturnsTrueOnceAcked(t *testing.T) {
	serverConn, clientConn, serverPC, clientPC := newWaitDrainedPair(t)
	defer serverPC.Close()
	defer clientPC.Close()
	defer serverConn.Close()
	defer clientConn.Close()

	stop := make(chan struct{})
	defer close(stop)
	serverWrapper := serverConn.wrapper
	clientWrapper := clientConn.wrapper
	go demux(serverPC, serverWrapper, serverConn, stop)
	go demux(clientPC, clientWrapper, clientConn, stop)

	if _, err := serverConn.Write([]byte("AUTH_FAILED\x00")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !serverConn.WaitDrained(5 * time.Second) {
		t.Fatal("WaitDrained returned false; expected the peer's ACK to drain the send window")
	}
}

// TestWaitDrainedReturnsFalseOnTimeout proves WaitDrained reports false,
// after actually waiting out the given timeout, when the peer never ACKs:
// with no demux running at all, the transmitted control packet is never
// delivered anywhere, so the send window can never drain.
func TestWaitDrainedReturnsFalseOnTimeout(t *testing.T) {
	serverConn, clientConn, serverPC, clientPC := newWaitDrainedPair(t)
	defer serverPC.Close()
	defer clientPC.Close()
	defer serverConn.Close()
	defer clientConn.Close()

	if _, err := serverConn.Write([]byte("AUTH_FAILED\x00")); err != nil {
		t.Fatalf("write: %v", err)
	}

	start := time.Now()
	const timeout = 200 * time.Millisecond
	if serverConn.WaitDrained(timeout) {
		t.Fatal("WaitDrained returned true; expected the send window to stay non-empty with no peer ACK")
	}
	if elapsed := time.Since(start); elapsed < timeout {
		t.Errorf("WaitDrained returned after %s, want at least %s (the full timeout)", elapsed, timeout)
	}
}

// TestWaitDrainedReturnsFalseOnClose proves WaitDrained unblocks promptly
// (not waiting out the full timeout) when the Conn is closed while a drain
// is still pending.
func TestWaitDrainedReturnsFalseOnClose(t *testing.T) {
	serverConn, clientConn, serverPC, clientPC := newWaitDrainedPair(t)
	defer serverPC.Close()
	defer clientPC.Close()
	defer clientConn.Close()

	if _, err := serverConn.Write([]byte("AUTH_FAILED\x00")); err != nil {
		t.Fatalf("write: %v", err)
	}

	done := make(chan bool, 1)
	go func() { done <- serverConn.WaitDrained(10 * time.Second) }()

	// Give WaitDrained a moment to start polling, then close from another
	// goroutine — mirroring how a real caller tears the Conn down
	// concurrently with (or immediately after) a bounded drain attempt.
	time.Sleep(50 * time.Millisecond)
	_ = serverConn.Close()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("WaitDrained returned true after Close; expected false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitDrained did not unblock within 2s of Close")
	}
}
