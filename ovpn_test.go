package ovpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

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
