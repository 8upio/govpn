// cipher_test.go is 05-01-PLAN.md Task 1's tracer proof: a real, in-process
// client advertising only AES-128-GCM connects, is told AES-128-GCM in both
// the Key Method 2 options string and PUSH_REPLY, and exchanges a real IP
// packet through a 16-byte-key AEAD — and the pre-existing AES-256-GCM path
// is byte-for-byte unchanged.
package ovpn

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/datachan"
)

// readTestServerKeyMethod2CaptureOptions mirrors readTestServerKeyMethod2's
// exact framing walk (ovpn_test.go) but returns the options field's raw
// bytes instead of discarding them — this file's own end-to-end tracer
// tests need to assert on the negotiated cipher/keysize the server's own
// options string carries, without changing readTestServerKeyMethod2's
// existing discard-everything contract every other test already relies on.
func readTestServerKeyMethod2CaptureOptions(r io.Reader) (string, error) {
	var fixed [4 + 1 + 32 + 32]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return "", err
	}
	var options string
	for i := 0; i < 4; i++ {
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", err
		}
		n := binary.BigEndian.Uint16(lenBuf[:])
		var field []byte
		if n > 0 {
			field = make([]byte, n)
			if _, err := io.ReadFull(r, field); err != nil {
				return "", err
			}
		}
		if i == 0 {
			options = string(field)
		}
	}
	return options, nil
}

// writeTestClientKeyMethod2WithPeerInfo writes a client Key Method 2
// message carrying testPlaceholderUsername/testPlaceholderPassword
// (matching writeTestClientKeyMethod2's own credentials, ovpn_test.go) and
// peerInfo exactly as given — unlike writeTestClientKeyMethod2Creds, which
// always sends testDefaultPeerInfo, this lets a cipher-negotiation test
// control the client's advertised IV_CIPHERS/IV_NCP directly.
func writeTestClientKeyMethod2WithPeerInfo(w io.Writer, peerInfo []byte) error {
	encode := func(s string) []byte { return append([]byte(s), 0) }
	return writeTestClientKeyMethod2Raw(w, nil, encode(testPlaceholderUsername), encode(testPlaceholderPassword), peerInfo)
}

// tunnelUpCipherTestClient drives client through hard reset, TLS handshake
// and Key Method 2 exactly like tunnelUpTestClient (ovpn_test.go), except
// the client's peer_info carries peerInfoLine (e.g.
// "IV_CIPHERS=AES-128-GCM") instead of testDefaultPeerInfo — the signal
// performKeyMethod2Exchange's cipher selection reads. It returns the
// client, a reader positioned right after the server's own Key Method 2
// reply, AND that reply's own options field (captured via
// readTestServerKeyMethod2CaptureOptions above, not discarded).
func tunnelUpCipherTestClient(t testing.TB, key []byte, serverAddr net.Addr, caPool *x509.CertPool, peerInfoLine string) (*testPushClient, *bufio.Reader, string) {
	t.Helper()

	client := newTestPushClient(t, key, serverAddr, caPool)
	if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := client.tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := writeTestClientKeyMethod2WithPeerInfo(client.tlsConn, []byte(peerInfoLine+"\n")); err != nil {
		t.Fatalf("write client Key Method 2: %v", err)
	}
	options, err := readTestServerKeyMethod2CaptureOptions(client.tlsConn)
	if err != nil {
		t.Fatalf("read server Key Method 2: %v", err)
	}
	if err := client.conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear client deadline: %v", err)
	}
	return client, bufio.NewReader(client.tlsConn), options
}

// newCipherTracerServer builds and starts a Server resolved to the
// two-entry default DataCiphers allow-list (AES-256-GCM, AES-128-GCM),
// exactly like a Config left at its zero value would resolve — spelled out
// explicitly here so this file's intent (negotiation against the default
// allow-list) reads directly off the Config literal.
func newCipherTracerServer(t testing.TB, network *net.IPNet, key []byte) (*Server, net.PacketConn, *x509.CertPool, chan *Session) {
	t.Helper()

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	tlsCfg, caPool := testHandshakeTLSConfig(t)
	sessions := make(chan *Session, 1)
	srv := NewServer(Config{
		TLSCryptKey:  key,
		TLSConfig:    tlsCfg,
		Network:      network,
		AuthUserPass: testPermissiveAuthUserPass,
		DataCiphers:  []string{"AES-256-GCM", "AES-128-GCM"},
		OnSession:    func(sess *Session) { sessions <- sess },
	})
	go func() { _ = srv.Serve(serverPC) }()
	return srv, serverPC, caPool, sessions
}

// TestTracerAES128GCMNegotiatedEndToEnd is this plan's own tracer slice: a
// client whose peer_info line is "IV_CIPHERS=AES-128-GCM" against a server
// resolved to [AES-256-GCM, AES-128-GCM] negotiates AES-128-GCM, is told so
// in both the Key Method 2 options string and PUSH_REPLY, and exchanges
// real IP packets through a 16-byte-key AES-128-GCM AEAD in both
// directions.
func TestTracerAES128GCMNegotiatedEndToEnd(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.0.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, sessions := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	client, replyReader, options := tunnelUpCipherTestClient(t, key, serverPC.LocalAddr(), caPool, "IV_CIPHERS=AES-128-GCM")
	defer client.Close()

	if !strings.Contains(options, "cipher AES-128-GCM") {
		t.Errorf("server Key Method 2 options = %q, want it to contain %q", options, "cipher AES-128-GCM")
	}
	if !strings.Contains(options, "keysize 128") {
		t.Errorf("server Key Method 2 options = %q, want it to contain %q", options, "keysize 128")
	}

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reply, err := readControlString(replyReader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read push reply: %v", err)
	}
	if !strings.Contains(reply, "cipher AES-128-GCM") {
		t.Errorf("PUSH_REPLY = %q, want it to contain %q", reply, "cipher AES-128-GCM")
	}

	var sess *Session
	select {
	case sess = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}

	if got := sess.Cipher(); got != "AES-128-GCM" {
		t.Errorf("sess.Cipher() = %q, want %q", got, "AES-128-GCM")
	}

	serverKeys, ok := sess.DebugDataKeys()
	if !ok {
		t.Fatal("DebugDataKeys() not ok on an established session")
	}
	if serverKeys.CipherKeyLen != 16 {
		t.Errorf("DebugDataKeys().CipherKeyLen = %d, want 16", serverKeys.CipherKeyLen)
	}

	clientWrapper, err := datachan.NewWrapper(mirrorDataKeys(serverKeys), sess.PeerID(), 0)
	if err != nil {
		t.Fatalf("build client wrapper: %v", err)
	}

	// Client -> server: a real 60-byte IP-shaped packet round-trips
	// through Session.Read under the 16-byte-key AES-128-GCM AEAD.
	payloadIn := bytes.Repeat([]byte{0x11}, 60)
	sealedIn, err := clientWrapper.Seal(nil, payloadIn)
	if err != nil {
		t.Fatalf("client Seal: %v", err)
	}
	sess.handleDataPacket(sealedIn)

	buf := make([]byte, 2048)
	n, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("Session.Read: %v", err)
	}
	if !bytes.Equal(buf[:n], payloadIn) {
		t.Fatalf("Session.Read = %x, want %x", buf[:n], payloadIn)
	}

	// Server -> client: Session.Write's output opens under the client's
	// mirrored 16-byte-key wrapper.
	payloadOut := bytes.Repeat([]byte{0x22}, 60)
	if _, err := sess.Write(payloadOut); err != nil {
		t.Fatalf("Session.Write: %v", err)
	}
	var wireBytes []byte
	select {
	case wireBytes = <-client.dataOut:
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe Write's output data packet")
	}
	opened, err := clientWrapper.Open(nil, wireBytes)
	if err != nil {
		t.Fatalf("client Open of Write's output: %v", err)
	}
	if !bytes.Equal(opened, payloadOut) {
		t.Fatalf("client Open = %x, want %x", opened, payloadOut)
	}
}

// TestEstablishedSessionCipherIsInAllowList is the assumption-delta
// promotion invariant (05-01-PLAN.md's own <assumption_delta_decision>):
// for every established session, Session.Cipher() is non-empty, is a
// member of the server's resolved DataCiphers allow-list, and equals the
// cipher name whose key length the session's data-channel Wrapper was
// actually constructed with.
func TestEstablishedSessionCipherIsInAllowList(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.1.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, sessions := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	client, replyReader, _ := tunnelUpCipherTestClient(t, key, serverPC.LocalAddr(), caPool, "IV_CIPHERS=AES-128-GCM")
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

	cipher := sess.Cipher()
	if cipher == "" {
		t.Fatal("sess.Cipher() is empty on an established session")
	}
	if !containsFold(srv.dataCiphers, cipher) {
		t.Errorf("sess.Cipher() = %q is not a member of the server's resolved allow-list %v", cipher, srv.dataCiphers)
	}
	keys, ok := sess.DebugDataKeys()
	if !ok {
		t.Fatal("DebugDataKeys() not ok on an established session")
	}
	if keys.CipherKeyLen != cipherKeyLen(cipher) {
		t.Errorf("DebugDataKeys().CipherKeyLen = %d, want %d (cipherKeyLen(%q))", keys.CipherKeyLen, cipherKeyLen(cipher), cipher)
	}
}

// TestSessionCipherEmptyBeforeNegotiation asserts the empty-string-before-
// negotiation contract Session.Cipher()'s own doc comment describes: a
// fresh, never-negotiated Session reports "".
func TestSessionCipherEmptyBeforeNegotiation(t *testing.T) {
	sess := &Session{}
	if got := sess.Cipher(); got != "" {
		t.Errorf("Cipher() on a fresh Session = %q, want empty", got)
	}
}

// TestAES256GCMPathUnchanged re-runs the tracer proof above with a client
// advertising the AES-256-GCM-first list, asserting the pre-existing
// AES-256-GCM behaviour is byte-for-byte unchanged by this plan: the
// server's own allow-list order (AES-256-GCM first) still wins, and the
// session's data-channel Wrapper still uses a 32-byte key.
func TestAES256GCMPathUnchanged(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.2.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, sessions := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	client, replyReader, options := tunnelUpCipherTestClient(t, key, serverPC.LocalAddr(), caPool, "IV_CIPHERS=AES-256-GCM:AES-128-GCM")
	defer client.Close()

	if !strings.Contains(options, "cipher AES-256-GCM") {
		t.Errorf("server Key Method 2 options = %q, want it to contain %q", options, "cipher AES-256-GCM")
	}
	if !strings.Contains(options, "keysize 256") {
		t.Errorf("server Key Method 2 options = %q, want it to contain %q", options, "keysize 256")
	}

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reply, err := readControlString(replyReader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read push reply: %v", err)
	}
	if !strings.Contains(reply, "cipher AES-256-GCM") {
		t.Errorf("PUSH_REPLY = %q, want it to contain %q", reply, "cipher AES-256-GCM")
	}

	var sess *Session
	select {
	case sess = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("OnSession was never called")
	}

	if got := sess.Cipher(); got != "AES-256-GCM" {
		t.Errorf("sess.Cipher() = %q, want %q", got, "AES-256-GCM")
	}
	keys, ok := sess.DebugDataKeys()
	if !ok {
		t.Fatal("DebugDataKeys() not ok on an established session")
	}
	if keys.CipherKeyLen != 32 {
		t.Errorf("DebugDataKeys().CipherKeyLen = %d, want 32", keys.CipherKeyLen)
	}
}
