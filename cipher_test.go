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
	"errors"
	"io"
	"net"
	"strings"
	"sync"
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

// stringSlicesEqual compares two []string by content and order (nil and an
// empty non-nil slice are NOT equal — several behaviour-table rows below
// depend on exactly that distinction).
func stringSlicesEqual(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestResolveDataCiphers is 05-02-PLAN.md Task 1's table-driven coverage of
// resolveDataCiphers's full behaviour table: the empty/nil-cipher default,
// the Config.Cipher one-element shorthand, canonicalization, duplicate
// rejection (including a case-only duplicate), and near-miss rejection with
// no repair attempt.
func TestResolveDataCiphers(t *testing.T) {
	tests := []struct {
		name        string
		dataCiphers []string
		cipher      string
		want        []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil dataCiphers, empty cipher resolves to the default pair",
			dataCiphers: nil,
			cipher:      "",
			want:        []string{"AES-256-GCM", "AES-128-GCM"},
		},
		{
			name:        "nil dataCiphers, cipher set resolves to the one-element shorthand",
			dataCiphers: nil,
			cipher:      "AES-256-GCM",
			want:        []string{"AES-256-GCM"},
		},
		{
			name:        "allocated empty slice behaves exactly like nil",
			dataCiphers: []string{},
			cipher:      "AES-128-GCM",
			want:        []string{"AES-128-GCM"},
		},
		{
			name:        "lower-case single entry is canonicalized",
			dataCiphers: []string{"aes-128-gcm"},
			cipher:      "",
			want:        []string{"AES-128-GCM"},
		},
		{
			name:        "duplicate differing only in case errors, naming the duplicate",
			dataCiphers: []string{"AES-128-GCM", "aes-128-gcm"},
			cipher:      "",
			wantErr:     true,
			errContains: "AES-128-GCM",
		},
		{
			name:        "near-miss spelling errors with no repair attempted",
			dataCiphers: []string{"AES128GCM"},
			cipher:      "",
			wantErr:     true,
			errContains: "AES128GCM",
		},
		{
			name:        "given two-entry order preserved, Config.Cipher ignored",
			dataCiphers: []string{"AES-128-GCM", "AES-256-GCM"},
			cipher:      "AES-256-GCM",
			want:        []string{"AES-128-GCM", "AES-256-GCM"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDataCiphers(tt.dataCiphers, tt.cipher)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveDataCiphers(%v, %q) = %v, nil; want an error", tt.dataCiphers, tt.cipher, got)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("resolveDataCiphers(%v, %q) error = %q, want it to contain %q", tt.dataCiphers, tt.cipher, err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveDataCiphers(%v, %q) unexpected error: %v", tt.dataCiphers, tt.cipher, err)
			}
			if !stringSlicesEqual(got, tt.want) {
				t.Errorf("resolveDataCiphers(%v, %q) = %v, want %v", tt.dataCiphers, tt.cipher, got, tt.want)
			}
		})
	}
}

// TestResolveDataCiphersDoesNotAliasCallerSlice proves the returned slice
// never aliases the caller's own backing array: mutating the caller's slice
// after the call must not change the resolved allow-list.
func TestResolveDataCiphersDoesNotAliasCallerSlice(t *testing.T) {
	input := []string{"AES-128-GCM", "AES-256-GCM"}
	got, err := resolveDataCiphers(input, "")
	if err != nil {
		t.Fatalf("resolveDataCiphers: %v", err)
	}
	input[0] = "MUTATED"
	if got[0] != "AES-128-GCM" {
		t.Errorf("resolved slice changed after mutating the caller's input: got[0] = %q, want %q", got[0], "AES-128-GCM")
	}
}

// TestServeRejectsInvalidDataCiphers drives Serve itself (not just
// resolveDataCiphers directly) with a duplicate and with a near-miss
// Config.DataCiphers, asserting a non-nil error naming Config.DataCiphers
// and that no listener was ever published (s.pc stays nil).
func TestServeRejectsInvalidDataCiphers(t *testing.T) {
	tests := []struct {
		name        string
		dataCiphers []string
	}{
		{name: "duplicate entries", dataCiphers: []string{"AES-256-GCM", "aes-256-gcm"}},
		{name: "near-miss spelling", dataCiphers: []string{"AES256GCM"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := testTLSCryptKey(t)
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer pc.Close()

			srv := NewServer(Config{
				TLSCryptKey:  key,
				TLSConfig:    testTLSConfig(t),
				AuthUserPass: testPermissiveAuthUserPass,
				DataCiphers:  tt.dataCiphers,
			})
			err = srv.Serve(pc)
			if err == nil {
				t.Fatal("Serve returned nil error for an invalid Config.DataCiphers")
			}
			if !strings.Contains(err.Error(), "Config.DataCiphers") {
				t.Errorf("Serve error = %q, want it to contain %q", err.Error(), "Config.DataCiphers")
			}
			srv.mu.Lock()
			published := srv.pc != nil
			srv.mu.Unlock()
			if published {
				t.Error("Serve published its packet connection despite a validation error")
			}
		})
	}
}

// TestPeerCipherList is 05-02-PLAN.md Task 2's table-driven coverage of
// peerCipherList's full boundary rule set, including the present-but-empty
// IV_CIPHERS= case that must NOT fall through to the IV_NCP implied list.
func TestPeerCipherList(t *testing.T) {
	tests := []struct {
		name     string
		peerInfo []byte
		want     []string
	}{
		{
			name:     "present-but-empty IV_CIPHERS does not fall through to IV_NCP",
			peerInfo: []byte("IV_CIPHERS=\nIV_NCP=2\n"),
			want:     []string{},
		},
		{
			name:     "absent IV_CIPHERS with IV_NCP=2 falls through to the implied list",
			peerInfo: []byte("IV_NCP=2\n"),
			want:     []string{"AES-256-GCM", "AES-128-GCM"},
		},
		{
			name:     "absent IV_CIPHERS with IV_NCP=1 yields nil",
			peerInfo: []byte("IV_NCP=1\n"),
			want:     nil,
		},
		{
			name:     "nil peer_info yields nil",
			peerInfo: nil,
			want:     nil,
		},
		{
			name:     "IV_CIPHERS with a value is split on ':'",
			peerInfo: []byte("IV_CIPHERS=AES-256-GCM:AES-128-GCM\n"),
			want:     []string{"AES-256-GCM", "AES-128-GCM"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerCipherList(tt.peerInfo)
			if !stringSlicesEqual(got, tt.want) {
				t.Errorf("peerCipherList(%q) = %#v, want %#v", tt.peerInfo, got, tt.want)
			}
		})
	}
}

// TestPeerSupportsNCP is 05-02-PLAN.md Task 2's table-driven coverage of
// peerSupportsNCP: true for IV_NCP>=2 or for an IV_CIPHERS= line present
// with any value (including empty), false for nil/empty peer_info or a
// sub-2 IV_NCP with no IV_CIPHERS.
func TestPeerSupportsNCP(t *testing.T) {
	tests := []struct {
		name     string
		peerInfo []byte
		want     bool
	}{
		{name: "nil peer_info", peerInfo: nil, want: false},
		{name: "IV_CIPHERS present with empty value", peerInfo: []byte("IV_CIPHERS=\n"), want: true},
		{name: "IV_CIPHERS present with a value", peerInfo: []byte("IV_CIPHERS=AES-128-GCM\n"), want: true},
		{name: "IV_NCP=2", peerInfo: []byte("IV_NCP=2\n"), want: true},
		{name: "IV_NCP=1", peerInfo: []byte("IV_NCP=1\n"), want: false},
		{name: "IV_NCP=3", peerInfo: []byte("IV_NCP=3\n"), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerSupportsNCP(tt.peerInfo); got != tt.want {
				t.Errorf("peerSupportsNCP(%q) = %v, want %v", tt.peerInfo, got, tt.want)
			}
		})
	}
}

// TestPeerInfoValueIsLineAnchored builds a peer_info in which another
// variable's value contains the literal text "IV_CIPHERS=" and asserts it
// is not matched — peerInfoValue anchors to the START of a line, not an
// unanchored substring search.
func TestPeerInfoValueIsLineAnchored(t *testing.T) {
	peerInfo := []byte("SOME_OTHER_VAR=xIV_CIPHERS=AES-128-GCM\n")

	if _, ok := peerInfoValue(peerInfo, "IV_CIPHERS="); ok {
		t.Error("peerInfoValue matched IV_CIPHERS= embedded inside another variable's value")
	}
	if got := peerCipherList(peerInfo); got != nil {
		t.Errorf("peerCipherList = %#v, want nil (no real capability signal present)", got)
	}
}

// TestParseOCCCipher is 05-02-PLAN.md Task 2's table-driven coverage of
// parseOCCCipher: first-match-wins token selection, and the no-match/
// empty-value/over-long-value rejection cases.
func TestParseOCCCipher(t *testing.T) {
	tests := []struct {
		name    string
		options []byte
		want    string
	}{
		{
			name:    "single cipher token",
			options: []byte("V4,dev-type tun,cipher AES-128-GCM,auth SHA1"),
			want:    "AES-128-GCM",
		},
		{
			name:    "two cipher tokens: first wins",
			options: []byte("cipher AES-128-GCM,auth SHA1,cipher AES-256-GCM"),
			want:    "AES-128-GCM",
		},
		{
			name:    "no cipher token",
			options: []byte("auth SHA1,keysize 128"),
			want:    "",
		},
		{
			name:    "empty options string",
			options: []byte(""),
			want:    "",
		},
		{
			name:    "cipher token with no trailing space has no value",
			options: []byte("cipher,auth SHA1"),
			want:    "",
		},
		{
			name:    "cipher token with an empty value",
			options: []byte("cipher ,auth SHA1"),
			want:    "",
		},
		{
			name:    "over-long value is rejected",
			options: []byte("cipher " + strings.Repeat("A", maxCipherNameLen+1)),
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseOCCCipher(tt.options); got != tt.want {
				t.Errorf("parseOCCCipher(%q) = %q, want %q", tt.options, got, tt.want)
			}
		})
	}
}

// TestSelectCipherBoundaries is 05-02-PLAN.md Task 2's table-driven
// coverage of selectCipher's boundary rules: exactly-one-shared, identical
// lists, opposite orders (the server's own order always wins), the empty-
// list failure cases, case-insensitive matching on both the client-list and
// OCC paths, and the null-cipher spellings that must never match.
func TestSelectCipherBoundaries(t *testing.T) {
	allowList := []string{"AES-256-GCM", "AES-128-GCM"}

	tests := []struct {
		name        string
		allowList   []string
		peerCiphers []string
		occCipher   string
		want        string
		wantErr     bool
	}{
		{
			name:        "exactly one shared cipher",
			allowList:   allowList,
			peerCiphers: []string{"AES-128-GCM"},
			want:        "AES-128-GCM",
		},
		{
			name:        "identical lists: server's first wins",
			allowList:   allowList,
			peerCiphers: []string{"AES-256-GCM", "AES-128-GCM"},
			want:        "AES-256-GCM",
		},
		{
			name:        "opposite orders: server's first wins, client order never wins",
			allowList:   allowList,
			peerCiphers: []string{"AES-128-GCM", "AES-256-GCM"},
			want:        "AES-256-GCM",
		},
		{
			name:        "empty client list and empty OCC cipher fails",
			allowList:   allowList,
			peerCiphers: []string{},
			occCipher:   "",
			wantErr:     true,
		},
		{
			name:        "empty allow-list fails",
			allowList:   []string{},
			peerCiphers: []string{"AES-256-GCM"},
			wantErr:     true,
		},
		{
			name:        "lower-case client list entry matches",
			allowList:   allowList,
			peerCiphers: []string{"aes-128-gcm"},
			want:        "AES-128-GCM",
		},
		{
			name:        "lower-case OCC entry matches",
			allowList:   allowList,
			peerCiphers: nil,
			occCipher:   "aes-256-gcm",
			want:        "AES-256-GCM",
		},
		{
			name:        "client offering only none fails",
			allowList:   allowList,
			peerCiphers: []string{"none"},
			wantErr:     true,
		},
		{
			name:        "client offering only [null-cipher] fails",
			allowList:   allowList,
			peerCiphers: []string{"[null-cipher]"},
			wantErr:     true,
		},
		{
			name:        "OCC none never matches",
			allowList:   allowList,
			peerCiphers: nil,
			occCipher:   "none",
			wantErr:     true,
		},
		{
			name:        "OCC [null-cipher] never matches",
			allowList:   allowList,
			peerCiphers: nil,
			occCipher:   "[null-cipher]",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCipher(tt.allowList, tt.peerCiphers, tt.occCipher)
			if tt.wantErr {
				if !errors.Is(err, errCipherNegotiationFailed) {
					t.Fatalf("selectCipher(%v, %v, %q) error = %v, want errCipherNegotiationFailed", tt.allowList, tt.peerCiphers, tt.occCipher, err)
				}
				if got != "" {
					t.Errorf("selectCipher(%v, %v, %q) = %q on error, want empty", tt.allowList, tt.peerCiphers, tt.occCipher, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectCipher(%v, %v, %q) unexpected error: %v", tt.allowList, tt.peerCiphers, tt.occCipher, err)
			}
			if got != tt.want {
				t.Errorf("selectCipher(%v, %v, %q) = %q, want %q", tt.allowList, tt.peerCiphers, tt.occCipher, got, tt.want)
			}
		})
	}
}

// TestTwoConcurrentSessionsNegotiateDifferentCiphers is this plan's
// in-process half of ROADMAP success criterion 1: two clients connected
// concurrently to one server, one advertising only AES-128-GCM and the
// other only AES-256-GCM, each negotiate their own cipher, and each
// session's data channel keeps working while the other is live — the
// cipher is per-session state, never a server-wide one. Run under -race and
// -count=5 so a shared-state bug cannot pass by scheduling luck.
func TestTwoConcurrentSessionsNegotiateDifferentCiphers(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.3.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, sessions := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	type clientResult struct {
		sess          *Session
		client        *testPushClient
		wantCipher    string
		wantKeyLen    int
		clientWrapper *datachan.Wrapper
	}

	// bringUp drives ONLY the client-side steps (handshake through reading
	// the push reply) and does NOT touch the shared sessions channel:
	// OnSession fires from the server's own per-session goroutine, whose
	// completion is not ordered against the client-side push-reply read
	// returning, so racing two goroutines each on their own "receive the
	// next session off the shared channel" would attribute session A to
	// client B whenever the scheduler interleaves the two arrivals — a bug
	// in a test asserting per-session state, not in the code under test.
	// Sessions are collected separately below and matched to a client by
	// their own negotiated cipher, which is unambiguous because the two
	// clients advertise different single ciphers.
	bringUp := func(peerInfoLine string) *testPushClient {
		t.Helper()
		client, replyReader, _ := tunnelUpCipherTestClient(t, key, serverPC.LocalAddr(), caPool, peerInfoLine)
		if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
			t.Fatalf("write push request: %v", err)
		}
		if _, err := readControlString(replyReader, maxControlStringLen); err != nil {
			t.Fatalf("read push reply: %v", err)
		}
		return client
	}

	var wg sync.WaitGroup
	results := make([]*clientResult, 2)
	specs := []struct {
		peerInfoLine string
		wantCipher   string
		wantKeyLen   int
	}{
		{"IV_CIPHERS=AES-128-GCM", "AES-128-GCM", 16},
		{"IV_CIPHERS=AES-256-GCM", "AES-256-GCM", 32},
	}
	for i, spec := range specs {
		i, spec := i, spec
		results[i] = &clientResult{wantCipher: spec.wantCipher, wantKeyLen: spec.wantKeyLen}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i].client = bringUp(spec.peerInfoLine)
		}()
	}
	wg.Wait()

	// Drain exactly two sessions off the shared channel (any order) and
	// match each to the clientResult whose wantCipher it negotiated.
	for n := 0; n < 2; n++ {
		var sess *Session
		select {
		case sess = <-sessions:
		case <-time.After(5 * time.Second):
			t.Fatal("OnSession was not called for both sessions")
		}
		cipher := sess.Cipher()
		matched := false
		for _, r := range results {
			if r.wantCipher == cipher && r.sess == nil {
				r.sess = sess
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("received a session with cipher %q that does not match any expected client (results: %+v)", cipher, results)
		}
	}

	for i, r := range results {
		defer r.client.Close()

		if got := r.sess.Cipher(); got != r.wantCipher {
			t.Errorf("client %d: sess.Cipher() = %q, want %q", i, got, r.wantCipher)
		}
		if got := r.sess.Stats().Cipher; got != r.wantCipher {
			t.Errorf("client %d: sess.Stats().Cipher = %q, want %q", i, got, r.wantCipher)
		}
		serverKeys, ok := r.sess.DebugDataKeys()
		if !ok {
			t.Fatalf("client %d: DebugDataKeys() not ok on an established session", i)
		}
		if serverKeys.CipherKeyLen != r.wantKeyLen {
			t.Errorf("client %d: DebugDataKeys().CipherKeyLen = %d, want %d", i, serverKeys.CipherKeyLen, r.wantKeyLen)
		}

		clientWrapper, err := datachan.NewWrapper(mirrorDataKeys(serverKeys), r.sess.PeerID(), 0)
		if err != nil {
			t.Fatalf("client %d: build client wrapper: %v", i, err)
		}
		results[i].clientWrapper = clientWrapper
	}

	// Both sessions are established at the same moment. Exchange a data
	// packet on EACH while the other is still live — this is the part that
	// would catch a shared wrapper or a last-writer-wins field, which
	// asserting the two cipher names differ alone cannot.
	for i, r := range results {
		payloadIn := bytes.Repeat([]byte{byte(0x30 + i)}, 60)
		sealedIn, err := r.clientWrapper.Seal(nil, payloadIn)
		if err != nil {
			t.Fatalf("client %d: Seal: %v", i, err)
		}
		r.sess.handleDataPacket(sealedIn)

		buf := make([]byte, 2048)
		n, err := r.sess.Read(buf)
		if err != nil {
			t.Fatalf("client %d: Session.Read: %v", i, err)
		}
		if !bytes.Equal(buf[:n], payloadIn) {
			t.Fatalf("client %d: Session.Read = %x, want %x", i, buf[:n], payloadIn)
		}

		payloadOut := bytes.Repeat([]byte{byte(0x40 + i)}, 60)
		if _, err := r.sess.Write(payloadOut); err != nil {
			t.Fatalf("client %d: Session.Write: %v", i, err)
		}
		var wireBytes []byte
		select {
		case wireBytes = <-r.client.dataOut:
		case <-time.After(2 * time.Second):
			t.Fatalf("client %d: did not observe Write's output data packet", i)
		}
		opened, err := r.clientWrapper.Open(nil, wireBytes)
		if err != nil {
			t.Fatalf("client %d: client Open of Write's output: %v", i, err)
		}
		if !bytes.Equal(opened, payloadOut) {
			t.Fatalf("client %d: client Open = %x, want %x", i, opened, payloadOut)
		}
	}

	if results[0].sess.Cipher() == results[1].sess.Cipher() {
		t.Fatalf("both sessions negotiated the same cipher %q, want distinct AES-128-GCM/AES-256-GCM", results[0].sess.Cipher())
	}
	if !containsFold(srv.dataCiphers, results[0].sess.Cipher()) || !containsFold(srv.dataCiphers, results[1].sess.Cipher()) {
		t.Fatalf("negotiated ciphers %q/%q are not both members of the server's allow-list %v", results[0].sess.Cipher(), results[1].sess.Cipher(), srv.dataCiphers)
	}
}

// dialOCCFallbackTestClient drives client through hard reset and TLS
// handshake, then writes a Key Method 2 message carrying options and
// peerInfo EXACTLY as given — a nil peerInfo produces a genuinely pre-NCP
// client (writeTestClientKeyMethod2Raw's own doc comment, ovpn_test.go).
// Unlike tunnelUpCipherTestClient, this does NOT read the server's own Key
// Method 2 reply: a cipher-negotiation refusal (CIPH-03) never sends one —
// performKeyMethod2Exchange returns its typed *authFailure before ever
// calling writeServerKeyMethod2AndDeriveKeys — so a caller testing the
// refusal path writes PUSH_REQUEST and reads AUTH_FAILED directly off
// client.tlsConn, exactly like auth_test.go's own TestAuthUserPassRejects
// OnHookError does for a credential rejection. A caller testing the accept
// path reads the server's Key Method 2 reply itself (readTestServerKeyMethod2)
// before proceeding.
func dialOCCFallbackTestClient(t testing.TB, key []byte, serverAddr net.Addr, caPool *x509.CertPool, options, peerInfo []byte) *testPushClient {
	t.Helper()

	client := newTestPushClient(t, key, serverAddr, caPool)
	if err := client.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := client.tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	encode := func(s string) []byte { return append([]byte(s), 0) }
	if err := writeTestClientKeyMethod2Raw(client.tlsConn, options, encode(testPlaceholderUsername), encode(testPlaceholderPassword), peerInfo); err != nil {
		t.Fatalf("write client Key Method 2: %v", err)
	}
	return client
}

// assertNoCipherNameLeaked fails the test if reply contains any of the
// server's allow-list cipher names, beyond the fixed reference sentence
// itself (T-05-16: the client-visible AUTH_FAILED reason must carry no
// server-side diagnostic detail).
func assertNoCipherNameLeaked(t *testing.T, reply string) {
	t.Helper()
	for _, name := range []string{"AES-256-GCM", "AES-128-GCM", "BF-CBC"} {
		if strings.Contains(reply, name) {
			t.Errorf("reply %q leaks cipher name %q — the client-visible reason must carry no server-side diagnostic detail", reply, name)
		}
	}
	if strings.HasPrefix(reply, "PUSH_REPLY") {
		t.Errorf("reply %q begins with PUSH_REPLY — a cipher-negotiation refusal must never write a PUSH_REPLY payload", reply)
	}
}

// TestPreNCPClientWithAllowedOCCCipherConnects is CIPH-03's accept path: a
// genuinely pre-NCP client (nil peer_info) whose options string names a
// cipher the server's allow-list contains connects normally and negotiates
// that cipher via the OCC fallback (ncp_get_best_cipher, ssl_ncp.c:247-290).
func TestPreNCPClientWithAllowedOCCCipherConnects(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.4.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, sessions := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	client := dialOCCFallbackTestClient(t, key, serverPC.LocalAddr(), caPool, []byte("cipher AES-128-GCM"), nil)
	defer client.Close()

	if err := readTestServerKeyMethod2(client.tlsConn); err != nil {
		t.Fatalf("read server Key Method 2: %v", err)
	}
	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reader := bufio.NewReader(client.tlsConn)
	if _, err := readControlString(reader, maxControlStringLen); err != nil {
		t.Fatalf("read push reply: %v", err)
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
}

// TestPreNCPClientWithDisallowedOCCCipherRefused is CIPH-03's refuse path:
// a genuinely pre-NCP client whose OCC cipher is NOT in the server's
// allow-list is refused with the reference's own client-visible sentence,
// leaking neither the server's allow-list nor the client's own token, and
// without ever writing a PUSH_REPLY.
func TestPreNCPClientWithDisallowedOCCCipherRefused(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.5.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, _ := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	client := dialOCCFallbackTestClient(t, key, serverPC.LocalAddr(), caPool, []byte("cipher BF-CBC"), nil)
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reader := bufio.NewReader(client.tlsConn)
	reply, err := readControlString(reader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read AUTH_FAILED: %v", err)
	}
	want := authFailedLiteral + "," + cipherNegotiationFailedReason
	if reply != want {
		t.Errorf("reply = %q, want %q", reply, want)
	}
	assertNoCipherNameLeaked(t, reply)
}

// TestClientWithNoCipherTokenRefused is CIPH-03's empty-edge case: a
// genuinely pre-NCP client whose options string names no cipher at all
// yields both an empty client capability list and an empty OCC cipher, and
// is refused with the same reference sentence — not silently accepted, not
// a distinct error.
func TestClientWithNoCipherTokenRefused(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.6.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, _ := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	client := dialOCCFallbackTestClient(t, key, serverPC.LocalAddr(), caPool, nil, nil)
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reader := bufio.NewReader(client.tlsConn)
	reply, err := readControlString(reader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read AUTH_FAILED: %v", err)
	}
	want := authFailedLiteral + "," + cipherNegotiationFailedReason
	if reply != want {
		t.Errorf("reply = %q, want %q", reply, want)
	}
	assertNoCipherNameLeaked(t, reply)
}

// TestIVCiphersPresentSuppressesOCCFallback is ssl_ncp.c:262-268's own
// zeroing rule (T-05-15): a client that sends an IV_CIPHERS line the server
// cannot use, ALONGSIDE an OCC cipher token the server otherwise would
// accept, is still refused — the OCC token can never rescue a failed
// IV_CIPHERS negotiation once the peer has signalled IV_CIPHERS at all.
func TestIVCiphersPresentSuppressesOCCFallback(t *testing.T) {
	_, network, err := net.ParseCIDR("10.45.7.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	key := testTLSCryptKey(t)

	srv, serverPC, caPool, _ := newCipherTracerServer(t, network, key)
	defer serverPC.Close()
	defer srv.Close()

	client := dialOCCFallbackTestClient(t, key, serverPC.LocalAddr(), caPool,
		[]byte("cipher AES-256-GCM"), []byte("IV_CIPHERS=BF-CBC\n"))
	defer client.Close()

	if err := writeControlString(client.tlsConn, pushRequestLiteral); err != nil {
		t.Fatalf("write push request: %v", err)
	}
	reader := bufio.NewReader(client.tlsConn)
	reply, err := readControlString(reader, maxControlStringLen)
	if err != nil {
		t.Fatalf("read AUTH_FAILED: %v", err)
	}
	want := authFailedLiteral + "," + cipherNegotiationFailedReason
	if reply != want {
		t.Errorf("reply = %q, want %q (the OCC cipher AES-256-GCM must NOT rescue the failed IV_CIPHERS negotiation)", reply, want)
	}
	assertNoCipherNameLeaked(t, reply)
}
