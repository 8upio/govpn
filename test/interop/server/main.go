// Command interop-server is the interop harness's real embedder of
// github.com/8upio/govpn: it builds a Config from the PKI material
// cmd/gentestpki generated, calls ovpn.NewServer and Serve on a UDP
// PacketConn, and proves — independently of any client-side log text — that
// a real client completed the full TLS handshake against the library:
// Config.OnSession fired with a verified peer CommonName. It then stays
// alive for a further two seconds (during which the real client's Key
// Method 2 payload arrives as TLS application data and is buffered,
// unread, by the library — Phase 1 scope stops at "TLS established") before
// printing its PASS line and exiting 0, so a crash or error on that
// post-handshake traffic would prevent the pass line from ever appearing.
//
// Before the handshake completes, it also observes protocol events by
// wrapping the net.PacketConn handed to Serve: the leading header byte
// (opcode<<3|keyID) and the 8-byte session ID that follow are
// cleartext-but-authenticated on every tls-crypt packet (RESEARCH Pattern
// 1), so a timeout can report the last protocol state actually reached
// without decrypting anything itself or reaching into ovpn's internals.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/8upio/govpn"
	"github.com/8upio/govpn/internal/wire"
)

// postHandshakeSurvival is how long the harness stays up after OnSession
// fires before printing PASS and exiting — long enough for the real
// client's Key Method 2 application data to arrive and be silently
// buffered, proving the server doesn't error or reset on it.
const postHandshakeSurvival = 2 * time.Second

func main() {
	pkiDir := flag.String("pki", "/pki", "directory containing ca.crt, server.crt, server.key, tls-crypt.key")
	listenAddr := flag.String("listen", "0.0.0.0:1194", "UDP address to listen on")
	deadline := flag.Duration("deadline", 30*time.Second, "how long to wait for the real client to complete the TLS handshake before exiting non-zero")
	flag.Parse()

	if err := run(*pkiDir, *listenAddr, *deadline); err != nil {
		fmt.Fprintln(os.Stderr, "interop-server:", err)
		os.Exit(1)
	}
}

func run(pkiDir, listenAddr string, deadline time.Duration) error {
	tlsCfg, tlsCryptKey, err := loadConfig(pkiDir)
	if err != nil {
		return fmt.Errorf("load PKI material: %w", err)
	}

	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", listenAddr, err)
	}

	obs := newObservingConn(pc)

	sessions := make(chan *ovpn.Session, 1)
	srv := ovpn.NewServer(ovpn.Config{
		TLSConfig:   tlsCfg,
		TLSCryptKey: tlsCryptKey,
		OnSession: func(sess *ovpn.Session) {
			select {
			case sessions <- sess:
			default:
				// Only the first session matters for this harness run.
			}
		},
	})

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(obs) }()

	select {
	case sess := <-sessions:
		state := sess.ConnectionState()
		log.Printf(
			"handshake established peer_cn=%s tls_version=%s cipher_suite=%s",
			sess.PeerCN, tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite),
		)

		// Stay up past the handshake: the real client sends its Key
		// Method 2 payload as TLS application data immediately after its
		// own handshake completes (RESEARCH Pitfall 5); the server must
		// not error, close, or reset on it. If it did, this sleep would
		// either observe the Serve goroutine having already exited
		// (serveErr readable below) or the process would have already
		// crashed — either way PASS would never print.
		log.Printf("surviving %s past handshake completion to prove post-handshake TLS application data doesn't disturb the session", postHandshakeSurvival)
		select {
		case err := <-serveErr:
			return fmt.Errorf("Serve exited unexpectedly during the post-handshake survival window: %v", err)
		case <-time.After(postHandshakeSurvival):
		}

		log.Printf(
			"PASS: session established and stable %s past handshake completion; peer_cn=%s tls_version=%s tls_version_raw=0x%04x cipher_suite=%s",
			postHandshakeSurvival, sess.PeerCN, tls.VersionName(state.Version), state.Version, tls.CipherSuiteName(state.CipherSuite),
		)

		_ = srv.Close()
		<-serveErr
		return nil

	case <-time.After(deadline):
		_ = srv.Close()
		<-serveErr
		return fmt.Errorf("timed out after %s waiting for the TLS handshake to complete; last observed protocol state: %s", deadline, obs.lastObservedSummary())
	}
}

func loadConfig(pkiDir string) (*tls.Config, []byte, error) {
	caPEM, err := os.ReadFile(pkiDir + "/ca.crt")
	if err != nil {
		return nil, nil, err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("no certificates found in %s/ca.crt", pkiDir)
	}

	serverCert, err := tls.LoadX509KeyPair(pkiDir+"/server.crt", pkiDir+"/server.key")
	if err != nil {
		return nil, nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	tlsCryptPEM, err := os.ReadFile(pkiDir + "/tls-crypt.key")
	if err != nil {
		return nil, nil, err
	}
	tlsCryptKey, err := ovpn.ParseStaticKeyV1(tlsCryptPEM)
	if err != nil {
		return nil, nil, err
	}

	return tlsCfg, tlsCryptKey, nil
}

// observingConn wraps a net.PacketConn purely to log every accepted
// control packet's opcode and session ID, so a timeout can report the last
// protocol state actually reached instead of a bare "timed out". This
// never decrypts anything; it only reads the cleartext-but-authenticated
// header byte and session ID that precede the tls-crypt ciphertext
// (RESEARCH Pattern 1). The pass condition itself (below) comes entirely
// from Config.OnSession, not from anything this type observes.
type observingConn struct {
	net.PacketConn

	mu           sync.Mutex
	lastObserved string
}

func newObservingConn(pc net.PacketConn) *observingConn {
	return &observingConn{PacketConn: pc}
}

func (o *observingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = o.PacketConn.ReadFrom(p)
	if err != nil || n < 1+wire.SessionIDSize {
		return n, addr, err
	}

	opcode, keyID := wire.ParseHeaderByte(p[0])
	var sid wire.SessionID
	copy(sid[:], p[1:1+wire.SessionIDSize])

	log.Printf("recv opcode=%d key_id=%d session=%x addr=%s", opcode, keyID, sid, addr)

	o.mu.Lock()
	o.lastObserved = fmt.Sprintf("recv opcode=%d session=%x addr=%s", opcode, sid, addr)
	o.mu.Unlock()

	return n, addr, err
}

func (o *observingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) >= 1+wire.SessionIDSize {
		opcode, keyID := wire.ParseHeaderByte(p[0])
		var sid wire.SessionID
		copy(sid[:], p[1:1+wire.SessionIDSize])
		log.Printf("send opcode=%d key_id=%d session=%x addr=%s", opcode, keyID, sid, addr)

		o.mu.Lock()
		o.lastObserved = fmt.Sprintf("send opcode=%d session=%x addr=%s", opcode, sid, addr)
		o.mu.Unlock()
	}
	return o.PacketConn.WriteTo(p, addr)
}

func (o *observingConn) lastObservedSummary() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lastObserved == "" {
		return "nothing"
	}
	return o.lastObserved
}
