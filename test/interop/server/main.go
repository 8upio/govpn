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
	"math/rand"
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
	dropRate := flag.Float64("drop-rate", 0, "server-to-client synthetic packet loss, as a percentage (0-100); 0 disables the decorator's drop behavior (01-04-PLAN.md Task 1)")
	reorderRate := flag.Float64("reorder-rate", 0, "server-to-client synthetic packet reordering, as a percentage (0-100) of non-dropped datagrams delayed before transmission")
	reorderDelay := flag.Duration("reorder-delay", 10*time.Millisecond, "delay applied to a datagram selected for reordering by -reorder-rate")
	seed := flag.Int64("seed", 1, "seed for the server-to-client loss/reorder decorator's PRNG, so a failing lossy run is reproducible")
	flag.Parse()

	if err := run(*pkiDir, *listenAddr, *deadline, *dropRate, *reorderRate, *reorderDelay, *seed); err != nil {
		fmt.Fprintln(os.Stderr, "interop-server:", err)
		os.Exit(1)
	}
}

func run(pkiDir, listenAddr string, deadline time.Duration, dropRatePct, reorderRatePct float64, reorderDelay time.Duration, seed int64) error {
	tlsCfg, tlsCryptKey, err := loadConfig(pkiDir)
	if err != nil {
		return fmt.Errorf("load PKI material: %w", err)
	}

	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", listenAddr, err)
	}

	var transport net.PacketConn = pc
	if dropRatePct > 0 || reorderRatePct > 0 {
		log.Printf("lossy decorator active: drop=%.1f%% reorder=%.1f%% reorder-delay=%s seed=%d", dropRatePct, reorderRatePct, reorderDelay, seed)
		transport = newLossyPacketConn(pc, dropRatePct/100, reorderRatePct/100, reorderDelay, seed)
	}

	obs := newObservingConn(transport)

	// tunnelNetwork is this harness's own throwaway tunnel-IP range
	// (02-02-PLAN.md D-01): the real client's client.conf never hardcodes
	// an ifconfig address, so whatever the server pushes here is exactly
	// what the client's tun interface ends up configured with.
	_, tunnelNetwork, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		return fmt.Errorf("parse tunnel network: %w", err)
	}

	sessions := make(chan *ovpn.Session, 1)
	srv := ovpn.NewServer(ovpn.Config{
		TLSConfig:   tlsCfg,
		TLSCryptKey: tlsCryptKey,
		Network:     tunnelNetwork,
		Cipher:      "AES-256-GCM",
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

		// km2=ok and assigned_ip=/peer_id= are unconditional here:
		// Config.OnSession only fires after runHandshake's Key Method 2
		// exchange AND its PUSH_REQUEST/PUSH_REPLY exchange have both
		// already succeeded (D-08) — a session whose exchange fails is
		// closed and never reaches OnSession — so sess.AssignedIP() is
		// guaranteed non-nil here. Only this diagnostic status and the
		// non-secret, test-only assigned tunnel address/peer-id are ever
		// printed (threat T-02-03/T-02-11); no key material.
		pushStatus := "not-seen"
		if sess.PushRequestSeen() {
			pushStatus = "seen"
		}
		log.Printf(
			"PASS: session established and stable %s past handshake completion; peer_cn=%s tls_version=%s tls_version_raw=0x%04x cipher_suite=%s km2=ok push_request=%s assigned_ip=%s peer_id=%d",
			postHandshakeSurvival, sess.PeerCN, tls.VersionName(state.Version), state.Version, tls.CipherSuiteName(state.CipherSuite), pushStatus, sess.AssignedIP(), sess.PeerID(),
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

	// The "large" cert profile (cmd/gentestpki -profile large) writes the
	// leaf to server.crt and the intermediate CA to a separate
	// intermediate.crt (01-04-PLAN.md Task 1) so the server presents the
	// full leaf+intermediate chain — tls.X509KeyPair accepts multiple
	// concatenated CERTIFICATE PEM blocks, leaf first, exactly this shape.
	// The "small" profile never writes intermediate.crt, so this is a
	// no-op concatenation for that profile.
	certPEM, err := os.ReadFile(pkiDir + "/server.crt")
	if err != nil {
		return nil, nil, err
	}
	if intPEM, err := os.ReadFile(pkiDir + "/intermediate.crt"); err == nil {
		certPEM = append(append([]byte{}, certPEM...), intPEM...)
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(pkiDir + "/server.key")
	if err != nil {
		return nil, nil, err
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
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

// lossyPacketConn is the server-to-client half of 01-04-PLAN.md Task 1's
// bidirectional loss injection: a seeded, reproducible drop-and-reorder
// decorator around the net.PacketConn the harness passes to ovpn.Serve —
// the client-to-server half is injected independently by
// test/interop/entrypoint.sh's tc netem on the client container's egress.
//
// The decorator only injects drop/delay on WriteTo (server -> client);
// ReadFrom is a pure pass-through. Injecting loss on ReadFrom too would
// duplicate what the client's own netem egress already does to the same
// client-to-server datagrams — the whole point of injecting independently
// per direction, with a different mechanism per direction (T-01-21), is
// that each side's own decorator owns exactly one direction.
//
// It runs entirely in userspace, in this harness process — it needs no
// elevated privilege the server container doesn't already have, which is
// the point (the server must stay unprivileged even in the lossy scenario,
// T-01-21).
type lossyPacketConn struct {
	net.PacketConn

	DropRate     float64 // [0,1]: fraction of WriteTo datagrams silently dropped
	ReorderRate  float64 // [0,1]: fraction of surviving datagrams delayed before send
	ReorderDelay time.Duration

	mu  sync.Mutex
	rng *rand.Rand //nolint:gosec // G404: simulated network loss for a test harness, not security-relevant randomness (crypto/rand governs session IDs and key material elsewhere in this project).

	wg sync.WaitGroup
}

func newLossyPacketConn(pc net.PacketConn, dropRate, reorderRate float64, reorderDelay time.Duration, seed int64) *lossyPacketConn {
	return &lossyPacketConn{
		PacketConn:   pc,
		DropRate:     dropRate,
		ReorderRate:  reorderRate,
		ReorderDelay: reorderDelay,
		rng:          rand.New(rand.NewSource(seed)), //nolint:gosec // G404: see field doc above.
	}
}

// WriteTo drops the datagram (reporting a successful write of its full
// length, exactly as a real UDP send that never reaches the peer would
// still report success locally) with probability DropRate, otherwise
// transmits it — after a delay with probability ReorderRate, so it can
// arrive out of order relative to later, non-delayed datagrams.
func (l *lossyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	l.mu.Lock()
	drop := l.rng.Float64() < l.DropRate
	reorder := !drop && l.ReorderRate > 0 && l.rng.Float64() < l.ReorderRate
	l.mu.Unlock()

	if drop {
		return len(p), nil
	}

	if reorder {
		payload := append([]byte(nil), p...)
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			time.Sleep(l.ReorderDelay)
			_, _ = l.PacketConn.WriteTo(payload, addr)
		}()
		return len(p), nil
	}

	return l.PacketConn.WriteTo(p, addr)
}

// Close waits for any in-flight delayed (reordered) writes to finish before
// closing the underlying connection, so a shutdown doesn't leak goroutines
// or silently drop an already-accepted delayed write.
func (l *lossyPacketConn) Close() error {
	l.wg.Wait()
	return l.PacketConn.Close()
}
