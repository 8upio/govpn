// Command interop-server is the interop harness's real embedder of
// github.com/8upio/govpn: it builds a Config from the PKI material
// cmd/gentestpki generated, calls ovpn.NewServer and Serve on a UDP
// PacketConn, and proves — independently of any client-side log text — that
// a real client's HARD_RESET_CLIENT_V2 was authenticated and answered, and
// that the client then sent a subsequent control packet from the same
// session (opcode P_CONTROL_V1 == 4).
//
// It observes protocol events by wrapping the net.PacketConn handed to
// Serve: the leading header byte (opcode<<3|keyID) and the 8-byte session
// ID that follows it are cleartext-but-authenticated on every tls-crypt
// packet (RESEARCH Pattern 1), so this command can log and assert on them
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

func main() {
	pkiDir := flag.String("pki", "/pki", "directory containing ca.crt, server.crt, server.key, tls-crypt.key")
	listenAddr := flag.String("listen", "0.0.0.0:1194", "UDP address to listen on")
	deadline := flag.Duration("deadline", 30*time.Second, "how long to wait for the real client to reach opcode 4 before exiting non-zero")
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

	srv := ovpn.NewServer(ovpn.Config{
		TLSConfig:   tlsCfg,
		TLSCryptKey: tlsCryptKey,
	})

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(obs) }()

	select {
	case <-obs.success:
		log.Printf("PASS: observed opcode 4 (P_CONTROL_V1) from the same client session that sent the accepted hard reset")
		_ = srv.Close()
		<-serveErr
		return nil
	case <-time.After(deadline):
		_ = srv.Close()
		<-serveErr
		return fmt.Errorf("timed out after %s waiting for opcode 4 from the reset session; last observed: %s", deadline, obs.lastObservedSummary())
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

// resetInfo identifies one client's most recent HARD_RESET_CLIENT_V2
// attempt: the remote address and the client's own session ID. A real
// client may reset and retry (RESEARCH Open Question 2, a valid transient
// state) — only the most recent attempt is tracked, since a later attempt
// supersedes an earlier one for the purpose of "did the client's own
// session get through".
type resetInfo struct {
	addr string
	sid  wire.SessionID
}

// observingConn wraps a net.PacketConn to log every accepted control
// packet's opcode and session ID, and to detect the harness's pass
// condition: a P_CONTROL_V1 (opcode 4) arriving from the same
// (address, session ID) pair as the most recently observed
// P_CONTROL_HARD_RESET_CLIENT_V2, after the server has answered with its
// own P_CONTROL_HARD_RESET_SERVER_V2. This never decrypts anything; it only
// reads the cleartext-but-authenticated header byte and session ID that
// precede the tls-crypt ciphertext (RESEARCH Pattern 1).
type observingConn struct {
	net.PacketConn

	success chan struct{}
	once    sync.Once

	mu           sync.Mutex
	lastReset    *resetInfo
	resetAcked   bool
	lastObserved string
}

func newObservingConn(pc net.PacketConn) *observingConn {
	return &observingConn{
		PacketConn: pc,
		success:    make(chan struct{}),
	}
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

	switch {
	case opcode == wire.OpControlHardResetClientV2 && keyID == 0:
		o.lastReset = &resetInfo{addr: addr.String(), sid: sid}
		o.resetAcked = false
	case opcode == wire.OpControlV1:
		if o.resetAcked && o.lastReset != nil && o.lastReset.addr == addr.String() && o.lastReset.sid == sid {
			o.mu.Unlock()
			o.once.Do(func() { close(o.success) })
			return n, addr, err
		}
	}
	o.mu.Unlock()

	return n, addr, err
}

func (o *observingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) >= 1+wire.SessionIDSize {
		opcode, keyID := wire.ParseHeaderByte(p[0])
		var sid wire.SessionID
		copy(sid[:], p[1:1+wire.SessionIDSize])
		log.Printf("send opcode=%d key_id=%d session=%x addr=%s", opcode, keyID, sid, addr)

		if opcode == wire.OpControlHardResetServerV2 {
			o.mu.Lock()
			if o.lastReset != nil && o.lastReset.addr == addr.String() {
				o.resetAcked = true
			}
			o.mu.Unlock()
		}
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
