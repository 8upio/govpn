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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/8upio/govpn"
	"github.com/8upio/govpn/internal/wire"
)

// postHandshakeSurvival is how long the harness stays up after OnSession
// fires before printing PASS and exiting — long enough for the real
// client's Key Method 2 application data to arrive and be silently
// buffered (proving the server doesn't error or reset on it), and long
// enough for entrypoint.sh's own ping of the server's tunnel IP (tun0
// coming up, then the full ICMP round-trip sequence) to complete and print
// its summary line before this process exits and pulls the whole compose
// run down via --abort-on-container-exit. 02-04-PLAN.md Task 1 raised this
// from 5s to 20s: VRFY-03's lossy-large assertions need entrypoint.sh's
// ping widened from 4 packets at a 0.2s interval to ~10 packets at a 1s
// interval (so the round trip spans several of docker-compose.lossy.yml's
// loss events, not just one), and a 10-second ping needs headroom on top
// of the tun0-up wait and scheduling jitter across all three scenarios,
// not only the lossy one — this constant is shared, not per-scenario.
const postHandshakeSurvival = 20 * time.Second

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

		// Write this session's derived data-channel key material and raw
		// Key Method 2 seed material to files inside this container's own
		// filesystem — never to stdout, never into the pcap capture
		// (02-04-PLAN.md Task 2). test/interop/interop_test.go's
		// runScenario retrieves these via `docker cp` while the container
		// still exists, the same ordering constraint the privilege check
		// already established (before `docker compose down` removes it).
		// Only -update-golden's own clean-large run ever reads them back;
		// every other scenario writes and discards them harmlessly.
		if err := writeDataChannelKeyExport(sess); err != nil {
			log.Printf("warning: failed to write data-channel key export: %v", err)
		}
		if err := writeKeyMethod2Export(sess); err != nil {
			log.Printf("warning: failed to write Key Method 2 export: %v", err)
		}

		// Start the harness's own ICMP echo responder as soon as the
		// Session is usable (D-08 guarantees it is, the moment OnSession
		// fires): this is harness code, not library code — the real
		// in-process ICMP responder is Phase 3's NET-03. It proves
		// Session.Read/Write are a genuine encrypted round trip against a
		// real client, not merely that OnSession fired.
		pingRx, pingTx := startICMPResponder(sess)

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
			"PASS: session established and stable %s past handshake completion; peer_cn=%s tls_version=%s tls_version_raw=0x%04x cipher_suite=%s km2=ok push_request=%s assigned_ip=%s peer_id=%d ping_rx=%d ping_tx=%d",
			postHandshakeSurvival, sess.PeerCN, tls.VersionName(state.Version), state.Version, tls.CipherSuiteName(state.CipherSuite), pushStatus, sess.AssignedIP(), sess.PeerID(),
			atomic.LoadInt64(pingRx), atomic.LoadInt64(pingTx),
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

// startICMPResponder starts a background goroutine that reads raw,
// decrypted IP packets from sess and, for every ICMP echo request it
// recognizes, writes back a well-formed echo reply through the SAME
// Session.Write path a real embedder would use — proving Session.Read/
// Write are a genuine encrypted round trip against a real OpenVPN client,
// not merely that Config.OnSession fired. This is harness code, not
// library code: the real in-process ICMP responder is Phase 3's NET-03.
// The goroutine exits when sess.Read returns an error (the session closed,
// via run's own srv.Close()). The returned counters are read with
// sync/atomic — startICMPResponder's own goroutine is the only writer.
func startICMPResponder(sess *ovpn.Session) (pingRx, pingTx *int64) {
	pingRx = new(int64)
	pingTx = new(int64)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := sess.Read(buf)
			if err != nil {
				return
			}
			reply, ok := icmpEchoReply(buf[:n])
			if !ok {
				continue
			}
			atomic.AddInt64(pingRx, 1)
			if _, err := sess.Write(reply); err != nil {
				return
			}
			atomic.AddInt64(pingTx, 1)
		}
	}()
	return pingRx, pingTx
}

// icmpEchoReply builds an ICMPv4 echo reply for pkt, an IPv4 packet as
// delivered by Session.Read, if and only if pkt is a well-formed IPv4
// packet carrying an ICMP (protocol 1) echo request (type 8). It swaps the
// IPv4 source/destination addresses, sets the ICMP type to 0 (echo reply,
// code unchanged), and recomputes both the IPv4 header checksum and the
// ICMP checksum (RFC 791 §3.1, RFC 792) — everything else (identifier,
// sequence number, payload) is left untouched, matching a real ICMP
// echo responder. Malformed or non-ICMP-echo-request packets are ignored
// (ok=false): this is harness code, not a production IP stack, so it does
// not need to handle IPv4 options, fragmentation, or any other IP
// protocol.
func icmpEchoReply(pkt []byte) (reply []byte, ok bool) {
	const (
		minIPv4HeaderLen = 20
		minICMPHeaderLen = 8
		protocolICMP     = 1
		icmpTypeEchoReq  = 8
		icmpTypeEchoRepl = 0
	)

	if len(pkt) < minIPv4HeaderLen {
		return nil, false
	}
	version := pkt[0] >> 4
	ihl := int(pkt[0]&0x0F) * 4
	if version != 4 || ihl < minIPv4HeaderLen || len(pkt) < ihl+minICMPHeaderLen {
		return nil, false
	}
	if pkt[9] != protocolICMP {
		return nil, false
	}
	icmp := pkt[ihl:]
	if icmp[0] != icmpTypeEchoReq {
		return nil, false
	}

	out := append([]byte(nil), pkt...)

	var src, dst [4]byte
	copy(src[:], out[12:16])
	copy(dst[:], out[16:20])
	copy(out[12:16], dst[:])
	copy(out[16:20], src[:])

	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], internetChecksum(out[:ihl]))

	outICMP := out[ihl:]
	outICMP[0] = icmpTypeEchoRepl
	outICMP[2], outICMP[3] = 0, 0
	binary.BigEndian.PutUint16(outICMP[2:4], internetChecksum(outICMP))

	return out, true
}

// dataChannelKeyExportPath/keyMethod2ExportPath are fixed in-container
// paths (this harness runs exactly one session per process) — /tmp is
// writable by any UID on the base images this harness builds from, so
// these writes succeed even under the server's own unprivileged
// "user: 65534:65534" (T-01-07), unlike a bind-mounted host volume, which
// would need matching host/container UID permissions the harness does not
// otherwise need to reason about.
const (
	dataChannelKeyExportPath = "/tmp/datachan-keys.json"
	keyMethod2ExportPath     = "/tmp/datachan-km2.json"
)

// dataChannelKeyExport is the on-disk (hex-encoded) shape of
// sess.DebugDataKeys()'s output — the server's own per-direction
// AES-256-GCM key/implicit-IV material (keyderiv.Key2.ServerSlots), read
// back by test/interop/golden_export.go and internal/datachan/golden_test.go
// to independently open/re-seal a captured session's P_DATA_V2 traffic
// (02-04-PLAN.md Task 2).
type dataChannelKeyExport struct {
	EncryptCipher     string `json:"encrypt_cipher"`
	EncryptImplicitIV string `json:"encrypt_implicit_iv"`
	DecryptCipher     string `json:"decrypt_cipher"`
	DecryptImplicitIV string `json:"decrypt_implicit_iv"`
}

// writeDataChannelKeyExport writes sess's derived data-channel key material
// to dataChannelKeyExportPath as JSON, hex-encoding every byte field so the
// file stays human-diffable, matching the plaintext-hex convention this
// project already uses for testdata/golden's own committed material.
func writeDataChannelKeyExport(sess *ovpn.Session) error {
	keys, ok := sess.DebugDataKeys()
	if !ok {
		return fmt.Errorf("session has no data-channel keys yet")
	}
	export := dataChannelKeyExport{
		EncryptCipher:     hex.EncodeToString(keys.EncryptCipher[:]),
		EncryptImplicitIV: hex.EncodeToString(keys.EncryptImplicitIV[:]),
		DecryptCipher:     hex.EncodeToString(keys.DecryptCipher[:]),
		DecryptImplicitIV: hex.EncodeToString(keys.DecryptImplicitIV[:]),
	}
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dataChannelKeyExportPath, append(data, '\n'), 0o600)
}

// keyMethod2Export is the on-disk (hex-encoded) shape of
// sess.DebugKeyMethod2Material()'s output — the raw Key Method 2 seed
// material (both sides' pre_master/random1/random2) and both
// control-channel session IDs, read back by
// internal/keyderiv/golden_test.go's TestGoldenKeyExpansionFromCapture to
// independently re-run keyderiv.DeriveKeys and confirm it reproduces the
// committed derived key material byte-for-byte from a real client's own
// captured exchange (02-04-PLAN.md Task 2, WIRE-03 against live evidence).
type keyMethod2Export struct {
	ClientPreMaster string `json:"client_pre_master"`
	ClientRandom1   string `json:"client_random1"`
	ClientRandom2   string `json:"client_random2"`
	ServerRandom1   string `json:"server_random1"`
	ServerRandom2   string `json:"server_random2"`
	ClientSessionID string `json:"client_session_id"`
	ServerSessionID string `json:"server_session_id"`
}

func writeKeyMethod2Export(sess *ovpn.Session) error {
	src, clientSID, serverSID, ok := sess.DebugKeyMethod2Material()
	if !ok {
		return fmt.Errorf("session has no Key Method 2 material yet")
	}
	export := keyMethod2Export{
		ClientPreMaster: hex.EncodeToString(src.Client.PreMaster[:]),
		ClientRandom1:   hex.EncodeToString(src.Client.Random1[:]),
		ClientRandom2:   hex.EncodeToString(src.Client.Random2[:]),
		ServerRandom1:   hex.EncodeToString(src.Server.Random1[:]),
		ServerRandom2:   hex.EncodeToString(src.Server.Random2[:]),
		ClientSessionID: hex.EncodeToString(clientSID[:]),
		ServerSessionID: hex.EncodeToString(serverSID[:]),
	}
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(keyMethod2ExportPath, append(data, '\n'), 0o600)
}

// internetChecksum computes the RFC 1071 Internet checksum over b: the
// one's complement of the one's-complement sum of b's 16-bit big-endian
// words, with a trailing odd byte treated as the high byte of a final
// zero-padded word. Callers must zero the checksum field in b before
// calling (as icmpEchoReply does).
func internetChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
