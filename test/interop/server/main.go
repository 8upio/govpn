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
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/8upio/govpn"
	"github.com/8upio/govpn/examples/tunnelweb/site"
	"github.com/8upio/govpn/internal/wire"
	"github.com/8upio/govpn/netstack"
)

// postHandshakeSurvival is the CEILING on how long the harness stays up
// after OnSession fires before printing PASS and exiting — it is no longer
// the normal path (03-06-PLAN.md Task 2). The normal path is probe-driven
// (see waitForProbes below): PASS prints as soon as at least one ICMP echo,
// one UDP datagram, and one HTTP request have all been observed, plus a
// short settle delay. This constant only matters when one of those three
// probe classes never arrives — a broken probe, not a slow one — in which
// case the harness still exits (non-hanging) after this ceiling elapses.
//
// Raised from 20s to 45s by 03-06-PLAN.md Task 2: three new probe classes
// (UDP echo, four HTTP page loads including a form POST, and a negative
// "unreachable outside the tunnel" check) would not reliably fit inside the
// old fixed 20s window on a slow CI machine or the lossy scenario, and
// 02-04-SUMMARY.md/02-03-SUMMARY.md already document the exact failure mode
// a too-short window causes: with --abort-on-container-exit, the server
// exiting first tears the whole compose run down, making an acceptance
// criterion structurally unreachable rather than merely failing. A
// probe-driven normal path removes the guesswork entirely; this ceiling is
// only the backstop for a genuinely broken run.
const postHandshakeSurvival = 45 * time.Second

// probePollInterval / probeSettleDelay drive waitForProbes' probe-driven
// survival window (03-06-PLAN.md Task 2): poll every probePollInterval and,
// once all three tracked probe classes (ICMP, UDP, HTTP) have each been
// observed at least once, wait probeSettleDelay before printing PASS.
//
// The three tracked classes become true from the FIRST probe of each kind
// entrypoint.sh runs — the ICMP condition is already true partway through
// the pre-existing ping sequence, and the HTTP condition is already true
// after the very first HTTP probe (http_landing) — so this moment does not
// coincide with "every probe entrypoint.sh will ever run has finished".
// probeSettleDelay must therefore comfortably cover BOTH: (a) the client's
// own udp_echo probe's unavoidable nc -u -w block (confirmed empirically:
// nc waits out its full idle timeout even after receiving a reply, since
// UDP has no EOF signal — entrypoint.sh uses a 1-second timeout precisely
// to keep this bounded), and (b) the handful of remaining HTTP probes
// (http_status/http_echo/http_headers, and Task 3's outside_tunnel) still
// left to run after that point — each a single near-instant local request,
// but several in sequence. 5 seconds is generous headroom for both on a
// working link while still finishing well before the old fixed 20-second
// window.
const (
	probePollInterval = 200 * time.Millisecond
	probeSettleDelay  = 5 * time.Second
)

// newHardenedHTTPServer builds the *http.Server this harness serves the
// tunnelweb site through, with WR-02's timeouts set — see
// examples/tunnelweb/main.go's own copy of this function for the full
// rationale (net/http never arms a read deadline at all unless one of
// these fields is set). Extracted so main_test.go can assert on the
// timeout values directly.
func newHardenedHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// interopLogger builds this harness's own ovpn.Config.Logger (quick
// 260908-na1): plain text to stderr at Info by default, or Debug when
// GOVPN_DEBUG=1 is set in the environment. Debug is per-packet — every
// datagram the library's dispatch drops — so it is only useful when a
// specific scenario is actually being debugged, never left on by default
// (it would otherwise mix into every scenario's own log.Printf output).
func interopLogger() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("GOVPN_DEBUG") == "1" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func main() {
	pkiDir := flag.String("pki", "/pki", "directory containing ca.crt, server.crt, server.key, tls-crypt.key")
	listenAddr := flag.String("listen", "0.0.0.0:1194", "UDP address to listen on")
	deadline := flag.Duration("deadline", 30*time.Second, "how long to wait for the real client to complete the TLS handshake before exiting non-zero")
	dropRate := flag.Float64("drop-rate", 0, "server-to-client synthetic packet loss, as a percentage (0-100); 0 disables the decorator's drop behavior (01-04-PLAN.md Task 1)")
	reorderRate := flag.Float64("reorder-rate", 0, "server-to-client synthetic packet reordering, as a percentage (0-100) of non-dropped datagrams delayed before transmission")
	reorderDelay := flag.Duration("reorder-delay", 10*time.Millisecond, "delay applied to a datagram selected for reordering by -reorder-rate")
	seed := flag.Int64("seed", 1, "seed for the server-to-client loss/reorder decorator's PRNG, so a failing lossy run is reproducible")
	httpPort := flag.Uint("http-port", 8080, "TCP port the tunnelweb example site listens on, over the netstack (03-06-PLAN.md Task 1)")
	udpPort := flag.Uint("udp-port", 9999, "UDP port the echo service listens on, over the netstack (03-06-PLAN.md Task 2)")
	renegSec := flag.Duration("reneg-sec", 0, "this server's own renegotiation deadline (ovpn.Config.RenegSec); 0 means the library's own 3600s default (04-03-PLAN.md Task 1)")
	hold := flag.Duration("hold", 0, "extra survival time the server waits AFTER waitForProbes' normal probe-driven trigger fires, before printing PASS and exiting; 0 means no extension (the pre-existing scenarios' unchanged behavior) — gives a shortened -reneg-sec's timer room to actually fire before the server tears the run down (04-03-PLAN.md Task 1)")
	soakCycles := flag.Int("soak-cycles", 0, "number of connect/use/clean-disconnect cycles to observe from ONE long-lived server process before printing PASS and exiting; 0 keeps every pre-existing scenario's normal single-session, probe-driven behavior completely unchanged (04-04-PLAN.md Task 1)")
	noClientCert := flag.Bool("no-client-cert", false, "use tls.NoClientCert instead of tls.RequireAndVerifyClientCert; false (default) leaves every pre-existing scenario's mandatory-client-cert posture unchanged (quick 260908-m4e)")
	authUserPass := flag.String("auth-user-pass", "", "\"user:pass\" to authenticate clients via ovpn.Config.AuthUserPass; empty (default) leaves the hook nil, unchanged behaviour (quick 260908-m4e)")
	dataCiphers := flag.String("data-ciphers", "", "colon-separated data-channel cipher allow-list in the server's own preference order (e.g. \"AES-256-GCM:AES-128-GCM\"), passed straight through to ovpn.Config.DataCiphers; empty (default) leaves it nil, which resolves to the library's own default AES-256-GCM/AES-128-GCM pair — every pre-existing scenario's behaviour is unchanged byte-for-byte (05-04-PLAN.md Task 1)")
	flag.Parse()

	// dataCiphersList is nil when -data-ciphers is empty, matching
	// ovpn.Config.DataCiphers' own "nil means the library's default" contract
	// (resolveDataCiphers) rather than passing a single empty-string element.
	var dataCiphersList []string
	if *dataCiphers != "" {
		dataCiphersList = strings.Split(*dataCiphers, ":")
	}

	// Soak mode (04-04-PLAN.md Task 1) is dispatched to its own entry point,
	// runSoak, entirely separate from run() below: run()'s single-OnSession,
	// probe-driven survival window (waitForProbes) is left byte-for-byte
	// untouched for every non-soak scenario, rather than threading a branch
	// through its tightly-coupled single-session channel/select logic.
	if *soakCycles > 0 {
		if err := runSoak(*pkiDir, *listenAddr, *deadline, uint16(*httpPort), uint16(*udpPort), *soakCycles, dataCiphersList); err != nil {
			fmt.Fprintln(os.Stderr, "interop-server:", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*pkiDir, *listenAddr, *deadline, *dropRate, *reorderRate, *reorderDelay, *seed, uint16(*httpPort), uint16(*udpPort), *renegSec, *hold, *noClientCert, *authUserPass, dataCiphersList); err != nil {
		fmt.Fprintln(os.Stderr, "interop-server:", err)
		os.Exit(1)
	}
}

// defaultDataCiphersDisplay is the human-readable rendering of the
// library's own default data-channel cipher allow-list (resolveDataCiphers'
// nil-DataCiphers fallback, cipher.go) — duplicated here (not imported,
// since resolveDataCiphers is unexported) purely so site.Options.Cipher can
// display what the server is willing to negotiate when -data-ciphers is
// unset, without the harness guessing at a string the library itself never
// exposes for display.
const defaultDataCiphersDisplay = "AES-256-GCM:AES-128-GCM"

// dataCiphersDisplay renders dataCiphers (nil or empty when -data-ciphers
// was not given) the way site.Options.Cipher should show it: the resolved
// allow-list, colon-joined, or defaultDataCiphersDisplay when the flag was
// left unset. This mirrors ovpn.Config.DataCiphers' own "nil resolves to
// the library's default pair" semantics for display purposes only — it
// does not itself validate or canonicalize names, that is Serve's job.
func dataCiphersDisplay(dataCiphers []string) string {
	if len(dataCiphers) == 0 {
		return defaultDataCiphersDisplay
	}
	return strings.Join(dataCiphers, ":")
}

func run(pkiDir, listenAddr string, deadline time.Duration, dropRatePct, reorderRatePct float64, reorderDelay time.Duration, seed int64, httpPort, udpPort uint16, renegSec, hold time.Duration, noClientCert bool, authUserPass string, dataCiphers []string) error {
	tlsCfg, tlsCryptKey, err := loadConfig(pkiDir, noClientCert)
	if err != nil {
		return fmt.Errorf("load PKI material: %w", err)
	}

	// authUserPassHook (quick 260908-m4e): empty (every pre-existing
	// scenario's default flag value) means Config.AuthUserPass stays nil —
	// unchanged behaviour, credentials parsed and ignored. When set, splits
	// on the FIRST ':' only (a password may itself contain colons) and
	// compares with crypto/subtle.ConstantTimeCompare on both fields; the
	// client is never told which field was wrong.
	var authUserPassHook func(username, password string, cs tls.ConnectionState) error
	if authUserPass != "" {
		idx := strings.IndexByte(authUserPass, ':')
		if idx < 0 {
			return fmt.Errorf("-auth-user-pass %q must be \"user:pass\" (missing ':')", authUserPass)
		}
		wantUser, wantPass := authUserPass[:idx], authUserPass[idx+1:]
		authUserPassHook = func(username, password string, _ tls.ConnectionState) error {
			userOK := subtle.ConstantTimeCompare([]byte(username), []byte(wantUser)) == 1
			passOK := subtle.ConstantTimeCompare([]byte(password), []byte(wantPass)) == 1
			if userOK && passOK {
				log.Printf("auth ok user=%s", username)
				return nil
			}
			log.Printf("auth rejected user=%s", username)
			return errors.New("invalid credentials")
		}
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

	// stack is this harness's netstack.Stack, terminating the same
	// server tunnel IP ippool.go reserves (base+1, the first host
	// address) and entrypoint.sh pings as TUNNEL_SERVER_IP. Built once,
	// before Serve starts, so it's ready the instant the first session's
	// OnSession fires. Phase 3's NET-03: the ICMP echo responder now
	// lives in netstack, not in this harness.
	stack, err := netstack.New(firstHostIP(tunnelNetwork))
	if err != nil {
		return fmt.Errorf("create netstack: %w", err)
	}
	defer stack.Close()

	// The harness serves the same examples/tunnelweb/site pages a developer
	// loads in a browser (03-06-PLAN.md Task 1) — no markup is duplicated
	// into the harness, so a curl content-marker assertion checks the page
	// that actually shipped. ListenTCP is created before srv.Serve starts
	// (below) so a client that connects instantly cannot race the listener
	// into existence.
	httpLn, err := stack.ListenTCP(httpPort)
	if err != nil {
		return fmt.Errorf("listen tcp %d over netstack: %w", httpPort, err)
	}
	defer httpLn.Close()

	var httpRequests atomic.Int64
	instrumented := newRequestCountingHandler(site.Handler(site.Options{
		// Cipher (05-04-PLAN.md Task 1): the resolved -data-ciphers
		// allow-list, not a fixed literal — site.Options.Cipher is a
		// process-wide value constructed before any session exists, so it
		// names what the server is WILLING to negotiate, not what one
		// session actually negotiated (reshaping the site package for
		// per-session display is out of this phase's scope).
		Cipher:    dataCiphersDisplay(dataCiphers),
		StartedAt: time.Now(),
	}), &httpRequests)
	// WR-02: an *http.Server with explicit timeouts, not the bare
	// http.Serve(httpLn, instrumented) this harness previously used —
	// http.Serve has no way to set them at all, so a slow/stalled client
	// (deliberately, given -drop-rate/-reorder-rate above, or just
	// misbehaving) could tie up a goroutine here indefinitely. Mirrors the
	// same fix applied to examples/tunnelweb/main.go, the harness's own
	// non-test analog.
	httpSrv := newHardenedHTTPServer(instrumented)
	go func() {
		if serveErr := httpSrv.Serve(httpLn); serveErr != nil {
			log.Printf("tunnelweb http.Serve exited: %v", serveErr)
		}
	}()

	// A UDP echo service over the same netstack (03-06-PLAN.md Task 2):
	// entrypoint.sh's udp_echo probe sends a fixed payload to
	// (TUNNEL_SERVER_IP, udpPort) via `nc -u` and expects it echoed back
	// (prefixed with udpEchoMarker so the client can distinguish a real
	// echo from its own transmitted bytes). Opened before srv.Serve starts,
	// same race-avoidance reasoning as httpLn above.
	udpConn, err := stack.ListenUDP(udpPort)
	if err != nil {
		return fmt.Errorf("listen udp %d over netstack: %w", udpPort, err)
	}
	defer udpConn.Close()

	var udpRx, udpTx atomic.Int64
	go runUDPEcho(udpConn, &udpRx, &udpTx)

	// establishedSession bundles the session-open timestamp and its
	// sessionCloseObserver alongside the *ovpn.Session itself (04-03-PLAN.md
	// Task 3), so the single value sent over sessions carries everything
	// run()'s post-handshake logic needs to compute exit_notify_close_after=.
	type establishedSession struct {
		sess     *ovpn.Session
		obs      *sessionCloseObserver
		openedAt time.Time
	}
	sessions := make(chan establishedSession, 1)
	srv := ovpn.NewServer(ovpn.Config{
		TLSConfig:   tlsCfg,
		TLSCryptKey: tlsCryptKey,
		Network:     tunnelNetwork,
		// DataCiphers (05-04-PLAN.md Task 1): the resolved -data-ciphers
		// allow-list, nil when the flag was unset — resolving to the
		// library's own default AES-256-GCM/AES-128-GCM pair, exactly what
		// the old fixed Cipher: "AES-256-GCM" resolved to for every
		// pre-existing scenario. Cipher is deliberately dropped here so a
		// scenario that passes -data-ciphers can only be exercising
		// Config.DataCiphers, never silently falling back to the
		// compatibility shorthand (T-05-23).
		DataCiphers: dataCiphers,
		// RenegSec (04-03-PLAN.md Task 1): 0 (every pre-existing scenario's
		// default flag value) means the library's own 3600s default — this
		// only shortens the server's own reneg-sec timer for the "reneg"
		// scenario's -reneg-sec flag.
		RenegSec: renegSec,
		// AuthUserPass (quick 260908-m4e): nil unless -auth-user-pass was
		// given — required by ovpn.Server.Serve's own D-07 guard whenever
		// -no-client-cert leaves ClientAuth below RequireAnyClientCert.
		AuthUserPass: authUserPassHook,
		Logger:       interopLogger(),
		OnSession: func(sess *ovpn.Session) {
			// D-02: the embedder attaches; nothing in ovpn.Config knows
			// the netstack exists. AssignedIP() is guaranteed non-nil
			// here (D-08: OnSession only fires after the PUSH_REQUEST/
			// PUSH_REPLY exchange has already completed).
			//
			// closeObs wraps sess purely to time WHEN netstack's own
			// single read-loop goroutine (Attach's documented one-reader
			// contract) observes sess.Read returning a non-nil error —
			// the client's explicit-exit-notify closing the session via
			// Session.Close (04-03-PLAN.md Task 3). It changes no
			// behavior: every call is forwarded to sess unchanged.
			closeObs := newSessionCloseObserver(sess)
			if err := stack.Attach(closeObs, sess.AssignedIP()); err != nil {
				log.Printf("warning: netstack attach failed for %s: %v", sess.AssignedIP(), err)
			}
			select {
			case sessions <- establishedSession{sess: sess, obs: closeObs, openedAt: time.Now()}:
			default:
				// Only the first session matters for this harness run.
			}
		},
	})

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(obs) }()

	select {
	case es := <-sessions:
		sess := es.sess
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

		// Stay up past the handshake: the real client sends its Key
		// Method 2 payload as TLS application data immediately after its
		// own handshake completes (RESEARCH Pitfall 5); the server must
		// not error, close, or reset on it. The window itself is
		// probe-driven (03-06-PLAN.md Task 2, see waitForProbes) rather
		// than a fixed sleep: it ends as soon as at least one ICMP echo,
		// one UDP datagram, and one HTTP request have all been observed
		// (proving post-handshake traffic doesn't disturb the session),
		// or when postHandshakeSurvival's ceiling elapses, whichever comes
		// first.
		// assertHandshakeCompleted (interop_test.go) asserts on the literal
		// word "surviving" appearing somewhere in this output — kept here
		// even though the window is now probe-driven, not fixed, so that
		// pre-existing Phase 1/2 assertion stays green unchanged.
		log.Printf("surviving the post-handshake window (probe-driven; %s is a ceiling, not the normal path) — waiting for the ICMP, UDP, and HTTP probes to be observed to prove post-handshake TLS application data doesn't disturb the session", postHandshakeSurvival)
		if err := waitForProbes(serveErr, stack, &udpRx, &httpRequests); err != nil {
			return err
		}

		// -hold (04-03-PLAN.md Task 1) / session-close observation
		// (04-03-PLAN.md Task 3): a SINGLE reactive survival-extension loop
		// past waitForProbes' own normal trigger, ending on WHICHEVER of
		// two conditions comes first — -hold's own deadline elapsing
		// (default 0, so every pre-existing scenario is unaffected and
		// this loop exits immediately, same as before -hold existed), or
		// es.obs.observedClose() reporting the session already closed.
		//
		// This is a bug fix discovered running this plan's own "reneg"
		// scenario for real (Rule 1): an EARLIER version slept the FULL
		// -hold duration UNCONDITIONALLY, then only afterward checked for
		// a close. Because docker compose's --abort-on-container-exit
		// tears the WHOLE run down the instant ANY container exits — and
		// the real client's own explicit-exit-notify makes IT exit within
		// a couple of seconds of the graceful stop, long before a 60-second
		// -hold sleep would ever complete — the client's own early exit
		// killed the server mid-sleep every time, before it ever reached
		// the close-check at all. Checking observedClose() on every poll
		// tick, not just once after the full sleep, lets the server react
		// and exit (printing PASS) within one poll interval of the close —
		// comfortably before the client's own explicit-exit-notify timer
		// (which keeps repeating OCC_EXIT for its own configured N seconds
		// before self-terminating) — so the SERVER's own exit is what
		// triggers the abort, exactly as --exit-code-from server intends,
		// rather than racing the client's.
		if hold > 0 {
			log.Printf("holding an additional %s past the probe-driven trigger (-hold), or until the session close is observed, whichever comes first", hold)
			holdDeadline := time.After(hold)
			holdTicker := time.NewTicker(probePollInterval)
		holdLoop:
			for {
				if _, closed := es.obs.observedClose(); closed {
					break holdLoop
				}
				select {
				case err := <-serveErr:
					holdTicker.Stop()
					return fmt.Errorf("Serve exited unexpectedly during the -hold survival extension: %v", err)
				case <-holdDeadline:
					break holdLoop
				case <-holdTicker.C:
				}
			}
			holdTicker.Stop()
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
		// netStats sources the PASS line's ping_rx=/ping_tx= fields from
		// the netstack's own ICMP counters (NET-03) rather than
		// harness-local counters — interop_test.go's pingRxTxRe/
		// assertPingRoundTrip keep working unchanged.
		netStats := stack.Stats()

		// exitNotifyField (04-03-PLAN.md Task 3) is appended to the PASS
		// line only when the close was actually observed — every
		// pre-existing scenario (and the "reneg" scenario's own probe
		// rounds, before its final graceful stop) never triggers this, so
		// the field is simply absent there, exactly as before this task.
		// The distinct close_observed_epoch=/opened_at_epoch= log line
		// (an absolute Unix-second timestamp, comparable across
		// containers sharing the host clock) is what
		// interop_test.go's assertExitNotifyClosesPromptly diffs against
		// entrypoint.sh's own exit_notify_stop_issued epoch= field — the
		// PASS line's own exit_notify_close_after= is a simpler,
		// self-contained (session-open-to-close) duration for a human
		// reading this log, not itself the cross-process proof.
		var exitNotifyField string
		if closedAt, closed := es.obs.observedClose(); closed {
			log.Printf(
				"session close observed (Read returned io.EOF) opened_at_epoch=%d close_observed_epoch=%d",
				es.openedAt.Unix(), closedAt.Unix(),
			)
			exitNotifyField = fmt.Sprintf(" exit_notify_close_after=%s", closedAt.Sub(es.openedAt).Round(time.Millisecond))
		}

		// data_cipher= (05-04-PLAN.md Task 1) reads sess.Cipher() — the
		// per-session NEGOTIATED data-channel cipher — distinct from the
		// pre-existing cipher_suite= field above it, which is the
		// control-channel TLS handshake's own cipher suite. Appended after
		// the pre-existing renegotiations= field and before the optional
		// exit_notify_close_after= field, so every pre-existing field keeps
		// its exact position.
		log.Printf(
			"PASS: session established and stable %s past handshake completion; peer_cn=%s tls_version=%s tls_version_raw=0x%04x cipher_suite=%s km2=ok push_request=%s assigned_ip=%s peer_id=%d ping_rx=%d ping_tx=%d udp_rx=%d udp_tx=%d http_requests=%d renegotiations=%d data_cipher=%s%s",
			postHandshakeSurvival, sess.PeerCN, tls.VersionName(state.Version), state.Version, tls.CipherSuiteName(state.CipherSuite), pushStatus, sess.AssignedIP(), sess.PeerID(),
			netStats.ICMPEchoRequests, netStats.ICMPEchoReplies, udpRx.Load(), udpTx.Load(), httpRequests.Load(), sess.RenegotiationCount(), sess.Cipher(), exitNotifyField,
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

// soakPollInterval is how often runSoak polls each open session's own
// sessionCloseObserver for its close, and how often it would otherwise be
// checking cycle-completion state (04-04-PLAN.md Task 1) — the same
// granularity 04-03-PLAN.md Task 3's -hold reactive loop already
// established for detecting a session close promptly without adding a
// second concurrent reader of the underlying *ovpn.Session (Session.Read's
// documented single-reader contract).
const soakPollInterval = 200 * time.Millisecond

// soakSampleSettleDelay is given before EVERY goroutine/heap sample this
// soak run takes (04-04-PLAN.md Task 2) — both the baseline, taken
// immediately after cycle 1's session is observed closed, and the final
// sample, taken after the last configured cycle's session is observed
// closed. A goroutine that is exiting (its stopCh case has already fired)
// but has not yet been descheduled by the Go runtime must not be
// miscounted as still alive: 250ms is comfortably longer than
// soakPollInterval's own close-detection granularity, giving every
// per-session goroutine (04-02-SUMMARY.md's own enumerated pump,
// keepalive, reneg/expiry ticker, reaper, and any lame-duck Conn
// retransmit loop) time to actually finish unwinding before
// runtime.NumGoroutine reads the count.
const soakSampleSettleDelay = 250 * time.Millisecond

// soakSample is one point-in-time reading of runtime.NumGoroutine and
// runtime.ReadMemStats' HeapAlloc (04-04-PLAN.md Task 2) — the two flatness
// properties this soak run exists to prove hold across many real
// connect/use/clean-disconnect cycles.
type soakSample struct {
	goroutines int
	heapAlloc  uint64
}

// takeSoakSample waits soakSampleSettleDelay, forces two full garbage
// collections — a single runtime.GC() call is not guaranteed to reclaim in
// the same pass memory that only becomes unreachable during that
// collection's OWN finalization, so a second call accounts for exactly
// that case — then reads runtime.NumGoroutine() and
// runtime.ReadMemStats().HeapAlloc.
func takeSoakSample() soakSample {
	time.Sleep(soakSampleSettleDelay)
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return soakSample{goroutines: runtime.NumGoroutine(), heapAlloc: m.HeapAlloc}
}

// soakTracker counts cycles opened/closed during a soak run and records
// each cycle's assigned tunnel IP in close order, so runSoak's PASS line
// can report soak_cycles_observed= and feed the pool-reuse assertion
// something to parse (04-04-PLAN.md Task 2). A session's close is detected
// by polling its own sessionCloseObserver (04-03-PLAN.md Task 3's own
// precedent), never by adding a second reader of the *ovpn.Session.
type soakTracker struct {
	cycles int

	mu     sync.Mutex
	opens  int
	closes int
	ips    []string

	// firstClosed and allClosed each close exactly once: firstClosed the
	// moment the FIRST cycle's session is observed closed — the baseline-
	// sampling trigger (04-04-PLAN.md Task 2). Baseline is deliberately
	// never sampled at process start: a cold-start baseline would hide the
	// first session's own lazily-initialized runtime state (listeners,
	// buffers, pools) and make ordinary warm-up look like a leak.
	// allClosed closes once every configured cycle has been observed
	// closed — this soak's own survival condition, in place of run()'s
	// probe-driven waitForProbes.
	firstClosed chan struct{}
	allClosed   chan struct{}
}

func newSoakTracker(cycles int) *soakTracker {
	return &soakTracker{cycles: cycles, firstClosed: make(chan struct{}), allClosed: make(chan struct{})}
}

// opened records a newly-established session and returns its 1-based
// cycle number.
func (s *soakTracker) opened() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opens++
	return s.opens
}

func (s *soakTracker) openedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opens
}

func (s *soakTracker) closedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

// ipHistory returns the assigned tunnel IPs in the order each cycle's
// session was observed CLOSED (not opened) — the order 04-04-PLAN.md
// Task 2's pool-reuse assertion cares about, since it is Close releasing
// the IP back to the pool that this soak run exists to prove.
func (s *soakTracker) ipHistory() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ips...)
}

// watchClose polls obs until this cycle's session close is observed, then
// records it — appending the assigned IP to ips and, once every configured
// cycle has been observed closed, closing allClosed exactly once (a second
// close of an already-closed channel would panic, so this path only runs
// once per soak run by construction: s.closes only ever increments here,
// under s.mu, and the done/isFirst checks happen in the same critical
// section as the increment that could make either true). firstClosed is
// likewise closed exactly once, the moment the very first cycle's session
// is observed closed.
func (s *soakTracker) watchClose(cycleNum int, obs *sessionCloseObserver) {
	ticker := time.NewTicker(soakPollInterval)
	defer ticker.Stop()
	for range ticker.C {
		if _, closed := obs.observedClose(); closed {
			ip := obs.sess.AssignedIP().String()

			s.mu.Lock()
			s.closes++
			s.ips = append(s.ips, ip)
			isFirst := s.closes == 1
			done := s.closes == s.cycles
			s.mu.Unlock()

			log.Printf("soak cycle %d/%d: session closed (Read observed io.EOF) assigned_ip=%s", cycleNum, s.cycles, ip)

			if isFirst {
				close(s.firstClosed)
			}
			if done {
				close(s.allClosed)
			}
			return
		}
	}
}

// runSoak is the harness's soak-mode entry point (04-04-PLAN.md Task 1):
// instead of run()'s single OnSession firing once against a probe-driven
// survival window, the server's survival condition becomes "cycles
// sessions have been opened and subsequently observed closed" — proving
// that dead sessions do not accumulate across many real connect/use/clean-
// disconnect cycles from ONE long-lived server process (ROADMAP Phase 4
// success criterion 3). run() above is left completely untouched; every
// non-soak scenario's behavior is unaffected by this function's existence.
func runSoak(pkiDir, listenAddr string, deadline time.Duration, httpPort, udpPort uint16, cycles int, dataCiphers []string) error {
	// The soak scenario is not part of quick 260908-m4e's scope — always
	// require a client certificate, exactly as before.
	tlsCfg, tlsCryptKey, err := loadConfig(pkiDir, false)
	if err != nil {
		return fmt.Errorf("load PKI material: %w", err)
	}

	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", listenAddr, err)
	}
	obs := newObservingConn(pc)

	// The same throwaway tunnel-IP range run() uses (02-02-PLAN.md D-01):
	// whatever the server pushes here is exactly what each cycle's client
	// tun interface ends up configured with, and — because Close releases
	// the allocation back to the pool (WR-04) — is exactly what Task 2's
	// pool-reuse assertion expects to see repeat across cycles rather than
	// climb.
	_, tunnelNetwork, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		return fmt.Errorf("parse tunnel network: %w", err)
	}

	stack, err := netstack.New(firstHostIP(tunnelNetwork))
	if err != nil {
		return fmt.Errorf("create netstack: %w", err)
	}
	defer stack.Close()

	httpLn, err := stack.ListenTCP(httpPort)
	if err != nil {
		return fmt.Errorf("listen tcp %d over netstack: %w", httpPort, err)
	}
	defer httpLn.Close()

	var httpRequests atomic.Int64
	instrumented := newRequestCountingHandler(site.Handler(site.Options{
		// Cipher: same reasoning as run()'s own site.Options construction
		// above (05-04-PLAN.md Task 1) — the resolved allow-list, not a
		// fixed literal.
		Cipher:    dataCiphersDisplay(dataCiphers),
		StartedAt: time.Now(),
	}), &httpRequests)
	httpSrv := newHardenedHTTPServer(instrumented)
	go func() {
		if serveErr := httpSrv.Serve(httpLn); serveErr != nil {
			log.Printf("soak: tunnelweb http.Serve exited: %v", serveErr)
		}
	}()

	udpConn, err := stack.ListenUDP(udpPort)
	if err != nil {
		return fmt.Errorf("listen udp %d over netstack: %w", udpPort, err)
	}
	defer udpConn.Close()
	var udpRx, udpTx atomic.Int64
	go runUDPEcho(udpConn, &udpRx, &udpTx)

	tracker := newSoakTracker(cycles)

	// baseline is sampled AFTER cycle 1's session is observed closed
	// (04-04-PLAN.md Task 2), asynchronously so it doesn't block cycle 2
	// from starting — the client's own cycle loop paces cycles far apart
	// enough (a full openvpn client restart) that this sample completes
	// long before it would otherwise matter.
	var baseline soakSample
	baselineReady := make(chan struct{})
	go func() {
		<-tracker.firstClosed
		baseline = takeSoakSample()
		log.Printf("soak baseline sampled after cycle 1: soak_goroutines_baseline=%d soak_heap_baseline=%d", baseline.goroutines, baseline.heapAlloc)
		close(baselineReady)
	}()

	srv := ovpn.NewServer(ovpn.Config{
		TLSConfig:   tlsCfg,
		TLSCryptKey: tlsCryptKey,
		Network:     tunnelNetwork,
		// DataCiphers: same reasoning as run()'s own ovpn.Config
		// construction above (05-04-PLAN.md Task 1) — Cipher dropped
		// entirely, DataCiphers carries the resolved allow-list (nil
		// resolves to the library's default pair).
		DataCiphers: dataCiphers,
		Logger:      interopLogger(),
		OnSession: func(sess *ovpn.Session) {
			cycleNum := tracker.opened()
			log.Printf("soak cycle %d/%d: session established assigned_ip=%s peer_id=%d", cycleNum, cycles, sess.AssignedIP(), sess.PeerID())

			// closeObs wraps sess purely to time when netstack's own single
			// read-loop goroutine (Attach's documented one-reader contract)
			// observes Read returning a non-nil error — this cycle's client
			// explicit-exit-notify closing the session (04-03-PLAN.md
			// Task 3's own precedent, reused verbatim here).
			closeObs := newSessionCloseObserver(sess)
			if err := stack.Attach(closeObs, sess.AssignedIP()); err != nil {
				log.Printf("warning: soak cycle %d: netstack attach failed for %s: %v", cycleNum, sess.AssignedIP(), err)
			}

			go tracker.watchClose(cycleNum, closeObs)
		},
	})

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(obs) }()

	select {
	case err := <-serveErr:
		return fmt.Errorf("Serve exited unexpectedly during the soak run: %v", err)
	case <-tracker.allClosed:
		// Every configured cycle's session was observed opened and then
		// closed — the soak's own survival condition (04-04-PLAN.md Task 1),
		// in place of run()'s probe-driven waitForProbes.
	case <-time.After(deadline):
		_ = srv.Close()
		<-serveErr
		return fmt.Errorf(
			"soak timed out after %s waiting for %d cycles to complete; observed %d opened, %d closed",
			deadline, cycles, tracker.openedCount(), tracker.closedCount(),
		)
	}

	// baselineReady is guaranteed already closed by this point: cycle 1
	// always closes strictly before the last configured cycle does (the
	// client's own cycle loop runs one connect/disconnect at a time, never
	// concurrently), so tracker.allClosed firing implies tracker.firstClosed
	// fired first. The receive below is therefore non-blocking in practice;
	// it exists for correctness (happens-before on baseline), not to wait.
	<-baselineReady
	final := takeSoakSample()
	log.Printf("soak final sample: soak_goroutines_final=%d soak_heap_final=%d", final.goroutines, final.heapAlloc)

	ips := tracker.ipHistory()
	log.Printf(
		"PASS: soak completed soak_cycles_observed=%d soak_goroutines_baseline=%d soak_goroutines_final=%d soak_heap_baseline=%d soak_heap_final=%d soak_ips=%s http_requests=%d udp_rx=%d udp_tx=%d",
		tracker.closedCount(), baseline.goroutines, final.goroutines, baseline.heapAlloc, final.heapAlloc, strings.Join(ips, ","), httpRequests.Load(), udpRx.Load(), udpTx.Load(),
	)

	_ = srv.Close()
	<-serveErr
	return nil
}

// waitForProbes blocks until all three probe classes (ICMP echo, UDP
// datagram, HTTP request) have each been observed at least once — then
// waits probeSettleDelay so an in-flight response finishes — or until
// postHandshakeSurvival's ceiling elapses, whichever comes first
// (03-06-PLAN.md Task 2). It also keeps watching serveErr throughout, so a
// Serve goroutine that dies during the window is reported as the failure
// it is, not silently treated as a probe timeout — the same behavior the
// fixed-sleep select it replaces already had.
func waitForProbes(serveErr <-chan error, stack *netstack.Stack, udpRx, httpRequests *atomic.Int64) error {
	deadline := time.After(postHandshakeSurvival)
	ticker := time.NewTicker(probePollInterval)
	defer ticker.Stop()

	for {
		select {
		case err := <-serveErr:
			return fmt.Errorf("Serve exited unexpectedly during the post-handshake survival window: %v", err)
		case <-deadline:
			return nil
		case <-ticker.C:
			st := stack.Stats()
			if st.ICMPEchoReplies > 0 && udpRx.Load() > 0 && httpRequests.Load() > 0 {
				time.Sleep(probeSettleDelay)
				return nil
			}
		}
	}
}

// udpEchoMarker prefixes every echoed UDP payload so entrypoint.sh's
// udp_echo probe can distinguish a real echo — round-tripped through the
// netstack's UDP demux and this goroutine — from its own transmitted bytes
// somehow arriving back via an unrelated path.
const udpEchoMarker = "govpn-udp-echo:"

// maxUDPEchoPayload is comfortably larger than any probe payload
// entrypoint.sh sends: net.PacketConn.ReadFrom truncates an oversized
// datagram rather than retaining it (silently corrupting the echo), so this
// buffer must never be undersized for a legitimate probe.
const maxUDPEchoPayload = 2048

// runUDPEcho loops on conn.ReadFrom, echoing the received payload back
// prefixed with udpEchoMarker via conn.WriteTo, and counting received/sent
// datagrams in udpRx/udpTx — which feed the PASS line's udp_rx=/udp_tx=
// fields and waitForProbes' probe-driven survival window. Returns once conn
// is closed (ReadFrom then returns a non-nil error).
func runUDPEcho(conn net.PacketConn, udpRx, udpTx *atomic.Int64) {
	buf := make([]byte, maxUDPEchoPayload)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		udpRx.Add(1)

		reply := append([]byte(udpEchoMarker), buf[:n]...)
		if _, err := conn.WriteTo(reply, addr); err == nil {
			udpTx.Add(1)
		}
	}
}

func loadConfig(pkiDir string, noClientCert bool) (*tls.Config, []byte, error) {
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

	// clientAuth (quick 260908-m4e): the one place that decides this
	// server's client-certificate posture, so buildTLSConfig's caller never
	// needs to mutate the returned *tls.Config afterward. ClientCAs stays
	// populated either way — it is simply unused when noClientCert is set.
	clientAuth := tls.RequireAndVerifyClientCert
	if noClientCert {
		clientAuth = tls.NoClientCert
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   clientAuth,
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

// sessionCloseObserver wraps an *ovpn.Session purely to record WHEN
// netstack's own single read-loop goroutine (Stack.Attach's documented
// one-reader-per-attachment contract) observes Read returning a non-nil
// error — the sole detach trigger (netstack's own D-02), and the moment a
// real client's explicit-exit-notify (or any other teardown cause) actually
// closed this session (04-03-PLAN.md Task 3). It changes no behavior: every
// Read/Write/Close call is forwarded to the underlying Session unchanged,
// and — because Attach starts EXACTLY one reader goroutine for whatever
// netstack.Session it is given — wrapping sess here does not add a second
// concurrent reader of the real *ovpn.Session, preserving Session.Read's own
// documented single-reader-goroutine contract.
type sessionCloseObserver struct {
	sess *ovpn.Session

	mu       sync.Mutex
	closedAt time.Time
	closed   bool
}

func newSessionCloseObserver(sess *ovpn.Session) *sessionCloseObserver {
	return &sessionCloseObserver{sess: sess}
}

func (o *sessionCloseObserver) Read(p []byte) (int, error) {
	n, err := o.sess.Read(p)
	if err != nil {
		o.mu.Lock()
		if !o.closed {
			o.closed = true
			o.closedAt = time.Now()
		}
		o.mu.Unlock()
	}
	return n, err
}

func (o *sessionCloseObserver) Write(p []byte) (int, error) {
	return o.sess.Write(p)
}

func (o *sessionCloseObserver) Close() error {
	return o.sess.Close()
}

// observedClose reports whether this session's Read loop has observed a
// close yet, and if so, when — safe to call repeatedly and concurrently
// with Read (guarded by its own mutex), unlike draining a one-shot channel.
func (o *sessionCloseObserver) observedClose() (time.Time, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closedAt, o.closed
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

// statusCapturingResponseWriter wraps an http.ResponseWriter purely to
// observe the status code a handler wrote, so the per-request log line
// (below) reports it — WriteHeader is not otherwise observable from outside
// net/http.
type statusCapturingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCapturingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// newRequestCountingHandler wraps h in a small middleware that increments
// reqCount on every request and logs one line per request with method,
// path, and status (03-06-PLAN.md Task 1) — the counter feeds the PASS
// line's http_requests= field, and the log lines are what a human reads
// first when a probe fails.
func newRequestCountingHandler(h http.Handler, reqCount *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		sw := &statusCapturingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		log.Printf("http %s %s -> %d", r.Method, r.URL.Path, sw.status)
	})
}

// firstHostIP returns network's first host address (base+1) — the same
// value ippool.go's own serverIP reserves for the library's server-side
// tunnel address and entrypoint.sh pings as TUNNEL_SERVER_IP. Computed
// generically over the network's flattened uint32 host-address space
// (mirroring ippool.go's own arithmetic, ippool.go:99-104) rather than
// assuming a specific prefix length.
func firstHostIP(network *net.IPNet) net.IP {
	ip4 := network.IP.To4()
	base := binary.BigEndian.Uint32(ip4)
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, base+1)
	return ip
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
// key/implicit-IV material (keyderiv.Key2.ServerSlots), read back by
// test/interop/golden_export.go and internal/datachan/golden_test.go to
// independently open/re-seal a captured session's P_DATA_V2 traffic
// (02-04-PLAN.md Task 2). The four hex fields always encode the FULL
// 32-byte key-expansion slot, regardless of Cipher/CipherKeyLen: the
// underlying slot is always 64 bytes wide (32 bytes cipher key + 32 bytes
// HMAC key) no matter which data-channel cipher was negotiated, and
// truncating the hex string to CipherKeyLen bytes for an AES-128-GCM
// session would break the fixed-width decoding golden_export.go and
// golden_test.go's hexDecodeFixed both depend on. Only the new
// Cipher/CipherKeyLen fields (05-04-PLAN.md Task 1) tell the reading side
// how many of those 32 bytes the AEAD construction actually uses.
type dataChannelKeyExport struct {
	EncryptCipher     string `json:"encrypt_cipher"`
	EncryptImplicitIV string `json:"encrypt_implicit_iv"`
	DecryptCipher     string `json:"decrypt_cipher"`
	DecryptImplicitIV string `json:"decrypt_implicit_iv"`

	// Cipher and CipherKeyLen (05-04-PLAN.md Task 1) record the negotiated
	// data-channel cipher (sess.Cipher()) and its AEAD key length in bytes
	// (keys.CipherKeyLen — 16 or 32), so plan 05-05's golden vectors know
	// which cipher a captured session's key material was actually derived
	// for, without guessing from the scenario name alone.
	Cipher       string `json:"cipher"`
	CipherKeyLen int    `json:"cipher_key_len"`
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
		Cipher:            sess.Cipher(),
		CipherKeyLen:      keys.CipherKeyLen,
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
