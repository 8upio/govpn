//go:build interop

// Package interop holds the Docker-based end-to-end harness: it drives a
// real, unmodified OpenVPN 2.6 client against a Go process embedding
// github.com/8upio/govpn. It is excluded from the fast `go test ./...` tier
// by this file's build tag; run it via `make interop` or
// `go test -tags interop ./test/interop/...`.
package interop

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// updateGolden regenerates testdata/golden from this run's clean-large
// scenario capture (01-04-PLAN.md Task 2) — a deliberate act via
// `make golden` / `go test -tags interop -run TestInteropScenarios
// -update-golden ./test/interop/`, never a side effect of an ordinary
// `make interop` run.
var updateGolden = flag.Bool("update-golden", false, "regenerate testdata/golden from this run's clean-large scenario capture")

// scenario names one docker-compose-driven interop run: which certificate
// profile cmd/gentestpki should generate, whether the lossy overlay
// (docker-compose.lossy.yml) applies, and how long to allow the whole
// `docker compose up` to run before giving up.
type scenario struct {
	name           string
	profile        string
	lossy          bool
	largeCert      bool
	contextTimeout time.Duration

	// composeOverlay (04-03-PLAN.md Task 1) names an extra docker-compose
	// overlay file (e.g. "docker-compose.lossy.yml", "docker-compose.reneg.yml")
	// to layer on top of docker-compose.yml, replacing the old
	// lossy-boolean-only overlay selection so a scenario can pick an overlay
	// without inheriting loss injection. Empty means no overlay — the
	// clean-small/clean-large scenarios' existing behavior. lossy above is
	// kept as its own field regardless: it drives the probe-strictness
	// convention (assertPingRoundTrip and friends), which is orthogonal to
	// which overlay file happens to be in play.
	composeOverlay string

	// clientDirectives (04-03-PLAN.md Task 1) are extra client.conf lines
	// passed through to cmd/gentestpki via repeated -client-directive flags.
	// nil for every pre-existing scenario, so their generated client.conf
	// stays byte-identical to before this field existed.
	clientDirectives []string

	// minRenegotiations (04-03-PLAN.md Task 1/2), when greater than 0,
	// asserts the server's PASS line reports at least this many completed
	// soft-reset rollovers (assertRenegotiation below). 0 (every
	// pre-existing scenario) skips the assertion entirely.
	minRenegotiations int
}

// scenarios covers, at minimum, the clean-small/clean-large/lossy-large
// table 01-04-PLAN.md Task 1 requires. contextTimeout values are sized
// generously against the reference's own 60-second handshake window
// (RESEARCH Pattern 3) rather than tuned to one observed run's timing —
// lossy-large's is intentionally the largest, since retransmission under
// loss is exactly what it needs room for.
// contextTimeout values are raised over 01-04-PLAN.md's originals
// (2/3/8 minutes) by 03-06-PLAN.md Task 1 to absorb the new HTTP/UDP/
// negative probes this plan adds after the existing ping: these are outer
// bounds on a context.WithTimeout, not sleeps, so raising them costs
// nothing on a passing run and only prevents a slow CI machine's timeout
// from looking like a protocol failure.
// The "reneg" scenario (04-03-PLAN.md, D-23) proves renegotiation and
// exit-notify against a real client: reneg-sec 15 on both the client
// (via clientDirectives, cmd/gentestpki -client-directive) and the server
// (docker-compose.reneg.yml's -reneg-sec 15s), with -hold giving the
// shortened timer room to actually fire before the server's own
// probe-driven survival window would otherwise let it exit.
var scenarios = []scenario{
	{name: "clean-small", profile: "small", lossy: false, largeCert: false, contextTimeout: 3 * time.Minute},
	{name: "clean-large", profile: "large", lossy: false, largeCert: true, contextTimeout: 4 * time.Minute},
	{name: "lossy-large", profile: "large", lossy: true, largeCert: true, contextTimeout: 10 * time.Minute, composeOverlay: "docker-compose.lossy.yml"},
	{
		name:              "reneg",
		profile:           "small",
		lossy:             false,
		largeCert:         false,
		contextTimeout:    3 * time.Minute,
		composeOverlay:    "docker-compose.reneg.yml",
		clientDirectives:  []string{"reneg-sec 15"},
		minRenegotiations: 1,
	},
}

// scenarioResult is one scenario's completed run: docker compose's combined
// output, its error (nil on a clean exit), and where this scenario's own
// packet capture and tls-crypt key were preserved to (both the pki
// directory and captures/interop.pcap are overwritten by the next
// scenario's run, so each scenario's artifacts are renamed out of the way
// immediately after that scenario's `up` completes).
type scenarioResult struct {
	composeOut     string
	composeErr     error
	capturePath    string
	keyPath        string
	privilegeCheck string // `docker inspect` output, captured while the server container still exists
	dataKeysPath   string // this scenario's own preserved copy of the server's /tmp/datachan-keys.json (02-04-PLAN.md Task 2)
	keyMethod2Path string // this scenario's own preserved copy of the server's /tmp/datachan-km2.json (02-04-PLAN.md Task 2)
}

// scenarioResults is populated once, in TestMain, before any Test function
// runs — see repoRoot's doc comment on why setup lives in TestMain rather
// than in any individual test body.
var scenarioResults = map[string]scenarioResult{}

// repoRoot resolves the module root from this test file's own directory
// (test/interop is always exactly two levels below the repo root).
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(wd, "..", ".."))
}

func TestMain(m *testing.M) {
	// TestMain must parse flags itself before reading -update-golden below
	// (testing.Main normally parses flags inside m.Run(), too late for
	// TestMain's own use of them).
	flag.Parse()

	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "interop: resolve repo root:", err)
		os.Exit(1)
	}
	interopDir := filepath.Join(root, "test", "interop")

	if err := os.MkdirAll(filepath.Join(interopDir, "captures"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "interop: create captures dir:", err)
		os.Exit(1)
	}

	for _, sc := range scenarios {
		scenarioResults[sc.name] = runScenario(root, interopDir, sc)
	}

	if *updateGolden {
		res := scenarioResults["clean-large"]
		if res.composeErr != nil {
			fmt.Fprintln(os.Stderr, "interop: -update-golden requested but the clean-large scenario did not pass; not regenerating testdata/golden")
			os.Exit(1)
		}
		outDir := filepath.Join(root, "testdata", "golden")
		if err := ExportGolden(res.capturePath, res.keyPath, res.dataKeysPath, res.keyMethod2Path, outDir); err != nil {
			fmt.Fprintln(os.Stderr, "interop: export golden vectors:", err)
			os.Exit(1)
		}
		fmt.Println("interop: testdata/golden regenerated from the clean-large scenario capture at", res.capturePath)
	}

	os.Exit(m.Run())
}

// runScenario regenerates the PKI for sc.profile, preserves the resulting
// tls-crypt key, runs `docker compose up` (with the lossy overlay if
// sc.lossy) to completion or sc.contextTimeout, preserves the resulting
// packet capture under a scenario-specific name (so the next scenario's run
// doesn't overwrite it before it can be inspected), and tears the compose
// project down unconditionally — including on a failing run, so the next
// scenario starts from a clean container/network state.
func runScenario(root, interopDir string, sc scenario) scenarioResult {
	genArgs := []string{"run", "./cmd/gentestpki", "-out", filepath.Join("test", "interop", "pki"), "-profile", sc.profile}
	for _, d := range sc.clientDirectives {
		genArgs = append(genArgs, "-client-directive", d)
	}
	genCmd := exec.Command("go", genArgs...)
	genCmd.Dir = root
	if out, genErr := genCmd.CombinedOutput(); genErr != nil {
		return scenarioResult{composeOut: string(out), composeErr: fmt.Errorf("gentestpki -profile %s: %w", sc.profile, genErr)}
	}

	keyPath := filepath.Join(interopDir, "captures", sc.name+"-tls-crypt.key")
	if cpErr := copyFile(filepath.Join(interopDir, "pki", "tls-crypt.key"), keyPath); cpErr != nil {
		return scenarioResult{composeErr: fmt.Errorf("preserve tls-crypt key for scenario %s: %w", sc.name, cpErr)}
	}

	// composeOverlay (04-03-PLAN.md Task 1) generalizes the old
	// sc.lossy-only overlay selection: a scenario names whichever overlay
	// file it needs (or none), independent of whether it also carries the
	// lossy strictness convention (lossy-large sets both; reneg sets only
	// composeOverlay).
	composeFiles := []string{"-f", "docker-compose.yml"}
	if sc.composeOverlay != "" {
		composeFiles = append(composeFiles, "-f", sc.composeOverlay)
	}

	upArgs := append(append([]string{"compose"}, composeFiles...), "up", "--build", "--abort-on-container-exit", "--exit-code-from", "server")

	ctx, cancel := context.WithTimeout(context.Background(), sc.contextTimeout)
	defer cancel()

	upCmd := exec.CommandContext(ctx, "docker", upArgs...)
	upCmd.Dir = interopDir

	var buf bytes.Buffer
	mw := io.MultiWriter(os.Stdout, &buf)
	upCmd.Stdout = mw
	upCmd.Stderr = mw
	upErr := upCmd.Run()
	composeOut := fmt.Sprintf("=== scenario %s ===\n%s", sc.name, buf.String())

	// The runtime privilege check (T-01-07/T-01-21) must run WHILE the
	// server container still exists — `down` below removes it, and a
	// Test function running later would find nothing left to inspect.
	// This is the harness's own re-run of plan 01-02's check, applied to
	// every scenario including the lossy one, whose decorator is the one
	// piece of loss-injection logic living inside the server process
	// itself (T-01-21).
	privOut, privErr := exec.Command("docker", "inspect",
		"-f", "{{.HostConfig.Privileged}} {{len .HostConfig.CapAdd}} {{len .HostConfig.Devices}}",
		"govpn-interop-server").CombinedOutput()
	privilegeCheck := strings.TrimSpace(string(privOut))
	if privErr != nil {
		privilegeCheck = fmt.Sprintf("docker inspect failed: %v: %s", privErr, privOut)
	}

	capturePath := filepath.Join(interopDir, "captures", sc.name+".pcap")
	src := filepath.Join(interopDir, "captures", "interop.pcap")
	if renameErr := os.Rename(src, capturePath); renameErr != nil {
		if upErr == nil {
			upErr = fmt.Errorf("preserve capture for scenario %s: %w", sc.name, renameErr)
		}
	}

	// Retrieve the server's own data-channel key export and Key Method 2
	// export via `docker cp` — WHILE the container still exists, the same
	// ordering constraint the privilege check above already established
	// (02-04-PLAN.md Task 2). A copy failure is non-fatal to the scenario
	// itself (every scenario writes these; only -update-golden's own
	// clean-large run ever reads them back), so it is logged, not folded
	// into upErr.
	dataKeysPath := filepath.Join(interopDir, "captures", sc.name+"-datachan-keys.json")
	if cpErr := dockerCopyFromContainer("govpn-interop-server", "/tmp/datachan-keys.json", dataKeysPath); cpErr != nil {
		fmt.Fprintf(os.Stderr, "interop: docker cp data-channel key export (%s): %v\n", sc.name, cpErr)
		dataKeysPath = ""
	}
	keyMethod2Path := filepath.Join(interopDir, "captures", sc.name+"-datachan-km2.json")
	if cpErr := dockerCopyFromContainer("govpn-interop-server", "/tmp/datachan-km2.json", keyMethod2Path); cpErr != nil {
		fmt.Fprintf(os.Stderr, "interop: docker cp Key Method 2 export (%s): %v\n", sc.name, cpErr)
		keyMethod2Path = ""
	}

	downArgs := append(append([]string{"compose"}, composeFiles...), "down", "--remove-orphans")
	downCmd := exec.Command("docker", downArgs...)
	downCmd.Dir = interopDir
	if dOut, dErr := downCmd.CombinedOutput(); dErr != nil {
		fmt.Fprintf(os.Stderr, "interop: docker compose down (%s): %v\n%s\n", sc.name, dErr, dOut)
	}

	return scenarioResult{
		composeOut:     composeOut,
		composeErr:     upErr,
		capturePath:    capturePath,
		keyPath:        keyPath,
		privilegeCheck: privilegeCheck,
		dataKeysPath:   dataKeysPath,
		keyMethod2Path: keyMethod2Path,
	}
}

// dockerCopyFromContainer runs `docker cp container:srcPath dstPath`,
// retrieving a file from inside a still-running (or already-stopped but not
// yet removed) container's own filesystem without needing a bind-mounted
// host volume or any particular in-container UID/permission alignment
// (02-04-PLAN.md Task 2).
func dockerCopyFromContainer(container, srcPath, dstPath string) error {
	out, err := exec.Command("docker", "cp", container+":"+srcPath, dstPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker cp %s:%s %s: %w: %s", container, srcPath, dstPath, err, out)
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func readTLSCryptKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return tlscrypt.ParseStaticKeyV1(data)
}

// tlsVersionRawRe extracts the numeric TLS version test/interop/server's
// PASS line prints (tls_version_raw=0xNNNN), so this test can assert
// numerically that the negotiated version is at least TLS 1.2 rather than
// string-matching a version name that could drift with Go's own
// tls.VersionName formatting.
var tlsVersionRawRe = regexp.MustCompile(`tls_version_raw=0x([0-9a-fA-F]{4})`)

// tlsVersion12 is tls.VersionTLS12's numeric value (0x0303), duplicated
// here rather than importing crypto/tls just for one constant.
const tlsVersion12 = 0x0303

// TestInteropScenarios is 01-04-PLAN.md Task 1's verification: a real,
// unmodified OpenVPN 2.6 client completes the full TLS handshake against
// the library across the scenario table above — including a 5-10% lossy,
// reordering link carrying a multi-kilobyte certificate chain fragmented
// over several control packets — without the server container ever gaining
// a privilege it would not have in production.
//
// Every assertion below matches on the generated CommonName strings
// cmd/gentestpki produced (govpn-interop-server / govpn-interop-client)
// rather than on any guessed OpenVPN client log wording — RESEARCH's own
// stated principle for keeping this honest without depending on the real
// client's exact phrasing.
func TestInteropScenarios(t *testing.T) {
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			res, ok := scenarioResults[sc.name]
			if !ok {
				t.Fatalf("no result recorded for scenario %q (TestMain setup failure?)", sc.name)
			}
			t.Log(res.composeOut)

			assertHandshakeCompleted(t, res)
			assertKeyExchangeCompleted(t, res)
			assertTunnelUp(t, res)

			// 02-04-PLAN.md Task 1 (VRFY-03): the ping round-trip proof
			// (the encrypted ping through Session.Read/Write) now runs
			// for every scenario, not only clean-small (02-03-PLAN.md's
			// original scope) — the lossy-large scenario needs it to
			// prove the tunnel itself, not just the handshake, survives
			// a lossy link. The clean scenarios keep the strict
			// zero-loss expectation; the lossy scenario tolerates a
			// dropped echo as a retry rather than a failure, asserting
			// only that at least one reply returned.
			assertPingRoundTrip(t, res, !sc.lossy)

			// 03-06-PLAN.md Task 1 (VRFY-02, XMPL-01 live half): a real
			// client's curl load of the tunnelweb landing page through
			// the tunnel, required on every scenario including the
			// lossy one — the netstack's fixed-RTO retransmission is
			// precisely what should carry a page load across a 5-10%
			// loss link.
			assertHTTPPageLoad(t, res)

			// 03-06-PLAN.md Task 2 (NET-01, VRFY-02): a UDP round trip
			// and the three remaining HTTP subpages, both parameterized
			// by the same !sc.lossy strictness convention
			// assertPingRoundTrip already established — see each
			// function's own doc comment for exactly what is tolerated
			// on the lossy scenario and why.
			assertUDPRoundTrip(t, res, !sc.lossy)
			assertHTTPSubpages(t, res, !sc.lossy)

			// 03-06-PLAN.md Task 3 (ROADMAP Phase 3 success criterion 3):
			// required on every scenario including the lossy one — see
			// the function's own doc comment for why the lossy link has
			// no bearing on this assertion.
			assertUnreachableOutsideTunnel(t, res)

			assertServerStaysUnprivileged(t, res)

			// 04-03-PLAN.md Task 1 (SESS-04 against a real client): the
			// "reneg" scenario's server PASS line must report at least
			// sc.minRenegotiations completed soft-reset rollovers. Every
			// other scenario leaves minRenegotiations at its zero value and
			// skips this assertion entirely.
			if sc.minRenegotiations > 0 {
				assertRenegotiation(t, res, sc.minRenegotiations)
			}

			if sc.largeCert {
				assertCertificateFlightFragmented(t, res)
			}
			if sc.lossy {
				assertLossyLoadFactorsInBand(t)
				logRetransmissionEvidence(t, res)
			}
		})
	}
}

// assertHandshakeCompleted is the completed-handshake condition plan 01-03
// established, applied to every scenario: the server's PASS line printed
// (handshake completed AND survived the post-handshake window), both sides
// report the peer's verified CommonName, and the negotiated TLS version is
// at least 1.2.
func assertHandshakeCompleted(t *testing.T, res scenarioResult) {
	t.Helper()

	if res.composeErr != nil {
		t.Fatalf("docker compose up did not exit cleanly — the server did not observe a completed, stable TLS handshake before its deadline: %v", res.composeErr)
	}

	if !strings.Contains(res.composeOut, "PASS: session established") {
		t.Fatal("server did not print its PASS line (handshake completed AND survived the post-handshake window) — see log above")
	}

	const wantClientCN = "peer_cn=govpn-interop-client"
	if !strings.Contains(res.composeOut, wantClientCN) {
		t.Fatalf("server output does not contain %q — see log above", wantClientCN)
	}

	// The real client's own output contains the SERVER's generated
	// CommonName — the client can only print this after it has parsed and
	// verified the server's certificate chain (Phase 1 success criterion
	// 2), regardless of whether that chain is one hop (small profile) or
	// leaf+intermediate (large profile).
	const wantServerCN = "CN=govpn-interop-server"
	if !strings.Contains(res.composeOut, wantServerCN) {
		t.Fatalf("client output does not contain %q — see log above", wantServerCN)
	}

	m := tlsVersionRawRe.FindStringSubmatch(res.composeOut)
	if m == nil {
		t.Fatal("server output does not contain a parsable tls_version_raw= field — see log above")
	}
	raw, err := strconv.ParseUint(m[1], 16, 16)
	if err != nil {
		t.Fatalf("parse tls_version_raw=%s: %v", m[1], err)
	}
	if raw < tlsVersion12 {
		t.Fatalf("negotiated TLS version 0x%04x is below TLS 1.2 (0x%04x)", raw, tlsVersion12)
	}
	t.Logf("negotiated TLS version: 0x%04x", raw)

	if !strings.Contains(res.composeOut, "surviving") {
		t.Fatal("server output does not show it entered the post-handshake survival window — see log above")
	}
}

// clientKeyNegotiationFailedRe matches the reference client's own
// key-negotiation-timeout log line (ssl.c:2919, "TLS Error: TLS key
// negotiation failed to occur within %d seconds (check your network
// connectivity)") — asserted absent, not present, so a regression that
// silently breaks Key Method 2 for the real client (while still leaving
// the server's own PASS line looking fine) still fails this test.
var clientKeyNegotiationFailedRe = regexp.MustCompile(`TLS key negotiation failed to occur within`)

// assertKeyExchangeCompleted is 02-01-PLAN.md Task 3's verification: a real
// OpenVPN 2.6.14 client's Key Method 2 message parses, the server's own
// message is accepted, and the client proceeds to request its tunnel
// configuration — proven by an assertion in the scenario table, not by
// reading a log by hand. Follows assertHandshakeCompleted's own shape
// (regexp/substring match over the captured combined output, fatal on
// mismatch, no t.Skip).
func assertKeyExchangeCompleted(t *testing.T, res scenarioResult) {
	t.Helper()

	if res.composeErr != nil {
		// assertHandshakeCompleted already fails loudly on this; avoid a
		// second, redundant fatal here obscuring the first.
		return
	}

	if !strings.Contains(res.composeOut, "km2=ok") {
		t.Fatal("server output does not contain \"km2=ok\" — the Key Method 2 exchange did not complete — see log above")
	}
	if !strings.Contains(res.composeOut, "push_request=seen") {
		t.Fatal("server output does not contain \"push_request=seen\" — the real client did not progress past key negotiation to request its tunnel configuration within the post-handshake survival window — see log above")
	}
	if clientKeyNegotiationFailedRe.MatchString(res.composeOut) {
		t.Fatal("client output reports a TLS key negotiation failure — see log above")
	}
}

// assignedIPRe/peerIDRe extract the assigned_ip=/peer_id= fields
// test/interop/server's PASS line carries (02-02-PLAN.md Task 1), so
// assertTunnelUp can check them numerically/textually rather than
// string-matching a whole log line that could drift.
var (
	assignedIPRe = regexp.MustCompile(`assigned_ip=(\d+\.\d+\.\d+\.\d+)`)
	peerIDRe     = regexp.MustCompile(`peer_id=(\d+)`)
)

// initSequenceCompletedRe matches the real client's own success line
// (init.c, unchanged across 2.6.x) — asserted present, not paraphrased.
var initSequenceCompletedRe = regexp.MustCompile(`Initialization Sequence Completed`)

// assertTunnelUp is 02-02-PLAN.md Task 1's verification: a real OpenVPN
// 2.6.14 client requests its configuration, receives a byte-exact
// PUSH_REPLY carrying an address from the server's configured tunnel
// network, and reports Initialization Sequence Completed with its tun
// interface configured with that same address — asserted by the scenario
// table, not read by hand.
func assertTunnelUp(t *testing.T, res scenarioResult) {
	t.Helper()

	if res.composeErr != nil {
		// assertHandshakeCompleted already fails loudly on this; avoid a
		// second, redundant fatal here obscuring the first.
		return
	}

	ipMatch := assignedIPRe.FindStringSubmatch(res.composeOut)
	if ipMatch == nil {
		t.Fatal("server output does not contain a parsable assigned_ip= field — see log above")
	}
	assignedIP := ipMatch[1]

	if peerIDRe.FindStringSubmatch(res.composeOut) == nil {
		t.Fatal("server output does not contain a parsable peer_id= field — see log above")
	}

	if !initSequenceCompletedRe.MatchString(res.composeOut) {
		t.Fatal("client output does not contain \"Initialization Sequence Completed\" — see log above")
	}

	// The server's own PASS line already contains assignedIP once; a
	// second occurrence proves the CLIENT's own log independently names
	// the same address (its own ifconfig/ip-addr tun-configuration line),
	// not just the server's side of the exchange.
	if strings.Count(res.composeOut, assignedIP) < 2 {
		t.Fatalf("assigned tunnel address %s appears only in the server's own PASS line, not in the client's tun interface configuration — see log above", assignedIP)
	}
}

// pingStatsRe matches iputils-ping's own summary line (the client image's
// iputils-ping package, added by 02-03-PLAN.md Task 1 specifically for
// this assertion): "N packets transmitted, M received, L% packet loss".
var pingStatsRe = regexp.MustCompile(`(\d+) packets transmitted, (\d+) received, (\d+)% packet loss`)

// pingRxTxRe extracts the ping_rx=/ping_tx= fields test/interop/server's
// PASS line carries (02-03-PLAN.md Task 1's harness ICMP echo responder,
// test/interop/server/main.go's startICMPResponder).
var pingRxTxRe = regexp.MustCompile(`ping_rx=(\d+) ping_tx=(\d+)`)

// assertPingRoundTrip is 02-03-PLAN.md Task 1's original verification
// (a real OpenVPN 2.6.14 client's ping of the server's own pushed tunnel
// IP, test/interop/entrypoint.sh, run once tun0 is up, round-trips through
// Session.Read/Write, and the server's own harness ICMP responder observed
// and answered at least one such packet), extended by 02-04-PLAN.md Task 1
// (VRFY-03) to run on every scenario, not only clean-small, with the
// zero-loss expectation parameterized by strict: the clean scenarios keep
// the original zero-loss assertion, while the lossy scenario tolerates a
// dropped echo as a retry rather than a failure — asserting only that at
// least one reply returned, since demanding zero loss at 7% synthetic loss
// in both directions would make the test flaky for a reason unrelated to
// correctness. All of this is proven by an assertion in the scenario
// table, never read by hand, and never via a skipped subtest (01-04-SUMMARY.md
// Deviation 2: skipping a subtest silently drops every later
// assertion in it).
func assertPingRoundTrip(t *testing.T, res scenarioResult, strict bool) {
	t.Helper()

	if res.composeErr != nil {
		// assertHandshakeCompleted already fails loudly on this; avoid a
		// second, redundant fatal here obscuring the first.
		return
	}

	m := pingStatsRe.FindStringSubmatch(res.composeOut)
	if m == nil {
		t.Fatal("client output does not contain a parsable ping summary line (\"N packets transmitted, M received, L% packet loss\") — see log above")
	}
	transmitted, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse ping transmitted count %q: %v", m[1], err)
	}
	received, err := strconv.Atoi(m[2])
	if err != nil {
		t.Fatalf("parse ping received count %q: %v", m[2], err)
	}
	lossPct, err := strconv.Atoi(m[3])
	if err != nil {
		t.Fatalf("parse ping loss percentage %q: %v", m[3], err)
	}
	if received == 0 {
		t.Fatalf("client ping received 0 of %d replies from the server's tunnel IP — see log above", transmitted)
	}
	if strict {
		if lossPct != 0 {
			t.Errorf("client ping reported %d%% packet loss on a clean scenario's link, want 0%% — see log above", lossPct)
		}
	} else {
		// Non-fatal evidence that this scenario's synthetic loss actually
		// struck data-channel traffic (mirrors logRetransmissionEvidence's
		// own precedent and rationale for the control channel below): a
		// nonzero loss percentage here is direct evidence the tunnel
		// delivered a reply despite tc netem/lossyPacketConn dropping or
		// reordering some of this ping's own encrypted packets, not merely
		// that the handshake survived. A 0% report is also valid (loss has
		// no user-controllable seed on the client's egress) and is not an
		// assertion failure either way — see VRFY-03's own tolerant intent.
		t.Logf("data-channel ping on the lossy link: %d/%d replies received (%d%% reported client-observed loss) — tolerated per VRFY-03; a nonzero value is direct evidence of reorder/retransmission on the data channel itself, not just the control channel", received, transmitted, lossPct)
	}

	rtm := pingRxTxRe.FindStringSubmatch(res.composeOut)
	if rtm == nil {
		t.Fatal("server output does not contain a parsable ping_rx=/ping_tx= field — see log above")
	}
	pingRx, err := strconv.Atoi(rtm[1])
	if err != nil {
		t.Fatalf("parse ping_rx=%q: %v", rtm[1], err)
	}
	pingTx, err := strconv.Atoi(rtm[2])
	if err != nil {
		t.Fatalf("parse ping_tx=%q: %v", rtm[2], err)
	}
	if pingRx == 0 || pingTx == 0 {
		t.Fatalf("server output reports ping_rx=%d ping_tx=%d, want both greater than zero — see log above", pingRx, pingTx)
	}
	t.Logf("data-channel round trip: client received %d/%d ping replies (%d%% loss); server observed ping_rx=%d ping_tx=%d", received, transmitted, lossPct, pingRx, pingTx)
}

// probeResultRe matches entrypoint.sh's structured probe-result line format
// (03-06-PLAN.md Task 1): "entrypoint: PROBE <name> result=<ok|fail> ...".
// One regexp for every probe this phase adds, so a later probe needs no new
// parser — only a new call to assertProbe below.
var probeResultRe = regexp.MustCompile(`PROBE (\w+) result=(\w+)`)

// parseProbeResults extracts every "PROBE <name> result=<ok|fail>" line from
// composeOut into a name->result map. A probe that never printed its line at
// all (e.g. the script aborted before reaching it) is simply absent from the
// map, which assertProbe treats as a failure for a required probe.
func parseProbeResults(composeOut string) map[string]string {
	results := make(map[string]string)
	for _, m := range probeResultRe.FindAllStringSubmatch(composeOut, -1) {
		results[m[1]] = m[2]
	}
	return results
}

// assertProbe fails the test when a required probe is missing or did not
// report result=ok. required=false records a non-ok/missing result as a
// log line instead of a failure — used for probes this plan's own strictness
// convention tolerates on the lossy scenario (mirroring assertPingRoundTrip's
// strict bool, interop_test.go:479).
func assertProbe(t *testing.T, res scenarioResult, name string, required bool) {
	t.Helper()
	results := parseProbeResults(res.composeOut)
	got, ok := results[name]
	if ok && got == "ok" {
		t.Logf("probe %s: result=ok", name)
		return
	}
	if !ok {
		got = "missing"
	}
	if required {
		t.Fatalf("probe %s: result=%s, want ok — see log above", name, got)
	}
	t.Logf("probe %s: result=%s (tolerated on this scenario) — see log above", name, got)
}

// landingPageH1 is the tunnelweb landing page's locked <h1> text (UI-SPEC §1
// "Landing"), the content marker http_landing's curl probe checks for — a
// named constant so a future copy change has one place to update and a
// reviewer can see the marker is contractual rather than arbitrary.
const landingPageH1 = "<h1>govpn tunnelweb</h1>"

// statusActiveMarker is the tunnelweb status page's locked "tunnel: active"
// indicator text (UI-SPEC §2 "Status"), entrypoint.sh's http_status probe's
// content marker.
const statusActiveMarker = "tunnel: active"

// echoProbeMsg is the fixed message entrypoint.sh's http_echo probe POSTs to
// /echo; echoRoundTripMarker is its expected populated-state rendering
// (UI-SPEC §4 "Echo-test", pages.go's "You sent: {{.Value}}" template) — kept
// in sync with entrypoint.sh's own ECHO_PROBE_MSG value.
const (
	echoProbeMsg        = "govpn-echo-probe-msg"
	echoRoundTripMarker = "You sent: " + echoProbeMsg
)

// headersReceivedFragment is the tunnelweb headers page's locked "{N}
// headers received" heading, checked as a fragment since N varies by
// request (UI-SPEC §5 "Headers"), entrypoint.sh's http_headers probe's
// content marker.
const headersReceivedFragment = "headers received"

// assertHTTPPageLoad is 03-06-PLAN.md Task 1's verification: a real,
// unmodified OpenVPN 2.6.14 client's curl request for the tunnelweb landing
// page, issued through the tunnel by entrypoint.sh's http_landing probe,
// returned a body containing the page's own locked <h1> text — served by
// examples/tunnelweb/site.Handler over the netstack's TCP listener, not a
// private stand-in page (XMPL-01 live half). It additionally asserts the
// server's own PASS line reports http_requests= greater than zero, so a
// probe that somehow reports ok without the server having served anything
// still fails.
func assertHTTPPageLoad(t *testing.T, res scenarioResult) {
	t.Helper()

	if res.composeErr != nil {
		// assertHandshakeCompleted already fails loudly on this; avoid a
		// second, redundant fatal here obscuring the first.
		return
	}

	assertProbe(t, res, "http_landing", true)

	m := httpRequestsRe.FindStringSubmatch(res.composeOut)
	if m == nil {
		t.Fatal("server output does not contain a parsable http_requests= field — see log above")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse http_requests=%q: %v", m[1], err)
	}
	if n == 0 {
		t.Fatal("server output reports http_requests=0, want greater than zero — the probe reported ok without the server having served anything")
	}
	t.Logf("server observed http_requests=%d", n)
}

// httpRequestsRe extracts the http_requests= field test/interop/server's
// PASS line carries (03-06-PLAN.md Task 1).
var httpRequestsRe = regexp.MustCompile(`http_requests=(\d+)`)

// udpRxTxRe extracts the udp_rx=/udp_tx= fields test/interop/server's PASS
// line carries (03-06-PLAN.md Task 2, test/interop/server/main.go's
// runUDPEcho).
var udpRxTxRe = regexp.MustCompile(`udp_rx=(\d+) udp_tx=(\d+)`)

// assertUDPRoundTrip is 03-06-PLAN.md Task 2's UDP verification (NET-01 live
// half): a real client's fixed payload, sent via entrypoint.sh's udp_echo
// probe, is echoed back by the netstack's UDP demux/runUDPEcho and observed
// by the server's own udp_rx=/udp_tx= counters. strict follows
// assertPingRoundTrip's own convention (interop_test.go:479): the clean
// scenarios require the probe to succeed and both counters greater than
// zero; the lossy scenario tolerates a failed probe — a bare UDP datagram
// has no retransmission by design, and the lossy scenario injects 5-10%
// loss on top of entrypoint.sh's own 3-attempt retry — logging loudly
// either way so a persistent failure stays visible rather than silently
// accepted (both choices recorded here per the plan's own instruction).
func assertUDPRoundTrip(t *testing.T, res scenarioResult, strict bool) {
	t.Helper()

	if res.composeErr != nil {
		return
	}

	assertProbe(t, res, "udp_echo", strict)

	m := udpRxTxRe.FindStringSubmatch(res.composeOut)
	if !strict {
		if m == nil {
			t.Log("server output does not contain a parsable udp_rx=/udp_tx= field on the lossy scenario — tolerated, see the udp_echo probe result logged above")
			return
		}
		t.Logf("server observed udp_rx=%s udp_tx=%s on the lossy scenario (probe result logged above)", m[1], m[2])
		return
	}

	if m == nil {
		t.Fatal("server output does not contain a parsable udp_rx=/udp_tx= field — see log above")
	}
	udpRx, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse udp_rx=%q: %v", m[1], err)
	}
	udpTx, err := strconv.Atoi(m[2])
	if err != nil {
		t.Fatalf("parse udp_tx=%q: %v", m[2], err)
	}
	if udpRx == 0 || udpTx == 0 {
		t.Fatalf("server output reports udp_rx=%d udp_tx=%d, want both greater than zero — see log above", udpRx, udpTx)
	}
	t.Logf("server observed udp_rx=%d udp_tx=%d", udpRx, udpTx)
}

// assertHTTPSubpages is 03-06-PLAN.md Task 2's remaining HTTP verification:
// /status, /echo (a form POST whose request and response bodies both cross
// the netstack's TCP — the strongest single proof in this run), and
// /headers, each checked against its UI-SPEC content marker by
// entrypoint.sh and asserted here via Task 1's assertProbe helper. Required
// on the clean scenarios (strict=true); tolerated as non-fatal log lines on
// the lossy scenario, whose own Task 2 acceptance criteria assert only
// http_landing and udp_echo explicitly for that scenario.
func assertHTTPSubpages(t *testing.T, res scenarioResult, strict bool) {
	t.Helper()

	if res.composeErr != nil {
		return
	}

	assertProbe(t, res, "http_status", strict)
	assertProbe(t, res, "http_echo", strict)
	assertProbe(t, res, "http_headers", strict)
}

// assertUnreachableOutsideTunnel is 03-06-PLAN.md Task 3's negative proof
// (ROADMAP Phase 3 success criterion 3's "unreachable from outside the
// tunnel" clause): entrypoint.sh's outside_tunnel probe curls the server
// container's own Docker-network alias directly, bypassing the tunnel
// entirely, and its result=ok means that connection was refused or timed
// out — the genuine, desired outcome, since the tunnelweb site binds no OS
// TCP socket for HTTP at all. Required on EVERY scenario including the
// lossy one: the lossy link only affects the client<->server UDP tunnel
// port, and has no bearing on whether a direct TCP connection to the
// server container's own network address is refused, so there is no reason
// to relax this probe there.
func assertUnreachableOutsideTunnel(t *testing.T, res scenarioResult) {
	t.Helper()

	if res.composeErr != nil {
		return
	}

	assertProbe(t, res, "outside_tunnel", true)
}

// assertServerStaysUnprivileged is plan 01-02's runtime privilege check,
// re-asserted in every scenario including the lossy one — the
// server-to-client loss decorator lives entirely in this harness's own
// userspace PacketConn wrapper (test/interop/server/main.go) precisely so
// the server container never needs a capability it wouldn't have in
// production (T-01-21). The `docker inspect` itself runs inside
// runScenario, while the server container still exists (before `down`
// tears it down) — by the time this Test function runs, the container is
// already gone, so the captured string is asserted here instead of
// re-inspecting a container that no longer exists.
//
// The failure message names this phase's own claim explicitly (03-06-
// PLAN.md Task 3): the server container serves real ICMP, UDP, and TCP
// traffic through a userspace netstack with zero added capabilities and
// zero mapped devices — so a future failure here reads as "the deployment
// premise broke", not merely "a string did not match".
func assertServerStaysUnprivileged(t *testing.T, res scenarioResult) {
	t.Helper()
	if res.privilegeCheck != "false 0 0" {
		t.Fatalf(
			"server container privilege check = %q, want \"false 0 0\" (not privileged, zero added capabilities, zero mapped devices) — this is the deployment premise the whole phase rests on: the server serves real ICMP, UDP, and TCP traffic through a userspace netstack while running as an ordinary, unprivileged process, with no /dev/net/tun and no CAP_NET_ADMIN",
			res.privilegeCheck,
		)
	}
}

// renegotiationsRe extracts the renegotiations= field test/interop/server's
// PASS line carries (04-03-PLAN.md Task 1, sess.RenegotiationCount()),
// modeled directly on the pre-existing udpRxTxRe/pingRxTxRe parsers above —
// a new PASS-line field needs a new regexp+assertion pair here, not a
// change to any existing one.
var renegotiationsRe = regexp.MustCompile(`renegotiations=(\d+)`)

// assertRenegotiation is 04-03-PLAN.md Task 1/2's rollover proof: the
// server's PASS line must report at least wantMin completed soft-reset
// rollovers (sess.RenegotiationCount(), incremented once per completed
// rollover inside ovpn.go's runRenegotiation) — proving a real client
// actually renegotiated against the library, not merely that the harness's
// shortened -reneg-sec flag was set.
func assertRenegotiation(t *testing.T, res scenarioResult, wantMin int) {
	t.Helper()

	if res.composeErr != nil {
		return
	}

	m := renegotiationsRe.FindStringSubmatch(res.composeOut)
	if m == nil {
		t.Fatal("server output does not contain a parsable renegotiations= field — see log above")
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse renegotiations=%q: %v", m[1], err)
	}
	if got < wantMin {
		t.Fatalf("server output reports renegotiations=%d, want at least %d — see log above", got, wantMin)
	}
	t.Logf("server observed renegotiations=%d (want at least %d)", got, wantMin)
}

// assertCertificateFlightFragmented is 01-04-PLAN.md Task 1's fragmentation
// proof: count the consecutive server-to-client P_CONTROL_V1 payloads
// carrying the maximum control payload size (internal/ctrlconn.MaxPayload)
// and require at least two, so a regression that stopped fragmenting (or
// silently truncated the certificate chain) would fail rather than pass. No
// exact fragment count is asserted — retransmission makes it vary,
// especially in the lossy scenario.
func assertCertificateFlightFragmented(t *testing.T, res scenarioResult) {
	t.Helper()

	key, err := readTLSCryptKey(res.keyPath)
	if err != nil {
		t.Fatalf("read tls-crypt key %s: %v", res.keyPath, err)
	}
	packets, err := decodeCapture(res.capturePath, key, tunnelPort, nil)
	if err != nil {
		t.Fatalf("decode capture %s: %v", res.capturePath, err)
	}

	maxConsecutive, current := 0, 0
	for _, p := range packets {
		isMaxFragment := p.Direction == DirServerToClient &&
			p.Control.Opcode == wire.OpControlV1 &&
			len(p.Control.Payload) == ctrlconn.MaxPayload
		if isMaxFragment {
			current++
			if current > maxConsecutive {
				maxConsecutive = current
			}
		} else {
			current = 0
		}
	}

	if maxConsecutive < 2 {
		t.Fatalf("only %d consecutive maximum-size (%d-byte) server-to-client control fragments observed in %s, want at least 2 — the large certificate flight may not have fragmented as expected", maxConsecutive, ctrlconn.MaxPayload, res.capturePath)
	}
	t.Logf("observed %d consecutive maximum-size (%d-byte) server-to-client control fragments", maxConsecutive, ctrlconn.MaxPayload)
}

// netemLossPctRe/dropRateRe/reorderRateRe extract the loss/reorder
// percentages actually wired into docker-compose.lossy.yml, so
// assertLossyLoadFactorsInBand checks the configuration in force for this
// run rather than a value merely duplicated in Go source that could drift
// from the YAML silently.
var (
	netemLossPctRe = regexp.MustCompile(`NETEM_LOSS_PCT=(\d+(?:\.\d+)?)`)
	dropRateRe     = regexp.MustCompile(`"-drop-rate",\s*"(\d+(?:\.\d+)?)"`)
	reorderRateRe  = regexp.MustCompile(`"-reorder-rate",\s*"(\d+(?:\.\d+)?)"`)
)

// assertLossyLoadFactorsInBand is 01-04-PLAN.md Task 1's acceptance
// criterion that the lossy scenario's configured loss is between 5 and 10
// percent inclusive on BOTH the client egress (netem) and the server
// decorator, asserted in the test rather than only set in configuration.
func assertLossyLoadFactorsInBand(t *testing.T) {
	t.Helper()

	root, err := repoRoot()
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	overlay, err := os.ReadFile(filepath.Join(root, "test", "interop", "docker-compose.lossy.yml"))
	if err != nil {
		t.Fatalf("read docker-compose.lossy.yml: %v", err)
	}
	text := string(overlay)

	clientLoss := extractPercent(t, text, netemLossPctRe, "client NETEM_LOSS_PCT")
	serverDrop := extractPercent(t, text, dropRateRe, "server -drop-rate")
	serverReorder := extractPercent(t, text, reorderRateRe, "server -reorder-rate")

	assertInBand(t, "client-egress loss (NETEM_LOSS_PCT)", clientLoss)
	assertInBand(t, "server decorator drop rate (-drop-rate)", serverDrop)
	t.Logf("server decorator reorder rate (-reorder-rate) = %.1f%%", serverReorder)
}

func extractPercent(t *testing.T, text string, re *regexp.Regexp, label string) float64 {
	t.Helper()
	m := re.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("docker-compose.lossy.yml does not set %s", label)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parse %s value %q: %v", label, m[1], err)
	}
	return v
}

func assertInBand(t *testing.T, label string, pct float64) {
	t.Helper()
	if pct < 5 || pct > 10 {
		t.Fatalf("%s = %.1f%%, want between 5 and 10 percent inclusive", label, pct)
	}
	t.Logf("%s = %.1f%% (within [5,10])", label, pct)
}

// logRetransmissionEvidence is the automated stand-in for this task's
// <verify> human-check ("confirm the handshake completed through genuine
// retransmission — there are duplicate reliability packet IDs on the wire
// and the session still reached TLS established") in an autonomous,
// non-interactive execution: it counts duplicate reliability packet IDs
// (the same PacketID appearing more than once for the same direction and
// opcode — a genuine retransmission, not a coincidence) in the lossy
// scenario's capture and logs the count.
//
// This is deliberately non-fatal (t.Log only, never t.Fatal): the client's
// own tc netem loss has no seed/reproducibility control (unlike the
// server-to-client decorator's -seed flag) — a run where every datagram
// happens to arrive on the first try at 7% loss is astronomically unlikely
// across a full handshake but not impossible, and this check exists to
// surface evidence for a human/CI-log reader, not to gate the build on
// kernel PRNG behavior this harness cannot control.
func logRetransmissionEvidence(t *testing.T, res scenarioResult) {
	t.Helper()

	key, err := readTLSCryptKey(res.keyPath)
	if err != nil {
		t.Logf("retransmission evidence: read tls-crypt key %s: %v", res.keyPath, err)
		return
	}
	packets, err := decodeCapture(res.capturePath, key, tunnelPort, nil)
	if err != nil {
		t.Logf("retransmission evidence: decode capture %s: %v", res.capturePath, err)
		return
	}

	seen := map[Direction]map[wire.PacketID]int{
		DirClientToServer: {},
		DirServerToClient: {},
	}
	duplicates := 0
	for _, p := range packets {
		if p.Control.Opcode == wire.OpAckV1 {
			continue // ack-only packets carry no own reliability packet ID
		}
		counts := seen[p.Direction]
		counts[p.Control.PacketID]++
		if counts[p.Control.PacketID] > 1 {
			duplicates++
		}
	}

	if duplicates == 0 {
		t.Logf("retransmission evidence: no duplicate reliability packet IDs observed in %s — either no synthetic loss struck a packet this run, or every retransmission also happened to be lost (both possible at 7%% loss, just increasingly unlikely)", res.capturePath)
		return
	}
	t.Logf("retransmission evidence: %d duplicate reliability packet ID occurrences observed in %s — the handshake completed through genuine retransmission, not by chance", duplicates, res.capturePath)
}
