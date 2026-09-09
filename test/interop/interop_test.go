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

	// probeRounds (04-03-PLAN.md Task 2), when greater than 1, drives
	// entrypoint.sh's ROUND_COUNT env var and switches this scenario's
	// assertions from the single-round assertHTTPPageLoad/assertUDPRoundTrip
	// pair to assertMultiRoundProbes (round-suffixed probe names) plus
	// assertNoReconnect (T-04-11: a rollover satisfied by a reconnect is a
	// failure, not a pass). 0 or 1 (every pre-existing scenario) keeps the
	// original single-round assertions unchanged.
	probeRounds int

	// noClientCert (quick 260908-m4e) passes -no-client-cert to
	// cmd/gentestpki, omitting the cert/key directives from the generated
	// client.conf. false (every pre-existing scenario) reproduces the
	// original client.conf exactly.
	noClientCert bool

	// credentials (quick 260908-m4e), when non-empty, passes -credentials
	// <value> ("user:pass") to cmd/gentestpki, which writes a credentials
	// file and appends auth-user-pass to client.conf. Empty (every
	// pre-existing scenario) adds no such directive.
	credentials string

	// wantDataCipher (05-04-PLAN.md Task 2), when non-empty, asserts (via
	// assertNegotiatedCipher) that BOTH the real client's own "Data
	// Channel: cipher '<name>'" log line and the server's PASS line
	// data_cipher= field equal this canonical cipher name. Empty (every
	// pre-existing scenario) skips the assertion entirely.
	wantDataCipher string
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
		name:           "reneg",
		profile:        "small",
		lossy:          false,
		largeCert:      false,
		contextTimeout: 4 * time.Minute,
		composeOverlay: "docker-compose.reneg.yml",
		// explicit-exit-notify 2 (04-03-PLAN.md Task 3) is carried by this
		// SAME scenario rather than a second one sharing the overlay: the
		// graceful-stop step (entrypoint.sh) runs strictly after every
		// probe round and subpage probe above has already finished, so
		// there is no timing conflict with the multi-round renegotiation
		// proof above — one shared run exercises both success criteria.
		clientDirectives:  []string{"reneg-sec 15", "explicit-exit-notify 2"},
		minRenegotiations: 2,
		probeRounds:       5,
	},
	{
		// "auth-user-pass" (quick 260908-m4e) proves a real, unmodified
		// OpenVPN 2.6 client authenticating by username/password with NO
		// client certificate: cmd/gentestpki -no-client-cert omits the
		// cert/key directives, -credentials writes the credentials file
		// and appends auth-user-pass to client.conf, and
		// docker-compose.auth.yml's server command carries the matching
		// -no-client-cert -auth-user-pass flags. Otherwise a plain
		// successful connection — no renegotiation, no multi-round
		// assertions, so the pre-existing single-round ping/HTTP/UDP
		// probe assertions apply unmodified.
		name:           "auth-user-pass",
		profile:        "small",
		lossy:          false,
		largeCert:      false,
		contextTimeout: 4 * time.Minute,
		composeOverlay: "docker-compose.auth.yml",
		noClientCert:   true,
		credentials:    "voxio:s3cr3t",
	},
	{
		// "cipher-128" (05-04-PLAN.md Task 2, ROADMAP success criterion 1)
		// proves a real, unmodified OpenVPN 2.6 client that can only speak
		// AES-128-GCM (data-ciphers AES-128-GCM, its sole entry) connects
		// to a server whose allow-list also contains only AES-128-GCM
		// (docker-compose.cipher-128.yml's -data-ciphers AES-128-GCM) —
		// negotiating AES-128-GCM and passing every probe, proving a
		// one-entry allow-list works against a real client, not only that
		// AES-128-GCM itself does.
		name:             "cipher-128",
		profile:          "small",
		lossy:            false,
		largeCert:        false,
		contextTimeout:   4 * time.Minute,
		composeOverlay:   "docker-compose.cipher-128.yml",
		clientDirectives: []string{"data-ciphers AES-128-GCM"},
		wantDataCipher:   "AES-128-GCM",
	},
	{
		// "cipher-order" (05-04-PLAN.md Task 2, ROADMAP success criterion 2)
		// proves the server's preference order wins a tie, never the
		// client's: the server's allow-list is AES-256-GCM:AES-128-GCM
		// (docker-compose.cipher-order.yml, its OWN order), while the
		// client is deliberately configured with the REVERSE order
		// (data-ciphers AES-128-GCM:AES-256-GCM). The expected outcome is
		// the server's first entry, AES-256-GCM — a failure mode this
		// scenario exists to catch (inverting whose preference decides a
		// tie) produces a working tunnel either way, so a unit test alone
		// cannot prove it against the reference implementation the way a
		// real client's own handshake log line can.
		name:             "cipher-order",
		profile:          "small",
		lossy:            false,
		largeCert:        false,
		contextTimeout:   4 * time.Minute,
		composeOverlay:   "docker-compose.cipher-order.yml",
		clientDirectives: []string{"data-ciphers AES-128-GCM:AES-256-GCM"},
		wantDataCipher:   "AES-256-GCM",
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

// runFlagOnlyTargets reports whether the test binary's own -run flag value
// is EXACTLY name (04-04-PLAN.md Task 1) — used by TestMain to skip the
// pre-existing scenarios table's setup when the caller asked for only
// TestSoak, so that test function's own timeout governs a soak run without
// also paying for the unrelated scenario table's Docker runs. A simple
// exact-string check rather than a full -run regexp evaluation: every
// caller this plan cares about (its own verify commands, the Makefile's
// `soak` target) passes exactly `-run 'TestSoak'`.
func runFlagOnlyTargets(name string) bool {
	f := flag.Lookup("test.run")
	if f == nil {
		return false
	}
	return f.Value.String() == name
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

	// TestSoak (04-04-PLAN.md Task 1) drives its own scenario directly,
	// deliberately outside the scenarios table below — "the soak scenario
	// is driven by its own test function, not folded into that table"
	// (04-04-PLAN.md's own key_links). runFlagOnlyTargets guards the
	// pre-existing scenario table's setup so `go test -run 'TestSoak'`
	// (this plan's own verify command, and the Makefile's `soak` target)
	// does not ALSO pay for clean-small/clean-large/lossy-large/reneg's own
	// several minutes of Docker runs it will never assert against — the
	// soak gets its own timeout, exactly like every other design constraint
	// this plan states for it (D-24, T-04-19).
	if !runFlagOnlyTargets("TestSoak") {
		for _, sc := range scenarios {
			scenarioResults[sc.name] = runScenario(root, interopDir, sc)
		}
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
	if sc.noClientCert {
		genArgs = append(genArgs, "-no-client-cert")
	}
	if sc.credentials != "" {
		genArgs = append(genArgs, "-credentials", sc.credentials)
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

			assertHandshakeCompleted(t, res, !sc.noClientCert)
			assertKeyExchangeCompleted(t, res)
			assertTunnelUp(t, res)

			// 05-04-PLAN.md Task 2 (ROADMAP success criteria 1/2): the
			// "cipher-128"/"cipher-order" scenarios assert the negotiated
			// data-channel cipher from BOTH ends. Every other scenario
			// leaves wantDataCipher at its zero value and skips this.
			if sc.wantDataCipher != "" {
				assertNegotiatedCipher(t, res, sc.wantDataCipher)
			}

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
			//
			// 03-06-PLAN.md Task 2 (NET-01, VRFY-02): a UDP round trip
			// and the three remaining HTTP subpages, both parameterized
			// by the same !sc.lossy strictness convention
			// assertPingRoundTrip already established — see each
			// function's own doc comment for exactly what is tolerated
			// on the lossy scenario and why.
			//
			// 04-03-PLAN.md Task 2 (T-04-11): a scenario with probeRounds > 1
			// (only "reneg") replaces this single-round
			// assertHTTPPageLoad/assertUDPRoundTrip pair's probe-name
			// checks — entrypoint.sh's round loop no longer emits the
			// unsuffixed "http_landing"/"udp_echo" probes once
			// ROUND_COUNT > 1 — with assertMultiRoundProbes' round-suffixed
			// equivalent, plus assertNoReconnect's zero-reconnect proof.
			if sc.probeRounds > 1 {
				assertMultiRoundProbes(t, res, sc.probeRounds)
				assertNoReconnect(t, res)
			} else {
				assertHTTPPageLoad(t, res)
				assertUDPRoundTrip(t, res, !sc.lossy)
			}
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

			// 04-03-PLAN.md Task 3 (SESS-05 against a real client): the
			// same "reneg" scenario's client carries explicit-exit-notify,
			// so its graceful stop (entrypoint.sh, after every probe round
			// and subpage probe above) must close the server's Session
			// well under the 60s idle-reap window. minRenegotiations > 0 is
			// reused as this scenario's own marker rather than adding a
			// third boolean field — this plan's only scenario carrying
			// either directive carries both.
			if sc.minRenegotiations > 0 {
				assertExitNotifyClosesPromptly(t, res)
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
// expectClientCN, when false (the "auth-user-pass" scenario, quick
// 260908-m4e — no client certificate is ever presented), skips the
// peer_cn= assertion below rather than requiring a CommonName the client
// structurally cannot present. Every pre-existing scenario passes true,
// unchanged.
func assertHandshakeCompleted(t *testing.T, res scenarioResult, expectClientCN bool) {
	t.Helper()

	if res.composeErr != nil {
		t.Fatalf("docker compose up did not exit cleanly — the server did not observe a completed, stable TLS handshake before its deadline: %v", res.composeErr)
	}

	if !strings.Contains(res.composeOut, "PASS: session established") {
		t.Fatal("server did not print its PASS line (handshake completed AND survived the post-handshake window) — see log above")
	}

	if expectClientCN {
		const wantClientCN = "peer_cn=govpn-interop-client"
		if !strings.Contains(res.composeOut, wantClientCN) {
			t.Fatalf("server output does not contain %q — see log above", wantClientCN)
		}
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

// assertMultiRoundProbes is assertHTTPPageLoad/assertUDPRoundTrip's
// multi-round analog (04-03-PLAN.md Task 2, for scenario.probeRounds > 1):
// every round's http_landing_rN/udp_echo_rN probe must report result=ok —
// strict, since the reneg scenario carries no loss injection, unlike
// lossy-large — and the server's own http_requests=/udp_rx=/udp_tx=
// PASS-line counters must each be greater than zero, exactly like the
// single-round assertions this replaces for a multi-round scenario.
func assertMultiRoundProbes(t *testing.T, res scenarioResult, rounds int) {
	t.Helper()

	if res.composeErr != nil {
		return
	}

	for i := 1; i <= rounds; i++ {
		assertProbe(t, res, fmt.Sprintf("http_landing_r%d", i), true)
		assertProbe(t, res, fmt.Sprintf("udp_echo_r%d", i), true)
	}

	if m := httpRequestsRe.FindStringSubmatch(res.composeOut); m == nil {
		t.Fatal("server output does not contain a parsable http_requests= field — see log above")
	} else if n, err := strconv.Atoi(m[1]); err != nil {
		t.Fatalf("parse http_requests=%q: %v", m[1], err)
	} else if n == 0 {
		t.Fatal("server output reports http_requests=0, want greater than zero — see log above")
	} else {
		t.Logf("server observed http_requests=%d across %d rounds", n, rounds)
	}

	m := udpRxTxRe.FindStringSubmatch(res.composeOut)
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
	t.Logf("server observed udp_rx=%d udp_tx=%d across %d rounds", udpRx, udpTx, rounds)
}

// clientSoftResetLogLine is the real Debian-packaged OpenVPN 2.6.3-based
// client's own renegotiation diagnostic line, captured VERBATIM from this
// project's own Task 1 interop run against the "reneg" scenario (not
// guessed): "TLS: soft reset sec=15/15 bytes=11024/-1 pkts=72/0" (ssl.c's
// own key_state_soft_reset()/tls_process() diagnostic, printed once per
// side that INITIATES a rollover — client or server). Only the fixed
// prefix is asserted on; the sec=/bytes=/pkts= fields vary run to run.
const clientSoftResetLogPrefix = "TLS: soft reset sec="

// assertNoReconnect is 04-03-PLAN.md Task 2's zero-reconnect proof
// (T-04-11 in this plan's own threat register): the renegotiation scenario
// must not be satisfiable by a reconnect. It asserts BOTH that the client's
// own log shows at least one renegotiation (clientSoftResetLogPrefix above)
// AND that the client's log contains EXACTLY ONE occurrence of
// "Initialization Sequence Completed" (initSequenceCompletedRe, the same
// literal assertTunnelUp already asserts is present at least once) — a
// SECOND occurrence would mean the tunnel was torn down and rebuilt rather
// than rekeyed in place, which is a failure, not a pass, no matter how many
// rollovers the server's own PASS line reports.
func assertNoReconnect(t *testing.T, res scenarioResult) {
	t.Helper()

	if res.composeErr != nil {
		return
	}

	if !strings.Contains(res.composeOut, clientSoftResetLogPrefix) {
		t.Fatalf("client output does not contain %q — the client's own log shows no evidence of a renegotiation — see log above", clientSoftResetLogPrefix)
	}

	n := len(initSequenceCompletedRe.FindAllStringIndex(res.composeOut, -1))
	if n != 1 {
		t.Fatalf("client output contains %d occurrences of \"Initialization Sequence Completed\", want exactly 1 — more than one means the tunnel was torn down and rebuilt (a reconnect), not rekeyed in place (T-04-11) — see log above", n)
	}
	t.Log("client log shows renegotiation evidence and exactly one completed initialization sequence — every rollover rekeyed in place, none reconnected")
}

// exitNotifyStopIssuedRe/sessionCloseObservedRe (04-03-PLAN.md Task 3)
// extract the two absolute Unix-second epoch timestamps
// assertExitNotifyClosesPromptly diffs: the client's own
// "PROBE exit_notify_stop_issued result=ok epoch=<N>" line (entrypoint.sh,
// when the graceful SIGTERM was issued) and the server's own
// "close_observed_epoch=<N>" field on its distinct close-observation log
// line (test/interop/server/main.go, when Read returning io.EOF was
// observed). Both containers share the host clock under docker compose, so
// the two epochs are directly comparable.
var (
	exitNotifyStopIssuedRe = regexp.MustCompile(`PROBE exit_notify_stop_issued result=ok epoch=(\d+)`)
	sessionCloseObservedRe = regexp.MustCompile(`close_observed_epoch=(\d+)`)
)

const exitNotifyThresholdSecs int64 = 15

// assertExitNotifyClosesPromptly is 04-03-PLAN.md Task 3's proof (T-04-12
// in this plan's own threat register): a real client's explicit-exit-notify
// closes the server's Session within seconds of the graceful stop being
// issued — comfortably below the 60s idle-reap window, so the close cannot
// be explained by the reap timer having simply expired on its own schedule.
// exitNotifyThresholdSecs (15s) is chosen well under 60s with generous
// margin for the client's own OCC_EXIT round trip (repeated once per
// second, sig.c:374-392) while still being far enough from 60 that a
// regression which silently fell back to the idle-reap path would fail
// this assertion rather than accidentally sneaking in under a threshold set
// too close to 60.
func assertExitNotifyClosesPromptly(t *testing.T, res scenarioResult) {
	t.Helper()

	if res.composeErr != nil {
		return
	}

	stopMatch := exitNotifyStopIssuedRe.FindStringSubmatch(res.composeOut)
	if stopMatch == nil {
		t.Fatal("client output does not contain a parsable PROBE exit_notify_stop_issued epoch= field — see log above")
	}
	stopEpoch, err := strconv.ParseInt(stopMatch[1], 10, 64)
	if err != nil {
		t.Fatalf("parse exit_notify_stop_issued epoch=%q: %v", stopMatch[1], err)
	}

	closeMatch := sessionCloseObservedRe.FindStringSubmatch(res.composeOut)
	if closeMatch == nil {
		t.Fatal("server output does not contain a parsable close_observed_epoch= field — the server never observed the session close (Session.Read returning io.EOF) — see log above")
	}
	closeEpoch, err := strconv.ParseInt(closeMatch[1], 10, 64)
	if err != nil {
		t.Fatalf("parse close_observed_epoch=%q: %v", closeMatch[1], err)
	}

	elapsed := closeEpoch - stopEpoch
	if elapsed < 0 {
		t.Fatalf("server observed the session close (epoch=%d) BEFORE the client's graceful stop was issued (epoch=%d) — see log above", closeEpoch, stopEpoch)
	}
	if elapsed > exitNotifyThresholdSecs {
		t.Fatalf(
			"elapsed time from the client's graceful stop to the server observing the session close = %ds, want at most %ds — comfortably under the 60s idle-reap window; a duration this close to 60s would not distinguish exit-notify from the idle-reap timer having simply expired on its own schedule — see log above",
			elapsed, exitNotifyThresholdSecs,
		)
	}
	t.Logf("exit-notify closed the session %ds after the client's graceful stop (well under the 60s idle-reap window and the %ds threshold)", elapsed, exitNotifyThresholdSecs)
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
//
// Anchored on the immediately preceding http_requests= field (mirroring
// udpRxTxRe/pingRxTxRe's own multi-field anchoring above), not a bare
// `renegotiations=(\d+)`: quick 260908-na1's own Config.Logger emits a
// "renegotiation completed" record whose renegotiations attr (D-04's
// mandated key — the plan's log_sites table, not a name this test file
// controls) ALSO matches a bare renegotiations= pattern, and since
// FindStringSubmatch returns the FIRST match in the composed log, an
// unanchored regexp would capture that earlier, smaller mid-run value
// instead of the PASS line's final count.
var renegotiationsRe = regexp.MustCompile(`http_requests=\d+ renegotiations=(\d+)`)

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

// dataChannelClientCipherRe matches the real client's own log line naming
// the negotiated data-channel cipher (init.c:2232-2236,
// tls_print_deferred_options_results, AEAD branch — GCM ciphers never take
// the ", auth '%s'" suffix, since that only fires for non-AEAD modes). The
// string is quoted verbatim from the reference source, not paraphrased.
var dataChannelClientCipherRe = regexp.MustCompile(`Data Channel: cipher '([A-Za-z0-9_-]+)'`)

// dataCipherServerRe extracts the data_cipher= field test/interop/server's
// PASS line carries (05-04-PLAN.md Task 1, sess.Cipher()), anchored on the
// immediately preceding renegotiations= field — the same anchoring
// reasoning as renegotiationsRe above: a bare `data_cipher=` pattern risks
// matching an unrelated occurrence first, since FindStringSubmatch returns
// only the first match in the composed log.
var dataCipherServerRe = regexp.MustCompile(`renegotiations=\d+ data_cipher=(\S+)`)

// interopSupportedDataCiphers duplicates cipher.go's own supportedDataCiphers
// table (unexported, package ovpn) purely so assertNegotiatedCipher can
// assert the ABSENCE of every OTHER supported cipher's client log line —
// this package cannot import the unexported slice, and hardcoding the two
// names here is no less precise than the regexp above already is about the
// reference's own fixed vocabulary.
var interopSupportedDataCiphers = []string{"AES-256-GCM", "AES-128-GCM"}

// assertNegotiatedCipher is 05-04-PLAN.md Task 2's two-ended cipher proof:
// the real client's own "Data Channel: cipher '<name>'" log line AND the
// server's PASS line data_cipher= field must both equal want, and the
// client's log must NOT ALSO contain the line for any other supported
// cipher — otherwise the "cipher-order" scenario could pass on a run where
// the client happened to log both ciphers somewhere in its output, which
// would prove nothing about which one was actually negotiated. Asserting
// both ends (not just the server's own PASS line) is deliberate (T-05-21):
// a harness that only asked itself would pass a broken negotiation.
func assertNegotiatedCipher(t *testing.T, res scenarioResult, want string) {
	t.Helper()

	if res.composeErr != nil {
		// assertHandshakeCompleted already fails loudly on this; avoid a
		// second, redundant fatal here obscuring the first.
		return
	}

	clientMatch := dataChannelClientCipherRe.FindStringSubmatch(res.composeOut)
	if clientMatch == nil {
		t.Fatal("client output does not contain a parsable \"Data Channel: cipher '<name>'\" line — see log above")
	}
	if clientMatch[1] != want {
		t.Fatalf("client negotiated cipher %q, want %q — see log above", clientMatch[1], want)
	}

	serverMatch := dataCipherServerRe.FindStringSubmatch(res.composeOut)
	if serverMatch == nil {
		t.Fatal("server output does not contain a parsable data_cipher= field on its PASS line — see log above")
	}
	if serverMatch[1] != want {
		t.Fatalf("server PASS line reports data_cipher=%s, want %s — see log above", serverMatch[1], want)
	}

	for _, other := range interopSupportedDataCiphers {
		if other == want {
			continue
		}
		otherLine := fmt.Sprintf("Data Channel: cipher '%s'", other)
		if strings.Contains(res.composeOut, otherLine) {
			t.Fatalf("client output ALSO contains %q — the client logged both ciphers, so this run cannot prove which one was actually negotiated — see log above", otherLine)
		}
	}

	t.Logf("negotiated data-channel cipher: %s (client and server agree)", want)
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

// soakCycleCount must match docker-compose.soak.yml's own hardcoded
// -soak-cycles/CYCLE_COUNT values exactly (04-04-PLAN.md Task 2, D-24) —
// kept as one named constant here, rather than duplicated across every
// assertion below, so both places that must agree change together.
const soakCycleCount = 20

// soakContextTimeout bounds TestSoak's own `docker compose up` context —
// generous against soakCycleCount cycles' own observed per-cycle cost (a
// fresh client handshake, a short ping, one HTTP probe, and a graceful
// exit-notify stop, each roughly 10-15s) rather than tuned to one observed
// run's timing.
const soakContextTimeout = 15 * time.Minute

// soakCyclesObservedRe extracts the soak_cycles_observed= field
// test/interop/server's PASS line carries in soak mode
// (test/interop/server/main.go's runSoak, 04-04-PLAN.md Task 1).
var soakCyclesObservedRe = regexp.MustCompile(`soak_cycles_observed=(\d+)`)

// soakGoroutinesRe/soakHeapRe extract the baseline/final goroutine and
// post-GC HeapAlloc fields test/interop/server's PASS line carries in soak
// mode (test/interop/server/main.go's takeSoakSample, 04-04-PLAN.md
// Task 2).
var (
	soakGoroutinesBaselineRe = regexp.MustCompile(`soak_goroutines_baseline=(\d+)`)
	soakGoroutinesFinalRe    = regexp.MustCompile(`soak_goroutines_final=(\d+)`)
	soakHeapBaselineRe       = regexp.MustCompile(`soak_heap_baseline=(\d+)`)
	soakHeapFinalRe          = regexp.MustCompile(`soak_heap_final=(\d+)`)
)

// soakIPsRe extracts the soak_ips= field (comma-separated, one entry per
// cycle in CLOSE order) test/interop/server's PASS line carries in soak
// mode (test/interop/server/main.go's soakTracker.ipHistory, 04-04-PLAN.md
// Task 2's pool-reuse assertion).
var soakIPsRe = regexp.MustCompile(`soak_ips=([0-9.,]+)`)

// soakGoroutineTolerance bounds how much runtime.NumGoroutine may grow
// between the baseline (sampled after cycle 1's session closes) and the
// final sample (sampled after cycle 20's session closes) — 04-04-PLAN.md
// Task 2's own tolerance choice. A per-session goroutine leak
// (04-02-SUMMARY.md's own enumerated pump, keepalive, reneg/expiry ticker,
// reaper, and any lame-duck Conn retransmit loop) shows up as roughly ONE
// extra goroutine PER CYCLE that never exits, so a real leak across 19
// remaining cycles would push the final count up by nearly 19 — this
// tolerance must stay far below that to actually catch one. Observed on a
// real 20-cycle run against this plan's own committed code:
// soak_goroutines_baseline=5 soak_goroutines_final=4 (delta=-1, well
// within noise — the final count can legitimately be LOWER than the
// baseline too, e.g. a transient goroutine alive only at the moment the
// baseline sample was taken) — the margin of 2 absorbs that kind of
// ordinary scheduler/runtime noise without absorbing anything close to a
// real per-cycle leak (Task 3 demonstrates this by deliberately disabling
// one goroutine's own exit path and observing the assertion fail).
const soakGoroutineTolerance = 2

// soakHeapToleranceBytes bounds how much runtime.ReadMemStats' HeapAlloc
// may grow between the baseline and final samples — loose enough to
// absorb Go's allocator behavior (arena growth, GC bookkeeping, one-time
// lazy initialization the runtime itself performs) without absorbing 19
// cycles' worth of retained per-session state (T-04-16: retained sessions,
// wrappers, or lame-duck slots). Observed on real 20-cycle runs against
// this plan's own committed code: two clean runs showed
// soak_heap_baseline/final deltas of +38240 and +40688 bytes (~37-40 KiB)
// — ordinary allocator noise. 256 KiB is roughly 6-7x that noise, generous
// run-to-run headroom, while sitting well below what deliberately
// retaining all 20 cycles' own closed *ovpn.Session values (each carrying
// its own TLS conn, ctrlconn buffers, and data-channel key material)
// actually produced when Task 3 demonstrated this assertion failing:
// delta=+621224 bytes (~606 KiB) — comfortably over this tolerance,
// confirming it is tight enough to catch a real per-session heap leak
// without flagging ordinary run-to-run noise.
const soakHeapToleranceBytes = 256 * 1024 // 256 KiB

// soakMaxDistinctIPs bounds how many DISTINCT tunnel IPs may appear across
// all soakCycleCount cycles (04-04-PLAN.md Task 2's pool-reuse assertion,
// T-04-17): this harness serves exactly one client at a time, so every
// cycle's Close (WR-04, session.go:491-511) must release its IP back to
// the pool before the next cycle's OnSession allocates again — a
// regression that stopped releasing IPs would climb toward
// soakCycleCount distinct addresses instead of reusing the same handful.
const soakMaxDistinctIPs = 2

// TestSoak is 04-04-PLAN.md's own verification, and ROADMAP Phase 4
// success criterion 3's proof: a single long-lived server process serves
// soakCycleCount real connect/use/clean-disconnect cycles from one real,
// unmodified OpenVPN 2.6 client, every cycle reaching tunnel-up and ending
// through explicit-exit-notify. It is deliberately its own test function,
// not folded into the scenarios table TestInteropScenarios drives
// (04-04-PLAN.md's key_links) — `make test` and `make interop` never
// invoke it; only `make soak` (04-04-PLAN.md Task 2) does, via its own
// long timeout.
func TestSoak(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	interopDir := filepath.Join(root, "test", "interop")

	if err := os.MkdirAll(filepath.Join(interopDir, "captures"), 0o755); err != nil {
		t.Fatalf("create captures dir: %v", err)
	}

	// explicit-exit-notify (via cmd/gentestpki -client-directive, the same
	// mechanism 04-03-PLAN.md Task 3 established) is what lets each cycle's
	// clean disconnect close the server's Session promptly through the
	// existing OCC_EXIT teardown path (04-02-PLAN.md) rather than the 60s
	// idle-reap timer — without it, 20 cycles in Task 2 would each cost a
	// full reap window instead of a couple of seconds.
	sc := scenario{
		name:             "soak",
		profile:          "small",
		composeOverlay:   "docker-compose.soak.yml",
		contextTimeout:   soakContextTimeout,
		clientDirectives: []string{"explicit-exit-notify 1"},
	}

	res := runScenario(root, interopDir, sc)
	t.Log(res.composeOut)

	if res.composeErr != nil {
		t.Fatalf("docker compose up did not exit cleanly — see log above: %v", res.composeErr)
	}

	assertServerStaysUnprivileged(t, res)
	assertSoakCyclesObserved(t, res, soakCycleCount)
	assertSoakProbesOK(t, res, soakCycleCount)
	assertSoakGoroutinesFlat(t, res)
	assertSoakHeapFlat(t, res)
	assertSoakIPsReused(t, res)
}

// assertSoakCyclesObserved is 04-04-PLAN.md Task 1's core proof: the
// server's own soak_cycles_observed= PASS-line field must equal EXACTLY
// want (never merely "at least") — a server that never observed the
// cycles, or that stopped early on a partial deadline, must fail this
// assertion rather than passing vacuously (T-04-18, this plan's own threat
// register).
func assertSoakCyclesObserved(t *testing.T, res scenarioResult, want int) {
	t.Helper()

	m := soakCyclesObservedRe.FindStringSubmatch(res.composeOut)
	if m == nil {
		t.Fatal("server output does not contain a parsable soak_cycles_observed= field — see log above")
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse soak_cycles_observed=%q: %v", m[1], err)
	}
	if got != want {
		t.Fatalf("server output reports soak_cycles_observed=%d, want exactly %d — see log above", got, want)
	}
	t.Logf("server observed %d soak cycles", got)
}

// assertSoakProbesOK requires every cycle's own http_landing_cN probe
// (entrypoint.sh's run_soak_cycles) to report result=ok, proving each
// cycle actually reached a working tunnel and not merely that the server
// counted an open/close pair.
func assertSoakProbesOK(t *testing.T, res scenarioResult, cycles int) {
	t.Helper()

	for i := 1; i <= cycles; i++ {
		assertProbe(t, res, fmt.Sprintf("http_landing_c%d", i), true)
	}
}

// parseSoakUint extracts and parses the first capture group re matches
// against res.composeOut, failing the test with a descriptive message if
// the field is missing or unparsable — shared by the four soak-flatness
// field extractions below.
func parseSoakUint(t *testing.T, res scenarioResult, re *regexp.Regexp, field string) uint64 {
	t.Helper()
	m := re.FindStringSubmatch(res.composeOut)
	if m == nil {
		t.Fatalf("server output does not contain a parsable %s= field — see log above", field)
	}
	v, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatalf("parse %s=%q: %v", field, m[1], err)
	}
	return v
}

// assertSoakGoroutinesFlat is 04-04-PLAN.md Task 2's goroutine flatness
// proof (T-04-15 in this plan's own threat register): the final
// runtime.NumGoroutine sample (after cycle 20's session closes) must be
// within soakGoroutineTolerance of the baseline (after cycle 1's session
// closes) — proving no per-session goroutine accumulates across 20 real
// connect/disconnect cycles.
func assertSoakGoroutinesFlat(t *testing.T, res scenarioResult) {
	t.Helper()

	baseline := parseSoakUint(t, res, soakGoroutinesBaselineRe, "soak_goroutines_baseline")
	final := parseSoakUint(t, res, soakGoroutinesFinalRe, "soak_goroutines_final")

	var delta int64
	if final >= baseline {
		delta = int64(final - baseline)
	} else {
		delta = -int64(baseline - final)
	}
	if delta > soakGoroutineTolerance || delta < -soakGoroutineTolerance {
		t.Fatalf(
			"goroutine count grew from baseline=%d to final=%d (delta=%d), want within +/-%d — a per-session goroutine is likely leaking across cycles (T-04-15) — see log above",
			baseline, final, delta, soakGoroutineTolerance,
		)
	}
	t.Logf("goroutine count: baseline=%d final=%d (delta=%d, within +/-%d)", baseline, final, delta, soakGoroutineTolerance)
}

// assertSoakHeapFlat is 04-04-PLAN.md Task 2's post-GC HeapAlloc flatness
// proof (T-04-16 in this plan's own threat register): the final HeapAlloc
// sample must be within soakHeapToleranceBytes of the baseline — proving
// no per-session heap state (sessions, wrappers, lame-duck slots) is
// retained across 20 real connect/disconnect cycles.
func assertSoakHeapFlat(t *testing.T, res scenarioResult) {
	t.Helper()

	baseline := parseSoakUint(t, res, soakHeapBaselineRe, "soak_heap_baseline")
	final := parseSoakUint(t, res, soakHeapFinalRe, "soak_heap_final")

	var delta int64
	if final >= baseline {
		delta = int64(final - baseline)
	} else {
		delta = -int64(baseline - final)
	}
	if delta > soakHeapToleranceBytes || delta < -soakHeapToleranceBytes {
		t.Fatalf(
			"post-GC HeapAlloc grew from baseline=%d to final=%d bytes (delta=%d), want within +/-%d bytes — per-session heap state is likely being retained across cycles (T-04-16) — see log above",
			baseline, final, delta, soakHeapToleranceBytes,
		)
	}
	t.Logf("post-GC HeapAlloc: baseline=%d final=%d bytes (delta=%d, within +/-%d)", baseline, final, delta, soakHeapToleranceBytes)
}

// assertSoakIPsReused is 04-04-PLAN.md Task 2's pool-reuse proof
// (T-04-17): the soak_ips= field's comma-separated list (one assigned
// tunnel IP per cycle, in close order) must contain at most
// soakMaxDistinctIPs distinct addresses across all soakCycleCount cycles —
// evidence that Close released each cycle's allocation back to the pool
// (WR-04's ordering) rather than exhausting the range.
func assertSoakIPsReused(t *testing.T, res scenarioResult) {
	t.Helper()

	m := soakIPsRe.FindStringSubmatch(res.composeOut)
	if m == nil {
		t.Fatal("server output does not contain a parsable soak_ips= field — see log above")
	}
	ips := strings.Split(m[1], ",")
	if len(ips) != soakCycleCount {
		t.Fatalf("soak_ips= lists %d addresses, want exactly %d (one per cycle) — see log above", len(ips), soakCycleCount)
	}

	distinct := make(map[string]bool, len(ips))
	for _, ip := range ips {
		distinct[ip] = true
	}
	if len(distinct) > soakMaxDistinctIPs {
		t.Fatalf(
			"soak_ips= contains %d distinct addresses across %d cycles (%v), want at most %d — the tunnel-IP pool may not be releasing addresses on Close (T-04-17) — see log above",
			len(distinct), soakCycleCount, ips, soakMaxDistinctIPs,
		)
	}
	t.Logf("tunnel IPs across %d cycles: %d distinct address(es) (%v), within the %d-address reuse bound", soakCycleCount, len(distinct), ips, soakMaxDistinctIPs)
}
