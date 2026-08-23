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
)

// harnessComposeErr/harnessComposeOut hold the single docker-compose-driven
// harness run's result, produced once in TestMain and read by both
// TestRealClientFirstContact and (indirectly, via the pki/captures
// directories it produces) TestCaptureIsFullyTLSCryptWrapped in
// capture_test.go.
//
// The harness run lives in TestMain rather than inside either individual
// test function specifically so it only runs once regardless of which
// test(s) `-run` selects or what order Go picks to run same-package test
// files in (Go compiles/orders source files alphabetically, and
// "capture_test.go" sorts before "interop_test.go" — a test-body-local
// setup in TestRealClientFirstContact would run too late for
// TestCaptureIsFullyTLSCryptWrapped to depend on it).
var (
	harnessComposeErr error
	harnessComposeOut string
)

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
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "interop: resolve repo root:", err)
		os.Exit(1)
	}
	interopDir := filepath.Join(root, "test", "interop")

	// Regenerate the PKI fresh for this run — a stale directory from a
	// previous run must never be silently reused.
	genCmd := exec.Command("go", "run", "./cmd/gentestpki", "-out", filepath.Join("test", "interop", "pki"))
	genCmd.Dir = root
	if out, err := genCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "interop: gentestpki failed: %v\n%s\n", err, out)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	upCmd := exec.CommandContext(ctx, "docker", "compose", "-f", "docker-compose.yml", "up",
		"--build", "--abort-on-container-exit", "--exit-code-from", "server")
	upCmd.Dir = interopDir

	var buf bytes.Buffer
	// Stream live to the test binary's own stdout (visible regardless of
	// -v) and simultaneously capture for TestRealClientFirstContact's
	// per-test log.
	mw := io.MultiWriter(os.Stdout, &buf)
	upCmd.Stdout = mw
	upCmd.Stderr = mw

	harnessComposeErr = upCmd.Run()
	harnessComposeOut = buf.String()

	code := m.Run()

	// Tear down unconditionally, including on a failing run, so the next
	// run starts clean. The bind-mounted pki/captures directories are not
	// affected by `down` and remain on disk for post-mortem inspection.
	downCmd := exec.Command("docker", "compose", "-f", "docker-compose.yml", "down", "--remove-orphans")
	downCmd.Dir = interopDir
	if out, err := downCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "interop: docker compose down: %v\n%s\n", err, out)
	}

	os.Exit(code)
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

// TestRealClientCompletesTLSHandshake is Phase 1 plan 01-03's Task 3
// verification: a real, unmodified OpenVPN 2.6 client completes the full
// TLS handshake against the library with mutual certificate authentication.
// The pass condition is Config.OnSession having fired (test/interop/
// server's own "PASS:" log line, printed only after it also survives
// postHandshakeSurvival past the handshake without erroring on the
// client's post-handshake Key Method 2 application data) and its non-zero
// exit on timeout naming the last protocol state reached.
//
// Every assertion below matches on the generated CommonName strings
// cmd/gentestpki produced (govpn-interop-server / govpn-interop-client)
// rather than on any guessed OpenVPN client log wording — RESEARCH's own
// stated principle for keeping this honest without depending on the real
// client's exact phrasing. The exact matched client line, at the time this
// plan was written, looks like:
//
//	client-1  | ... VERIFY OK: depth=0, CN=govpn-interop-server
//
// If a future OpenVPN client version changes that wording, tighten the
// match here rather than loosening it to something that could pass
// vacuously.
func TestRealClientCompletesTLSHandshake(t *testing.T) {
	t.Log(harnessComposeOut)
	if harnessComposeErr != nil {
		t.Fatalf("docker compose up did not exit cleanly — the server did not observe a completed, stable TLS handshake before its deadline: %v", harnessComposeErr)
	}

	if !strings.Contains(harnessComposeOut, "PASS: session established") {
		t.Fatal("server did not print its PASS line (handshake completed AND survived the post-handshake window) — see log above")
	}

	// The server printed the verified CLIENT CommonName gentestpki
	// generated.
	const wantClientCN = "peer_cn=govpn-interop-client"
	if !strings.Contains(harnessComposeOut, wantClientCN) {
		t.Fatalf("server output does not contain %q — see log above", wantClientCN)
	}

	// The real client's own output contains the SERVER's generated
	// CommonName — the client can only print this after it has parsed and
	// verified the server's certificate chain (this is the direct
	// expression of Phase 1 success criterion 2).
	const wantServerCN = "CN=govpn-interop-server"
	if !strings.Contains(harnessComposeOut, wantServerCN) {
		t.Fatalf("client output does not contain %q — see log above", wantServerCN)
	}

	m := tlsVersionRawRe.FindStringSubmatch(harnessComposeOut)
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

	// The server explicitly logs that it survived the post-handshake
	// window before printing PASS (test/interop/server/main.go); if the
	// client's Key Method 2 application data had disturbed the session,
	// Serve would have exited during that window and PASS would never
	// have printed above.
	if !strings.Contains(harnessComposeOut, "surviving") {
		t.Fatal("server output does not show it entered the post-handshake survival window — see log above")
	}
}
