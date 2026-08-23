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

// TestRealClientFirstContact is Phase 1 plan 01-02's tracer verification: a
// real, unmodified OpenVPN 2.6 client's P_CONTROL_HARD_RESET_CLIENT_V2 is
// authenticated and answered by the library, and the client then sends at
// least one P_CONTROL_V1 packet from the same session — proving the real
// client accepted the server's reset rather than retrying its own. The pass
// condition is entirely protocol-event-based (test/interop/server's own
// opcode observation, see its "PASS:" log line in harnessComposeOut below,
// and its non-zero exit on timeout) — this test never greps OpenVPN client
// log text, which RESEARCH Open Question 2 and the plan's own prohibitions
// flag as a vacuous assertion.
func TestRealClientFirstContact(t *testing.T) {
	t.Log(harnessComposeOut)
	if harnessComposeErr != nil {
		t.Fatalf("docker compose up did not exit cleanly — the server did not observe a P_CONTROL_V1 from the accepted reset session before its deadline: %v", harnessComposeErr)
	}
}
