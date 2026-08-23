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
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// repoRoot resolves the module root from this test file's own directory
// (test/interop is always exactly two levels below the repo root), so the
// test works regardless of the caller's working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root, err := filepath.Abs(filepath.Join(wd, "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

// testLineWriter streams a subprocess's combined output into t.Log() one
// line at a time as it arrives, rather than buffering everything until the
// process exits — so a hung or slow interop run is still observable in the
// test log, and the human-check step (reading the opcode sequence) has
// real output to read even if the automated assertion below is what
// actually gates pass/fail.
type testLineWriter struct {
	t   testing.TB
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *testLineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		b := w.buf.Bytes()
		idx := bytes.IndexByte(b, '\n')
		if idx < 0 {
			break
		}
		w.t.Log(string(b[:idx]))
		w.buf.Next(idx + 1)
	}
	return len(p), nil
}

func (w *testLineWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		w.t.Log(w.buf.String())
		w.buf.Reset()
	}
}

// generatePKI runs cmd/gentestpki fresh for this test run — a stale PKI
// directory from a previous run must never be silently reused.
func generatePKI(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("go", "run", "./cmd/gentestpki", "-out", filepath.Join("test", "interop", "pki"))
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("gentestpki:\n%s", out)
	}
	if err != nil {
		t.Fatalf("gentestpki failed: %v", err)
	}
}

// composeDown tears the project down unconditionally, including on a
// failing run — deferred via t.Cleanup so it always executes even if the
// test fails partway through.
func composeDown(t *testing.T, interopDir string) {
	t.Helper()
	cmd := exec.Command("docker", "compose", "-f", "docker-compose.yml", "down", "--remove-orphans")
	cmd.Dir = interopDir
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("docker compose down:\n%s", out)
	}
	if err != nil {
		t.Logf("docker compose down returned an error (non-fatal cleanup): %v", err)
	}
}

// TestRealClientFirstContact is Phase 1 plan 01-02's tracer verification: a
// real, unmodified OpenVPN 2.6 client's P_CONTROL_HARD_RESET_CLIENT_V2 is
// authenticated and answered by the library, and the client then sends at
// least one P_CONTROL_V1 packet from the same session — proving the real
// client accepted the server's reset rather than retrying its own. The pass
// condition is entirely protocol-event-based (test/interop/server's own
// opcode observation, see its "PASS:" log line and non-zero exit on
// timeout) — this test never greps OpenVPN client log text, which RESEARCH
// Open Question 2 and the plan's own prohibitions flag as a vacuous
// assertion.
func TestRealClientFirstContact(t *testing.T) {
	root := repoRoot(t)
	interopDir := filepath.Join(root, "test", "interop")

	generatePKI(t, root)

	t.Cleanup(func() { composeDown(t, interopDir) })

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", "docker-compose.yml", "up",
		"--build", "--abort-on-container-exit", "--exit-code-from", "server")
	cmd.Dir = interopDir

	w := &testLineWriter{t: t}
	cmd.Stdout = w
	cmd.Stderr = w

	err := cmd.Run()
	w.flush()

	if err != nil {
		t.Fatalf("docker compose up did not exit cleanly — the server did not observe a P_CONTROL_V1 from the accepted reset session before its deadline: %v", err)
	}
}
