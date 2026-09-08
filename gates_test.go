// gates_test.go turns this phase's own declared prohibitions
// (must_haves.prohibitions across 02-01 through 02-04's plans) into a
// fast-tier test wired into the default Make target and the CI fast job,
// so a regression fails a normal `go test` run rather than sitting in a
// document nobody greps (02-04-PLAN.md Task 3). No build tag, no Docker.
//
// Every check below walks the repository with filepath.WalkDir and parses
// Go source with go/parser + go/ast rather than matching raw text: a raw
// text search for, say, "ExportKeyingMaterial" would also flag this
// project's own documentation of why that API is forbidden (CLAUDE.md's
// "What NOT to Use" table, RESEARCH.md's Alternatives Considered row, and
// this very file's own doc comments) — an AST walk matches call syntax,
// never prose or comments.
package ovpn

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skipDir reports whether name is a directory this walk must never descend
// into: .git (not source), .planning (this project's own planning
// documents, which legitimately discuss and name every forbidden
// construction by design), and testdata (committed golden vectors and
// throwaway keys, asserted separately by TestPhase2GoldenCorpusIsTestOnly
// below rather than walked as Go source).
func skipDir(name string) bool {
	switch name {
	case ".git", ".planning", "testdata":
		return true
	default:
		return false
	}
}

// walkGoFiles calls fn for every .go file under root, skipping skipDir's
// directories and gates_test.go itself — the one _test.go file that exists
// only to assert these prohibitions, not to be walked by them (avoids this
// file's own doc comments, which necessarily discuss every forbidden
// construction by name, being mistaken for a violation of the checks below
// that inspect declarations/imports/calls rather than comments).
func walkGoFiles(t *testing.T, fn func(path string, file *ast.File, fset *token.FileSet)) {
	t.Helper()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if filepath.Base(path) == "gates_test.go" {
			return nil
		}

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		fn(path, file, fset)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
}

// TestPhase2NoThirdPartyDependencies asserts go.mod stays stdlib-only: no
// `require` directive, no `replace` directive — the module line and the go
// directive are the only non-blank content. Reads go.mod directly rather
// than shelling out to `go list` (T-02-SC), so this runs with no network
// and no module cache warm-up, in a clean CI container.
func TestPhase2NoThirdPartyDependencies(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "module ") || strings.HasPrefix(trimmed, "go ") {
			continue
		}
		t.Fatalf(
			"go.mod contains %q — the core module and its tests stay stdlib-only (CLAUDE.md's Dependencies constraint: \"any third-party dependency needs explicit justification and discussion before adoption\"); only a `module` line and a `go` directive are permitted",
			trimmed,
		)
	}
}

// exportKeyingMaterialMethod is the exact TLS 1.3-native keying-material
// export method CLAUDE.md's "What NOT to Use" table forbids for
// data-channel key derivation: a different construction (RFC 5705) than
// OpenVPN's own Key Method 2 PRF, which would produce keys a real client
// can never derive — a silent failure that only surfaces as undecryptable
// traffic (RESEARCH.md's Alternatives Considered row).
const exportKeyingMaterialMethod = "ExportKeyingMaterial"

// TestPhase2NoTLSKeyingMaterialExport asserts no .go file outside
// .planning/ and testdata/ calls the crypto/tls connection-state
// keying-material export method — matching a selector-expression call
// whose selector is exportKeyingMaterialMethod (call syntax), never
// prose: this project's own documentation (CLAUDE.md, RESEARCH.md, this
// file's own doc comment above) all NAME the forbidden API as part of
// explaining why it is forbidden, and a raw text search would flag its own
// rationale as a violation.
func TestPhase2NoTLSKeyingMaterialExport(t *testing.T) {
	walkGoFiles(t, func(path string, file *ast.File, fset *token.FileSet) {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == exportKeyingMaterialMethod {
				pos := fset.Position(call.Pos())
				t.Errorf(
					"%s:%d: calls .%s() — this is TLS's own RFC 5705 keying-material export, a different construction from OpenVPN's own Key Method 2 PRF, and would produce keys a real OpenVPN client can never derive (a silent failure that only surfaces as undecryptable data-channel traffic). See CLAUDE.md's \"What NOT to Use\" table and internal/keyderiv's own hand-rolled openvpn_PRF.",
					pos.Filename, pos.Line, exportKeyingMaterialMethod,
				)
			}
			return true
		})
	})
}

// weakHashImportPaths are the two stdlib packages this project's own
// Key Method 2 PRF (internal/keyderiv, RFC 2246 §5.6.4.1) mandates for
// wire compatibility with a real OpenVPN client — flagged by gosec's
// G401 (crypto/md5) and G505 (crypto/sha1) rules as weak crypto in
// general, correctly, but a false positive here: these are label-mixing
// PRF components, not this project's security boundary (that's TLS plus
// AES-256-GCM). CLAUDE.md's Development Tools row calls for an inline
// //nolint:gosec annotation with a written rationale at the import site,
// never a global rule disable.
var weakHashImportPaths = map[string]bool{
	"crypto/md5":  true,
	"crypto/sha1": true,
}

// TestPhase2WeakHashImportsAreAnnotated asserts every file importing
// crypto/md5 or crypto/sha1 carries a linter-suppression annotation naming
// both G401 and G505 somewhere in the file (the written rationale
// CLAUDE.md's Development Tools row requires), and that no repository-level
// linter configuration file disables those rules wholesale — the failure
// mode CLAUDE.md explicitly calls out: the suppression belongs at the
// import site with a written reason, so the rule keeps working everywhere
// else in the codebase.
func TestPhase2WeakHashImportsAreAnnotated(t *testing.T) {
	walkGoFiles(t, func(path string, file *ast.File, fset *token.FileSet) {
		importsWeakHash := false
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if weakHashImportPaths[importPath] {
				importsWeakHash = true
				break
			}
		}
		if !importsWeakHash {
			return
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		if !strings.Contains(text, "G401") || !strings.Contains(text, "G505") {
			t.Errorf(
				"%s imports crypto/md5 and/or crypto/sha1 but does not carry a linter-suppression annotation naming both G401 and G505 with a written rationale — see internal/keyderiv/prf.go's own import-site //nolint:gosec comments for the established pattern (CLAUDE.md's Development Tools row)",
				path,
			)
		}
	})

	assertNoGlobalGosecDisable(t)
}

// gosecDisablingConfigFiles are the linter configuration file names this
// project might introduce; none exist yet, but the check runs regardless
// so a future config file that disables G401/G505 (or gosec entirely)
// wholesale is caught, not merely relied on by convention never to
// appear.
var gosecDisablingConfigFiles = []string{".golangci.yml", ".golangci.yaml", ".golangci.toml", ".golangci.json"}

func assertNoGlobalGosecDisable(t *testing.T) {
	t.Helper()
	for _, name := range gosecDisablingConfigFiles {
		data, err := os.ReadFile(name)
		if err != nil {
			continue // not present — nothing to check
		}
		text := strings.ToLower(string(data))
		// A crude but sufficient signal: any linter config that both
		// mentions gosec and mentions "disable" is worth a human's eyes,
		// since this project's own policy (CLAUDE.md) is per-import-site
		// //nolint:gosec annotations, never a config-level rule disable.
		if strings.Contains(text, "gosec") && strings.Contains(text, "disable") {
			t.Errorf(
				"%s mentions both \"gosec\" and \"disable\" — CLAUDE.md's Development Tools row requires weak-hash suppressions to live at the import site with a written rationale, never as a repository-level linter rule disable; review this config file's gosec/G401/G505 handling",
				name,
			)
		}
	}
}

// epochIdentifierSubstring flags any declared const or type name that
// mentions "epoch" (case-insensitive) — the newer AEAD data-channel packet
// format (16-bit epoch + 48-bit counter, OpenVPN 2.7 development branch)
// this project's v1 scope explicitly excludes (D-09, CONTEXT.md's Deferred
// Ideas). RESEARCH.md's own State of the Art table documents why this
// format is out of scope BY NAME, so this check inspects declared
// identifiers, not prose or comments — matching only what a future
// implementation attempt would actually introduce into the type system.
const epochIdentifierSubstring = "epoch"

// TestPhase2NoEpochDataFormat asserts no .go file declares an epoch-format
// packet-ID constant or a 48-bit counter type: classic non-epoch only
// (D-09). The classic short-form packet ID this project actually
// implements (internal/datachan's 4-byte explicit packet-id, RESEARCH
// Pattern 5) never has "epoch" in its name anywhere in this codebase, so
// this check has zero legitimate matches to exclude.
func TestPhase2NoEpochDataFormat(t *testing.T) {
	check := func(path string, name string, pos token.Position) {
		if strings.Contains(strings.ToLower(name), epochIdentifierSubstring) {
			t.Errorf(
				"%s:%d: declares %q — the epoch data-channel packet-ID format (16-bit epoch + 48-bit counter) is out of v1 scope (D-09, CONTEXT.md Deferred Ideas); this project implements the classic non-epoch, short-form (4-byte) packet ID only",
				pos.Filename, pos.Line, name,
			)
		}
	}

	walkGoFiles(t, func(path string, file *ast.File, fset *token.FileSet) {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.TYPE) {
				continue
			}
			for _, spec := range gd.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					for _, name := range s.Names {
						check(path, name.Name, fset.Position(name.Pos()))
					}
				case *ast.TypeSpec:
					check(path, s.Name.Name, fset.Position(s.Name.Pos()))
				}
			}
		}
	})
}

// TestPhase2GoldenCorpusIsTestOnly asserts testdata/golden/README.md
// contains a provenance statement declaring the committed keys throwaway,
// and that no committed key file (*.key) lives outside testdata/ — the
// golden corpus's own committed key material (tls-crypt.key,
// data-channel.key) must never be mistaken for anything protecting real
// traffic (T-02-20).
func TestPhase2GoldenCorpusIsTestOnly(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("testdata", "golden", "README.md"))
	if err != nil {
		t.Fatalf("read testdata/golden/README.md: %v", err)
	}
	if !strings.Contains(strings.ToLower(string(readme)), "throwaway") {
		t.Error("testdata/golden/README.md does not contain a provenance statement declaring the committed key material throwaway (expected the word \"throwaway\" somewhere in the file)")
	}

	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// .git/.planning are never source; test/interop/pki and
			// test/interop/captures are .gitignore'd, locally-generated
			// per-run PKI/capture output (this project's own
			// .gitignore, "Never commit generated tls-crypt/PKI
			// material") — real on disk during/after a local `make
			// interop` run, but never committed, so they must not be
			// walked by a check whose own stated scope is committed key
			// files.
			if path != "." && (d.Name() == ".git" || d.Name() == ".planning" || d.Name() == "pki" || d.Name() == "captures") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".key") {
			return nil
		}
		rel, relErr := filepath.Rel(".", path)
		if relErr != nil {
			rel = path
		}
		if !strings.HasPrefix(rel, "testdata"+string(filepath.Separator)) {
			t.Errorf("%s: a committed key file exists outside testdata/ — every committed key must come from the throwaway interop PKI/data-channel material under testdata/golden/ (T-02-20)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository for *.key files: %v", err)
	}
}

// Phase 3's own standing prohibitions (03-01-PLAN.md Task 3), turned into
// assertions matching gates_test.go's own AST-based discipline (file
// header, lines 1-13): a raw text search would flag this project's own
// planning documents and doc comments, which name every forbidden
// construction by design when explaining why it is forbidden.

// corePackage / coreInternalPrefix / netstackPackagePrefix are the import
// paths the Phase 3 gates below check the dependency-direction boundary
// against.
const (
	corePackage           = "github.com/8upio/govpn"
	coreInternalPrefix    = "github.com/8upio/govpn/internal/"
	netstackPackagePrefix = "github.com/8upio/govpn/netstack"
)

// isUnderDir reports whether the walked path lies under dir (a
// slash-terminated, repo-root-relative prefix such as "netstack/") on any
// OS, normalizing path separators first.
func isUnderDir(path, dir string) bool {
	return strings.HasPrefix(filepath.ToSlash(path), dir)
}

// TestPhase3NetstackDoesNotImportCoreLibrary asserts D-01/D-18: no file
// under netstack/ imports the core ovpn module or anything under its
// internal/ tree. The netstack proves the Session boundary is clean by
// consuming a locally-declared structural interface (D-01/D-18), and
// RESEARCH.md Pitfall 4: TCP sequence numbers must never be confused with
// the control-channel reliability, tls-crypt, or data-channel packet-ID
// spaces those internal packages own.
func TestPhase3NetstackDoesNotImportCoreLibrary(t *testing.T) {
	walkGoFiles(t, func(path string, file *ast.File, fset *token.FileSet) {
		if !isUnderDir(path, "netstack/") {
			return
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if importPath == corePackage || strings.HasPrefix(importPath, coreInternalPrefix) {
				pos := fset.Position(imp.Pos())
				t.Errorf(
					"%s:%d: imports %q — netstack must never import the core ovpn module or its internal/ packages (D-01/D-18: the netstack proves the Session boundary is clean by consuming a locally-declared structural interface; RESEARCH.md Pitfall 4: TCP sequence numbers must never be confused with the control-channel reliability, tls-crypt, or data-channel packet-ID spaces those internal packages own)",
					pos.Filename, pos.Line, importPath,
				)
			}
		}
	})
}

// TestPhase3CoreDoesNotImportNetstack asserts the dependency arrow points
// one way only: an embedder (examples/, test/) imports both ovpn and
// netstack, but the core library and its internal packages import
// neither (D-01).
func TestPhase3CoreDoesNotImportNetstack(t *testing.T) {
	embedderDirs := []string{"netstack/", "examples/", "test/"}

	walkGoFiles(t, func(path string, file *ast.File, fset *token.FileSet) {
		for _, dir := range embedderDirs {
			if isUnderDir(path, dir) {
				return
			}
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if importPath == netstackPackagePrefix || strings.HasPrefix(importPath, netstackPackagePrefix+"/") {
				pos := fset.Position(imp.Pos())
				t.Errorf(
					"%s:%d: imports %q — the dependency arrow points one way only: an embedder imports both ovpn and netstack, but the core library and its internal packages import neither (D-01)",
					pos.Filename, pos.Line, importPath,
				)
			}
		}
	})
}

// TestPhase3StdlibOnlyImports asserts every import in every walked .go
// file is either a standard-library path or is prefixed
// github.com/8upio/govpn — no gVisor netstack, no TUN/TAP library, no
// third-party packet library anywhere in the module (CLAUDE.md's "What
// NOT to Use" table, D-16). "Standard-library path" is detected
// structurally: the first path segment of a stdlib import never contains
// a dot, while every module path does — this single check subsumes the
// whole "What NOT to Use" list and keeps working for names nobody has
// thought of yet. test/interop/'s own tooling is walked by this too and
// is currently stdlib-only; if a future plan adopts a packet library for
// test assertions it must live in a separate module with its own go.mod
// (CLAUDE.md's own stated policy), not be excepted here.
// serverServiceBlock isolates test/interop/docker-compose.yml's server:
// service block — from its own 2-space-indented "  server:" key line up to
// (but excluding) the next 2-space-indented top-level service key —
// following this file's own header-comment precedent (line 1-13) of
// reading a specific non-Go file with plain text handling rather than
// pulling in a YAML-parsing dependency this project doesn't otherwise need.
func serverServiceBlock(t *testing.T, composeYAML string) string {
	t.Helper()
	lines := strings.Split(composeYAML, "\n")

	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "  server:") {
			start = i
			break
		}
	}
	if start == -1 {
		t.Fatal("test/interop/docker-compose.yml does not contain a top-level \"  server:\" service key")
	}

	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" {
			continue
		}
		indent := len(line) - len(trimmed)
		if indent == 2 {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// stripYAMLCommentLines drops every line whose first non-space character is
// '#' — the server service block's own comments (docker-compose.yml:14-21)
// NAME every one of the forbidden keys below as part of explaining why they
// are deliberately absent, so a naive substring scan over the raw block
// would flag that rationale as a violation. This mirrors the hazard this
// file's own header comment already documents for AST versus raw text
// matching elsewhere in this file — here applied to YAML instead of Go.
func stripYAMLCommentLines(block string) string {
	var kept []string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// TestPhase3ServerContainerRequestsNoPrivileges is 03-06-PLAN.md Task 3's
// static gate: test/interop/docker-compose.yml's server service block, AS
// COMMITTED, must declare no capability-add key, no devices key, and no
// privileged mode, and must still pin a non-root user: value. This is
// independent of test/interop/interop_test.go's assertServerStaysUnprivileged,
// which re-asserts the container's posture AS LAUNCHED via `docker
// inspect` — the two fail independently, one on the file, one on the
// running container, and this one runs on every `make test` with no Docker
// required (the `gates` target's filter already matches
// 'TestPhase2|TestPhase3', widened by 03-01-PLAN.md Task 3).
func TestPhase3ServerContainerRequestsNoPrivileges(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("test", "interop", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read test/interop/docker-compose.yml: %v", err)
	}

	block := serverServiceBlock(t, string(data))
	stripped := stripYAMLCommentLines(block)

	for _, forbidden := range []string{"cap_add:", "devices:", "privileged:"} {
		if strings.Contains(stripped, forbidden) {
			t.Errorf(
				"test/interop/docker-compose.yml's server service block declares %q — the server must run entirely unprivileged (no added capabilities, no device mappings, no privileged mode); the client service legitimately needs both because it is the real OpenVPN client creating a kernel tun interface, and that asymmetry must never be mirrored onto the server to make a run pass (T-01-07)",
				forbidden,
			)
		}
	}

	if !strings.Contains(stripped, "user:") {
		t.Error("test/interop/docker-compose.yml's server service block does not declare a user: value — a pinned non-root uid/gid is part of the server's unprivileged posture")
	}
}

// Phase 4's own standing prohibitions (04-01-PLAN.md Task 3), scoped to
// ovpn.go specifically — the single file this phase's own action text and
// acceptance-criteria greps name as the enforcement point for these three
// checks (`grep -n 'tlscrypt.NewWrapper' ovpn.go`, `grep -n 'dataChannelKeyID'
// ovpn.go session.go`) — rather than walkGoFiles's repo-wide sweep, which
// would also flag this package's own test harness files
// (ovpn_test.go/reneg_test.go) for legitimately constructing synthetic
// Conns/Wrappers with test-chosen key-ids that have no locally-computed
// nextKeyID provenance to trace.

// parseGoFile parses exactly one repo-relative .go file, mirroring this
// file's own single-file-read precedent (TestPhase2GoldenCorpusIsTestOnly,
// TestPhase3ServerContainerRequestsNoPrivileges) rather than walkGoFiles's
// whole-repository sweep.
func parseGoFile(t *testing.T, path string) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return file, fset
}

// TestPhase4RenegotiationNeverRepeatsPushExchange asserts runRenegotiation's
// body contains no call to performPushExchange or pool.allocate, and no
// assignment to the session's assigned IP or peer-id fields — the
// renegotiation driver must stop after Key Method 2 and never repeat the
// one-shot PUSH_REQUEST/PUSH_REPLY exchange or reallocate the tunnel
// IP/peer-id (04-RESEARCH.md Pattern 4, Anti-Pattern 2).
func TestPhase4RenegotiationNeverRepeatsPushExchange(t *testing.T) {
	file, fset := parseGoFile(t, "ovpn.go")
	found := false
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "runRenegotiation" || fd.Body == nil {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "performPushExchange":
					pos := fset.Position(node.Pos())
					t.Errorf(
						"%s:%d: runRenegotiation calls performPushExchange — renegotiation must never repeat the PUSH_REQUEST/PUSH_REPLY exchange (04-RESEARCH.md Pattern 4, Anti-Pattern 2)",
						pos.Filename, pos.Line,
					)
				case "allocate":
					pos := fset.Position(node.Pos())
					t.Errorf(
						"%s:%d: runRenegotiation calls .allocate() — renegotiation must never allocate a new tunnel IP/peer-id from the pool (Anti-Pattern 2)",
						pos.Filename, pos.Line,
					)
				}
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					if sel.Sel.Name == "assignedIP" || sel.Sel.Name == "peerID" {
						pos := fset.Position(node.Pos())
						t.Errorf(
							"%s:%d: runRenegotiation assigns to .%s — renegotiation must never write the session's assigned IP or peer-id; those are fixed for the session's whole lifetime (Anti-Pattern 2)",
							pos.Filename, pos.Line, sel.Sel.Name,
						)
					}
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("ovpn.go declares no runRenegotiation function to check")
	}
}

// TestPhase4RenegotiationReusesSessionTLSCryptWrapper asserts ovpn.go
// constructs a tls-crypt Wrapper (tlscrypt.NewWrapper) in exactly two
// functions — Serve's fail-fast validation and handleDatagram's
// per-session allocation — and nowhere else, so a renegotiation can never
// accidentally allocate a fresh Wrapper instead of reusing sess.wrapper
// (Anti-Pattern 1: a fresh Wrapper breaks the tls-crypt packet-id
// continuum the real client expects within one session; T-04-05).
func TestPhase4RenegotiationReusesSessionTLSCryptWrapper(t *testing.T) {
	file, fset := parseGoFile(t, "ovpn.go")
	allowed := map[string]bool{"Serve": true, "handleDatagram": true}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "tlscrypt" || sel.Sel.Name != "NewWrapper" {
				return true
			}
			if !allowed[fd.Name.Name] {
				pos := fset.Position(call.Pos())
				t.Errorf(
					"%s:%d: %s calls tlscrypt.NewWrapper — a fresh tls-crypt Wrapper is only ever allocated in Serve's fail-fast validation and handleDatagram's per-session allocation; renegotiation must reuse the session's existing sess.wrapper (Anti-Pattern 1, T-04-05)",
					pos.Filename, pos.Line, fd.Name.Name,
				)
			}
			return true
		})
	}
}

// TestPhase4KeyIDNeverTrustedFromPeer asserts every construction of a
// renegotiation Conn (ctrlconn.NewWithKeyID) in ovpn.go passes a key-id
// this same function locally computed via a call to nextKeyID — never a
// peer-supplied packet field (T-04-02, ssl.c:3983-3990: the server
// computes the expected next key-id itself and treats any other value as
// a hard error, not something to trust from the wire).
func TestPhase4KeyIDNeverTrustedFromPeer(t *testing.T) {
	file, fset := parseGoFile(t, "ovpn.go")
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}

		// Identifiers this function assigned directly from a call to
		// nextKeyID — the only source of a locally-computed key-id.
		localNextKeyID := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != len(assign.Rhs) {
				return true
			}
			for i, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				callee, ok := call.Fun.(*ast.Ident)
				if !ok || callee.Name != "nextKeyID" {
					continue
				}
				if lhsIdent, ok := assign.Lhs[i].(*ast.Ident); ok {
					localNextKeyID[lhsIdent.Name] = true
				}
			}
			return true
		})

		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "ctrlconn" || sel.Sel.Name != "NewWithKeyID" {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			last := call.Args[len(call.Args)-1]
			ident, ok := last.(*ast.Ident)
			if !ok || !localNextKeyID[ident.Name] {
				pos := fset.Position(call.Pos())
				t.Errorf(
					"%s:%d: %s calls ctrlconn.NewWithKeyID with a key-id that is not this function's own locally-computed nextKeyID result — every renegotiation Conn's key-id must come from the server's own local computation, never trusted from a parsed packet field (T-04-02, ssl.c:3983-3990)",
					pos.Filename, pos.Line, fd.Name.Name,
				)
			}
			return true
		})
	}
}

// TestPhase4NoNewModuleDependencies mirrors
// TestPhase2NoThirdPartyDependencies's own go.mod check, re-asserted under
// this phase's own gate name per 04-01-PLAN.md Task 3's action text: this
// phase adds no package-manager installs (T-04-SC).
func TestPhase4NoNewModuleDependencies(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "module ") || strings.HasPrefix(trimmed, "go ") {
			continue
		}
		t.Fatalf(
			"go.mod contains %q — this phase adds no new module dependencies (T-04-SC); the core module and its tests stay stdlib-only",
			trimmed,
		)
	}
}

// isStopChSelector reports whether e is a selector expression ending in
// ".stopCh" — used by TestPhase4TeardownAlwaysFlowsThroughClose to find
// close(...stopCh) call sites regardless of receiver name (s.stopCh,
// sess.stopCh, etc.).
func isStopChSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "stopCh"
}

// TestPhase4TeardownAlwaysFlowsThroughClose asserts that closing a
// session's stopCh, deleting it from Server.sessions/Server.dataSessions,
// and releasing its tunnel IP/peer-id back to the pool all happen ONLY
// from inside Session.closeWithReason's own stopOnce body (or a helper it
// calls, i.e. removeSession) — never from a second, independently-grown
// teardown path (D-22: reaping and exit-notify both flow through the
// existing closeWithReason/stopOnce contract, adding no new coupling).
// closeWithReason is the single teardown funnel every internal teardown
// site now names a CloseReason and calls directly; the exported Close is a
// thin wrapper over it (closeWithReason(CloseReasonEmbedder)) — this gate
// is actually STRENGTHENED by that refactor, not weakened: there is still
// exactly one function in the package allowed to close stopCh, and it is
// now impossible to reach that function without also naming why.
// performPushExchange's own allocate-then-immediately-roll-back-on-error
// calls to pool.release are a narrower, pre-existing exception: they
// release an IP that was allocated moments earlier in the SAME function
// call, before it was ever published anywhere a session teardown could
// observe it — not a teardown path.
func TestPhase4TeardownAlwaysFlowsThroughClose(t *testing.T) {
	allowedStopChClose := map[string]bool{"closeWithReason": true}
	allowedSessionsDelete := map[string]bool{"removeSession": true}
	allowedDataSessionsDelete := map[string]bool{"closeWithReason": true}
	allowedPoolRelease := map[string]bool{"closeWithReason": true, "performPushExchange": true}

	check := func(path string) {
		file, fset := parseGoFile(t, path)
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					if fun.Name == "close" && len(call.Args) == 1 && isStopChSelector(call.Args[0]) {
						if !allowedStopChClose[fd.Name.Name] {
							pos := fset.Position(call.Pos())
							t.Errorf("%s:%d: %s closes stopCh outside Close's stopOnce body (D-22)", pos.Filename, pos.Line, fd.Name.Name)
						}
					}
					if fun.Name == "delete" && len(call.Args) == 2 {
						if sel, ok := call.Args[0].(*ast.SelectorExpr); ok {
							switch sel.Sel.Name {
							case "sessions":
								if !allowedSessionsDelete[fd.Name.Name] {
									pos := fset.Position(call.Pos())
									t.Errorf("%s:%d: %s deletes from Server.sessions outside Close/removeSession (D-22)", pos.Filename, pos.Line, fd.Name.Name)
								}
							case "dataSessions":
								if !allowedDataSessionsDelete[fd.Name.Name] {
									pos := fset.Position(call.Pos())
									t.Errorf("%s:%d: %s deletes from Server.dataSessions outside Close (D-22)", pos.Filename, pos.Line, fd.Name.Name)
								}
							}
						}
					}
				case *ast.SelectorExpr:
					if fun.Sel.Name == "release" && !allowedPoolRelease[fd.Name.Name] {
						pos := fset.Position(call.Pos())
						t.Errorf("%s:%d: %s calls pool.release outside Close/performPushExchange's own rollback-on-error path (D-22)", pos.Filename, pos.Line, fd.Name.Name)
					}
				}
				return true
			})
		}
	}
	check("session.go")
	check("ovpn.go")
}

// TestPhase4ExitNotifyCheckedOnlyPostDecrypt asserts isExitNotify is called
// from exactly one place in the whole package: inside handleDataPacket,
// after a successful Wrapper.Open — never from handleDatagram or
// handleDataDatagram (or anywhere else), which only ever see ciphertext
// (T-04-06: the exit-notify check must never move earlier than decrypt).
func TestPhase4ExitNotifyCheckedOnlyPostDecrypt(t *testing.T) {
	allowed := map[string]bool{"handleDataPacket": true}

	check := func(path string) {
		file, fset := parseGoFile(t, path)
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != "isExitNotify" {
					return true
				}
				if !allowed[fd.Name.Name] {
					pos := fset.Position(call.Pos())
					t.Errorf(
						"%s:%d: %s calls isExitNotify — the ONLY allowed call site is handleDataPacket, after a successful decrypt (T-04-06); handleDatagram/handleDataDatagram only ever see ciphertext",
						pos.Filename, pos.Line, fd.Name.Name,
					)
				}
				return true
			})
		}
	}
	check("session.go")
	check("ovpn.go")
}

// TestPhase4InteropClientConfigCarriesLifecycleDirectives is 04-03-PLAN.md
// Task 3's own standing gate: the interop scenario table's renegotiation/
// exit-notify entry ("reneg", test/interop/interop_test.go's own
// clientDirectives field) must carry BOTH the shortened-reneg-sec directive
// and the explicit-exit-notify directive in its client directive list — a
// static, AST-based check over that file's source (parsing does not care
// about its own "interop" build tag) so a later edit that quietly drops
// either directive from the scenario table fails `make gates` immediately
// rather than leaving the "reneg" scenario passing vacuously (T-04-11/
// T-04-12: a scenario satisfied by nothing is itself a risk this plan's
// threat register flags).
func TestPhase4InteropClientConfigCarriesLifecycleDirectives(t *testing.T) {
	file, fset := parseGoFile(t, filepath.Join("test", "interop", "interop_test.go"))

	var directives []string
	found := false
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "scenarios" {
				continue
			}
			for _, val := range vs.Values {
				cl, ok := val.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range cl.Elts {
					scLit, ok := elt.(*ast.CompositeLit)
					if !ok {
						continue
					}

					isReneg := false
					var cdLit *ast.CompositeLit
					for _, f := range scLit.Elts {
						kv, ok := f.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if !ok {
							continue
						}
						switch key.Name {
						case "name":
							if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Value == `"reneg"` {
								isReneg = true
							}
						case "clientDirectives":
							if lit, ok := kv.Value.(*ast.CompositeLit); ok {
								cdLit = lit
							}
						}
					}
					if !isReneg {
						continue
					}
					found = true
					if cdLit != nil {
						for _, d := range cdLit.Elts {
							bl, ok := d.(*ast.BasicLit)
							if !ok {
								continue
							}
							directives = append(directives, strings.Trim(bl.Value, `"`))
						}
					}
				}
			}
		}
	}

	if !found {
		t.Fatal("test/interop/interop_test.go's scenarios table declares no \"reneg\" scenario entry to check")
	}

	hasReneg, hasExitNotify := false, false
	for _, d := range directives {
		if strings.HasPrefix(d, "reneg-sec ") {
			hasReneg = true
		}
		if strings.HasPrefix(d, "explicit-exit-notify ") {
			hasExitNotify = true
		}
	}
	pos := fset.Position(file.Pos())
	if !hasReneg {
		t.Errorf("%s: the \"reneg\" scenario's clientDirectives no longer carries a \"reneg-sec \" directive — D-23's renegotiation proof would be untestable against a real client", pos.Filename)
	}
	if !hasExitNotify {
		t.Errorf("%s: the \"reneg\" scenario's clientDirectives no longer carries an \"explicit-exit-notify \" directive — this plan's exit-notify proof would be untestable against a real client", pos.Filename)
	}
}

// TestPhase4SoakSamplesBaselineAfterFirstCycle is 04-04-PLAN.md Task 3's own
// standing gate (T-04-18 in this plan's own threat register): the soak
// harness's baseline sample (test/interop/server/main.go's runSoak) must be
// taken from a goroutine that receives from tracker.firstClosed — the
// completed-first-cycle event — BEFORE ever calling takeSoakSample. A later
// edit that moved the baseline to a cold-start sample (process start,
// before any session has even opened) would make every soak result
// trivially flat, certifying the property it does not check.
func TestPhase4SoakSamplesBaselineAfterFirstCycle(t *testing.T) {
	path := filepath.Join("test", "interop", "server", "main.go")
	file, fset := parseGoFile(t, path)

	var runSoak *ast.FuncDecl
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok && fd.Name.Name == "runSoak" {
			runSoak = fd
		}
	}
	if runSoak == nil {
		t.Fatalf("%s declares no runSoak function to check", path)
	}

	checkedAny := false
	ast.Inspect(runSoak.Body, func(n ast.Node) bool {
		fl, ok := n.(*ast.FuncLit)
		if !ok || fl.Body == nil {
			return true
		}

		firstClosedRecvIdx, takeSampleIdx := -1, -1
		for i, stmt := range fl.Body.List {
			ast.Inspect(stmt, func(inner ast.Node) bool {
				if ue, ok := inner.(*ast.UnaryExpr); ok && ue.Op == token.ARROW {
					if sel, ok := ue.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "firstClosed" && firstClosedRecvIdx == -1 {
						firstClosedRecvIdx = i
					}
				}
				if call, ok := inner.(*ast.CallExpr); ok {
					if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "takeSoakSample" && takeSampleIdx == -1 {
						takeSampleIdx = i
					}
				}
				return true
			})
		}

		if takeSampleIdx == -1 {
			return true // this closure doesn't sample; not the one we're checking
		}
		checkedAny = true
		if firstClosedRecvIdx == -1 || firstClosedRecvIdx >= takeSampleIdx {
			pos := fset.Position(fl.Pos())
			t.Errorf(
				"%s:%d: this closure calls takeSoakSample without first receiving from tracker.firstClosed earlier in the same statement list — the baseline must be sampled after cycle 1 closes, never at process start (T-04-18)",
				pos.Filename, pos.Line,
			)
		}
		return true
	})
	if !checkedAny {
		t.Fatalf("%s's runSoak declares no closure calling takeSoakSample to check the baseline-after-first-cycle ordering against", path)
	}
}

// makefileTargetRecipe extracts the tab-indented recipe lines immediately
// following a "target:" header line in a Makefile's raw text — used by
// TestPhase4SoakIsNotInDefaultTargets below to inspect exactly one
// target's own commands without false-matching an unrelated target that
// merely mentions the same word in a comment elsewhere in the file.
func makefileTargetRecipe(t *testing.T, text, target string) string {
	t.Helper()
	prefix := target + ":"
	inTarget := false
	var recipe []string
	for _, line := range strings.Split(text, "\n") {
		if inTarget {
			if strings.HasPrefix(line, "\t") {
				recipe = append(recipe, line)
				continue
			}
			break
		}
		if strings.HasPrefix(line, prefix) {
			inTarget = true
		}
	}
	if len(recipe) == 0 {
		t.Fatalf("Makefile declares no recipe lines under target %q", target)
	}
	return strings.Join(recipe, "\n")
}

// TestPhase4SoakIsNotInDefaultTargets is 04-04-PLAN.md Task 3's own
// standing gate (T-04-19): the Makefile's `test` and `interop` target
// recipes must never invoke the soak test or the `soak` target itself, and
// .DEFAULT_GOAL must keep pointing at `test` — a soak run costs minutes,
// far more than either of those two targets is meant to cost a developer
// on every invocation.
func TestPhase4SoakIsNotInDefaultTargets(t *testing.T) {
	data, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	text := string(data)

	if !strings.Contains(text, ".DEFAULT_GOAL := test") {
		t.Error("Makefile's .DEFAULT_GOAL no longer points at test — the cheap check must stay reflexive (T-04-19)")
	}

	for _, target := range []string{"test", "interop"} {
		recipe := makefileTargetRecipe(t, text, target)
		if strings.Contains(recipe, "TestSoak") || strings.Contains(recipe, "soak") {
			t.Errorf(
				"Makefile's %q target recipe mentions the soak test/target (%q) — the soak must never run as part of `make test` or `make interop` (T-04-19)",
				target, recipe,
			)
		}
	}
}

// TestPhase4SoakAssertsObservedCycleCount is 04-04-PLAN.md Task 3's own
// standing gate (T-04-18): test/interop/interop_test.go's
// assertSoakCyclesObserved must compare the observed soak_cycles_observed=
// field against its configured "want" argument with a strict inequality
// (!=, never a "got < want" that a server reporting MORE cycles than
// configured could satisfy trivially) and fail the test via Fatalf on
// mismatch — a server that never observed the cycles must not be able to
// pass this assertion.
func TestPhase4SoakAssertsObservedCycleCount(t *testing.T) {
	path := filepath.Join("test", "interop", "interop_test.go")
	file, fset := parseGoFile(t, path)

	var fd *ast.FuncDecl
	for _, decl := range file.Decls {
		f, ok := decl.(*ast.FuncDecl)
		if ok && f.Name.Name == "assertSoakCyclesObserved" {
			fd = f
		}
	}
	if fd == nil {
		t.Fatalf("%s declares no assertSoakCyclesObserved function to check", path)
	}

	hasExactComparison, hasFatal := false, false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if be, ok := n.(*ast.BinaryExpr); ok && be.Op == token.NEQ {
			if ident, ok := be.X.(*ast.Ident); ok && ident.Name == "want" {
				hasExactComparison = true
			}
			if ident, ok := be.Y.(*ast.Ident); ok && ident.Name == "want" {
				hasExactComparison = true
			}
		}
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Fatalf" {
			hasFatal = true
		}
		return true
	})

	pos := fset.Position(fd.Pos())
	if !hasExactComparison {
		t.Errorf("%s:%d: assertSoakCyclesObserved no longer compares the observed count against \"want\" with != — a server reporting a different cycle count than configured must fail this assertion (T-04-18)", pos.Filename, pos.Line)
	}
	if !hasFatal {
		t.Errorf("%s:%d: assertSoakCyclesObserved no longer calls Fatalf on mismatch — a soft failure would let the soak pass vacuously", pos.Filename, pos.Line)
	}
}

func TestPhase3StdlibOnlyImports(t *testing.T) {
	walkGoFiles(t, func(path string, file *ast.File, fset *token.FileSet) {
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if importPath == corePackage || strings.HasPrefix(importPath, corePackage+"/") {
				continue
			}
			firstSegment := importPath
			if idx := strings.Index(importPath, "/"); idx >= 0 {
				firstSegment = importPath[:idx]
			}
			if strings.Contains(firstSegment, ".") {
				pos := fset.Position(imp.Pos())
				t.Errorf(
					"%s:%d: imports %q — a third-party module path (its first path segment %q contains a dot); this project is stdlib-only outside its own module (CLAUDE.md's \"What NOT to Use\" table: no gVisor, no TUN/TAP library, no external packet-decoding library, no golang.org/x/*)",
					pos.Filename, pos.Line, importPath, firstSegment,
				)
			}
		}
	})
}
