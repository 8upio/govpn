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
