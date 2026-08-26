---
phase: 03-in-process-termination
plan: "05"
subsystem: examples/tunnelweb
tags: [http, html-template, xss, example, netstack, embedder, ui-spec]

requires:
  - phase: 03-in-process-termination
    provides: "Stack.ListenTCP's accepted net.Conn honoring net/http's deadline/CloseWrite contract, proven with unmodified stdlib http.Serve/http.Client — plan 03-04"
  - phase: 03-in-process-termination
    provides: "Stack.New/Attach/ListenTCP, the local structural Session interface — plan 03-01"
provides:
  - "examples/tunnelweb/site: an importable, stdlib-only http.Handler (Handler(Options)) serving landing/status/about/echo/headers/style.css plus the site's own 404 — testable entirely via net/http/httptest with no tunnel, no netstack, no ovpn import"
  - "examples/tunnelweb: a one-command binary wiring ovpn.NewServer + netstack.New/Attach + stack.ListenTCP + http.Serve, the canonical embedder reference for D-01/D-02/D-09"
affects: [03-06-real-client-verification]

actuals:
  tokens: 14466
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Two-pass html/template rendering: a page's own content template executes first into a buffer (auto-escaping any dynamic value in context), then that already-safe output is wrapped as template.HTML and passed into a shared layout template — preserves html/template's contextual escaping end-to-end while still sharing one header/nav/footer skeleton across every page"
    - "Single site-wide <nav> (with per-link one-line descriptions) lives inside <header> and is reused on every page, rather than a bare compact nav plus a separate descriptive nav on the landing page — satisfies both UI-SPEC's landing-page nav contract and Accessibility Basics' 'nav inside header' rule with one element, not two"
    - "Locked Copywriting Contract strings (echo empty-state body, echo error copy) are declared once as Go constants and threaded through template data rather than hardcoded separately in the template and the test suite — a single source of truth for text that must match verbatim"
    - "http.MaxBytesReader bounds a POST body at read time (roughly double the real message-size ceiling, not unbounded) while the *exact* 4096-byte rule is applied afterward to the decoded form value — separates the DoS-defense bound (approximate, generous) from the UI-SPEC boundary rule (exact, asserted on both sides) so neither has to double as the other"

key-files:
  created:
    - examples/tunnelweb/main.go
    - examples/tunnelweb/README.md
    - examples/tunnelweb/site/site.go
    - examples/tunnelweb/site/pages.go
    - examples/tunnelweb/site/style.css
    - examples/tunnelweb/site/site_test.go

key-decisions:
  - "Single shared <nav> in <header> (not a duplicate descriptive nav on landing) resolves UI-SPEC's landing-page nav-with-descriptions requirement without violating TestSemanticLandmarks' one-nav-per-page assumption — described in the tech-stack patterns above."
  - "Status/echo/headers pages were registered with placeholder content in Task 1's commit (routes return 200, carry the site's header/nav) rather than deferred entirely, so the tracer's own end-to-end claim (every route works) holds from Task 1 forward, exactly as the plan's action text requires; Tasks 2/3 then replaced the placeholders with full implementations in their own commits."
  - "The echo page's error state returns HTTP 200, not 400 (UI-SPEC's explicit instruction): a browser showing a bare 400 body is a worse demo than a page that re-renders with the exact error copy — documented in code so the status code doesn't look like an oversight to a future reviewer."
  - "maxEchoBodyBytesLimit (the http.MaxBytesReader ceiling) is set to roughly double maxEchoMsgBytes (4096) rather than a tight '4096 + a few bytes' bound — enough headroom for the 'msg=' key and ordinary form-encoding overhead while remaining a small, fixed ceiling; the exact 4096-byte accept/reject boundary is enforced independently, after ParseForm, on the decoded value length, so the MaxBytesReader bound never has to be pixel-perfect to keep the boundary test deterministic."

patterns-established:
  - "renderPage(w, status, contentTmpl, title, data) is the one path every handler uses to produce a page: it buffers the content template's output, buffers the layout's output around it, and only writes to the ResponseWriter once both have succeeded — a template execution error produces a clean 500 rather than a half-written page."
  - "Every fallible per-request derivation on the status page (net.SplitHostPort on RemoteAddr, the http.LocalAddrContextKey type assertion) funnels through splitHostPortOrEmDash, which never returns an error to the caller — only emDash on failure — so the handler has no path that can panic or that omits a locked row."

requirements-completed: [XMPL-01]

coverage:
  - id: D1
    description: "go run ./examples/tunnelweb is one command that starts an OpenVPN server embedding ovpn plus netstack and serves the site to any connected tunnel client — no build step, no asset pipeline, no external service"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "go build ./... && go run ./examples/tunnelweb -h (exits 0, lists -pki/-listen/-network/-http-port)"
        status: pass
      - kind: manual_procedural
        ref: "examples/tunnelweb/main.go wires ovpn.NewServer + netstack.New/Attach + stack.ListenTCP + http.Serve in the exact order the plan specifies; full real-client verification is plan 03-06's scope"
        status: pass
    human_judgment: false
  - id: D2
    description: "The site serves a landing page plus exactly 4 subpages (/status, /about, /echo, /headers) via stdlib http.Serve on the netstack TCP listener, and the site binds no OS TCP socket for HTTP — its only listener is stack.ListenTCP"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestAllRoutesReturn200"
        status: pass
      - kind: manual_procedural
        ref: "examples/tunnelweb/main.go: the only http.Server.Serve call is against ln := stack.ListenTCP(httpPort); no net.Listen/net.ListenTCP call exists anywhere in the binary"
        status: pass
    human_judgment: false
  - id: D3
    description: "Every page renders with zero network access beyond the tunnel — one stylesheet at /style.css, no CDN font/script/analytics/favicon, zero JavaScript anywhere"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestNoExternalOriginsReferenced"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestNoScriptElements"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoNoJavaScript"
        status: pass
    human_judgment: false
  - id: D4
    description: "Landing (/) shows a display-sized h1, one sentence stating no TUN device/no CAP_NET_ADMIN, and a nav of exactly 4 links with one-line descriptions; About (/about) states the same fact in plain language"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestLandingPageStructure"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestLandingStatesTheCoreClaim"
        status: pass
    human_judgment: false
  - id: D5
    description: "Echo (/echo) HTML-escapes the submitted value so a submitted <script> string renders as text, never as markup, and Headers (/headers) does the same for every reflected header value"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoEscapesSubmittedValue"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestHeadersPageEscapesValues"
        status: pass
    human_judgment: false
  - id: D6
    description: "Headers (/headers) lists every parsed header in a two-column table with th scope=col, sorted alphabetically for deterministic output, under the exact '{N} headers received' heading, with a working empty-state backstop"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestHeadersPageSorted"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestHeadersPageHeadingCount"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestHeadersPageEmptyBackstop"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestTableSemantics"
        status: pass
    human_judgment: false
  - id: D7
    description: "Status (/status) renders every UI-SPEC locked field (assigned tunnel IP, server tunnel IP, cipher, tunnel: active) from live request data, with an em-dash fallback that never omits a row or panics on a malformed RemoteAddr"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestStatusPageLockedFields"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestStatusPageDerivesAddresses"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestStatusPagePartialFallback"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestStatusValuesUseMonospace"
        status: pass
    human_judgment: false
  - id: D8
    description: "Echo (/echo) round-trips a message with a plain HTML form POST and full page reload, a 4KB bound enforced at read time and asserted on both sides of the boundary, and the exact Copywriting Contract empty/error strings"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoRoundTrip"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoAtSizeBoundary"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoEmptyBodyError"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoOversizedBodyError"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoEmptyState"
        status: pass
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestEchoIsStateless"
        status: pass
    human_judgment: false
  - id: D9
    description: "examples/tunnelweb/site does not import github.com/8upio/govpn — it is a pure http.Handler testable with httptest alone, and go test -race ./examples/tunnelweb/site/ completes in under 5 seconds"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "go list -deps ./examples/tunnelweb/site/ | grep '^github.com/8upio/govpn' | grep -v '/site$' (0 matches — the self-listed package path is the only match go list -deps' own inclusion-of-self produces)"
        status: pass
      - kind: unit
        ref: "go test -race ./examples/tunnelweb/site/ (~1.3s)"
        status: pass
    human_judgment: false
  - id: D10
    description: "Design tokens (:root block, 4 type sizes, 2 weights, the 8-point spacing scale, the 60/30/10 color split with --color-accent used only for nav links/Send echo/focus-visible/tunnel: active) are declared once and honored across every page"
    requirement: "XMPL-01"
    verification:
      - kind: unit
        ref: "examples/tunnelweb/site/site_test.go#TestStyleSheetServedFromOwnRoute"
        status: pass
      - kind: manual_procedural
        ref: "examples/tunnelweb/site/style.css: single :root block; --color-accent used only on nav a, .status-active, button, and :focus-visible outlines"
        status: pass
    human_judgment: false
  - id: D11
    description: "go test -race ./..., go vet ./..., and make gates all exit 0; gofmt -l reports no files; go.mod is unmodified"
    verification:
      - kind: unit
        ref: "go test -race ./... && go vet ./... && make gates (all exit 0)"
        status: pass
      - kind: unit
        ref: "gofmt -l . (no output); git diff --stat go.mod (no output)"
        status: pass
    human_judgment: false
---

# Phase 3 Plan 5: tunnelweb Example Server Summary

**A one-command example (`go run ./examples/tunnelweb`) that embeds `ovpn` + `netstack` and serves a landing page plus 4 subpages — status, about, echo, headers — over stdlib `http.Serve` on the netstack's own TCP listener, with the pages themselves living in a stdlib-only, `ovpn`-free `site` package testable entirely via `net/http/httptest`.**

## Performance

- **Duration:** ~40 min
- **Tasks:** 3/3
- **Files modified:** 6 (all new)

## Accomplishments

- `examples/tunnelweb/site` is a pure `http.Handler` (`Handler(Options) http.Handler`) serving `/`, `/status`, `/about`, `/echo`, `/headers`, and `/style.css`, plus the site's own 404 page — no bare stdlib 404 anywhere. The package imports nothing but the Go standard library: no `ovpn`, no `netstack`, proven both by `go list -deps` and by the fact its entire test suite runs against `net/http/httptest` with no tunnel.
- `examples/tunnelweb/main.go` is the canonical embedder reference: `netstack.New(serverIP)` → `stack.ListenTCP(httpPort)` → `go http.Serve(ln, site.Handler(...))` → `ovpn.NewServer(ovpn.Config{OnSession: func(sess) { stack.Attach(sess, sess.AssignedIP()) }})` → `srv.Serve(pc)`. The `OnSession` line is the load-bearing property the whole phase demonstrates: the embedder attaches, nothing in `ovpn.Config` knows the netstack exists (D-02).
- The landing page renders UI-SPEC's locked `<h1>`, the exact no-TUN-device/no-`CAP_NET_ADMIN` sentence, and a single site-wide `<nav>` (living inside `<header>`, reused on every page) carrying all 4 subpage links with their one-line descriptions — one element satisfying both the landing page's nav-with-descriptions contract and Accessibility Basics' "nav inside header" rule.
- The status page derives its four locked fields from live request data (`r.RemoteAddr`, `http.LocalAddrContextKey`) with an em-dash fallback that never omits a row or panics on a malformed address; the headers page renders every parsed header in a deterministic, alphabetically-sorted, screen-reader-labeled table with the exact `"{N} headers received"` heading and a tested (if never-expected-to-trigger) empty-state backstop.
- The echo page is the one interactive proof: a plain `<form method="post" action="/echo">` with an explicit `<label for="msg">`, a 4KB bound enforced via `http.MaxBytesReader` at read time and asserted on both sides of the exact boundary, the Copywriting Contract's locked empty/error strings (defined once as Go constants shared between the template and the test suite), and a 200 (never 400) on the error path per UI-SPEC's explicit instruction.
- Every dynamic value on every page renders through `html/template`'s contextual auto-escaping via a two-pass render (`renderPage`: content template executes into a buffer first, then that already-safe output is wrapped as `template.HTML` inside the shared layout) — a submitted `<script>` tag on the echo page or a `<script>`-carrying header value both render as visible text, never as markup.
- `go test -race ./examples/tunnelweb/site/` runs all 29 tests in ~1.3 seconds with no Docker and no tunnel; `go test -race ./...`, `go vet ./...`, `make gates`, and `gofmt -l .` all exit clean; `go.mod` is unmodified.

## Task Commits

Each task was committed atomically:

1. **Task 1: One command starts the server and a browser inside the tunnel loads the landing page** - `ea75401` (feat)
2. **Task 2: The status and headers pages are live proof, with every UI state covered** - `99dc254` (feat)
3. **Task 3: The echo test is the one interactive proof, and it is safe** - `3b2e570` (feat)

**Plan metadata:** commit pending (this SUMMARY.md — worktree mode excludes STATE.md/ROADMAP.md per the orchestrator's own note)

## Files Created/Modified

- `examples/tunnelweb/main.go` - the embedder wiring: flags (`-pki`, `-listen`, `-network`, `-http-port`), `loadConfig` (PKI + tls-crypt loading with a clear `gentestpki` error message on missing files), `firstHostIP`, and the `netstack.New`/`stack.ListenTCP`/`http.Serve`/`ovpn.NewServer`/`OnSession`/`srv.Serve` wiring with SIGINT/SIGTERM shutdown
- `examples/tunnelweb/README.md` - the one-command walkthrough (generate PKI, run the binary, connect a real client, open the URL) and a short design note on the `site` package's independence
- `examples/tunnelweb/site/site.go` - `Options`, `Handler`, the embedded `style.css`, and `/style.css`'s handler
- `examples/tunnelweb/site/pages.go` - the shared layout template, `renderPage`'s two-pass render, and every page's content template/handler: landing, about, 404 (Task 1); status (with `splitHostPortOrEmDash`), headers (with sorted/escaped rows) (Task 2); echo (with `echoPageData`, the size-boundary constants, and the three-state template) (Task 3)
- `examples/tunnelweb/site/style.css` - the `:root` token block, base/header/nav/main/footer styles (Task 1); table/mono/wrap rules (Task 2); form rules (Task 3)
- `examples/tunnelweb/site/site_test.go` - 29 tests driven entirely by `net/http/httptest`, added incrementally per task: 8 structural/landing tests (Task 1), 12 status/headers tests (Task 2), 9 echo tests (Task 3)

## Decisions Made

- **Single shared `<nav>` in `<header>`**, not a duplicate descriptive nav on the landing page — resolves UI-SPEC's landing-page nav-with-descriptions contract without producing two `<nav>` elements on one page (see tech-stack patterns above for the full reasoning).
- **Placeholder status/echo/headers content in Task 1's commit**, replaced by full implementations in Tasks 2/3's own commits — keeps the tracer task's "every route works" claim true from Task 1 forward while still giving each task a clean, reviewable, atomic diff.
- **Echo error state returns HTTP 200**, matching UI-SPEC's explicit instruction that the page re-renders with error copy rather than producing a blank/broken 400 response; documented in code so this doesn't read as an oversight later.
- **`maxEchoBodyBytesLimit` set to roughly double `maxEchoMsgBytes`** rather than a tight `4096 + a few bytes` bound, so the `http.MaxBytesReader` DoS-defense ceiling and the exact UI-SPEC 4096-byte accept/reject boundary are two independent checks — the former generous and approximate, the latter exact and asserted on both sides of the boundary by `TestEchoAtSizeBoundary`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Style.css's own doc comments accidentally matched the "no external resource" test patterns**
- **Found during:** Task 1, first run of `TestNoExternalOriginsReferenced`
- **Issue:** The stylesheet's header comment documented the Delivery constraint using the literal substrings `url()` and `@import` (as prose, describing what the file must *not* contain) — the test's own `strings.Contains(css, "url(")` check, written to catch a real CSS `url()` reference, matched the prose describing the prohibition instead.
- **Fix:** Reworded the comment to describe the same constraint without using the literal `url(`/`@import` substrings (e.g. "no cross-origin CSS resource reference of any kind").
- **Files modified:** `examples/tunnelweb/site/style.css`
- **Verification:** `TestNoExternalOriginsReferenced` passes; `grep -n "url(\|@import"` against the file returns nothing.
- **Committed in:** `ea75401` (Task 1 commit)

**2. [Rule 1 - Bug] A table-rules doc comment in style.css contained the literal substring "nowrap", tripping the anti-horizontal-scroll test**
- **Found during:** Task 2, first run of `TestLongHeaderValueWraps`
- **Issue:** A comment explaining that "no fixed-width or `white-space: nowrap` rule" exists in the file used the word "nowrap" as prose, which the test's `strings.Contains(css, "nowrap")` check (written to catch an actual `white-space: nowrap` declaration) matched instead.
- **Fix:** Reworded the comment to state the same constraint without the literal word ("no rule anywhere in this file pins a cell's width or forbids line breaking").
- **Files modified:** `examples/tunnelweb/site/style.css`
- **Verification:** `TestLongHeaderValueWraps` passes; `grep -n nowrap` against the file returns nothing.
- **Committed in:** `99dc254` (Task 2 commit)

**3. [Rule 1 - Bug] A Go raw string literal in pages.go's echo template contained a backtick inside its own HTML comment, terminating the raw string early**
- **Found during:** Task 3, first `go build` after adding the echo template
- **Issue:** The echo template's inline HTML comment (explaining why no JavaScript/spinner exists) quoted UI-SPEC's `loading` row using backtick-quoting inside the Go raw string literal (`` `...UI-SPEC's `loading` row...` ``), which closed the outer raw string at the first inner backtick and produced a syntax error.
- **Fix:** Reworded the comment to reference the row name without backtick-quoting it (plain text: "UI-SPEC's loading row").
- **Files modified:** `examples/tunnelweb/site/pages.go`
- **Verification:** `go build ./...` succeeds; all `TestEcho*` tests pass.
- **Committed in:** `3b2e570` (Task 3 commit)

---

**Total deviations:** 3 auto-fixed (3 bugs, all Rule 1)
**Impact on plan:** All three were self-inflicted authoring mistakes in this plan's own doc comments/template source (prose accidentally matching the very test patterns it was documenting, and a backtick inside a backtick-quoted raw string) — none touched production logic, page content, or test intent. No scope creep, no architectural change.

## Issues Encountered

**`go list -deps` acceptance criterion wording:** the plan's stated check (`go list -deps ./examples/tunnelweb/site/ | grep -c '^github.com/8upio/govpn'` returns 0) does not account for `go list -deps` always including the queried package itself in its own output — `examples/tunnelweb/site` itself matches the `^github.com/8upio/govpn` prefix, so the literal command returns `1`, not `0`. Verified the actual intent (the site package pulls in *no other* part of this module) holds with `go list -deps ./examples/tunnelweb/site/ | grep '^github.com/8upio/govpn' | grep -v '^github.com/8upio/govpn/examples/tunnelweb/site$'`, which returns `0`. Documented here rather than silently treated as a pass/fail judgment call — the underlying property (no coupling) is genuinely satisfied; the literal acceptance-criterion command as written is off by the self-listing quirk.

## Known Stubs

None. All five routes render full, UI-SPEC-compliant content by the end of Task 3; the Task 1 placeholder content for status/echo/headers was fully replaced in Tasks 2/3, and every UI Considerations row this plan's `must_haves` names — including the 🧪 backstop empty-headers row — is implemented and unit-tested, not merely documented.

## User Setup Required

None — no external service configuration required. A developer wanting to run the example end-to-end still needs to generate a PKI (`go run ./cmd/gentestpki -out <dir> -profile small`) and connect a real OpenVPN client, both documented in `examples/tunnelweb/README.md`; neither is a setup step this plan's own automated verification depends on.

## Next Phase Readiness

- `examples/tunnelweb/site` is import-ready for plan 03-06's interop harness: `site.Handler(site.Options{...})` can be served by the harness's own `http.Serve` call over the same netstack listener, so the `curl` content-marker assertions plan 03-06 writes will test byte-identical pages to what a developer sees in a browser (this plan's own `key_links` entry).
- `examples/tunnelweb/main.go` is the concrete, working reference for "how do I embed this library" — D-01/D-02/D-09 are all demonstrated in a single, thin, readable `main` with no netstack coupling in `ovpn.Config`.
- No blockers identified for 03-06.

## Self-Check: PASSED

- All 6 files listed under "Files Created/Modified" confirmed present on disk.
- All three task commits (`ea75401`, `99dc254`, `3b2e570`) confirmed present via `git log --oneline`.
- `go build ./...`, `go vet ./...`, `go test -race ./...` (all packages), and `make gates` all confirmed exit 0 immediately before writing this summary.
- `gofmt -l .` produced no output; `git diff --stat go.mod` produced no output.
- `go run ./examples/tunnelweb -h` confirmed to exit 0 and list all four flags.

---
*Phase: 03-in-process-termination*
*Completed: 2026-08-27*
