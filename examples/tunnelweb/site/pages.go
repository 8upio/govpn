package site

import (
	"bytes"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// emDash is UI-SPEC's fallback rendering for a locked field that is
// genuinely unavailable — the row stays, its value becomes this, and the
// handler never panics or omits the row (UI-SPEC's `partial` state rule).
const emDash = "—"

// layoutTmpl is the one shared layout every page renders through: a
// <header> carrying the site brand and the site-wide <nav> (with its
// per-link one-line descriptions, satisfying both UI-SPEC's landing-page
// nav contract and Accessibility Basics' "nav inside header" rule in a
// single element, reused on every page rather than duplicated), a <main>
// holding the page's own content, and an optional small <footer>. This is
// what makes TestSemanticLandmarks' "exactly one <header>, exactly one
// <main>, at most one <footer>, nav inside header" hold uniformly across
// every route without each page having to reimplement it.
//
// The landing page's own <h1> and body copy live inside its content
// template (below), not here — UI-SPEC's Typography table scopes the
// "Display" role's <h1> to the landing page only; every other page's own
// heading is an <h2> inside its content template instead.
var layoutTmpl = template.Must(template.New("layout").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - govpn tunnelweb</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header>
<a href="/" class="brand">govpn tunnelweb</a>
<nav>
<ul>
<li><a href="/status">Status</a><span class="nav-desc">Live facts about your tunnel session</span></li>
<li><a href="/about">About</a><span class="nav-desc">What this demo proves and how</span></li>
<li><a href="/echo">Echo test</a><span class="nav-desc">Send a message through the tunnel and get it back</span></li>
<li><a href="/headers">Headers</a><span class="nav-desc">See the raw HTTP headers this server received from you</span></li>
</ul>
</nav>
</header>
<main>
{{.Content}}
</main>
<footer>served via govpn</footer>
</body>
</html>
`))

// layoutData is layoutTmpl's execution data. Content is already
// html/template-escaped output from a page's own content template (see
// renderPage) — wrapping it as template.HTML here does not reintroduce an
// escaping gap, it only tells the layout template not to re-escape output
// that was already safely produced.
type layoutData struct {
	Title   string
	Content template.HTML
}

// renderPage renders content (a page's own content template) into a
// buffer first, then wraps that already-escaped output into layoutTmpl,
// and only writes to w once both steps have succeeded — a template error
// produces a clean 500 rather than a half-written page (Rule 2: this
// project's own error-handling discipline, not stated verbatim by the
// plan but required for correctness).
func renderPage(w http.ResponseWriter, status int, content *template.Template, title string, data any) {
	var body bytes.Buffer
	if err := content.Execute(&body, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var page bytes.Buffer
	if err := layoutTmpl.Execute(&page, layoutData{Title: title, Content: template.HTML(body.String())}); err != nil { //nolint:gosec // G203: body.String() is the OUTPUT of content.Execute above, already escaped by html/template's contextual auto-escaping — this wraps already-safe output, it does not bypass escaping of untrusted input.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(page.Bytes())
}

// landingTmpl is UI-SPEC §1's locked landing content: a display-sized
// <h1> and exactly one sentence of body copy naming both "no TUN device"
// and "CAP_NET_ADMIN" in plain language. The nav itself lives in the
// shared layout (see layoutTmpl doc comment above).
var landingTmpl = template.Must(template.New("landing").Parse(`<h1>govpn tunnelweb</h1>
<p>This page is served entirely inside the OpenVPN tunnel you just connected through — no TUN device, no CAP_NET_ADMIN, no process outside this one Go binary.</p>
`))

func (s *site) handleLanding(w http.ResponseWriter, r *http.Request) {
	// A stdlib ServeMux "/" pattern matches every path that no more
	// specific pattern matched — without this check, an unknown path
	// would fall through to a bare "landing page" response instead of
	// this site's own 404 (see handleNotFound), which is exactly the
	// property TestAllRoutesReturn200 asserts.
	if r.URL.Path != "/" {
		s.handleNotFound(w, r)
		return
	}
	renderPage(w, http.StatusOK, landingTmpl, "govpn tunnelweb", nil)
}

// aboutTmpl is D-15 discretion in its exact wording (2-4 short
// paragraphs), but must state the no-TUN-device / no-CAP_NET_ADMIN fact in
// plain language — UI-SPEC §3 marks this the one thing this page must not
// omit.
var aboutTmpl = template.Must(template.New("about").Parse(`<h2>About this demo</h2>
<p>govpn is a pure-Go implementation of the server side of the OpenVPN protocol. This page — like every page on this site — is served entirely inside the OpenVPN tunnel you connected through.</p>
<p>There is no TUN device and no CAP_NET_ADMIN capability anywhere in this process. Decrypted IP packets from your session are handed instead to a small userspace network stack that speaks just enough IPv4, TCP, and ICMP to terminate an HTTP connection and answer a ping — without ever touching the host kernel's own network stack.</p>
<p>That means this whole demo runs as an ordinary, unprivileged process in any container. Nothing on the host or container network is listening for HTTP at all: the only way to reach this page is through the tunnel itself.</p>
`))

func (s *site) handleAbout(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, aboutTmpl, "About", nil)
}

// notFoundTmpl carries this site's own header and nav on a 404 response —
// TestAllRoutesReturn200 asserts an unknown path never falls back to the
// stdlib's bare-text 404.
var notFoundTmpl = template.Must(template.New("notfound").Parse(`<h2>Page not found</h2>
<p>There's no page at this address. Use the navigation above, or head back to the <a href="/">landing page</a>.</p>
`))

func (s *site) handleNotFound(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusNotFound, notFoundTmpl, "Not Found", nil)
}

// statusPageData carries the status page's locked fields (assigned tunnel
// IP, server tunnel IP, cipher, the "tunnel: active" indicator — always
// rendered literally, not from this struct) plus the discretionary fields
// this plan's objective table names as cheaply available: client source
// port, request time, and server uptime. Every field is a string so the
// em-dash fallback (see emDash above) is representable uniformly; deriving
// these values is fallible (an unparseable RemoteAddr, a missing context
// value), and every failure path renders emDash for that one value while
// the row itself always stays (UI-SPEC's `partial` state rule).
type statusPageData struct {
	AssignedIP  string
	ServerIP    string
	Cipher      string
	SourcePort  string
	RequestedAt string
	Uptime      string
}

// statusTmpl is UI-SPEC §2's locked status page: a definition-style table
// (<th scope="row">) of the four locked fields plus the discretionary
// ones, in the order the plan's objective assumption table lists them.
// IP/identifier values carry the "mono" class (font-family: var(--font-
// mono); word-break: break-all — UI-SPEC's `overflow` row) rather than a
// fifth type role; the "tunnel: active" indicator is text in
// --color-accent, never a colored dot alone (UI-SPEC's no-color-only-
// signaling rule).
var statusTmpl = template.Must(template.New("status").Parse(`<h2>Status</h2>
<table>
<tbody>
<tr><th scope="row">Assigned tunnel IP</th><td class="mono">{{.AssignedIP}}</td></tr>
<tr><th scope="row">Server tunnel IP</th><td class="mono">{{.ServerIP}}</td></tr>
<tr><th scope="row">Cipher</th><td>{{.Cipher}}</td></tr>
<tr><th scope="row">Session</th><td class="status-active">tunnel: active</td></tr>
<tr><th scope="row">Client source port</th><td class="mono">{{.SourcePort}}</td></tr>
<tr><th scope="row">Request time</th><td>{{.RequestedAt}}</td></tr>
<tr><th scope="row">Server uptime</th><td>{{.Uptime}}</td></tr>
</tbody>
</table>
`))

// splitHostPortOrEmDash splits hostport into its host and port halves,
// returning emDash for both on any parse failure — the single fallback
// path every fallible address derivation on the status page shares, so a
// malformed or missing address never panics the handler and never omits
// its row (UI-SPEC's `partial` state rule).
func splitHostPortOrEmDash(hostport string) (host, port string) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return emDash, emDash
	}
	return h, p
}

// handleStatus computes every fact synchronously, before the response is
// written — there is no async loading state on this stack (UI-SPEC's
// `loading` row). The assigned tunnel IP and its source port come from
// r.RemoteAddr; for a netstack conn this IS the client's assigned tunnel
// IP (this plan's own objective, "Planner assumption" table). The server
// tunnel IP comes from http.LocalAddrContextKey, which net/http populates
// from the accepted conn's own LocalAddr() — the same *net.TCPAddr plan
// 03-03 proved the netstack's TCP conn returns.
func (s *site) handleStatus(w http.ResponseWriter, r *http.Request) {
	data := statusPageData{
		Cipher:      s.opts.Cipher,
		RequestedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		Uptime:      time.Since(s.opts.StartedAt).Round(time.Second).String(),
	}
	if data.Cipher == "" {
		data.Cipher = emDash
	}

	data.AssignedIP, data.SourcePort = splitHostPortOrEmDash(r.RemoteAddr)

	data.ServerIP = emDash
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if ip, _ := splitHostPortOrEmDash(addr.String()); ip != emDash {
			data.ServerIP = ip
		}
	}

	renderPage(w, http.StatusOK, statusTmpl, "Status", data)
}

// headerRow is one row of the headers page's table: a single header name
// and its (possibly comma-joined, for multi-valued headers) value.
type headerRow struct {
	Name  string
	Value string
}

// headersPageData carries the headers page's proof line (method, path,
// Host) and its sorted row set. Count is rendered separately from
// len(Rows) so the "{N} headers received" heading still reads correctly
// in the same shape even if a future change renders rows differently.
type headersPageData struct {
	Method string
	Path   string
	Host   string
	Count  int
	Rows   []headerRow
}

// headersTmpl is UI-SPEC §5's locked headers page: the method/path/Host
// proof line, the numeral-only "{N} headers received" heading (no
// singular/plural branching), and — when at least one header exists — a
// two-column <table> with <th scope="col">. The empty case (🧪 backstop:
// expected to never trigger against a real HTTP client, but implemented
// and unit-tested rather than merely hoped for) renders "No headers
// received" instead of an empty table. The value column carries the
// "wrap" class (overflow-wrap: anywhere), covering both UI-SPEC's
// `overflow` and `long-text` rows with one CSS rule.
var headersTmpl = template.Must(template.New("headers").Parse(`<p>{{.Method}} {{.Path}} via Host: {{.Host}}</p>
<h2>{{.Count}} headers received</h2>
{{if .Rows}}
<table>
<thead><tr><th scope="col">Header</th><th scope="col">Value</th></tr></thead>
<tbody>
{{range .Rows}}<tr><td>{{.Name}}</td><td class="wrap">{{.Value}}</td></tr>
{{end}}</tbody>
</table>
{{else}}
<p>No headers received</p>
{{end}}
`))

// handleHeaders collects header names from r.Header, sorts them with
// sort.Strings, and joins multi-valued headers with a comma and a space
// rather than dropping duplicates. Sorting is not cosmetic — it is what
// makes the page's output deterministic and byte-identical across two
// renders of the same request (TestHeadersPageSorted), and therefore
// assertable by plan 03-06's curl content-marker probe. Escaping is
// automatic through html/template (see renderPage); a future refactor to
// text/template or string concatenation for "performance" would fail
// TestHeadersPageEscapesValues rather than shipping a reflected-XSS
// surface on a page whose entire content is attacker-supplied (T-03-25).
func (s *site) handleHeaders(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]headerRow, 0, len(names))
	for _, name := range names {
		rows = append(rows, headerRow{Name: name, Value: strings.Join(r.Header[name], ", ")})
	}

	data := headersPageData{
		Method: r.Method,
		Path:   r.URL.Path,
		Host:   r.Host,
		Count:  len(rows),
		Rows:   rows,
	}
	renderPage(w, http.StatusOK, headersTmpl, "Headers", data)
}

const (
	// echoEmptyBodyCopy and echoErrorCopy are the Copywriting Contract's
	// exact, locked strings — defined once here so both the template
	// (which renders them) and the test suite (which asserts on them)
	// share a single source of truth rather than risking drift between
	// two independently-typed copies of the same locked text.
	echoEmptyBodyCopy = "Type a message above and submit — it travels through the tunnel to this server and back before the page reloads with the result."
	echoErrorCopy     = "Echo failed — the message was empty or too large. Type something under 4KB and try again."

	// echoPlaceholder is the empty textarea's locked placeholder text
	// (UI-SPEC UI Considerations, `empty` row).
	echoPlaceholder = "Type something to echo through the tunnel…"

	// maxEchoMsgBytes is the exact 4KB rule asserted on both sides of the
	// boundary (UI-SPEC §4, T-03-26): a message of exactly this many
	// bytes is accepted, one byte over is rejected.
	maxEchoMsgBytes = 4096

	// maxEchoBodyBytesLimit bounds http.MaxBytesReader at read time, "a
	// little above" maxEchoMsgBytes so the size rule is enforced before
	// ParseForm ever buffers an arbitrarily large body (T-03-26) — not
	// merely after. Roughly double maxEchoMsgBytes: enough headroom for
	// the "msg=" key and ordinary form-encoding overhead, while still a
	// small, fixed ceiling that can never let an attacker force megabytes
	// into memory before the value's own length is even inspected. A
	// request that trips this reader produces the same error copy as the
	// exact-4096 check below — the two paths are indistinguishable to the
	// client by design, since both mean "too large".
	maxEchoBodyBytesLimit = maxEchoMsgBytes * 2
)

// echoPageData carries the echo page's one dynamic axis: which of the
// three UI-SPEC states (empty, populated, error) to render, plus the
// value/error text that state needs. EmptyBody is threaded through data
// (rather than hardcoded twice, once here and once in the template) so
// echoEmptyBodyCopy stays the single source of truth for that locked
// string.
type echoPageData struct {
	State     string // "empty", "populated", or "error"
	Value     string
	EmptyBody string
	ErrorMsg  string
}

// echoTmpl is UI-SPEC §4's locked echo-test page: a plain
// method="post" form with an explicit, visible <label> (never
// placeholder-only — Accessibility Basics) whose for/id match, and a
// state-dependent block above it. There is no client-side loading
// indicator to build (UI-SPEC's `loading` row: a plain form POST triggers
// the browser's own native full-page-reload indicator) — the comment
// below the form exists so a later contributor does not add a spinner and
// a fetch call, which would require JavaScript this site deliberately
// never ships.
var echoTmpl = template.Must(template.New("echo").Parse(`{{if eq .State "empty"}}<h2>Nothing to echo yet</h2>
<p>{{.EmptyBody}}</p>
{{else if eq .State "error"}}<h2>Echo test</h2>
<p class="echo-error">{{.ErrorMsg}}</p>
{{else}}<h2>Echo test</h2>
<p class="echo-result">You sent: {{.Value}}</p>
{{end}}
<!-- No JavaScript here on purpose: a plain form POST triggers the
     browser's own full-page-reload loading indicator (UI-SPEC's loading
     row). Do not add a spinner or a fetch call. -->
<form method="post" action="/echo">
<label for="msg">Message to echo</label>
<textarea id="msg" name="msg" placeholder="` + echoPlaceholder + `"></textarea>
<button type="submit">Send echo</button>
</form>
`))

// handleEcho serves the echo page's GET (always the empty state — no
// echoed value is ever shown on a fresh load) and POST (round-trip)
// behavior. The page is idempotent and stateless: no cookie, no
// server-side store, nothing that outlives a single request/response.
func (s *site) handleEcho(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderPage(w, http.StatusOK, echoTmpl, "Echo test", echoPageData{
			State:     "empty",
			EmptyBody: echoEmptyBodyCopy,
		})
		return
	}
	s.handleEchoPost(w, r)
}

// handleEchoPost bounds the request body with http.MaxBytesReader before
// ever calling ParseForm — enforcing the size rule at read time rather
// than after buffering an arbitrarily large body (T-03-26) — then applies
// the exact 4096-byte rule to the decoded msg value itself, independent of
// the reader's own bound. An empty, whitespace-only, or oversized value
// renders the error state and — deliberately — a 200, not a 400: UI-SPEC's
// `error` row specifies the page re-renders with error copy rather than
// producing a blank/broken response, and a browser showing a bare 400
// body is a worse demo than a page that explains what went wrong.
func (s *site) handleEchoPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxEchoBodyBytesLimit)

	if err := r.ParseForm(); err != nil {
		s.renderEchoError(w)
		return
	}

	msg := r.FormValue("msg")
	if strings.TrimSpace(msg) == "" || len(msg) > maxEchoMsgBytes {
		s.renderEchoError(w)
		return
	}

	renderPage(w, http.StatusOK, echoTmpl, "Echo test", echoPageData{
		State: "populated",
		Value: msg,
	})
}

// renderEchoError renders the exact Copywriting Contract error string —
// always 200, never the submitted value (UI-SPEC §4).
func (s *site) renderEchoError(w http.ResponseWriter) {
	renderPage(w, http.StatusOK, echoTmpl, "Echo test", echoPageData{
		State:    "error",
		ErrorMsg: echoErrorCopy,
	})
}
