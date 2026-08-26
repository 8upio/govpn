package site

import (
	"bytes"
	"html/template"
	"net/http"
)

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

// statusTmpl is a placeholder for this task: registered now so
// TestAllRoutesReturn200 passes from this task forward (a route that
// 404s until a later task would make the tracer's own end-to-end claim
// false), fully implemented with live tunnel/session facts and the
// em-dash fallback rule in Task 2.
var statusTmpl = template.Must(template.New("status").Parse(`<h2>Status</h2>
<p>Coming in Task 2: live facts about your tunnel session.</p>
`))

func (s *site) handleStatus(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, statusTmpl, "Status", nil)
}

// headersTmpl is a placeholder for this task, matching statusTmpl above;
// fully implemented (sorted, escaped request-header table) in Task 2.
var headersTmpl = template.Must(template.New("headers").Parse(`<h2>Headers</h2>
<p>Coming in Task 2: the raw HTTP headers this server received from you.</p>
`))

func (s *site) handleHeaders(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, headersTmpl, "Headers", nil)
}

// echoTmpl is a placeholder for this task, matching statusTmpl above;
// fully implemented (the interactive echo-test form) in Task 3.
var echoTmpl = template.Must(template.New("echo").Parse(`<h2>Echo test</h2>
<p>Coming in Task 3: send a message through the tunnel and get it back.</p>
`))

func (s *site) handleEcho(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, echoTmpl, "Echo test", nil)
}
