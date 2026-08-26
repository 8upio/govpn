// Package site implements the tunnelweb example's web pages: a landing
// page plus /status, /about, /echo, and /headers, and the single
// stylesheet all of them share. Package site imports only the Go standard
// library — no github.com/8upio/govpn, no netstack — so it can be served
// by both examples/tunnelweb/main.go (over the real OpenVPN tunnel) and
// plan 03-06's interop harness, and so its own test suite runs entirely
// against net/http/httptest with no netstack and no tunnel (this plan's
// own prohibition; see TestSitePackageDoesNotNeedOvpn).
//
// Every dynamic value is rendered through html/template, never through
// text/template or raw string concatenation — this is what makes the echo
// page's and the headers page's escaping of untrusted, peer-supplied text
// structural rather than dependent on remembering to escape at each call
// site (T-03-25).
package site

import (
	_ "embed"
	"net/http"
	"time"
)

//go:embed style.css
var styleCSS []byte

// Options carries the embedder-supplied facts the pages cannot derive from
// an *http.Request alone. Keep it minimal: anything derivable from a
// request (assigned tunnel IP, server tunnel IP, headers, method, path)
// must be derived there, not passed here.
type Options struct {
	// Cipher is the data-channel cipher name the status page displays
	// (e.g. "AES-256-GCM").
	Cipher string

	// StartedAt is when the embedding server started, used to compute the
	// status page's uptime row.
	StartedAt time.Time
}

// site holds the options every handler closes over.
type site struct {
	opts Options
}

// Handler returns an http.Handler serving the tunnelweb site: landing,
// status, about, echo, headers, and the shared stylesheet, plus the
// site's own 404 page for any other path (never the stdlib's bare-text
// 404 — every page, including the not-found page, carries this site's
// header and nav).
func Handler(opts Options) http.Handler {
	s := &site{opts: opts}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleLanding)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/about", s.handleAbout)
	mux.HandleFunc("/echo", s.handleEcho)
	mux.HandleFunc("/headers", s.handleHeaders)
	mux.HandleFunc("/style.css", s.handleStyle)
	return mux
}

// handleStyle serves the single embedded stylesheet every page links to
// with a same-origin relative href — no CDN, no inline duplication across
// pages (UI-SPEC Delivery constraint, locked).
func (s *site) handleStyle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(styleCSS)
}
