// site_test.go drives every behavior this plan specifies purely through
// net/http/httptest against site.Handler — no tunnel, no netstack, no
// Docker. The site is a pure http.Handler, and testing it as one keeps
// this suite fast (TestSitePackageDoesNotNeedOvpn is the standing proof of
// that decoupling) and honestly free of library coupling.
package site

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testOptions() Options {
	return Options{Cipher: "AES-256-GCM", StartedAt: time.Now()}
}

// doRequest builds a request against h and returns the recorded response.
// If body is non-empty, the request is a form-encoded POST-shaped body;
// callers that need a specific method still pass it explicitly.
func doRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// extractBetween returns the substring of s starting at the first
// occurrence of start and ending at (and including) the following
// occurrence of end, used to scope assertions to a single element (e.g.
// "only inside <nav>...</nav>") rather than the whole page body.
func extractBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], end)
	if j < 0 {
		return s[i:]
	}
	return s[i : i+j+len(end)]
}

func TestLandingPageStructure(t *testing.T) {
	h := Handler(testOptions())
	w := doRequest(h, http.MethodGet, "/", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	body := w.Body.String()
	if got := strings.Count(body, "<h1"); got != 1 {
		t.Fatalf("body has %d <h1> elements, want exactly 1:\n%s", got, body)
	}

	navSection := extractBetween(body, "<nav", "</nav>")
	if navSection == "" {
		t.Fatal("no <nav> element found")
	}
	wantLinks := []struct{ label, href string }{
		{"Status", "/status"},
		{"About", "/about"},
		{"Echo test", "/echo"},
		{"Headers", "/headers"},
	}
	for _, l := range wantLinks {
		if !strings.Contains(navSection, `href="`+l.href+`"`) {
			t.Errorf("nav missing href %q:\n%s", l.href, navSection)
		}
		if !strings.Contains(navSection, ">"+l.label+"<") {
			t.Errorf("nav missing visible label %q:\n%s", l.label, navSection)
		}
	}
	if got := strings.Count(navSection, "<a "); got != 4 {
		t.Fatalf("nav has %d anchors, want exactly 4:\n%s", got, navSection)
	}
}

func TestLandingStatesTheCoreClaim(t *testing.T) {
	h := Handler(testOptions())
	body := doRequest(h, http.MethodGet, "/", "").Body.String()
	if !strings.Contains(body, "no TUN device") {
		t.Error("landing page does not name 'no TUN device'")
	}
	if !strings.Contains(body, "CAP_NET_ADMIN") {
		t.Error("landing page does not name CAP_NET_ADMIN")
	}
}

func TestAllRoutesReturn200(t *testing.T) {
	h := Handler(testOptions())
	routes := []string{"/", "/status", "/about", "/echo", "/headers", "/style.css"}
	for _, route := range routes {
		w := doRequest(h, http.MethodGet, route, "")
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", route, w.Code)
		}
	}

	w := doRequest(h, http.MethodGet, "/this-path-does-not-exist", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET unknown path = %d, want 404", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<header") || !strings.Contains(body, "<nav") {
		t.Error("404 page does not carry the site's own header/nav — got a bare stdlib-style 404")
	}
}

func TestStyleSheetServedFromOwnRoute(t *testing.T) {
	h := Handler(testOptions())
	w := doRequest(h, http.MethodGet, "/style.css", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/css; charset=utf-8", ct)
	}
	body := w.Body.String()
	tokens := []string{
		"--color-bg", "--color-surface", "--color-border", "--color-text",
		"--color-text-muted", "--color-accent",
		"--font-sans", "--font-mono",
		"--text-sm", "--text-base", "--text-lg", "--text-xl",
		"--space-xs", "--space-sm", "--space-md", "--space-lg", "--space-xl",
		"--space-2xl", "--space-3xl",
		"--radius",
	}
	for _, tok := range tokens {
		if !strings.Contains(body, tok) {
			t.Errorf("stylesheet missing declared token %q", tok)
		}
	}
}

func TestNoExternalOriginsReferenced(t *testing.T) {
	h := Handler(testOptions())
	for _, route := range []string{"/", "/status", "/about", "/echo", "/headers"} {
		body := doRequest(h, http.MethodGet, route, "").Body.String()
		if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Errorf("%s references an external origin:\n%s", route, body)
		}
	}
	css := doRequest(h, http.MethodGet, "/style.css", "").Body.String()
	if strings.Contains(css, "url(") || strings.Contains(css, "@import") {
		t.Error("stylesheet references an external resource (url() or @import)")
	}
}

func TestNoScriptElements(t *testing.T) {
	h := Handler(testOptions())
	for _, route := range []string{"/", "/status", "/about", "/echo", "/headers"} {
		body := doRequest(h, http.MethodGet, route, "").Body.String()
		if strings.Contains(body, "<script") {
			t.Errorf("%s contains a <script> element", route)
		}
	}
}

func TestSemanticLandmarks(t *testing.T) {
	h := Handler(testOptions())
	for _, route := range []string{"/", "/status", "/about", "/echo", "/headers"} {
		body := doRequest(h, http.MethodGet, route, "").Body.String()
		if got := strings.Count(body, "<header"); got != 1 {
			t.Errorf("%s has %d <header> elements, want exactly 1", route, got)
		}
		if got := strings.Count(body, "<main"); got != 1 {
			t.Errorf("%s has %d <main> elements, want exactly 1", route, got)
		}
		if got := strings.Count(body, "<footer"); got > 1 {
			t.Errorf("%s has %d <footer> elements, want at most 1", route, got)
		}
		headerSection := extractBetween(body, "<header", "</header>")
		if !strings.Contains(headerSection, "<nav") {
			t.Errorf("%s: nav is not inside header", route)
		}
	}
}

func TestSitePackageDoesNotNeedOvpn(t *testing.T) {
	h := Handler(testOptions())
	routes := []string{"/", "/status", "/about", "/echo", "/headers", "/style.css"}
	for _, route := range routes {
		w := doRequest(h, http.MethodGet, route, "")
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (site.Handler must be fully self-contained and driven only by httptest)", route, w.Code)
		}
	}
}
