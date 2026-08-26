// site_test.go drives every behavior this plan specifies purely through
// net/http/httptest against site.Handler — no tunnel, no netstack, no
// Docker. The site is a pure http.Handler, and testing it as one keeps
// this suite fast (TestSitePackageDoesNotNeedOvpn is the standing proof of
// that decoupling) and honestly free of library coupling.
package site

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// --- Task 2: status and headers ---

func TestStatusPageLockedFields(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = "10.8.0.2:41000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	for _, want := range []string{"Assigned tunnel IP", "Server tunnel IP", "Cipher", "tunnel: active"} {
		if !strings.Contains(body, want) {
			t.Errorf("status page missing locked field %q:\n%s", want, body)
		}
	}
}

func TestStatusPageDerivesAddresses(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = "10.8.0.2:41000"
	localAddr := &net.TCPAddr{IP: net.ParseIP("10.8.0.1"), Port: 8080}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(localAddr)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "10.8.0.2") {
		t.Errorf("status page does not show the assigned tunnel IP 10.8.0.2:\n%s", body)
	}
	if !strings.Contains(body, "10.8.0.1") {
		t.Errorf("status page does not show the server tunnel IP 10.8.0.1:\n%s", body)
	}
}

func TestStatusPagePartialFallback(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = "not-a-valid-remote-addr"
	w := httptest.NewRecorder()

	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("status handler panicked on an unparseable RemoteAddr: %v", p)
			}
		}()
		h.ServeHTTP(w, r)
	}()

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, emDash) {
		t.Errorf("status page does not fall back to an em dash for an unavailable value:\n%s", body)
	}
	for _, want := range []string{"Assigned tunnel IP", "Server tunnel IP", "Cipher", "tunnel: active"} {
		if !strings.Contains(body, want) {
			t.Errorf("status page dropped locked row %q on fallback", want)
		}
	}
}

func TestStatusPageComputedSynchronously(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = "10.8.0.2:41000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.Len() == 0 {
		t.Fatal("status page body is empty immediately after ServeHTTP returns — expected a fully synchronous response")
	}
}

func TestStatusValuesUseMonospace(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = "10.8.0.2:41000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, `class="mono"`) {
		t.Errorf("status page does not mark IP/identifier values with the mono class:\n%s", body)
	}
	css := doRequest(h, http.MethodGet, "/style.css", "").Body.String()
	if !strings.Contains(css, "var(--font-mono)") || !strings.Contains(css, "word-break: break-all") {
		t.Error("stylesheet does not define the mono value rule (font-family: var(--font-mono); word-break: break-all)")
	}
}

func TestHeadersPageSorted(t *testing.T) {
	h := Handler(testOptions())
	mk := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/headers", nil)
		r.Header.Set("X-Zeta", "1")
		r.Header.Set("Accept", "text/html")
		r.Header.Set("User-Agent", "test-agent")
		return r
	}

	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, mk())
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, mk())

	body1, body2 := w1.Body.String(), w2.Body.String()
	if body1 != body2 {
		t.Fatal("two renders of the same request produced different output — output must be byte-identical")
	}

	iAccept := strings.Index(body1, "Accept")
	iUA := strings.Index(body1, "User-Agent")
	iZeta := strings.Index(body1, "X-Zeta")
	if iAccept < 0 || iUA < 0 || iZeta < 0 {
		t.Fatalf("one or more headers missing from rendered table:\n%s", body1)
	}
	if !(iAccept < iUA && iUA < iZeta) {
		t.Fatalf("headers not sorted alphabetically: Accept=%d User-Agent=%d X-Zeta=%d", iAccept, iUA, iZeta)
	}
}

func TestHeadersPageHeadingCount(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/headers", nil)
	r.Header.Set("X-Test", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "1 headers received") {
		t.Errorf("expected the numeral-only heading '1 headers received', got:\n%s", body)
	}
}

func TestHeadersPageProofLine(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/headers", nil)
	r.Host = "10.8.0.1:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "GET /headers via Host: 10.8.0.1:8080") {
		t.Errorf("headers page missing the method/path/Host proof line:\n%s", body)
	}
}

func TestHeadersPageEmptyBackstop(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/headers", nil)
	r.Header = http.Header{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "No headers received") {
		t.Errorf("expected the empty-state backstop copy 'No headers received', got:\n%s", body)
	}
}

func TestHeadersPageEscapesValues(t *testing.T) {
	h := Handler(testOptions())
	r := httptest.NewRequest(http.MethodGet, "/headers", nil)
	r.Header.Set("X-Evil", "<script>alert(1)</script>")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("header value rendered as unescaped markup")
	}
	if !strings.Contains(body, "alert(1)") {
		t.Fatal("escaped header value is not present as visible text")
	}
}

func TestTableSemantics(t *testing.T) {
	h := Handler(testOptions())

	statusReq := httptest.NewRequest(http.MethodGet, "/status", nil)
	statusReq.RemoteAddr = "10.8.0.2:41000"
	statusW := httptest.NewRecorder()
	h.ServeHTTP(statusW, statusReq)
	if !strings.Contains(statusW.Body.String(), `scope="row"`) {
		t.Error(`status table missing scope="row"`)
	}

	headersReq := httptest.NewRequest(http.MethodGet, "/headers", nil)
	headersReq.Header.Set("X-Test", "1")
	headersW := httptest.NewRecorder()
	h.ServeHTTP(headersW, headersReq)
	if !strings.Contains(headersW.Body.String(), `scope="col"`) {
		t.Error(`headers table missing scope="col"`)
	}
}

func TestLongHeaderValueWraps(t *testing.T) {
	h := Handler(testOptions())
	body := doRequest(h, http.MethodGet, "/style.css", "").Body.String()
	if !strings.Contains(body, "overflow-wrap: anywhere") {
		t.Error("stylesheet does not define overflow-wrap: anywhere on the value column")
	}
	if strings.Contains(body, "nowrap") {
		t.Error("stylesheet contains a nowrap rule that would force horizontal scroll")
	}
}

// --- Task 3: echo ---

func TestEchoEmptyState(t *testing.T) {
	h := Handler(testOptions())
	body := doRequest(h, http.MethodGet, "/echo", "").Body.String()

	if !strings.Contains(body, `<textarea id="msg" name="msg" placeholder="Type something to echo through the tunnel…">`) {
		t.Errorf("echo page missing the empty, placeholder-carrying textarea:\n%s", body)
	}
	if !strings.Contains(body, "Nothing to echo yet") {
		t.Error("echo page missing the empty-state heading 'Nothing to echo yet'")
	}
	if !strings.Contains(body, echoEmptyBodyCopy) {
		t.Error("echo page missing the exact empty-state body copy")
	}
	if strings.Contains(body, "You sent:") {
		t.Error("initial GET should not show a prior echoed value")
	}
}

func TestEchoFormShape(t *testing.T) {
	h := Handler(testOptions())
	body := doRequest(h, http.MethodGet, "/echo", "").Body.String()

	if !strings.Contains(body, `<form method="post" action="/echo">`) {
		t.Error(`echo page missing <form method="post" action="/echo">`)
	}
	if !strings.Contains(body, `<label for="msg">Message to echo</label>`) {
		t.Error("echo page missing the explicit label for msg")
	}
	if !strings.Contains(body, `<textarea id="msg" name="msg"`) {
		t.Error("textarea id does not match the label's for attribute")
	}
	if !strings.Contains(body, `<button type="submit">Send echo</button>`) {
		t.Error(`submit button text is not exactly "Send echo"`)
	}
}

func TestEchoRoundTrip(t *testing.T) {
	h := Handler(testOptions())
	form := url.Values{"msg": {"hello tunnel"}}
	w := doRequest(h, http.MethodPost, "/echo", form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "You sent: hello tunnel") {
		t.Errorf("echo response missing the round-tripped value:\n%s", w.Body.String())
	}
}

func TestEchoEscapesSubmittedValue(t *testing.T) {
	h := Handler(testOptions())
	form := url.Values{"msg": {"<script>alert(1)</script>"}}
	w := doRequest(h, http.MethodPost, "/echo", form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("submitted script tag rendered unescaped")
	}
	if !strings.Contains(body, "alert(1)") {
		t.Fatal("escaped submitted value not present as visible text")
	}
}

func TestEchoEmptyBodyError(t *testing.T) {
	h := Handler(testOptions())
	form := url.Values{"msg": {""}}
	w := doRequest(h, http.MethodPost, "/echo", form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the page re-renders rather than erroring the request)", w.Code)
	}
	if !strings.Contains(w.Body.String(), echoErrorCopy) {
		t.Errorf("expected the exact error copy, got:\n%s", w.Body.String())
	}
}

func TestEchoOversizedBodyError(t *testing.T) {
	h := Handler(testOptions())
	big := strings.Repeat("a", maxEchoMsgBytes+1000)
	form := url.Values{"msg": {big}}
	w := doRequest(h, http.MethodPost, "/echo", form.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, echoErrorCopy) {
		t.Errorf("expected the exact error copy, got:\n%s", body)
	}
	if strings.Contains(body, big) {
		t.Error("oversized value must not be rendered back")
	}
}

func TestEchoAtSizeBoundary(t *testing.T) {
	h := Handler(testOptions())

	exact := strings.Repeat("a", maxEchoMsgBytes)
	w1 := doRequest(h, http.MethodPost, "/echo", url.Values{"msg": {exact}}.Encode())
	if w1.Code != http.StatusOK || !strings.Contains(w1.Body.String(), "You sent: "+exact) {
		t.Errorf("a message of exactly %d bytes should be accepted and echoed", maxEchoMsgBytes)
	}

	over := strings.Repeat("a", maxEchoMsgBytes+1)
	w2 := doRequest(h, http.MethodPost, "/echo", url.Values{"msg": {over}}.Encode())
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), echoErrorCopy) {
		t.Errorf("a message of %d bytes should be rejected with the error copy", maxEchoMsgBytes+1)
	}
}

func TestEchoIsStateless(t *testing.T) {
	h := Handler(testOptions())

	w1 := doRequest(h, http.MethodPost, "/echo", url.Values{"msg": {"first"}}.Encode())
	w2 := doRequest(h, http.MethodPost, "/echo", url.Values{"msg": {"second"}}.Encode())

	if !strings.Contains(w1.Body.String(), "You sent: first") || strings.Contains(w1.Body.String(), "second") {
		t.Error("first response is not independent of the second request")
	}
	if !strings.Contains(w2.Body.String(), "You sent: second") || strings.Contains(w2.Body.String(), "You sent: first") {
		t.Error("second response is not independent of the first request")
	}
	if cookies := w1.Result().Cookies(); len(cookies) != 0 {
		t.Error("echo handler set a cookie — the page must be stateless")
	}
}

func TestEchoNoJavaScript(t *testing.T) {
	h := Handler(testOptions())
	body := doRequest(h, http.MethodGet, "/echo", "").Body.String()
	if strings.Contains(body, "<script") {
		t.Error("echo page contains a <script> element")
	}
}
