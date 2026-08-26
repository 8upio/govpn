package main

import (
	"net/http"
	"testing"
)

// TestNewHardenedHTTPServerSetsTimeouts (WR-02): mirrors
// examples/tunnelweb/main_test.go's own test for the harness's copy of the
// same fix. The pre-fix code called the package-level http.Serve directly
// with no *http.Server at all, so there was no way to set any timeout;
// this test fails without WR-02's fix.
func TestNewHardenedHTTPServerSetsTimeouts(t *testing.T) {
	srv := newHardenedHTTPServer(http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %v, want a positive duration", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout <= 0 {
		t.Fatalf("ReadTimeout = %v, want a positive duration", srv.ReadTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Fatalf("WriteTimeout = %v, want a positive duration", srv.WriteTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout = %v, want a positive duration", srv.IdleTimeout)
	}
	if srv.Handler == nil {
		t.Fatal("Handler was not set")
	}
}
