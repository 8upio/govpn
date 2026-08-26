package main

import (
	"net/http"
	"testing"
)

// TestNewHardenedHTTPServerSetsTimeouts (WR-02): the *http.Server this
// example serves the tunnelweb site through must set ReadHeaderTimeout (at
// minimum) — net/http only arms a read deadline on an accepted connection
// once one of ReadHeaderTimeout/ReadTimeout/WriteTimeout/IdleTimeout is
// set, so a zero-valued Server (the pre-fix &http.Server{Handler: ...}
// literal) lets a client that sends headers slowly, or never, tie up a
// goroutine forever. This test fails without WR-02's fix, since the
// pre-fix literal left every one of these fields at its zero value.
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
