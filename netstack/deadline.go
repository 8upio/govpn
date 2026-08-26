// deadline.go implements the net.Conn/net.PacketConn deadline machinery
// every future netstack conn (plan 03-02's udpConn, plan 03-04's TCP conn)
// consumes, created here in wave 1 so neither plan creates a competing
// copy.
//
// RESEARCH.md Pitfall 1: net/http's (*http.conn).readRequest calls
// c.rwc.SetReadDeadline unconditionally (net/http/server.go:992), and a
// blocked Read that outlives its deadline must return an error that BOTH
// satisfies net.Error with Timeout() == true AND wraps
// os.ErrDeadlineExceeded so errors.Is(err, os.ErrDeadlineExceeded)
// succeeds (net/net.go:158-159's own doc comment: "I/O methods will return
// an error that wraps os.ErrDeadlineExceeded. This can be tested using
// errors.Is(err, os.ErrDeadlineExceeded)."). An error that is merely "an
// error" makes an ordinary idle keep-alive read look like a broken
// connection to net/http.
package netstack

import (
	"net"
	"os"
	"sync"
	"time"
)

// timeoutError is the netstack's net.Error-shaped deadline sentinel.
type timeoutError struct{}

func (timeoutError) Error() string   { return "netstack: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
func (timeoutError) Unwrap() error   { return os.ErrDeadlineExceeded }

// errDeadlineExceeded is the shared instance every deadlineTimer's wait
// channel closing represents.
var errDeadlineExceeded error = timeoutError{}

var _ net.Error = timeoutError{}

// deadlineTimer guards a deadline (a time.Time) and a channel that closes
// when that deadline passes, for a net.Conn/net.PacketConn's
// SetDeadline/SetReadDeadline/SetWriteDeadline implementation.
//
// set is safe to call from a goroutine other than the one blocked in
// wait() — the standard net.Conn usage pattern where a supervisor
// goroutine sets deadlines on a connection another goroutine is reading.
//
// This deliberately uses real time.AfterFunc, not the injected Clock from
// clock.go: deadlines are the caller's wall-clock contract with net/http,
// not this package's own internal protocol timing (retransmit/TIME_WAIT),
// and conflating the two would make an injected test clock silently change
// http.Server's timeout behavior.
type deadlineTimer struct {
	mu      sync.Mutex
	timer   *time.Timer
	ch      chan struct{}
	expired bool
}

// newDeadlineTimer returns a deadlineTimer with no deadline armed: wait()
// never closes until set is called with a non-zero, non-past time.Time.
func newDeadlineTimer() *deadlineTimer {
	return &deadlineTimer{ch: make(chan struct{})}
}

// set arms, re-arms, or clears the deadline. A zero time.Time clears any
// current deadline; if the previous deadline had already fired, a fresh,
// unexpired channel is armed so a future wait() call blocks correctly
// again. A past (or immediately-due) time.Time fires the deadline
// synchronously.
func (d *deadlineTimer) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}

	if d.expired {
		d.ch = make(chan struct{})
		d.expired = false
	}

	if t.IsZero() {
		return
	}

	dur := time.Until(t)
	if dur <= 0 {
		d.expired = true
		close(d.ch)
		return
	}

	ch := d.ch
	d.timer = time.AfterFunc(dur, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.expired {
			return
		}
		d.expired = true
		close(ch)
	})
}

// wait returns the channel that closes when the current deadline passes.
// A blocked reader/writer selects on it alongside its own data-ready
// channel.
func (d *deadlineTimer) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ch
}

// stop cancels any pending timer without affecting whether an
// already-fired deadline is still reported as expired.
func (d *deadlineTimer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}
