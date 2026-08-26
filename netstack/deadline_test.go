package netstack

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestDeadlineErrorSatisfiesNetError asserts RESEARCH.md Pitfall 1's
// contract: the netstack's deadline sentinel satisfies net.Error with
// Timeout() == true, AND errors.Is(err, os.ErrDeadlineExceeded) succeeds —
// net/http's readRequest depends on both halves.
func TestDeadlineErrorSatisfiesNetError(t *testing.T) {
	var err error = errDeadlineExceeded

	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatal("the netstack's deadline sentinel does not satisfy net.Error")
	}
	if !netErr.Timeout() {
		t.Fatal("the netstack's deadline sentinel's Timeout() = false, want true")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("errors.Is(err, os.ErrDeadlineExceeded) = false, want true")
	}
}

// TestDeadlineTimerFires exercises deadlineTimer's three documented cases:
// a future deadline fires, a zero (cleared) deadline never fires, and set
// called from a goroutine other than the one blocked in wait() is
// race-free under -race and still wakes the waiter.
func TestDeadlineTimerFires(t *testing.T) {
	dt := newDeadlineTimer()
	dt.set(time.Now().Add(10 * time.Millisecond))
	select {
	case <-dt.wait():
	case <-time.After(time.Second):
		t.Fatal("deadline set 10ms out did not fire within 1s")
	}

	dt2 := newDeadlineTimer()
	dt2.set(time.Time{})
	select {
	case <-dt2.wait():
		t.Fatal("a zero-time deadline fired; it must never fire")
	case <-time.After(50 * time.Millisecond):
	}

	dt3 := newDeadlineTimer()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-dt3.wait()
	}()
	time.Sleep(10 * time.Millisecond) // let the goroutine above block in wait() first.
	dt3.set(time.Now().Add(10 * time.Millisecond))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a waiter blocked in wait() did not observe a deadline set from a different goroutine")
	}
}
