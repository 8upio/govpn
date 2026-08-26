// clock.go provides an injectable Clock/Timer pair, mirroring
// internal/reliable's own Clock/SystemClock precedent
// (internal/reliable/reliable.go:79-89) in spirit but extended with a
// Timer that actually FIRES rather than merely comparing timestamps: plan
// 03-03's TCP retransmit and TIME_WAIT machinery must be driven
// deterministically in tests, with no real sleeps, which requires a timer
// a fake clock can advance and fire on demand (see the fakeClock in
// stack_test.go, which the whole wave-2 TCP suite depends on existing).
package netstack

import "time"

// Clock abstracts wall-clock time and timer creation so a stateful
// component's retransmit/backoff timers can be driven from an injected
// fake clock in tests instead of real sleeps.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer abstracts a running timer: C returns the channel the timer fires
// on, Reset and Stop mirror time.Timer's own semantics.
type Timer interface {
	C() <-chan time.Time
	Reset(d time.Duration) bool
	Stop() bool
}

// SystemClock is the default Clock, backed by time.Now and time.NewTimer.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// NewTimer implements Clock.
func (SystemClock) NewTimer(d time.Duration) Timer {
	return &systemTimer{t: time.NewTimer(d)}
}

// systemTimer adapts *time.Timer to the Timer interface.
type systemTimer struct {
	t *time.Timer
}

func (s *systemTimer) C() <-chan time.Time        { return s.t.C }
func (s *systemTimer) Reset(d time.Duration) bool { return s.t.Reset(d) }
func (s *systemTimer) Stop() bool                 { return s.t.Stop() }
