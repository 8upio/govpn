package netstacktest

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strconv"
	"sync"
)

// ErrShortReadBuffer mirrors ovpn.Session.Read's own "packet retained for a
// future Read" error shape (session.go:305-320) closely enough for tests: a
// caller providing an undersized buffer gets an error, and the packet is
// retained rather than dropped or truncated.
var ErrShortReadBuffer = errors.New("netstacktest: read buffer too small; packet retained")

// FakeSession is a fast-tier, in-memory Session (D-12): no Docker needed to
// drive a netstack.Stack with hand-built packets. Its Read/Write shape
// mirrors the real ovpn.Session's own contract (session.go:305-355) closely
// enough that a test against FakeSession cannot pass in a way the real
// Session would fail: Read is datagram-shaped and retains an oversized
// packet on a too-small buffer (session.go:305-320) rather than truncating
// or dropping it, and Close makes subsequent Reads return io.EOF.
type FakeSession struct {
	inbound  chan []byte
	outbound chan []byte

	mu          sync.Mutex
	pendingRead []byte
	closed      bool
	doneCh      chan struct{}

	readMu         sync.Mutex
	readActive     bool
	readOverlapped bool
	readerIDs      map[int64]bool
}

// NewFakeSession returns a ready-to-use FakeSession with buffered
// inbound/outbound queues.
func NewFakeSession() *FakeSession {
	return &FakeSession{
		inbound:  make(chan []byte, 16),
		outbound: make(chan []byte, 16),
		doneCh:   make(chan struct{}),
	}
}

// Read implements Session (structurally satisfying netstack.Session /
// io.ReadWriteCloser). It wraps doRead with the single-reader-tracking
// bookkeeping ReadObservations reports.
func (f *FakeSession) Read(p []byte) (int, error) {
	f.markReadEnter()
	defer f.markReadExit()
	return f.doRead(p)
}

func (f *FakeSession) doRead(p []byte) (int, error) {
	f.mu.Lock()
	if f.pendingRead != nil {
		pkt := f.pendingRead
		if len(p) < len(pkt) {
			f.mu.Unlock()
			return 0, ErrShortReadBuffer
		}
		f.pendingRead = nil
		n := copy(p, pkt)
		f.mu.Unlock()
		return n, nil
	}
	f.mu.Unlock()

	select {
	case pkt, ok := <-f.inbound:
		if !ok {
			return 0, io.EOF
		}
		if len(p) < len(pkt) {
			f.mu.Lock()
			f.pendingRead = pkt
			f.mu.Unlock()
			return 0, ErrShortReadBuffer
		}
		return copy(p, pkt), nil
	case <-f.doneCh:
		return 0, io.EOF
	}
}

func (f *FakeSession) markReadEnter() {
	f.readMu.Lock()
	defer f.readMu.Unlock()
	if f.readActive {
		f.readOverlapped = true
	}
	f.readActive = true
	if f.readerIDs == nil {
		f.readerIDs = make(map[int64]bool)
	}
	f.readerIDs[goroutineID()] = true
}

func (f *FakeSession) markReadExit() {
	f.readMu.Lock()
	f.readActive = false
	f.readMu.Unlock()
}

// goroutineID extracts the calling goroutine's numeric ID by parsing the
// leading "goroutine N [running]:" line of a runtime.Stack dump. Used
// solely so a caller's test can assert the literal number of distinct
// goroutines that ever called Read via ReadObservations, a stronger and
// more direct check than overlap detection alone.
func goroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	fields := bytes.Fields(buf[:n])
	if len(fields) < 2 {
		return -1
	}
	id, err := strconv.ParseInt(string(fields[1]), 10, 64)
	if err != nil {
		return -1
	}
	return id
}

// Write implements Session: it copies p (the caller's buffer must not be
// retained past the call) onto the outbound channel for a caller to drain
// via Outbound().
func (f *FakeSession) Write(p []byte) (int, error) {
	pkt := append([]byte(nil), p...)
	select {
	case f.outbound <- pkt:
		return len(p), nil
	case <-f.doneCh:
		return 0, io.EOF
	}
}

// Close implements Session: idempotent, makes subsequent Read calls return
// io.EOF (mirroring ovpn.Session.Close's stopOnce-guarded, idempotent
// teardown, session.go:463-519).
func (f *FakeSession) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	close(f.doneCh)
	return nil
}

// Inject sends frame on FakeSession's inbound channel, as if it had arrived
// from the network — the caller-facing replacement for writing directly to
// the (now unexported) inbound channel.
func (f *FakeSession) Inject(frame []byte) {
	f.inbound <- frame
}

// Outbound returns the channel a caller drains to observe packets this
// FakeSession's owner (typically a netstack.Stack) wrote to it.
func (f *FakeSession) Outbound() <-chan []byte {
	return f.outbound
}

// ReadObservations is FakeSession's exported single-reader bookkeeping,
// the replacement for reaching into readOverlapped/readerIDs directly.
type ReadObservations struct {
	// DistinctReaders is the number of distinct goroutines that have ever
	// called Read on this FakeSession.
	DistinctReaders int

	// Overlapped reports whether any two Read calls were ever in flight
	// at the same time (one call entered while another had not yet
	// returned).
	Overlapped bool
}

// ReadObservations returns a snapshot of this FakeSession's single-reader
// bookkeeping — used to assert a Session.Read single-reader contract (e.g.
// netstack.Stack.Attach starts exactly one reader goroutine per attached
// session).
func (f *FakeSession) ReadObservations() ReadObservations {
	f.readMu.Lock()
	defer f.readMu.Unlock()
	return ReadObservations{
		DistinctReaders: len(f.readerIDs),
		Overlapped:      f.readOverlapped,
	}
}
