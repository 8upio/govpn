// fakesession_test.go is the fast tier's in-memory Session (D-12): no
// Docker needed to drive Stack with hand-built packets. fakeSession's
// Read/Write shape mirrors the real ovpn.Session's own contract
// (session.go:305-355) so a test against fakeSession cannot pass in a way
// the real Session would fail: Read is datagram-shaped and retains an
// oversized packet on a too-small buffer (session.go:305-320) rather than
// truncating or dropping it, and Close makes subsequent Reads return
// io.EOF.
package netstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
)

// errShortReadBuffer mirrors ovpn.Session.Read's own "packet retained for
// a future Read" error shape (session.go:305-320) closely enough for
// tests: a caller providing an undersized buffer gets an error, and the
// packet is retained rather than dropped or truncated.
var errShortReadBuffer = errors.New("fakeSession: read buffer too small; packet retained")

// fakeSession is the fast tier's in-memory Session. inbound/outbound are
// buffered channels a test feeds/drains directly. readMu/readActive/
// readOverlapped/readerIDs support TestSingleReaderPerSession's assertion
// that Stack.Attach never starts more than one reader goroutine per
// session (session.go:305-313's single-reader contract) — captured via a
// per-Read active-flag (an overlap is a call entering while another is
// still in flight) and, since the technique the plan calls for is cheap
// per-Read bookkeeping rather than reaching for runtime goroutine IDs as
// the primary mechanism, a secondary goroutine-identity set for the exact
// "distinct goroutine count" assertion the test also makes.
type fakeSession struct {
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

func newFakeSession() *fakeSession {
	return &fakeSession{
		inbound:  make(chan []byte, 16),
		outbound: make(chan []byte, 16),
		doneCh:   make(chan struct{}),
	}
}

// Read implements Session. See the type doc comment for the
// single-reader-tracking bookkeeping wrapped around doRead below.
func (f *fakeSession) Read(p []byte) (int, error) {
	f.markReadEnter()
	defer f.markReadExit()
	return f.doRead(p)
}

func (f *fakeSession) doRead(p []byte) (int, error) {
	f.mu.Lock()
	if f.pendingRead != nil {
		pkt := f.pendingRead
		if len(p) < len(pkt) {
			f.mu.Unlock()
			return 0, errShortReadBuffer
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
			return 0, errShortReadBuffer
		}
		return copy(p, pkt), nil
	case <-f.doneCh:
		return 0, io.EOF
	}
}

func (f *fakeSession) markReadEnter() {
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

func (f *fakeSession) markReadExit() {
	f.readMu.Lock()
	f.readActive = false
	f.readMu.Unlock()
}

// goroutineID extracts the calling goroutine's numeric ID by parsing the
// leading "goroutine N [running]:" line of a runtime.Stack dump. Test-only
// (isolated to this _test.go file): used solely so
// TestSingleReaderPerSession can assert the literal number of distinct
// goroutines that ever called Read, a stronger and more direct check than
// overlap detection alone.
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
// retained past the call) onto the outbound channel for a test to drain.
func (f *fakeSession) Write(p []byte) (int, error) {
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
func (f *fakeSession) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	close(f.doneCh)
	return nil
}

// mustAddr converts ip (must have a usable IPv4 form) to a netip.Addr,
// panicking otherwise — test-helper only, never called with untrusted
// input.
func mustAddr(ip net.IP) netip.Addr {
	ip4 := ip.To4()
	if ip4 == nil {
		panic("mustAddr: not an IPv4 address")
	}
	return netip.AddrFrom4([4]byte(ip4))
}

// buildICMPEchoRequest builds a complete, checksummed IPv4+ICMP echo
// request packet from src to dst, with the given identifier, sequence
// number, and payload — so tests read as intent (source, destination,
// identifier, sequence, payload), not as hand-assembled byte arithmetic.
func buildICMPEchoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, minICMPHeaderLen+len(payload))
	icmp[0] = icmpTypeEchoRequest
	icmp[1] = 0 // code
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))

	return buildIPv4(nil, src, dst, protocolICMP, icmp)
}

// buildFragmentForTest builds one IPv4 fragment carrying payload: a normal
// packet from buildIPv4, with the Identification field set to id, the
// flags/fragment-offset word set from offsetBytes (in BYTES — divided by 8
// here so no test ever has to do that arithmetic itself) and mf, and the
// header checksum recomputed over the patched header. Every fragment test
// in this package builds its fragments through this one helper, so a test
// reads as intent (which datagram, which offset, more-to-come or not)
// rather than as hand-assembled byte arithmetic.
func buildFragmentForTest(src, dst netip.Addr, proto uint8, id uint16, offsetBytes int, mf bool, payload []byte) []byte {
	pkt := buildIPv4(nil, src, dst, proto, payload)

	binary.BigEndian.PutUint16(pkt[4:6], id)

	flagsFragOffset := uint16(offsetBytes / 8)
	if mf {
		flagsFragOffset |= flagMoreFragments
	}
	binary.BigEndian.PutUint16(pkt[6:8], flagsFragOffset)

	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:minIPv4HeaderLen]))
	return pkt
}
