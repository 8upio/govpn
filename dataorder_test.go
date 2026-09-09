package ovpn

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/datachan"
)

// newOrderTestServer starts a real Serve loop and returns the server plus
// its bound socket. Only TLSCryptKey/TLSConfig are needed: these tests
// never reach the handshake, they inject sessions into dataSessions
// directly.
func newOrderTestServer(t *testing.T) (*Server, net.PacketConn) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if udpConn, ok := pc.(*net.UDPConn); ok {
		_ = udpConn.SetReadBuffer(1 << 20)
	}

	tlsCfg, _ := testHandshakeTLSConfig(t)
	// Serve's D-07 guard requires ClientAuth to mandate a client cert (or
	// Config.AuthUserPass to be set); these tests never reach the
	// handshake, so either satisfies Serve — RequireAnyClientCert is the
	// cheaper of the two.
	tlsCfg.ClientAuth = tls.RequireAnyClientCert
	srv := NewServer(Config{TLSCryptKey: testTLSCryptKey(t), TLSConfig: tlsCfg})

	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		srv.Close()
		pc.Close()
	})

	return srv, pc
}

// registerOrderTestSession builds a Session with a symmetric data wrapper
// (so the test can Seal what the server will Open) and publishes it into
// srv.dataSessions under peerID, with an ipInbound deep enough that a
// correctly-ordered run never drops.
func registerOrderTestSession(t *testing.T, srv *Server, peerID uint32, queue int) (*Session, *datachan.Wrapper) {
	t.Helper()

	wrapper, err := datachan.NewWrapper(testSymmetricDataKeys(t), peerID, 0)
	if err != nil {
		t.Fatalf("NewWrapper: %v", err)
	}

	sess := &Session{
		srv:       srv,
		primary:   keySlot{wrapper: wrapper},
		ipInbound: make(chan []byte, queue),
		stopCh:    make(chan struct{}),
	}

	srv.mu.Lock()
	srv.dataSessions[peerID] = sess
	srv.mu.Unlock()

	return sess, wrapper
}

// orderTestPayload builds a fixed 20-byte payload whose first 4 bytes are
// the big-endian-encoded seq — decode with binary.BigEndian.Uint32.
func orderTestPayload(seq uint32) []byte {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint32(payload[:4], seq)
	return payload
}

// TestDataPacketsReachReadInSocketOrder is the core B3 regression: one
// sender goroutine seals and sends 500 packets in ascending seq order over
// a real UDP socket to a single session; a reader goroutine drains
// Session.Read concurrently. Any inversion in the collected seq order is a
// direct reproduction of the reordering the embedder observed in
// production (640 reorder events in 3.5 minutes).
func TestDataPacketsReachReadInSocketOrder(t *testing.T) {
	srv, pc := newOrderTestServer(t)
	srvAddr := pc.LocalAddr()

	const peerID = 7
	const n = 500
	sess, wrapper := registerOrderTestSession(t, srv, peerID, 4096)

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	type result struct {
		got []uint32
	}
	resultCh := make(chan result, 1)

	go func() {
		got := make([]uint32, 0, n)
		buf := make([]byte, 1024)
		for len(got) < n {
			nRead, err := sess.Read(buf)
			if err != nil {
				break
			}
			if nRead < 4 {
				continue
			}
			got = append(got, binary.BigEndian.Uint32(buf[:4]))
		}
		resultCh <- result{got: got}
	}()

	for i := uint32(1); i <= n; i++ {
		sealed, err := wrapper.Seal(nil, orderTestPayload(i))
		if err != nil {
			t.Fatalf("Seal(%d): %v", i, err)
		}
		if _, err := clientPC.WriteTo(sealed, srvAddr); err != nil {
			t.Fatalf("WriteTo(%d): %v", i, err)
		}
	}

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for packets")
	}

	got := res.got
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Fatalf("order inversion: got[%d]=%d <= got[%d]=%d", i, got[i], i-1, got[i-1])
		}
	}
	if len(got) < n/2 {
		t.Fatalf("too few packets arrived: got %d, want >= %d (n=%d)", len(got), n/2, n)
	}
	t.Logf("received %d/%d packets, InboundQueueDropped=%d", len(got), n, sess.Stats().InboundQueueDropped)
}

// TestPerSessionOrderHoldsWithTwoSessionsInterleaved proves the ordering
// guarantee holds independently per session even when their packets are
// interleaved on the wire.
func TestPerSessionOrderHoldsWithTwoSessionsInterleaved(t *testing.T) {
	srv, pc := newOrderTestServer(t)
	srvAddr := pc.LocalAddr()

	const n = 250
	sessA, wrapperA := registerOrderTestSession(t, srv, 11, 4096)
	sessB, wrapperB := registerOrderTestSession(t, srv, 12, 4096)

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	collect := func(sess *Session) chan []uint32 {
		ch := make(chan []uint32, 1)
		go func() {
			got := make([]uint32, 0, n)
			buf := make([]byte, 1024)
			for len(got) < n {
				nRead, err := sess.Read(buf)
				if err != nil {
					break
				}
				if nRead < 4 {
					continue
				}
				got = append(got, binary.BigEndian.Uint32(buf[:4]))
			}
			ch <- got
		}()
		return ch
	}

	chA := collect(sessA)
	chB := collect(sessB)

	for i := uint32(1); i <= n; i++ {
		sealedA, err := wrapperA.Seal(nil, orderTestPayload(i))
		if err != nil {
			t.Fatalf("Seal A(%d): %v", i, err)
		}
		if _, err := clientPC.WriteTo(sealedA, srvAddr); err != nil {
			t.Fatalf("WriteTo A(%d): %v", i, err)
		}
		sealedB, err := wrapperB.Seal(nil, orderTestPayload(i))
		if err != nil {
			t.Fatalf("Seal B(%d): %v", i, err)
		}
		if _, err := clientPC.WriteTo(sealedB, srvAddr); err != nil {
			t.Fatalf("WriteTo B(%d): %v", i, err)
		}
	}

	deadline := time.After(10 * time.Second)
	var gotA, gotB []uint32
	for gotA == nil || gotB == nil {
		select {
		case gotA = <-chA:
		case gotB = <-chB:
		case <-deadline:
			t.Fatalf("timed out waiting for packets (haveA=%v haveB=%v)", gotA != nil, gotB != nil)
		}
	}

	check := func(name string, got []uint32) {
		for i := 1; i < len(got); i++ {
			if got[i] <= got[i-1] {
				t.Fatalf("%s: order inversion: got[%d]=%d <= got[%d]=%d", name, i, got[i], i-1, got[i-1])
			}
		}
		if len(got) < n/2 {
			t.Fatalf("%s: too few packets arrived: got %d, want >= %d (n=%d)", name, len(got), n/2, n)
		}
	}
	check("session 11", gotA)
	check("session 12", gotB)
}

// TestBlockedSessionDoesNotStallAnotherSessionsData is the guard on the
// risk this fix introduces: an inline read-loop path that could block
// would be worse than the reordering bug it fixes. Session "stalled" has
// a queue depth of 1 and no reader — its ipInbound fills immediately and
// every subsequent packet must be dropped via the non-blocking default
// case (session.go's handleDataPacket, D-06), never by blocking the read
// loop. Session "live" must keep receiving its own packets in order and
// well inside the deadline regardless of what happens to "stalled".
//
// This also structurally guarantees the bug report's third scenario
// ("data must not be delayed behind the control path"): data never
// touches sess.inbound or pump at all — the AST gate
// (TestGateServeDispatchesDataInline) is what keeps it that way.
func TestBlockedSessionDoesNotStallAnotherSessionsData(t *testing.T) {
	srv, pc := newOrderTestServer(t)
	srvAddr := pc.LocalAddr()

	const n = 100
	stalled, wrapperStalled := registerOrderTestSession(t, srv, 21, 1)
	live, wrapperLive := registerOrderTestSession(t, srv, 22, 4096)

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientPC.Close()

	liveCh := make(chan []uint32, 1)
	go func() {
		got := make([]uint32, 0, n)
		buf := make([]byte, 1024)
		for len(got) < n {
			nRead, err := live.Read(buf)
			if err != nil {
				break
			}
			if nRead < 4 {
				continue
			}
			got = append(got, binary.BigEndian.Uint32(buf[:4]))
		}
		liveCh <- got
	}()

	for i := uint32(1); i <= n; i++ {
		sealedStalled, err := wrapperStalled.Seal(nil, orderTestPayload(i))
		if err != nil {
			t.Fatalf("Seal stalled(%d): %v", i, err)
		}
		if _, err := clientPC.WriteTo(sealedStalled, srvAddr); err != nil {
			t.Fatalf("WriteTo stalled(%d): %v", i, err)
		}
		sealedLive, err := wrapperLive.Seal(nil, orderTestPayload(i))
		if err != nil {
			t.Fatalf("Seal live(%d): %v", i, err)
		}
		if _, err := clientPC.WriteTo(sealedLive, srvAddr); err != nil {
			t.Fatalf("WriteTo live(%d): %v", i, err)
		}
	}

	var got []uint32
	select {
	case got = <-liveCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for live session's packets — read loop may have blocked on the stalled session")
	}

	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Fatalf("order inversion: got[%d]=%d <= got[%d]=%d", i, got[i], i-1, got[i-1])
		}
	}
	if len(got) < n/2 {
		t.Fatalf("too few packets arrived for live session: got %d, want >= %d (n=%d)", len(got), n/2, n)
	}

	if dropped := stalled.Stats().InboundQueueDropped; dropped == 0 {
		t.Fatalf("stalled session never overflowed (InboundQueueDropped=0) — test is vacuous")
	}
}
