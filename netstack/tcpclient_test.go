// tcpclient_test.go is the test-only minimal TCP client (D-12) that makes
// this whole plan testable without Docker: it wraps a netstacktest.FakeSession plus a
// client IP/port, drives a handshake, a data stream, and a close sequence
// against a Stack's ListenTCP, and exposes raw escape hatches
// (sendRaw/recvRaw) for hand-crafting adversarial or intentionally
// out-of-order/dropped segments. It is deliberately dumb — it must not
// share code with the production state machine (tcp_state.go/tcp_conn.go/
// tcp_timer.go), or a symmetric bug would cancel out and both sides would
// agree on something a real client would reject.
package netstack

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/8upio/govpn/netstack/netstacktest"
)

// tcpTestClient is the fast tier's stand-in for a real OpenVPN client's TCP
// stack, driving a netstacktest.FakeSession with hand-built segments.
type tcpTestClient struct {
	t *testing.T

	fs *netstacktest.FakeSession

	localIP    netip.Addr
	localPort  uint16
	remoteIP   netip.Addr
	remotePort uint16

	isn       uint32 // this client's own initial sequence number
	sndNext   uint32 // next sequence number this client will send
	serverISN uint32
	rcvNext   uint32 // next sequence number expected from the server
	serverMSS uint16
}

// newTCPTestClient builds a client with a fixed, low ISN (1000) — this is
// a test double, not the production ISN-generation path
// (tcp_conn.go's randomISN), so a fixed value keeps test assertions
// readable; TestTCPISNIsRandom exercises the real production path
// directly, never through this client.
func newTCPTestClient(t *testing.T, fs *netstacktest.FakeSession, clientIP net.IP, clientPort uint16, serverIP net.IP, serverPort uint16) *tcpTestClient {
	t.Helper()
	return &tcpTestClient{
		t:          t,
		fs:         fs,
		localIP:    netstacktest.MustAddr(clientIP),
		localPort:  clientPort,
		remoteIP:   netstacktest.MustAddr(serverIP),
		remotePort: serverPort,
		isn:        1000,
	}
}

// sendRaw builds seg into a complete IPv4+TCP packet and delivers it to the
// fake session's inbound channel, as if the client had sent it on the wire.
func (c *tcpTestClient) sendRaw(seg tcpSegment) {
	tcpBytes := buildTCP(nil, seg, c.localIP, c.remoteIP)
	pkt := buildIPv4(nil, c.localIP, c.remoteIP, protocolTCP, tcpBytes)
	c.fs.Inject(pkt)
}

// recvRaw reads the next outbound packet the stack wrote to this client's
// session and parses it as a TCP segment, failing the test on a timeout or
// a parse error.
func (c *tcpTestClient) recvRaw(timeout time.Duration) tcpSegment {
	c.t.Helper()
	select {
	case pkt := <-c.fs.Outbound():
		hdr, err := parseIPv4(pkt)
		if err != nil {
			c.t.Fatalf("recvRaw: parseIPv4: %v", err)
		}
		seg, err := parseTCP(pkt[hdr.payloadOff:hdr.totalLen])
		if err != nil {
			c.t.Fatalf("recvRaw: parseTCP: %v", err)
		}
		return seg
	case <-time.After(timeout):
		c.t.Fatal("recvRaw: timed out waiting for an outbound TCP segment")
		return tcpSegment{}
	}
}

// tryRecvRaw is recvRaw's non-fatal twin: it reports ok=false on a timeout
// instead of failing the test, for tests that need to assert the ABSENCE
// of a segment.
func (c *tcpTestClient) tryRecvRaw(timeout time.Duration) (tcpSegment, bool) {
	select {
	case pkt := <-c.fs.Outbound():
		hdr, err := parseIPv4(pkt)
		if err != nil {
			return tcpSegment{}, false
		}
		seg, err := parseTCP(pkt[hdr.payloadOff:hdr.totalLen])
		if err != nil {
			return tcpSegment{}, false
		}
		return seg, true
	case <-time.After(timeout):
		return tcpSegment{}, false
	}
}

// connect drives a full three-way handshake: SYN, expect SYN-ACK
// (capturing the server's ISN and advertised MSS/window), then ACK.
func (c *tcpTestClient) connect() {
	c.t.Helper()
	c.sendRaw(tcpSegment{
		srcPort: c.localPort,
		dstPort: c.remotePort,
		seq:     c.isn,
		flags:   flagSYN,
		window:  65535,
		hasMSS:  true,
		mss:     1460,
	})

	synack := c.recvRaw(time.Second)
	if synack.flags != flagSYN|flagACK {
		c.t.Fatalf("connect: SYN-ACK flags = %#x, want SYN|ACK", synack.flags)
	}
	if synack.ack != c.isn+1 {
		c.t.Fatalf("connect: SYN-ACK ack = %d, want %d (client ISN+1)", synack.ack, c.isn+1)
	}

	c.serverISN = synack.seq
	c.rcvNext = synack.seq + 1
	c.serverMSS = synack.mss
	c.sndNext = c.isn + 1

	c.sendRaw(tcpSegment{
		srcPort: c.localPort,
		dstPort: c.remotePort,
		seq:     c.sndNext,
		ack:     c.rcvNext,
		flags:   flagACK,
		window:  65535,
	})
}

// sendData segments data by the server's advertised MSS (defaulting to 536
// if somehow zero) and sends it, expecting (and consuming) one ACK per
// segment.
func (c *tcpTestClient) sendData(data []byte) {
	c.t.Helper()
	mss := int(c.serverMSS)
	if mss <= 0 {
		mss = 536
	}
	for len(data) > 0 {
		chunk := data
		if len(chunk) > mss {
			chunk = chunk[:mss]
		}
		c.sendRaw(tcpSegment{
			srcPort: c.localPort,
			dstPort: c.remotePort,
			seq:     c.sndNext,
			ack:     c.rcvNext,
			flags:   flagACK,
			window:  65535,
			payload: chunk,
		})
		c.sndNext += uint32(len(chunk))
		data = data[len(chunk):]

		ack := c.recvRaw(time.Second)
		if ack.flags&flagACK == 0 {
			c.t.Fatalf("sendData: expected an ACK, got flags %#x", ack.flags)
		}
		if ack.ack != c.sndNext {
			c.t.Fatalf("sendData: ack = %d, want %d", ack.ack, c.sndNext)
		}
	}
}

// recvData reads and ACKs incoming data segments from the server until want
// bytes have been reassembled, skipping any bare (payload-less) ACK.
func (c *tcpTestClient) recvData(want int, timeout time.Duration) []byte {
	c.t.Helper()
	var out []byte
	deadline := time.Now().Add(timeout)
	for len(out) < want {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			c.t.Fatalf("recvData: timed out with %d/%d bytes", len(out), want)
		}
		seg := c.recvRaw(remaining)
		if len(seg.payload) == 0 {
			continue
		}
		if seg.seq != c.rcvNext {
			c.t.Fatalf("recvData: unexpected seq %d, want %d", seg.seq, c.rcvNext)
		}
		out = append(out, seg.payload...)
		c.rcvNext += uint32(len(seg.payload))
		c.sendRaw(tcpSegment{
			srcPort: c.localPort,
			dstPort: c.remotePort,
			seq:     c.sndNext,
			ack:     c.rcvNext,
			flags:   flagACK,
			window:  65535,
		})
	}
	return out
}

// expectServerFINAndClose consumes the server's FIN (ACKing it), sends this
// client's own FIN, and consumes the server's final ACK — the client's
// half of a server-initiated close (RFC 9293 §3.6's passive-side sequence,
// mirrored from the client's perspective).
func (c *tcpTestClient) expectServerFINAndClose() {
	c.t.Helper()
	fin := c.recvRaw(time.Second)
	if fin.flags&flagFIN == 0 {
		c.t.Fatalf("expectServerFINAndClose: expected a FIN, got flags %#x", fin.flags)
	}
	c.rcvNext = fin.seq + 1
	c.sendRaw(tcpSegment{
		srcPort: c.localPort,
		dstPort: c.remotePort,
		seq:     c.sndNext,
		ack:     c.rcvNext,
		flags:   flagACK,
		window:  65535,
	})

	c.sendRaw(tcpSegment{
		srcPort: c.localPort,
		dstPort: c.remotePort,
		seq:     c.sndNext,
		ack:     c.rcvNext,
		flags:   flagFIN | flagACK,
		window:  65535,
	})
	c.sndNext++

	finalAck := c.recvRaw(time.Second)
	if finalAck.flags&flagACK == 0 {
		c.t.Fatalf("expectServerFINAndClose: expected a final ACK, got flags %#x", finalAck.flags)
	}
	if finalAck.ack != c.sndNext {
		c.t.Fatalf("expectServerFINAndClose: final ack = %d, want %d", finalAck.ack, c.sndNext)
	}
}
