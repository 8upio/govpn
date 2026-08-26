package netstack

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestICMPNonEchoDropped asserts D-11: the responder answers echo requests
// only. Destination unreachable (3), time exceeded (11), and echo reply
// (0) addressed to the server IP each produce no outbound packet and no
// generated ICMP error.
func TestICMPNonEchoDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	for _, icmpType := range []byte{3, 11, 0} {
		icmp := make([]byte, minICMPHeaderLen)
		icmp[0] = icmpType
		binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))
		pkt := buildIPv4(nil, mustAddr(ip), mustAddr(testServerIP()), protocolICMP, icmp)

		fs.inbound <- pkt
		assertNoOutbound(t, fs, 50*time.Millisecond)
	}
}
