// udpaddr_test.go asserts the shape of the *net.UDPAddr values ListenUDP's
// conn produces via ReadFrom and LocalAddr — Network(), String(), and a
// 4-byte-representable IPv4 address — so an embedder printing or comparing
// them sees exactly what a real UDP socket would produce.
package netstack

import (
	"net"
	"testing"
	"time"

	"github.com/8upio/govpn/netstack/netstacktest"
)

func TestUDPAddrShape(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(11000)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	assertUDPAddrShape(t, conn.LocalAddr(), testServerIP(), 11000)

	pkt := netstacktest.BuildUDP(netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP()), 5000, 11000, []byte("x"))
	fs.Inject(pkt)

	buf := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	assertUDPAddrShape(t, addr, clientIP, 5000)
}

func assertUDPAddrShape(t *testing.T, addr net.Addr, wantIP net.IP, wantPort int) {
	t.Helper()
	if addr.Network() != "udp" {
		t.Errorf("Network() = %q, want %q", addr.Network(), "udp")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("addr type = %T, want *net.UDPAddr", addr)
	}
	if ip4 := udpAddr.IP.To4(); ip4 == nil {
		t.Errorf("IP %v is not 4-byte representable", udpAddr.IP)
	}
	if !udpAddr.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", udpAddr.IP, wantIP)
	}
	if udpAddr.Port != wantPort {
		t.Errorf("Port = %d, want %d", udpAddr.Port, wantPort)
	}
	wantString := (&net.UDPAddr{IP: wantIP, Port: wantPort}).String()
	if addr.String() != wantString {
		t.Errorf("String() = %q, want %q", addr.String(), wantString)
	}
}
