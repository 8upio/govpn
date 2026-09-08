package netstack

// netstacktest_frames_test.go is the contract test the Welle-2 requirement
// calls for: every netstacktest builder's output is fed to netstack's own
// parseIPv4 (and parseUDP for the UDP frame), proving the two packages stay
// consistent. This is also why netstacktest cannot import netstack — this
// file, in package netstack, is the one place both are imported together.

import (
	"net"
	"testing"

	"github.com/8upio/govpn/netstack/netstacktest"
)

func TestNetstackTestBuildIPv4AcceptedByParseIPv4(t *testing.T) {
	src := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())
	dst := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())
	payload := []byte("hello")

	pkt := netstacktest.BuildIPv4(src, dst, protocolUDP, payload)

	hdr, err := parseIPv4(pkt)
	if err != nil {
		t.Fatalf("parseIPv4: %v", err)
	}
	if hdr.protocol != protocolUDP {
		t.Errorf("protocol = %d, want %d", hdr.protocol, protocolUDP)
	}
	if hdr.totalLen != minIPv4HeaderLen+len(payload) {
		t.Errorf("totalLen = %d, want %d", hdr.totalLen, minIPv4HeaderLen+len(payload))
	}
	if hdr.src != src {
		t.Errorf("src = %v, want %v", hdr.src, src)
	}
	if hdr.dst != dst {
		t.Errorf("dst = %v, want %v", hdr.dst, dst)
	}
	if cs := internetChecksum(pkt[:hdr.ihl]); cs != 0 {
		t.Errorf("internetChecksum over the parsed header = %#04x, want 0", cs)
	}
}

func TestNetstackTestBuildUDPAcceptedByParseUDP(t *testing.T) {
	src := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())
	dst := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())
	payload := []byte("udp payload")

	pkt := netstacktest.BuildUDP(src, dst, 5000, 9999, payload)

	hdr, err := parseIPv4(pkt)
	if err != nil {
		t.Fatalf("parseIPv4: %v", err)
	}
	if hdr.protocol != protocolUDP {
		t.Fatalf("protocol = %d, want %d (UDP)", hdr.protocol, protocolUDP)
	}
	if hdr.src != src || hdr.dst != dst {
		t.Fatalf("src/dst = %v/%v, want %v/%v", hdr.src, hdr.dst, src, dst)
	}

	segment := pkt[hdr.payloadOff:hdr.totalLen]
	srcPort, dstPort, data, err := parseUDP(segment)
	if err != nil {
		t.Fatalf("parseUDP: %v", err)
	}
	if srcPort != 5000 {
		t.Errorf("srcPort = %d, want 5000", srcPort)
	}
	if dstPort != 9999 {
		t.Errorf("dstPort = %d, want 9999", dstPort)
	}
	if string(data) != string(payload) {
		t.Errorf("data = %q, want %q", data, payload)
	}
	if cs := transportChecksum(src, dst, protocolUDP, segment); cs != 0 {
		t.Errorf("transportChecksum did not verify (fold to zero): got %#04x", cs)
	}
}

func TestNetstackTestBuildICMPEchoRequestAcceptedByParseIPv4(t *testing.T) {
	src := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())
	dst := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())
	payload := []byte("ping")

	pkt := netstacktest.BuildICMPEchoRequest(src, dst, 42, 7, payload)

	hdr, err := parseIPv4(pkt)
	if err != nil {
		t.Fatalf("parseIPv4: %v", err)
	}
	if hdr.protocol != protocolICMP {
		t.Fatalf("protocol = %d, want %d (ICMP)", hdr.protocol, protocolICMP)
	}
	icmpMsg := pkt[hdr.payloadOff:hdr.totalLen]
	if len(icmpMsg) < minICMPHeaderLen {
		t.Fatalf("ICMP message too short: %d bytes", len(icmpMsg))
	}
	if icmpMsg[0] != icmpTypeEchoRequest {
		t.Errorf("ICMP type = %d, want %d (echo request)", icmpMsg[0], icmpTypeEchoRequest)
	}
	if cs := internetChecksum(icmpMsg); cs != 0 {
		t.Errorf("ICMP checksum did not fold to zero: got %#04x", cs)
	}
	if cs := internetChecksum(pkt[:hdr.ihl]); cs != 0 {
		t.Errorf("IPv4 header checksum did not fold to zero: got %#04x", cs)
	}
}

func TestNetstackTestBuildFragmentAcceptedByParseIPv4(t *testing.T) {
	src := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())
	dst := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())
	payload := make([]byte, 16)

	frag := netstacktest.BuildFragment(src, dst, protocolUDP, 0x1234, 1480, true, payload)

	hdr, err := parseIPv4(frag)
	if err != nil {
		t.Fatalf("parseIPv4: %v", err)
	}
	if hdr.id != 0x1234 {
		t.Errorf("id = %#04x, want %#04x", hdr.id, 0x1234)
	}
	if !hdr.moreFragments {
		t.Error("moreFragments = false, want true (mf argument was true)")
	}
	if hdr.fragOffset != 1480 {
		t.Errorf("fragOffset = %d bytes, want 1480 bytes (185 in 8-octet units)", hdr.fragOffset)
	}
	if cs := internetChecksum(frag[:hdr.ihl]); cs != 0 {
		t.Errorf("internetChecksum over the parsed header = %#04x, want 0", cs)
	}

	// Also verify the not-more-fragments, zero-offset case is accepted and
	// reported correctly, so both BuildFragment argument combinations are
	// covered.
	last := netstacktest.BuildFragment(src, dst, protocolUDP, 0x1234, 0, false, payload)
	hdrLast, err := parseIPv4(last)
	if err != nil {
		t.Fatalf("parseIPv4(last fragment): %v", err)
	}
	if hdrLast.moreFragments {
		t.Error("moreFragments = true, want false (mf argument was false)")
	}
	if hdrLast.fragOffset != 0 {
		t.Errorf("fragOffset = %d, want 0", hdrLast.fragOffset)
	}
}
