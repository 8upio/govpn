package ovpn

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestPushReplyStringExact(t *testing.T) {
	_, network, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	clientIP := net.ParseIP("10.8.0.2")

	got := buildPushReply(clientIP, network, 0, "AES-256-GCM")

	want := append([]byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id 0,cipher AES-256-GCM,ping 10,ping-restart 60"), 0)

	if !bytes.Equal(got, want) {
		t.Errorf("buildPushReply() = %q, want %q", got, want)
	}
}

func TestPushReplyNetmaskFromPrefix(t *testing.T) {
	cases := []struct {
		cidr        string
		clientIP    string
		wantNetmask string
	}{
		{"10.9.0.0/16", "10.9.0.2", "255.255.0.0"},
		{"10.10.0.0/30", "10.10.0.2", "255.255.255.252"},
	}

	for _, c := range cases {
		_, network, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatalf("parse network %s: %v", c.cidr, err)
		}
		reply := buildPushReply(net.ParseIP(c.clientIP), network, 1, "AES-256-GCM")
		wantSegment := "ifconfig " + c.clientIP + " " + c.wantNetmask
		if !bytes.Contains(reply, []byte(wantSegment)) {
			t.Errorf("buildPushReply(%s) = %q, want it to contain %q", c.cidr, reply, wantSegment)
		}
	}
}

// TestPushReplyNormalizesSixteenByteMask is WR-01's regression test:
// net.IPNet.Mask can be a 16-byte slice even for an IPv4 network (e.g. a
// manually-built *net.IPNet, not just one parsed from a CIDR string), and
// buildPushReply must normalize it exactly like newIPPool already does,
// rather than formatting the raw 16 bytes as an IPv6 address in the
// ifconfig line.
func TestPushReplyNormalizesSixteenByteMask(t *testing.T) {
	network := &net.IPNet{
		IP:   net.ParseIP("10.8.0.0").To4(),
		Mask: net.CIDRMask(24, 32), // net.CIDRMask always returns a 4-byte
	}
	// Force the 16-byte shape newIPPool's own doc comment calls out as the
	// exact case it defends against.
	sixteenByteMask := make(net.IPMask, net.IPv6len)
	copy(sixteenByteMask[12:], network.Mask)
	network.Mask = sixteenByteMask

	reply := buildPushReply(net.ParseIP("10.8.0.2"), network, 0, "AES-256-GCM")

	wantSegment := "ifconfig 10.8.0.2 255.255.255.0"
	if !bytes.Contains(reply, []byte(wantSegment)) {
		t.Errorf("buildPushReply() with a 16-byte Mask = %q, want it to contain %q (normalized dotted-decimal netmask, not the raw 16-byte IPv6-shaped mask)", reply, wantSegment)
	}
}

func TestPushReplyEndsWithSingleNUL(t *testing.T) {
	_, network, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		t.Fatalf("parse network: %v", err)
	}
	reply := buildPushReply(net.ParseIP("10.8.0.2"), network, 0, "AES-256-GCM")

	if n := bytes.Count(reply, []byte{0}); n != 1 {
		t.Fatalf("reply contains %d NUL bytes, want exactly 1: %q", n, reply)
	}
	if reply[len(reply)-1] != 0 {
		t.Fatalf("reply does not end with a NUL byte: %q", reply)
	}
}

func TestReadPushRequestAcceptsExactLiteral(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("PUSH_REQUEST\x00"))
	got, err := readControlString(r, maxControlStringLen)
	if err != nil {
		t.Fatalf("readControlString: %v", err)
	}
	if got != pushRequestLiteral {
		t.Errorf("readControlString() = %q, want %q", got, pushRequestLiteral)
	}
}

func TestReadPushRequestRejectsWrongLiteral(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("SOMETHING_ELSE\x00trailing garbage that must not be consumed"))
	got, err := readControlString(r, maxControlStringLen)
	if err != nil {
		t.Fatalf("readControlString: %v", err)
	}
	if got == pushRequestLiteral {
		t.Fatalf("readControlString() = %q, want a different string than the push-request literal", got)
	}
	if got != "SOMETHING_ELSE" {
		t.Errorf("readControlString() = %q, want %q", got, "SOMETHING_ELSE")
	}

	// Confirm the reader stopped exactly at its own NUL, not past it: the
	// next byte read should be the start of "trailing garbage...", not
	// consumed as part of the first string.
	next, err := r.ReadByte()
	if err != nil {
		t.Fatalf("read next byte: %v", err)
	}
	if next != 't' {
		t.Errorf("byte after the terminator = %q, want 't' (readControlString consumed past its own NUL)", next)
	}
}

func TestReadPushRequestRejectsUnterminatedFlood(t *testing.T) {
	flood := bytes.Repeat([]byte{'A'}, 64*1024)
	r := bufio.NewReader(bytes.NewReader(flood))

	_, err := readControlString(r, maxControlStringLen)
	if err == nil {
		t.Fatal("readControlString did not error on a 64KiB flood with no NUL terminator")
	}
}

func TestWriteControlStringAppendsSingleNUL(t *testing.T) {
	var buf bytes.Buffer
	if err := writeControlString(&buf, "PUSH_REPLY,foo"); err != nil {
		t.Fatalf("writeControlString: %v", err)
	}
	want := append([]byte("PUSH_REPLY,foo"), 0)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("writeControlString wrote %q, want %q", buf.Bytes(), want)
	}
}
