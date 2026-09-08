package netstack

import (
	"net"
	"testing"
	"time"

	"github.com/8upio/govpn/netstack/netstacktest"
)

func testClientAddr() net.IP { return net.IPv4(10, 8, 0, 2).To4() }

// TestTCPSegmentRoundTrip: building a segment with sequence 0x11223344, ack
// 0x55667788, flags SYN|ACK, window 65535, and one MSS option, then parsing
// it back, reproduces every field; the data offset reflects the 4-byte
// option (header length 24, not 20); the checksum re-verified over the
// pseudo-header folds to zero.
func TestTCPSegmentRoundTrip(t *testing.T) {
	src := netstacktest.MustAddr(testClientAddr())
	dst := netstacktest.MustAddr(testServerIP())

	seg := tcpSegment{
		srcPort: 12345,
		dstPort: 80,
		seq:     0x11223344,
		ack:     0x55667788,
		flags:   flagSYN | flagACK,
		window:  65535,
		hasMSS:  true,
		mss:     1460,
	}

	built := buildTCP(nil, seg, src, dst)
	if len(built) != tcpHeaderMinLen+mssOptionLen {
		t.Fatalf("built length = %d, want %d (20-byte header + 4-byte MSS option)", len(built), tcpHeaderMinLen+mssOptionLen)
	}
	if dataOffsetNibble := built[12] >> 4; int(dataOffsetNibble)*4 != tcpHeaderMinLen+mssOptionLen {
		t.Fatalf("data offset = %d bytes, want %d", int(dataOffsetNibble)*4, tcpHeaderMinLen+mssOptionLen)
	}

	parsed, err := parseTCP(built)
	if err != nil {
		t.Fatalf("parseTCP: %v", err)
	}
	if parsed.srcPort != seg.srcPort || parsed.dstPort != seg.dstPort {
		t.Fatalf("ports = %d/%d, want %d/%d", parsed.srcPort, parsed.dstPort, seg.srcPort, seg.dstPort)
	}
	if parsed.seq != seg.seq || parsed.ack != seg.ack {
		t.Fatalf("seq/ack = %#x/%#x, want %#x/%#x", parsed.seq, parsed.ack, seg.seq, seg.ack)
	}
	if parsed.flags != seg.flags {
		t.Fatalf("flags = %#x, want %#x", parsed.flags, seg.flags)
	}
	if parsed.window != seg.window {
		t.Fatalf("window = %d, want %d", parsed.window, seg.window)
	}
	if !parsed.hasMSS || parsed.mss != seg.mss {
		t.Fatalf("MSS = (%v, %d), want (true, %d)", parsed.hasMSS, parsed.mss, seg.mss)
	}

	// The checksum, re-verified over the pseudo-header plus the full
	// segment WITH its own (correctly-computed) checksum field intact,
	// folds to zero — standard one's-complement checksum self-verification.
	if cs := transportChecksum(src, dst, protocolTCP, built); cs != 0 {
		t.Fatalf("transportChecksum over the built segment (with its own checksum intact) = %#x, want 0", cs)
	}
}

// TestTCPParseNeverPanics: every prefix length from 0 to 19 of a TCP
// header, a data-offset field of 0, a data offset of 15 on a 24-byte
// buffer, and an options region truncated mid-option, all return a typed
// error and never panic.
func TestTCPParseNeverPanics(t *testing.T) {
	src := netstacktest.MustAddr(testClientAddr())
	dst := netstacktest.MustAddr(testServerIP())
	full := buildTCP(nil, tcpSegment{srcPort: 1, dstPort: 2, flags: flagACK, window: 100}, src, dst)

	for n := 0; n < tcpHeaderMinLen; n++ {
		n := n
		t.Run("prefix", func(t *testing.T) {
			if _, err := parseTCP(full[:n]); err == nil {
				t.Fatalf("parseTCP(%d-byte prefix) succeeded, want an error", n)
			}
		})
	}

	t.Run("dataOffsetZero", func(t *testing.T) {
		buf := append([]byte(nil), full...)
		buf[12] = 0x00 // data offset nibble 0 -> 0 bytes, below minimum
		if _, err := parseTCP(buf); err == nil {
			t.Fatal("parseTCP with data offset 0 succeeded, want an error")
		}
	})

	t.Run("dataOffset15On24ByteBuffer", func(t *testing.T) {
		buf := make([]byte, 24)
		buf[12] = 0xF0 // data offset nibble 15 -> 60 bytes, exceeds len(buf)
		if _, err := parseTCP(buf); err == nil {
			t.Fatal("parseTCP with data offset 60 on a 24-byte buffer succeeded, want an error")
		}
	})

	t.Run("truncatedOption", func(t *testing.T) {
		// Data offset claims a 24-byte header (one 4-byte option) but the
		// option's own length byte claims more than remains.
		buf := make([]byte, 24)
		buf[12] = 0x60 // data offset nibble 6 -> 24 bytes
		buf[20] = mssOptionKind
		buf[21] = 0xFF // claims a huge option length
		if _, err := parseTCP(buf); err == nil {
			t.Fatal("parseTCP with a truncated option succeeded, want an error")
		}
	})

	t.Run("zeroLengthOption", func(t *testing.T) {
		buf := make([]byte, 24)
		buf[12] = 0x60
		buf[20] = 5 // an arbitrary non-end, non-NOP kind
		buf[21] = 0 // zero length: must not infinite-loop or index out of range
		if _, err := parseTCP(buf); err == nil {
			t.Fatal("parseTCP with a zero-length option succeeded, want an error")
		}
	})
}

// TestTCPMSSOption: a SYN carrying MSS 536 makes the connection's send MSS
// 536 (the clamp of min(1460, 536)); a SYN carrying MSS 9000 makes it 1460;
// a SYN with no MSS option makes it 536, RFC 9293's default when the
// option is absent. Exercised through the full handshake path (the clamp
// itself lives in tcp_listener.go's handleSYN), not by calling a bare
// helper — this is the behavior that actually matters.
func TestTCPMSSOption(t *testing.T) {
	cases := []struct {
		name      string
		hasMSS    bool
		clientMSS uint16
		wantMSS   uint16
	}{
		{"clampedDown", true, 536, 536},
		{"clampedUp", true, 9000, 1460},
		{"absent", false, 0, 536},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack := newTestStack(t)
			defer stack.Close()
			ln, err := stack.ListenTCP(80)
			if err != nil {
				t.Fatalf("ListenTCP: %v", err)
			}
			defer ln.Close()

			fs := netstacktest.NewFakeSession()
			if err := stack.Attach(fs, testClientAddr()); err != nil {
				t.Fatalf("Attach: %v", err)
			}

			client := newTCPTestClient(t, fs, testClientAddr(), 12345, testServerIP(), 80)
			syn := tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535}
			if tc.hasMSS {
				syn.hasMSS = true
				syn.mss = tc.clientMSS
			}
			client.sendRaw(syn)

			// SYN-ACK always advertises the SERVER's own MSS (defaultMSS);
			// the client's MSS affects the server's SEND mss instead,
			// asserted below via a large write's first segment size.
			synack := client.recvRaw(time.Second)
			if synack.mss != defaultMSS {
				t.Fatalf("SYN-ACK MSS = %d, want %d (the server's own MSS, independent of the client's)", synack.mss, defaultMSS)
			}

			client.serverISN = synack.seq
			client.rcvNext = synack.seq + 1
			client.sndNext = client.isn + 1
			client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535})

			conn, err := ln.Accept()
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			defer conn.Close()

			large := make([]byte, 3000)
			for i := range large {
				large[i] = byte(i)
			}
			go conn.Write(large)

			first := client.recvRaw(time.Second)
			if len(first.payload) != int(tc.wantMSS) {
				t.Fatalf("first segment payload = %d bytes, want %d (clamped MSS)", len(first.payload), tc.wantMSS)
			}
		})
	}
}
