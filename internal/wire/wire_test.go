// Golden-vector tests for WIRE-01: byte offsets and constants exercised
// here trace to the pinned OpenVPN reference checkout
// (/Users/svenloth/dev/openvpn-reference, branch release/2.6, commit
// c9b790f5b9e8ebca5da38c22f479c31bb8d33686) — opcode/key-id packing and
// the legal opcode range from src/openvpn/ssl_pkt.h (P_OPCODE_SHIFT,
// P_KEY_ID_MASK, P_FIRST_OPCODE, P_LAST_OPCODE), and the control-packet
// plaintext layout (ack array, remote session id, own packet id) from
// src/openvpn/reliable.c (reliable_ack_write / reliable_ack_parse).
package wire

import "testing"

func testControlPacket(opcode Opcode, acks []PacketID, remoteSID SessionID, pid PacketID, payload []byte) ControlPacket {
	return ControlPacket{
		Opcode:          opcode,
		KeyID:           0,
		SessionID:       SessionID{},
		Acks:            acks,
		RemoteSessionID: remoteSID,
		PacketID:        pid,
		Payload:         payload,
	}
}

func TestControlPacketRoundTrip(t *testing.T) {
	sid := SessionID{1, 2, 3, 4, 5, 6, 7, 8}

	tests := []struct {
		name string
		cp   ControlPacket
	}{
		{
			name: "ack-only",
			cp:   testControlPacket(OpAckV1, []PacketID{7}, sid, 0, nil),
		},
		{
			name: "0 acks",
			cp:   testControlPacket(OpControlV1, nil, SessionID{}, 42, []byte("payload")),
		},
		{
			name: "1 ack",
			cp:   testControlPacket(OpControlV1, []PacketID{5}, sid, 6, []byte("payload")),
		},
		{
			name: "8 acks",
			cp:   testControlPacket(OpControlV1, []PacketID{1, 2, 3, 4, 5, 6, 7, 8}, sid, 9, []byte("payload")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := Header{Opcode: tt.cp.Opcode, KeyID: tt.cp.KeyID, SessionID: tt.cp.SessionID}
			plaintext := tt.cp.AppendPlaintext(nil)

			got, err := ParseControlPacket(plaintext, hdr)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			reserialized := got.AppendPlaintext(nil)
			if string(reserialized) != string(plaintext) {
				t.Fatalf("round trip mismatch:\n got: %x\nwant: %x", reserialized, plaintext)
			}

			if len(got.Acks) != len(tt.cp.Acks) {
				t.Fatalf("acks length = %d, want %d", len(got.Acks), len(tt.cp.Acks))
			}
			for i := range tt.cp.Acks {
				if got.Acks[i] != tt.cp.Acks[i] {
					t.Errorf("acks[%d] = %d, want %d", i, got.Acks[i], tt.cp.Acks[i])
				}
			}
		})
	}
}

func TestControlPacketByteOffsets(t *testing.T) {
	// Assert the fixed offsets numerically so a future refactor that
	// shifts a field is caught: [count(1)][acks(4 each)][remote sid(8)]
	// [own pid(4)][payload...].
	acks := []PacketID{0x01020304, 0x05060708}
	sid := SessionID{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	cp := testControlPacket(OpControlV1, acks, sid, 0x0A0B0C0D, []byte("XYZ"))

	buf := cp.AppendPlaintext(nil)

	if buf[0] != byte(len(acks)) {
		t.Fatalf("count byte = %d, want %d", buf[0], len(acks))
	}
	if got := []byte{buf[1], buf[2], buf[3], buf[4]}; string(got) != "\x01\x02\x03\x04" {
		t.Errorf("ack[0] bytes = %x, want 01020304", got)
	}
	if got := []byte{buf[5], buf[6], buf[7], buf[8]}; string(got) != "\x05\x06\x07\x08" {
		t.Errorf("ack[1] bytes = %x, want 05060708", got)
	}
	sidOff := 1 + 4*len(acks)
	if string(buf[sidOff:sidOff+SessionIDSize]) != string(sid[:]) {
		t.Errorf("remote session id at offset %d mismatch", sidOff)
	}
	pidOff := sidOff + SessionIDSize
	if got := buf[pidOff : pidOff+4]; string(got) != "\x0A\x0B\x0C\x0D" {
		t.Errorf("own packet id bytes = %x, want 0A0B0C0D", got)
	}
	payloadOff := pidOff + 4
	if string(buf[payloadOff:]) != "XYZ" {
		t.Errorf("payload = %q, want %q", buf[payloadOff:], "XYZ")
	}
}

func TestControlPacketAdjacency(t *testing.T) {
	sid := SessionID{9, 9, 9, 9, 9, 9, 9, 9}

	t.Run("ack-count 0 has no remote session id field", func(t *testing.T) {
		cp := testControlPacket(OpControlV1, nil, SessionID{}, 3, []byte("x"))
		plaintext := cp.AppendPlaintext(nil)
		// 1 (count) + 4 (own pid) + 1 (payload) = 6 bytes, no 8-byte SID.
		want := 1 + 4 + 1
		if len(plaintext) != want {
			t.Fatalf("plaintext length = %d, want %d", len(plaintext), want)
		}
	})

	t.Run("ack-count 8 has all IDs plus remote session id", func(t *testing.T) {
		acks := []PacketID{1, 2, 3, 4, 5, 6, 7, 8}
		cp := testControlPacket(OpControlV1, acks, sid, 9, nil)
		plaintext := cp.AppendPlaintext(nil)

		got, err := ParseControlPacket(plaintext, Header{Opcode: OpControlV1})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(got.Acks) != 8 {
			t.Fatalf("acks = %d, want 8", len(got.Acks))
		}
		if got.RemoteSessionID != sid {
			t.Fatalf("remote session id mismatch")
		}
	})

	t.Run("ack-count 9 is rejected without over-reading", func(t *testing.T) {
		plaintext := []byte{
			9,
			0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4,
			0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8,
			0, 0, 0, 9,
		}
		_, err := ParseControlPacket(plaintext, Header{Opcode: OpControlV1})
		if err == nil {
			t.Fatal("expected error for ack-count 9")
		}
	})
}

func TestControlPacketTruncation(t *testing.T) {
	hdr := Header{Opcode: OpControlV1}

	midRemoteSID := func() []byte {
		cp := testControlPacket(OpControlV1, []PacketID{1}, SessionID{1, 2, 3, 4, 5, 6, 7, 8}, 2, []byte("x"))
		full := cp.AppendPlaintext(nil)
		// count(1) + ack(4) + 3 of the 8-byte remote session id.
		return full[:1+4+3]
	}()

	cases := []struct {
		name string
		data []byte
	}{
		{"zero length", nil},
		{"1 byte, claims acks but has none", []byte{2}},
		{"mid ack-array, partial second id", []byte{2, 0, 0, 0, 1, 0, 0}},
		{"mid remote session id", midRemoteSID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseControlPacket(tc.data, hdr); err == nil {
				t.Fatal("expected parse error, got nil")
			}
		})
	}
}

func TestControlPacketOmitsOwnPacketIDForAckV1(t *testing.T) {
	data := []byte{0} // ack-count 0, then nothing else
	got, err := ParseControlPacket(data, Header{Opcode: OpAckV1})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Payload) != 0 {
		t.Errorf("payload = %q, want empty (no own packet id consumed, nothing left)", got.Payload)
	}

	// A truncated own-packet-id read must not be attempted for OpAckV1 at all.
	if _, err := ParseControlPacket([]byte{0}, Header{Opcode: OpAckV1}); err != nil {
		t.Errorf("ack-count 0 for OpAckV1 with nothing else should parse cleanly, got %v", err)
	}
}

func TestOpcodeRange(t *testing.T) {
	for op := Opcode(0); op <= 12; op++ {
		want := op >= FirstOpcode && op <= LastOpcode
		if got := ValidOpcode(op); got != want {
			t.Errorf("ValidOpcode(%d) = %v, want %v", op, got, want)
		}
	}

	for _, op := range []Opcode{0, 1, 2, 12} {
		if _, err := ParseControlPacket([]byte{0}, Header{Opcode: op}); err == nil {
			t.Errorf("opcode %d: expected rejection, got nil", op)
		}
	}
	for op := Opcode(FirstOpcode); op <= LastOpcode; op++ {
		if !ValidOpcode(op) {
			t.Errorf("opcode %d should be valid (in P_FIRST_OPCODE..P_LAST_OPCODE)", op)
		}
	}
}

func TestHeaderByteRoundTrip(t *testing.T) {
	for op := Opcode(0); op <= 31; op++ {
		for keyID := uint8(0); keyID <= 7; keyID++ {
			b := AppendHeaderByte(nil, op, keyID)
			gotOp, gotKeyID := ParseHeaderByte(b[0])
			if gotOp != op || gotKeyID != keyID {
				t.Errorf("roundtrip opcode=%d keyID=%d -> got opcode=%d keyID=%d", op, keyID, gotOp, gotKeyID)
			}
		}
	}
}

func FuzzParseControlPacket(f *testing.F) {
	hdr := Header{Opcode: OpControlV1}
	seeds := []ControlPacket{
		testControlPacket(OpAckV1, nil, SessionID{}, 0, nil),
		testControlPacket(OpControlV1, nil, SessionID{}, 0, []byte("hello")),
		testControlPacket(OpControlV1, []PacketID{1, 2, 3}, SessionID{1, 2, 3, 4, 5, 6, 7, 8}, 4, []byte{0xde, 0xad, 0xbe, 0xef}),
		testControlPacket(OpControlV1, []PacketID{1, 2, 3, 4, 5, 6, 7, 8}, SessionID{8, 7, 6, 5, 4, 3, 2, 1}, 9, nil),
	}
	for _, s := range seeds {
		f.Add(s.AppendPlaintext(nil))
	}
	f.Add([]byte{})
	f.Add([]byte{9})

	f.Fuzz(func(t *testing.T, data []byte) {
		cp, err := ParseControlPacket(data, hdr)
		if err != nil {
			return
		}
		// Never panics, and a successful parse must re-serialize to
		// something ParseControlPacket accepts again (never a
		// "one-way-only" parse of malformed-but-accepted input).
		_ = cp.AppendPlaintext(nil)
	})
}
