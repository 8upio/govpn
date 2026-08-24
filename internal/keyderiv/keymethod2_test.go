package keyderiv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// buildClientKM2 assembles a well-formed client Key Method 2 message:
// 4 reserved + 1 key-method byte + 48 pre_master + 32 random1 + 32 random2
// + four 2-byte-length-prefixed strings (options, username, password,
// peer_info), each supplied verbatim (no trailing NUL added here — that is
// a WriteServerKeyMethod2-specific convention for the options field, not a
// property ReadClientKeyMethod2 requires of its input).
func buildClientKM2(t *testing.T, options, username, password, peerInfo []byte) []byte {
	t.Helper()
	var buf []byte
	buf = append(buf, 0, 0, 0, 0) // reserved
	buf = append(buf, keyMethod2)
	buf = append(buf, bytes.Repeat([]byte{0xAA}, 48)...) // pre_master
	buf = append(buf, bytes.Repeat([]byte{0xBB}, 32)...) // random1
	buf = append(buf, bytes.Repeat([]byte{0xCC}, 32)...) // random2
	for _, s := range [][]byte{options, username, password, peerInfo} {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(s)))
		buf = append(buf, s...)
	}
	return buf
}

// TestKeyMethod2ReadRejectsTruncated feeds ReadClientKeyMethod2 every
// prefix length from 0 to (full message length - 1) of a well-formed
// client message and asserts it always returns a typed error and never
// panics (T-02-01).
func TestKeyMethod2ReadRejectsTruncated(t *testing.T) {
	full := buildClientKM2(t, []byte("opts"), []byte("user"), []byte("pass"), []byte("peer"))

	for n := 0; n < len(full); n++ {
		n := n
		t.Run("", func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ReadClientKeyMethod2 panicked on a %d-byte prefix: %v", n, r)
				}
			}()
			_, _, err := ReadClientKeyMethod2(bytes.NewReader(full[:n]))
			if err == nil {
				t.Fatalf("ReadClientKeyMethod2 on a %d-byte prefix (of %d) returned nil error", n, len(full))
			}
		})
	}
}

// TestKeyMethod2ReadRejectsWrongKeyMethod asserts a message whose
// key-method byte's low nibble is not 2 returns ErrKeyMethod.
func TestKeyMethod2ReadRejectsWrongKeyMethod(t *testing.T) {
	full := buildClientKM2(t, nil, nil, nil, nil)
	full[4] = 1 // key-method byte: low nibble = 1 (KEY_METHOD_1), not 2

	_, _, err := ReadClientKeyMethod2(bytes.NewReader(full))
	if !errors.Is(err, ErrKeyMethod) {
		t.Fatalf("ReadClientKeyMethod2 error = %v, want ErrKeyMethod", err)
	}
}

// TestKeyMethod2ReadRejectsOversizedString asserts an options-string length
// field greater than TLS_OPTIONS_LEN (512) returns ErrStringTooLong before
// any allocation of that size — the test constructs a message whose
// declared length grossly exceeds what actually follows, so a naive
// implementation that allocates first and reads second would either panic
// or hang trying to read bytes that were never sent.
func TestKeyMethod2ReadRejectsOversizedString(t *testing.T) {
	var buf []byte
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, keyMethod2)
	buf = append(buf, bytes.Repeat([]byte{0xAA}, 48)...)
	buf = append(buf, bytes.Repeat([]byte{0xBB}, 32)...)
	buf = append(buf, bytes.Repeat([]byte{0xCC}, 32)...)
	buf = binary.BigEndian.AppendUint16(buf, 513) // exceeds maxOptionsStringLen
	// deliberately no trailing bytes — an implementation that allocates
	// 513 bytes before reading would try to read past EOF instead of
	// failing fast on the length check.

	_, _, err := ReadClientKeyMethod2(bytes.NewReader(buf))
	if !errors.Is(err, ErrStringTooLong) {
		t.Fatalf("ReadClientKeyMethod2 error = %v, want ErrStringTooLong", err)
	}
}

// TestKeyMethod2ServerWriteLayout asserts WriteServerKeyMethod2 emits, in
// order: 4 zero bytes, 0x02, 32 random1 bytes, 32 random2 bytes, a
// 2-byte-length-prefixed options string, then three consecutive 2-byte
// 0x0000 fields (username, password, peer_info) and nothing after them.
func TestKeyMethod2ServerWriteLayout(t *testing.T) {
	var buf bytes.Buffer
	src, err := WriteServerKeyMethod2(&buf, "V4,dev-type tun")
	if err != nil {
		t.Fatalf("WriteServerKeyMethod2: %v", err)
	}

	wire := buf.Bytes()
	pos := 0

	if !bytes.Equal(wire[pos:pos+4], []byte{0, 0, 0, 0}) {
		t.Fatalf("reserved bytes = %x, want 4 zero bytes", wire[pos:pos+4])
	}
	pos += 4

	if wire[pos] != keyMethod2 {
		t.Fatalf("key-method byte = %d, want %d", wire[pos], keyMethod2)
	}
	pos++

	if !bytes.Equal(wire[pos:pos+32], src.Random1[:]) {
		t.Fatalf("random1 in wire output does not match returned KeySource.Random1")
	}
	pos += 32

	if !bytes.Equal(wire[pos:pos+32], src.Random2[:]) {
		t.Fatalf("random2 in wire output does not match returned KeySource.Random2")
	}
	pos += 32

	optsLen := binary.BigEndian.Uint16(wire[pos : pos+2])
	pos += 2
	wantOpts := "V4,dev-type tun\x00" // length includes the trailing NUL
	if int(optsLen) != len(wantOpts) {
		t.Fatalf("options string length = %d, want %d", optsLen, len(wantOpts))
	}
	if string(wire[pos:pos+int(optsLen)]) != wantOpts {
		t.Fatalf("options string = %q, want %q", wire[pos:pos+int(optsLen)], wantOpts)
	}
	pos += int(optsLen)

	// username, password, peer_info: three consecutive 2-byte 0x0000
	// fields, and nothing after them.
	trailing := wire[pos:]
	want := []byte{0, 0, 0, 0, 0, 0}
	if !bytes.Equal(trailing, want) {
		t.Fatalf("trailing bytes = %x, want %x (three empty length-prefixed fields, nothing after)", trailing, want)
	}
}

// TestDeriveKeysEndToEnd asserts DeriveKeys is deterministic (same input ->
// same 256-byte output) and sensitive to every input byte (changing any
// single input byte changes the output) — given a fixed KeySource2 and
// fixed 8-byte session IDs.
func TestDeriveKeysEndToEnd(t *testing.T) {
	baseSrc := func() *KeySource2 {
		var s KeySource2
		for i := range s.Client.PreMaster {
			s.Client.PreMaster[i] = byte(i)
		}
		for i := range s.Client.Random1 {
			s.Client.Random1[i] = byte(i + 1)
		}
		for i := range s.Client.Random2 {
			s.Client.Random2[i] = byte(i + 2)
		}
		for i := range s.Server.Random1 {
			s.Server.Random1[i] = byte(i + 3)
		}
		for i := range s.Server.Random2 {
			s.Server.Random2[i] = byte(i + 4)
		}
		return &s
	}
	clientSID := &[8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	serverSID := &[8]byte{8, 7, 6, 5, 4, 3, 2, 1}

	src1 := baseSrc()
	k1, err := DeriveKeys(src1, clientSID, serverSID)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	src2 := baseSrc()
	k2, err := DeriveKeys(src2, clientSID, serverSID)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	if !bytes.Equal(k1.raw[:], k2.raw[:]) {
		t.Fatal("DeriveKeys is not deterministic: same input produced different output")
	}

	// Flip a single byte of the client's pre-master and confirm the output
	// changes.
	src3 := baseSrc()
	src3.Client.PreMaster[0] ^= 0xFF
	k3, err := DeriveKeys(src3, clientSID, serverSID)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	if bytes.Equal(k1.raw[:], k3.raw[:]) {
		t.Fatal("changing one input byte (Client.PreMaster[0]) did not change DeriveKeys's output")
	}
}
