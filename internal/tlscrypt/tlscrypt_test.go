// Golden-vector tests for WIRE-04. See tlscrypt.go's package doc for the
// pinned reference file/line citations behind the offsets and algorithm
// exercised here.
package tlscrypt

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func testKey(t testing.TB) []byte {
	t.Helper()
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func testHeader() []byte {
	// opcode 7 (P_CONTROL_HARD_RESET_CLIENT_V2) << 3 | keyID 0, then an
	// arbitrary 8-byte session id.
	h := make([]byte, 0, OffPID)
	h = append(h, byte(7)<<3)
	h = append(h, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}...)
	return h
}

func TestWrapUnwrap(t *testing.T) {
	key := testKey(t)
	server, err := NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}
	client, err := NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	header := testHeader()
	plaintext := []byte("hello control channel")

	wrapped, err := server.Wrap(nil, header, plaintext)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(wrapped) != len(header)+PIDSize+TagSize+len(plaintext) {
		t.Fatalf("wrapped length = %d, want %d", len(wrapped), len(header)+PIDSize+TagSize+len(plaintext))
	}

	gotHeader, gotPlaintext, err := client.Unwrap(nil, wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(gotPlaintext) != string(plaintext) {
		t.Errorf("plaintext = %q, want %q", gotPlaintext, plaintext)
	}
	if string(gotHeader) != string(header) {
		t.Errorf("header = %x, want %x", gotHeader, header)
	}

	// Opposing direction: client encrypts, server decrypts.
	wrapped2, err := client.Wrap(nil, header, plaintext)
	if err != nil {
		t.Fatalf("client wrap: %v", err)
	}
	_, gotPlaintext2, err := server.Unwrap(nil, wrapped2)
	if err != nil {
		t.Fatalf("server unwrap: %v", err)
	}
	if string(gotPlaintext2) != string(plaintext) {
		t.Errorf("client->server plaintext = %q, want %q", gotPlaintext2, plaintext)
	}
}

func TestUnwrapRejectsShortPacket(t *testing.T) {
	key := testKey(t)
	client, err := NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	for _, n := range []int{0, 1, OffCT - 1} {
		if _, _, err := client.Unwrap(nil, make([]byte, n)); err == nil {
			t.Errorf("length %d: expected error, got nil", n)
		}
	}
}

func TestUnwrapRejectsTamperedPacket(t *testing.T) {
	key := testKey(t)
	server, err := NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}
	client, err := NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}

	header := testHeader()
	plaintext := []byte("tamper me")

	wrapped, err := server.Wrap(nil, header, plaintext)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	positions := map[string]int{
		"header byte": 0,
		"session id":  3,
		"packet id":   OffPID,
		"tag":         OffTag,
		"ciphertext":  OffCT,
	}
	for name, pos := range positions {
		t.Run(name, func(t *testing.T) {
			if pos >= len(wrapped) {
				t.Skip("position not present for this plaintext length")
			}
			tampered := append([]byte(nil), wrapped...)
			tampered[pos] ^= 0x01
			if _, _, err := client.Unwrap(nil, tampered); err == nil {
				t.Errorf("tampered byte at %d: expected error, got nil plaintext", pos)
			}
		})
	}
}

func TestUnwrapRejectsReplay(t *testing.T) {
	key := testKey(t)
	server, err := NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}
	client, err := NewWrapper(key, false)
	if err != nil {
		t.Fatalf("client wrapper: %v", err)
	}
	header := testHeader()

	first, err := server.Wrap(nil, header, []byte("first"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	if _, _, err := client.Unwrap(nil, first); err != nil {
		t.Fatalf("first unwrap: %v", err)
	}
	if _, _, err := client.Unwrap(nil, first); err == nil {
		t.Error("duplicate delivery: expected replay error, got nil")
	}

	// Advance the client's replay window well past the first packet's
	// sequence number, then confirm the original is rejected as below the
	// window floor (not just as an exact duplicate).
	for i := 0; i < replayWindowSize+5; i++ {
		w, err := server.Wrap(nil, header, []byte("advance"))
		if err != nil {
			t.Fatalf("wrap %d: %v", i, err)
		}
		if _, _, err := client.Unwrap(nil, w); err != nil {
			t.Fatalf("advance unwrap %d: %v", i, err)
		}
	}

	if _, _, err := client.Unwrap(nil, first); err == nil {
		t.Error("below window floor: expected replay error, got nil")
	}
}

// TestWrapPacketIDRolloverGate is a regression test for WR-02 (01-REVIEW.md,
// iteration 1): once Wrapper.sendSeq is at its maximum value and a rollover
// has already happened at or after the current wall-clock second, Wrap must
// fail closed (mirroring packet_id_send_update's "TLS-CRYPT ERROR: packet ID
// roll over.", packet_id.c:323-344) instead of silently wrapping sendSeq
// back around to a no-longer-monotonic 0.
//
// sendRolloverAt is set directly (white-box) to a timestamp in the future
// so the test is deterministic and never depends on two Wrap calls
// happening to land in the same wall-clock second.
func TestWrapPacketIDRolloverGate(t *testing.T) {
	key := testKey(t)
	w, err := NewWrapper(key, true)
	if err != nil {
		t.Fatalf("new wrapper: %v", err)
	}

	w.sendSeq = 0xFFFFFFFF
	w.sendRolloverAt = time.Now().Unix() + 1000

	header := testHeader()
	if _, err := w.Wrap(nil, header, []byte("payload")); err == nil {
		t.Fatal("Wrap did not return an error at the packet-ID rollover boundary")
	}
	if w.sendSeq != 0xFFFFFFFF {
		t.Errorf("sendSeq = %#x after a rejected rollover, want it left unchanged at 0xFFFFFFFF", w.sendSeq)
	}
}

// TestWrapPacketIDTimestampFrozenPerKey is a regression test for WR-04
// (01-REVIEW.md, iteration 2): the wire packet-ID's long-form timestamp
// field must be frozen at the value captured on the very first Wrap call
// for the life of the key (packet_id_send_update's "if (!p->time) { p->time
// = now; }", packet_id.c:323-326) — NOT a fresh time.Now() on every call,
// which would defeat a real OpenVPN client's replay-window backtrack logic
// (see WR-04's Issue section).
func TestWrapPacketIDTimestampFrozenPerKey(t *testing.T) {
	key := testKey(t)
	w, err := NewWrapper(key, true)
	if err != nil {
		t.Fatalf("new wrapper: %v", err)
	}
	header := testHeader()

	first, err := w.Wrap(nil, header, []byte("a"))
	if err != nil {
		t.Fatalf("wrap 1: %v", err)
	}
	firstTS := binary.BigEndian.Uint32(first[OffPID+4 : OffPID+8])

	second, err := w.Wrap(nil, header, []byte("b"))
	if err != nil {
		t.Fatalf("wrap 2: %v", err)
	}
	secondTS := binary.BigEndian.Uint32(second[OffPID+4 : OffPID+8])

	if firstTS != secondTS {
		t.Errorf("packet-ID timestamp changed between calls (%d != %d); want frozen per key, not time.Now() per call", firstTS, secondTS)
	}
	if w.sendTime == 0 || firstTS != uint32(w.sendTime) {
		t.Errorf("wire timestamp %d does not match Wrapper's own frozen sendTime %d", firstTS, w.sendTime)
	}
}

func TestWrapConcurrentSequenceIDs(t *testing.T) {
	key := testKey(t)
	server, err := NewWrapper(key, true)
	if err != nil {
		t.Fatalf("server wrapper: %v", err)
	}
	header := testHeader()

	const n = 200
	type wrapResult struct {
		seq uint32
		err error
	}
	results := make([]wrapResult, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			wrapped, err := server.Wrap(nil, header, []byte("x"))
			if err != nil {
				results[i] = wrapResult{err: err}
				return
			}
			results[i] = wrapResult{seq: binary.BigEndian.Uint32(wrapped[OffPID : OffPID+4])}
		}()
	}
	wg.Wait()

	seen := make(map[uint32]bool, n)
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("wrap %d: %v", i, r.err)
		}
		if seen[r.seq] {
			t.Errorf("duplicate sequence number %d", r.seq)
		}
		seen[r.seq] = true
	}
	if len(seen) != n {
		t.Errorf("got %d distinct sequence numbers, want %d", len(seen), n)
	}
}

func FuzzUnwrap(f *testing.F) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("rand: %v", err)
	}
	server, err := NewWrapper(key, true)
	if err != nil {
		f.Fatalf("server wrapper: %v", err)
	}
	client, err := NewWrapper(key, false)
	if err != nil {
		f.Fatalf("client wrapper: %v", err)
	}

	header := testHeader()
	for _, pt := range [][]byte{nil, []byte("a"), []byte("hello control channel")} {
		wrapped, err := server.Wrap(nil, header, pt)
		if err != nil {
			f.Fatalf("seed wrap: %v", err)
		}
		f.Add(wrapped)
	}
	f.Add([]byte{})
	f.Add(make([]byte, OffCT-1))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic, regardless of what garbage arrives.
		_, _, _ = client.Unwrap(nil, data)
	})
}
