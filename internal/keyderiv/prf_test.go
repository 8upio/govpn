package keyderiv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestPRFReferenceVector reproduces the OpenVPN reference's own committed
// unit-test vector for ssl_tls1_PRF/tls1_P_hash byte-for-byte, zero
// tolerance. Source: tests/unit_tests/openvpn/test_crypto.c:140-166, read
// against the pinned reference checkout
// (/Users/svenloth/dev/openvpn-reference, commit
// c9b790f5b9e8ebca5da38c22f479c31bb8d33686) this plan. This is WIRE-02's own
// acceptance gate and the STATE.md Phase-2 blocker's closure condition — it
// must be green before any plan in this phase runs live data-channel
// traffic.
func TestPRFReferenceVector(t *testing.T) {
	secret := []byte("Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua.")
	seed := []byte("Quis aute iure reprehenderit in voluptate velit esse cillum dolore")

	want, err := hex.DecodeString("d98c8518c85e94692791" +
		"6acfc2d592fbb1567e4b" +
		"4b1459e6a904ac2ddab7" +
		"2d67")
	if err != nil {
		t.Fatalf("decode expected hex: %v", err)
	}
	if len(want) != 32 {
		t.Fatalf("expected vector length = %d, want 32", len(want))
	}

	got := PRF(secret, seed, 32)
	if !bytes.Equal(got, want) {
		t.Fatalf("PRF(secret, seed, 32) = %x, want %x", got, want)
	}
}

// TestPRFOutputLengthNotBlockAligned proves the P_hash A(i) chaining is
// truncation-correct — each shorter output is a prefix of the next-longer
// one — rather than being recomputed independently per requested length,
// for lengths that don't align to the underlying hash's block size.
func TestPRFOutputLengthNotBlockAligned(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 48)
	seed := []byte("some non-block-aligned seed material")

	lengths := []int{1, 17, 33, 100}
	outputs := make([][]byte, len(lengths))
	for i, n := range lengths {
		outputs[i] = PRF(secret, seed, n)
		if len(outputs[i]) != n {
			t.Fatalf("PRF(secret, seed, %d) returned %d bytes", n, len(outputs[i]))
		}
	}

	for i := 0; i < len(lengths)-1; i++ {
		shorter, longer := outputs[i], outputs[i+1]
		if !bytes.Equal(longer[:len(shorter)], shorter) {
			t.Fatalf("PRF output for length %d is not a prefix of the output for length %d", lengths[i], lengths[i+1])
		}
	}
}
