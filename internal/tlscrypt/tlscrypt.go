// Package tlscrypt implements OpenVPN's --tls-crypt control-channel
// encryption: a hand-assembled MAC-then-encrypt construction with a
// synthetic IV derived from the HMAC tag (SIV-style) — NOT a standard AEAD
// call. cipher.NewGCM/AEAD.Seal do not apply here at all.
//
// Byte layout and constants are traceable to the pinned OpenVPN reference
// checkout (/Users/svenloth/dev/openvpn-reference, branch release/2.6,
// commit c9b790f5b9e8ebca5da38c22f479c31bb8d33686):
//
//   - on-wire layout and offsets: src/openvpn/tls_crypt.h:89-95
//     (TLS_CRYPT_TAG_SIZE, TLS_CRYPT_PID_SIZE, TLS_CRYPT_BLOCK_SIZE,
//     TLS_CRYPT_OFF_PID/OFF_TAG/OFF_CT)
//   - wrap/unwrap algorithm: src/openvpn/tls_crypt.c:145-318
//     (tls_crypt_wrap, tls_crypt_unwrap)
//   - cipher/digest choice: src/openvpn/tls_crypt.c:49-53
//     (tls_crypt_kt: "AES-256-CTR", "SHA256")
//   - key-direction slot assignment: src/openvpn/tls_crypt.c:61-74
//     (tls_crypt_init_key), src/openvpn/crypto.c:1505-1532
//     (key_direction_state_init)
package tlscrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	// TagSize: tls_crypt.h:89 (TLS_CRYPT_TAG_SIZE = 256/8).
	TagSize = 32

	// BlockSize: tls_crypt.h:91 (TLS_CRYPT_BLOCK_SIZE = 128/8) — also the
	// AES-256-CTR IV size; the top 128 bits of the auth tag double as the IV.
	BlockSize = 16

	// PIDSize: tls_crypt.h:90 (TLS_CRYPT_PID_SIZE = sizeof(packet_id_type) +
	// sizeof(net_time_t)) — 4-byte big-endian sequence number followed by a
	// 4-byte big-endian unix timestamp (long form, packet_id.c:298-321,347-386).
	// This is tls-crypt's OWN packet ID, unrelated to and independently
	// sequenced from the control-channel reliability layer's packet ID
	// (internal/wire.PacketID) — see RESEARCH Pitfall 1.
	PIDSize = 8

	// OffPID/OffTag/OffCT: tls_crypt.h:93-95.
	//   OffPID = 1 (header byte) + SID_SIZE(8) = 9
	//   OffTag = OffPID + PIDSize(8) = 17
	//   OffCT  = OffTag + TagSize(32) = 49
	OffPID = 1 + 8
	OffTag = OffPID + PIDSize
	OffCT  = OffTag + TagSize

	cipherKeySize = 32 // AES-256 key size
	hmacKeySize   = 32 // SHA-256 key size

	// replayWindowSize is the width of the sliding anti-replay window
	// (independent of, and unrelated to, the reliability layer's own
	// packet-ID window — RESEARCH Pitfall 1). Not sourced from the C
	// reference (crypto_check_replay uses a configurable window); 64 is a
	// reasonable, conservative default for Phase 1's scope.
	replayWindowSize = 64
)

// Errors returned by Wrapper.Unwrap.
var (
	ErrShort  = errors.New("tlscrypt: packet shorter than the tls-crypt prefix")
	ErrAuth   = errors.New("tlscrypt: authentication failed")
	ErrReplay = errors.New("tlscrypt: packet ID replay")
)

// keySlot holds one (Ke, Ka) pair — cipher key and HMAC key — sized exactly
// to the first 32 bytes actually consumed from each 64-byte slot of the
// reference's struct key (crypto.c:824-866 init_key_ctx only reads
// cipher_kt_key_size / the digest's key-size bytes from each 64-byte field).
type keySlot struct {
	cipher [cipherKeySize]byte
	hmac   [hmacKeySize]byte
}

// replayWindow is a sliding anti-replay window over tls-crypt's own 4-byte
// sequence number (the low 32 bits of the 8-byte long-form packet ID).
type replayWindow struct {
	mu      sync.Mutex
	init    bool
	highest uint32
	seen    uint64 // bit i set means (highest - i) has been seen
}

// accept reports whether seq is acceptable (not a duplicate, not below the
// window floor) and marks it seen if so.
func (r *replayWindow) accept(seq uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.init {
		r.init = true
		r.highest = seq
		r.seen = 1
		return true
	}

	if seq > r.highest {
		shift := seq - r.highest
		if shift >= replayWindowSize {
			r.seen = 1
		} else {
			r.seen = (r.seen << shift) | 1
		}
		r.highest = seq
		return true
	}

	diff := r.highest - seq
	if diff >= replayWindowSize {
		return false // below the window floor
	}
	bit := uint64(1) << diff
	if r.seen&bit != 0 {
		return false // duplicate
	}
	r.seen |= bit
	return true
}

// Wrapper implements the tls-crypt wrap/unwrap construction (tls_crypt.c:
// 145-318). --tls-crypt has no configurable key direction in the reference
// (unlike --tls-auth's optional key-direction flag) — the server always
// encrypts with keys[0] and decrypts with keys[1]; the client is the mirror
// image. Getting this backwards makes every packet fail HMAC verification
// from the very first HARD_RESET_CLIENT_V2 (RESEARCH Pitfall 2).
type Wrapper struct {
	encrypt keySlot
	decrypt keySlot

	mu      sync.Mutex
	sendSeq uint32 // this side's own monotonic tls-crypt packet-ID sequence counter

	replay replayWindow
}

// NewWrapper builds a Wrapper from the 256-byte Static key V1 body (see
// ParseStaticKeyV1), assigning encrypt/decrypt slots per the server/client
// key-direction convention: server encrypts with keys[0] and decrypts with
// keys[1]; client is the reverse (tls_crypt.c:61-74, crypto.c:1505-1532).
func NewWrapper(key256 []byte, server bool) (*Wrapper, error) {
	if len(key256) != 256 {
		return nil, errors.New("tlscrypt: key material must be exactly 256 bytes")
	}

	var keys [2]keySlot
	copy(keys[0].cipher[:], key256[0:32])
	copy(keys[0].hmac[:], key256[64:96])
	copy(keys[1].cipher[:], key256[128:160])
	copy(keys[1].hmac[:], key256[192:224])

	w := &Wrapper{}
	if server {
		w.encrypt, w.decrypt = keys[0], keys[1]
	} else {
		w.encrypt, w.decrypt = keys[1], keys[0]
	}
	return w, nil
}

// Wrap authenticates and encrypts plaintext, appending the resulting
// wire-format packet to dst. header must be the 9-byte cleartext
// opcode+key-id+session-id prefix (tls_crypt.h's "header" field: "opcode (1
// byte) || session_id (8 bytes)").
//
// Wrap owns its own monotonic tls-crypt packet-ID sequence counter, guarded
// so concurrent callers can never emit a duplicate sequence number — a
// separate, independently-sequenced counter from the reliability layer's
// packet ID (internal/wire.PacketID; RESEARCH Pitfall 1).
func (w *Wrapper) Wrap(dst, header, plaintext []byte) ([]byte, error) {
	if len(header) != OffPID {
		return nil, errors.New("tlscrypt: header must be exactly 9 bytes (opcode+key-id byte + 8-byte session id)")
	}

	w.mu.Lock()
	w.sendSeq++
	seq := w.sendSeq
	w.mu.Unlock()

	var pid [PIDSize]byte
	binary.BigEndian.PutUint32(pid[0:4], seq)
	binary.BigEndian.PutUint32(pid[4:8], uint32(time.Now().Unix()))

	aad := make([]byte, 0, OffTag)
	aad = append(aad, header...)
	aad = append(aad, pid[:]...)

	mac := hmac.New(sha256.New, w.encrypt.hmac[:])
	mac.Write(aad)
	mac.Write(plaintext)
	tag := mac.Sum(nil) // 32 bytes; top 16 double as the AES-256-CTR IV

	block, err := aes.NewCipher(w.encrypt.cipher[:])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, tag[:BlockSize])
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	dst = append(dst, aad...)
	dst = append(dst, tag...)
	dst = append(dst, ciphertext...)
	return dst, nil
}

// Unwrap authenticates and, if the tag verifies, decrypts packet, appending
// the plaintext to dst. header is the same 9-byte cleartext prefix Wrap
// consumes.
//
// The wire tag doubles as the AES-256-CTR IV (top 128 bits) — this is
// intrinsic to the SIV-style construction (tls_crypt.c:255
// cipher_ctx_reset is keyed on the RECEIVED tag, not a recomputed one), so
// decryption necessarily happens before the tag can be checked: the tag
// itself is computed over the plaintext. What this function guarantees is
// the fail-closed boundary that actually matters — the decrypted bytes are
// never returned to any caller (and in particular never reach
// wire.ParseControlPacket) unless the recomputed tag matches the wire tag
// via hmac.Equal (constant-time). A mismatch drops the packet before replay
// checking or anything else runs (tls_crypt.c:222-318 tls_crypt_unwrap,
// RESEARCH Security Domain ASVS V5/V6).
func (w *Wrapper) Unwrap(dst, packet []byte) (header []byte, plaintext []byte, err error) {
	if len(packet) < OffCT {
		return nil, nil, ErrShort
	}

	aad := packet[:OffTag]
	wireTag := packet[OffTag:OffCT]
	ciphertext := packet[OffCT:]

	block, err := aes.NewCipher(w.decrypt.cipher[:])
	if err != nil {
		return nil, nil, err
	}
	decrypted := make([]byte, len(ciphertext))
	cipher.NewCTR(block, wireTag[:BlockSize]).XORKeyStream(decrypted, ciphertext)

	mac := hmac.New(sha256.New, w.decrypt.hmac[:])
	mac.Write(aad)
	mac.Write(decrypted)
	computed := mac.Sum(nil)
	if !hmac.Equal(wireTag, computed) {
		return nil, nil, ErrAuth
	}

	seq := binary.BigEndian.Uint32(packet[OffPID : OffPID+4])
	if !w.replay.accept(seq) {
		return nil, nil, ErrReplay
	}

	header = append([]byte(nil), packet[:OffPID]...)
	plaintext = append(dst, decrypted...)
	return header, plaintext, nil
}
