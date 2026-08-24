// Package datachan implements OpenVPN's AES-256-GCM data channel: encrypting
// and decrypting P_DATA_V2 packets, absorbing keepalive pings (see ping.go),
// and rejecting replayed/out-of-window packets (see replay.go).
//
// Byte layout, key-direction convention, and constants below are traceable
// to the pinned OpenVPN reference checkout
// (/Users/svenloth/dev/openvpn-reference, branch release/2.6, commit
// c9b790f5b9e8ebca5da38c22f479c31bb8d33686):
//
//   - wire layout and tag ordering: src/openvpn/crypto.c:62-151,340-470
//     (openvpn_encrypt_aead, openvpn_decrypt_aead)
//   - header construction: src/openvpn/ssl.c:4142-4155 (tls_prepend_opcode_v2)
//   - tag length: src/openvpn/crypto_backend.h:42 (OPENVPN_AEAD_TAG_LENGTH)
//   - replay backtrack: src/openvpn/packet_id.h:100 (DEFAULT_SEQ_BACKTRACK)
//
// This package's key-direction input comes from keyderiv.Key2.ServerSlots(),
// whose convention is the deliberate mirror opposite of
// internal/tlscrypt.NewWrapper's own server/client key-slot assignment for
// the same "server" boolean — see internal/keyderiv's own doc comment and
// 02-RESEARCH.md Pitfall 1. Do not copy tlscrypt's slot-assignment pattern
// into this package.
//
// The data-channel packet ID is short form only (4 bytes, no timestamp) —
// unlike internal/tlscrypt's own long-form (sequence + timestamp) packet
// ID, and unlike the control-channel reliability layer's own packet ID.
// These are three genuinely independent, never-shared sequence spaces
// (02-RESEARCH.md Pitfall 5); this package never imports "time" or
// "crypto/sha256".
package datachan

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/wire"
)

const (
	// Wire offsets for a P_DATA_V2 packet (RESEARCH Pattern 5):
	//
	//	[opcode+keyid(1B)][peer-id(3B)][packet-id(4B)][tag(16B)][ciphertext(N)]
	//	└──────────────── headerSize(8B), the AAD ─────────────┘└── AEAD ───┘
	//
	// The tag comes BEFORE the ciphertext on the wire — the opposite of Go's
	// cipher.AEAD.Seal/Open convention (tag appended after ciphertext);
	// Seal/Open below perform the reorder explicitly, in one place each.
	offPeerID     = 1
	offPacketID   = 4
	offTag        = 8
	offCiphertext = offTag + TagSize
	headerSize    = offTag // opcode+keyid+peer-id+packet-id — the AAD

	// TagSize: crypto_backend.h:42 (OPENVPN_AEAD_TAG_LENGTH = 16) — matches
	// Go's default GCM tag size (aead.Overhead() == 16), no
	// NewGCMWithTagSize override needed.
	TagSize = 16

	// NonceSize: crypto.c:78-101 — 4-byte explicit packet-id concatenated
	// with an 8-byte implicit IV. Matches cipher.NewGCM's own "standard
	// nonce length" of 12 bytes exactly, so no NewGCMWithNonceSize override
	// is needed either.
	NonceSize = 12
)

// Sentinel errors, mirroring internal/tlscrypt's style.
var (
	ErrShort  = errors.New("datachan: packet shorter than the P_DATA_V2 header+tag")
	ErrAuth   = errors.New("datachan: AEAD authentication failed")
	ErrReplay = errors.New("datachan: packet ID replay")

	// ErrPacketIDExhausted is returned by Seal when this Wrapper's send-side
	// packet-ID counter is already at 0xFFFFFFFF. The short form has no
	// rollover (packet_id_send_update only permits PACKET_ID_MAX -> 0 when
	// long_form is true, which the data channel never uses) — wrapping
	// would reuse a GCM nonce under the same key, which is catastrophic
	// rather than merely wrong. Phase 4's renegotiation (SESS-04, out of
	// this phase's scope) is what prevents a production session ever
	// reaching this ceiling.
	ErrPacketIDExhausted = errors.New("datachan: packet ID counter exhausted; short-form data-channel packet IDs never roll over")

	// ErrPingAbsorbed is returned by Open when the decrypted plaintext is
	// exactly the 16-byte ping magic (ping.go, D-11): the packet
	// authenticated successfully but carries no payload for the caller —
	// it must never be delivered to Session.Read's caller and never counts
	// as a delivered IP packet.
	ErrPingAbsorbed = errors.New("datachan: packet is a ping keepalive, absorbed")
)

// Wrapper implements the data channel's AES-256-GCM Seal/Open for one
// session, one key ID. Unlike internal/tlscrypt.Wrapper, it carries no
// sendTime/sendRolloverAt: the data-channel packet ID is short form only,
// with no timestamp field and no wraparound path (Pitfall 5).
type Wrapper struct {
	peerID uint32 // 24-bit peer-id, written into every sealed packet's header
	keyID  uint8  // TLS key slot id; always 0 in v1 (no renegotiation, SESS-04)

	encryptAEAD cipher.AEAD
	encryptIV   [8]byte // implicit IV, first 8 bytes of key2.keys[encIdx].hmac

	decryptAEAD cipher.AEAD
	decryptIV   [8]byte

	mu      sync.Mutex
	sendSeq uint32 // last packet ID assigned; 0 means "none yet" (first is 1)

	replay replayWindow // 64-wide sliding anti-replay window (replay.go, DATA-02)
}

// NewWrapper builds a Wrapper from keys (keyderiv.Key2.ServerSlots()'s
// output — do not re-derive which slot is encrypt vs decrypt here, Pitfall
// 1), peerID (this session's allocated 24-bit peer-id, D-16) and keyID (the
// TLS key slot, 0 in v1).
func NewWrapper(keys keyderiv.DataKeys, peerID uint32, keyID uint8) (*Wrapper, error) {
	encBlock, err := aes.NewCipher(keys.EncryptCipher[:])
	if err != nil {
		return nil, err
	}
	encAEAD, err := cipher.NewGCM(encBlock)
	if err != nil {
		return nil, err
	}

	decBlock, err := aes.NewCipher(keys.DecryptCipher[:])
	if err != nil {
		return nil, err
	}
	decAEAD, err := cipher.NewGCM(decBlock)
	if err != nil {
		return nil, err
	}

	return &Wrapper{
		peerID:      peerID,
		keyID:       keyID,
		encryptAEAD: encAEAD,
		encryptIV:   keys.EncryptImplicitIV,
		decryptAEAD: decAEAD,
		decryptIV:   keys.DecryptImplicitIV,
	}, nil
}

// nextPacketID returns the next monotonic send-side packet ID (starting at
// 1, matching packet_id_send_update, packet_id.c:323-344), or
// ErrPacketIDExhausted if the counter is already at its ceiling.
func (w *Wrapper) nextPacketID() (uint32, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sendSeq == 0xFFFFFFFF {
		return 0, ErrPacketIDExhausted
	}
	w.sendSeq++
	return w.sendSeq, nil
}

// Seal encrypts plaintext as one P_DATA_V2 packet and appends the result to
// dst: header, then tag, then ciphertext (Pitfall 2 — the opposite of Go's
// cipher.AEAD.Seal's own tag-after-ciphertext convention). The nonce is the
// 12-byte concatenation packetID(4) || implicitIV(8) — never a bitwise XOR,
// despite CLAUDE.md's own loose shorthand phrasing (RESEARCH Pattern 5).
func (w *Wrapper) Seal(dst, plaintext []byte) ([]byte, error) {
	seq, err := w.nextPacketID()
	if err != nil {
		return nil, err
	}
	return w.sealWithSeq(dst, seq, plaintext), nil
}

// SealWithPacketID performs the identical seal algorithm as Seal but with
// an explicit packetID instead of auto-incrementing w.sendSeq, and never
// touches sendSeq — so it can never be mistaken for the live-traffic path.
// Reproduction-only: it exists so a byte-exact re-seal of a captured
// historical vector (whose packet ID is fixed by the capture, not the next
// one this Wrapper would otherwise assign) is possible at all — mirroring
// internal/tlscrypt.Wrapper.WrapWithPacketID's own precedent
// (01-04-SUMMARY.md Deviation 4, 02-04-PLAN.md Task 2).
func (w *Wrapper) SealWithPacketID(dst []byte, packetID uint32, plaintext []byte) []byte {
	return w.sealWithSeq(dst, packetID, plaintext)
}

// sealWithSeq is Seal/SealWithPacketID's shared implementation: build the
// header, assemble the nonce, seal via the AEAD, and reorder Go's own
// ciphertext||tag convention into the wire's tag||ciphertext order
// (Pitfall 2) — the single seam both callers go through, so the reorder is
// tested once, not duplicated.
func (w *Wrapper) sealWithSeq(dst []byte, seq uint32, plaintext []byte) []byte {
	var header [headerSize]byte
	header[0] = byte(wire.OpDataV2)<<3 | w.keyID&0x07
	header[offPeerID+0] = byte(w.peerID >> 16)
	header[offPeerID+1] = byte(w.peerID >> 8)
	header[offPeerID+2] = byte(w.peerID)
	binary.BigEndian.PutUint32(header[offPacketID:offTag], seq)

	var nonce [NonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], seq)
	copy(nonce[4:12], w.encryptIV[:])

	sealed := w.encryptAEAD.Seal(nil, nonce[:], plaintext, header[:])
	// sealed = ciphertext(N) || tag(TagSize) — Go's own convention. Split
	// once, here, so the wire reorder is a single testable seam rather than
	// inlined at every call site (Pitfall 2).
	ciphertext, tag := sealed[:len(sealed)-TagSize], sealed[len(sealed)-TagSize:]

	dst = append(dst, header[:]...)
	dst = append(dst, tag...)
	dst = append(dst, ciphertext...)
	return dst
}

// SealPing seals the 16-byte ping keepalive magic (ping.go's pingMagic) as
// an ordinary data packet — a ping is encrypted through exactly the same
// AEAD path as any other data packet (ping.c:74-90), not a distinct wire
// opcode. Emission and absorption (Open below, via IsPing) share this one
// magic constant and one set of offsets.
func (w *Wrapper) SealPing(dst []byte) ([]byte, error) {
	return w.Seal(dst, pingMagic[:])
}

// Open authenticates and decrypts packet, returning the plaintext IP
// payload appended to dst. It rejects anything shorter than the
// header+tag prefix with ErrShort before any indexing, recomposes Go's
// expected ciphertext||tag order from the wire's tag||ciphertext order,
// and returns ErrAuth (no plaintext) on any authentication failure. Only
// after that AEAD check succeeds is the 64-wide sliding replay window
// (replay.go, DATA-02) consulted — an ErrAuth return leaves it
// byte-for-byte unchanged (T-02-15): an unauthenticated packet can never
// advance or mark a victim's window. A decrypted ping (D-11) is absorbed
// here: ErrPingAbsorbed is returned instead of the plaintext, and it is
// never mistaken for a fresh IP packet by any caller checking err == nil.
func (w *Wrapper) Open(dst, packet []byte) ([]byte, error) {
	if len(packet) < offCiphertext {
		return nil, ErrShort
	}

	header := packet[:headerSize]
	seq := binary.BigEndian.Uint32(packet[offPacketID:offTag])
	tag := packet[offTag:offCiphertext]
	ciphertext := packet[offCiphertext:]

	var nonce [NonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], seq)
	copy(nonce[4:12], w.decryptIV[:])

	// Recompose Go's expected ciphertext||tag order from the wire's
	// tag||ciphertext order (Pitfall 2) in a fresh buffer — packet must
	// never be mutated, it may be a shared read buffer.
	sealed := make([]byte, 0, len(ciphertext)+TagSize)
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	prefixLen := len(dst)
	plaintext, err := w.decryptAEAD.Open(dst, nonce[:], sealed, header)
	if err != nil {
		return nil, ErrAuth
	}

	if !w.replay.accept(seq) {
		return nil, ErrReplay
	}

	decrypted := plaintext[prefixLen:]
	if IsPing(decrypted) {
		return nil, ErrPingAbsorbed
	}

	return plaintext, nil
}
