package keyderiv

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// keyMethod2 / keyMethodMask: ssl.h:113,116 (KEY_METHOD_2 = 2,
// KEY_METHOD_MASK = 0x0F).
const (
	keyMethod2    = 2
	keyMethodMask = 0x0F

	// maxOptionsStringLen: ssl.h:69 (TLS_OPTIONS_LEN = 512) — the ceiling
	// every length-prefixed string field in a Key Method 2 message is
	// checked against before any allocation of that size (T-02-01).
	maxOptionsStringLen = 512
)

// Sentinel errors returned by ReadClientKeyMethod2.
var (
	ErrKeyMethod     = errors.New("keyderiv: key-method byte is not KEY_METHOD_2")
	ErrStringTooLong = errors.New("keyderiv: length-prefixed string exceeds TLS_OPTIONS_LEN")
)

// ClientOptions holds the four length-prefixed strings a client's Key
// Method 2 message carries after its random material. They are read and
// retained only for diagnostics — this project does not branch on any of
// them (RESEARCH.md Assumption A2; options_cmp_equal, ssl.c:2498, is
// warning-only on mismatch, so byte-exact reproduction of the reference's
// own OCC options string is not required for interop).
type ClientOptions struct {
	Options  []byte
	Username []byte
	Password []byte
	PeerInfo []byte
}

// ReadClientKeyMethod2 reads a client's Key Method 2 message from r, in
// order (ssl.c:2387-2431, key_method_2_read):
//
//	4 reserved bytes (discarded)
//	1 key-method byte (low nibble must equal KEY_METHOD_2)
//	48 pre_master, 32 random1, 32 random2 (key_source2_read, ssl.c:1890-1905)
//	4 length-prefixed byte strings, in order: options, username, password,
//	  peer_info (a length field of 0 yields a nil string,
//	  write_empty_string's counterpart, ssl.c:1952-1959)
//
// Every fixed-length field is read with io.ReadFull, so a short read is
// always an error, never a silent partial parse; every length-prefixed
// string's length is checked against maxOptionsStringLen BEFORE any
// allocation of that size — this function never panics on adversarial
// input (T-02-01).
func ReadClientKeyMethod2(r io.Reader) (*KeySource, *ClientOptions, error) {
	var reserved [4]byte
	if _, err := io.ReadFull(r, reserved[:]); err != nil {
		return nil, nil, err
	}

	var methodByte [1]byte
	if _, err := io.ReadFull(r, methodByte[:]); err != nil {
		return nil, nil, err
	}
	if methodByte[0]&keyMethodMask != keyMethod2 {
		return nil, nil, ErrKeyMethod
	}

	var src KeySource
	if _, err := io.ReadFull(r, src.PreMaster[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, src.Random1[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, src.Random2[:]); err != nil {
		return nil, nil, err
	}

	opts := &ClientOptions{}
	var err error
	if opts.Options, err = readLengthPrefixedString(r); err != nil {
		return nil, nil, err
	}
	if opts.Username, err = readLengthPrefixedString(r); err != nil {
		return nil, nil, err
	}
	if opts.Password, err = readLengthPrefixedString(r); err != nil {
		return nil, nil, err
	}
	if opts.PeerInfo, err = readLengthPrefixedString(r); err != nil {
		return nil, nil, err
	}

	return &src, opts, nil
}

// readLengthPrefixedString reads one 2-byte-big-endian-length-prefixed
// byte string. A length of 0 returns a nil string (mirroring
// write_empty_string's counterpart, ssl.c:1952-1959) without attempting a
// zero-length read. A length above maxOptionsStringLen is rejected with
// ErrStringTooLong before any allocation.
func readLengthPrefixedString(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, nil
	}
	if n > maxOptionsStringLen {
		return nil, ErrStringTooLong
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteServerKeyMethod2 writes the server's own Key Method 2 message to w:
// 4 zero bytes, KEY_METHOD_2, fresh random1/random2 (crypto/rand — the
// server never sends a pre_master, ssl.c:1890-1896's server branch never
// populates one), the given opts string (its wire length includes a
// trailing NUL, per write_string's own convention), and three empty
// (2-byte 0x0000) fields for username, password and peer_info — a P2MP
// server's push_peer_info_detail default is 0, i.e. "nothing"
// (ssl.c:2030-2039, ssl.c:2081). It returns the freshly-generated KeySource
// so the caller can feed it into DeriveKeys.
func WriteServerKeyMethod2(w io.Writer, opts string) (*KeySource, error) {
	var src KeySource
	if _, err := rand.Read(src.Random1[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(src.Random2[:]); err != nil {
		return nil, err
	}

	var buf []byte
	buf = append(buf, 0, 0, 0, 0) // reserved
	buf = append(buf, keyMethod2)
	buf = append(buf, src.Random1[:]...)
	buf = append(buf, src.Random2[:]...)

	optsBytes := append([]byte(opts), 0) // trailing NUL, per write_string
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(optsBytes)))
	buf = append(buf, optsBytes...)

	// username, password, peer_info: write_empty_string — 2-byte 0x0000,
	// no trailing byte (ssl.c:1952-1959).
	buf = append(buf, 0, 0, 0, 0, 0, 0)

	if _, err := w.Write(buf); err != nil {
		return nil, err
	}
	return &src, nil
}
