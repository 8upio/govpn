package tlscrypt

import (
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// staticKeyHead / staticKeyFoot: crypto.c:1162-1163 (static_key_head,
	// static_key_foot) — the OpenVPN "Static key V1" PEM-style envelope.
	staticKeyHead = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyFoot = "-----END OpenVPN Static key V1-----"

	// staticKeyBodyLen: crypto.c:1189 "const int keylen = sizeof(key2->keys)"
	// == 2 * sizeof(struct key) == 2 * (64 + 64) == 256 bytes.
	staticKeyBodyLen = 256
)

// Errors returned by ParseStaticKeyV1.
var (
	ErrBadEnvelope = errors.New("tlscrypt: not a valid OpenVPN Static key V1 file")
	ErrBadBodyLen  = errors.New("tlscrypt: static key body must decode to exactly 256 bytes")
)

// ParseStaticKeyV1 parses an OpenVPN "Static key V1" PEM-style envelope
// (crypto.c:1161-1163 static_key_head/static_key_foot, crypto.c:1122-1260
// read_key_file) — a hex-encoded body between BEGIN/END marker lines — into
// its 256 raw bytes.
//
// Those 256 bytes decode directly into the reference's key2 layout
// (crypto.h:149-155,171-185; crypto.c:1189-1190 "uint8_t *out = (uint8_t *)
// &key2->keys"):
//
//	offset   0- 63 : keys[0].cipher (first 32 bytes used — AES-256 key size)
//	offset  64-127 : keys[0].hmac   (first 32 bytes used — SHA256 key size)
//	offset 128-191 : keys[1].cipher
//	offset 192-255 : keys[1].hmac
//
// See NewWrapper for the server/client key-direction slot assignment
// (crypto.c:1505-1532 key_direction_state_init; tls_crypt.c:61-74
// tls_crypt_init_key).
func ParseStaticKeyV1(data []byte) ([]byte, error) {
	text := string(data)

	headIdx := strings.Index(text, staticKeyHead)
	if headIdx < 0 {
		return nil, ErrBadEnvelope
	}
	rest := text[headIdx+len(staticKeyHead):]

	footIdx := strings.Index(rest, staticKeyFoot)
	if footIdx < 0 {
		return nil, ErrBadEnvelope
	}
	body := rest[:footIdx]

	var hexDigits strings.Builder
	for _, r := range body {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			hexDigits.WriteRune(r)
		case r == '\n' || r == '\r' || r == ' ' || r == '\t':
			continue
		default:
			return nil, ErrBadEnvelope
		}
	}

	raw, err := hex.DecodeString(hexDigits.String())
	if err != nil {
		return nil, ErrBadEnvelope
	}
	if len(raw) != staticKeyBodyLen {
		return nil, ErrBadBodyLen
	}
	return raw, nil
}
