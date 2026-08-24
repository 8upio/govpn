package keyderiv

import "errors"

// KeySource mirrors struct key_source (ssl_common.h:116-136, read against
// the pinned reference this plan): PreMaster is populated only for the
// client's half (the server never contributes pre-master entropy — see
// DeriveKeys); Random1/Random2 are populated for both halves.
type KeySource struct {
	PreMaster [48]byte
	Random1   [32]byte
	Random2   [32]byte
}

// KeySource2 mirrors struct key_source2 (ssl_common.h:116-136): the client
// and server halves of the Key Method 2 exchange, together supplying every
// input DeriveKeys needs.
type KeySource2 struct {
	Client KeySource
	Server KeySource
}

// Key2 holds the 256-byte key-expansion output (struct key2, crypto.h) as
// two 128-byte per-direction slots, each itself split into a 64-byte cipher
// field and a 64-byte hmac field per struct key (crypto.h:149-155):
//
//	keys[0].cipher = key2[  0: 64]   keys[0].hmac = key2[ 64:128]
//	keys[1].cipher = key2[128:192]   keys[1].hmac = key2[192:256]
//
// Only the first 32 bytes of each cipher slot (AES-256 key size) and the
// first 8 bytes of each hmac slot (AEAD implicit IV) are consumed — the
// same "prefix of a 64-byte slot" pattern internal/tlscrypt's own keySlot
// already established (tlscrypt.go:75-82).
type Key2 struct {
	raw [256]byte
}

// NewKey2 builds a Key2 from exactly 256 bytes of key-expansion output.
func NewKey2(b []byte) (*Key2, error) {
	if len(b) != 256 {
		return nil, errors.New("keyderiv: key expansion output must be exactly 256 bytes")
	}
	k := &Key2{}
	copy(k.raw[:], b)
	return k, nil
}

// keyDirection returns the per-direction key2.keys[] slot index for encrypt
// and decrypt traffic, mirroring the reference's key_direction selection
// (ssl.c:1519-1530) and its implicit-IV counterpart
// (crypto.c:1506-1531, key_direction_state_init):
//
//	key_direction = server ? KEY_DIRECTION_INVERSE : KEY_DIRECTION_NORMAL;
//	KEY_DIRECTION_NORMAL:   out_key(encrypt)=keys[0], in_key(decrypt)=keys[1]
//	KEY_DIRECTION_INVERSE:  out_key(encrypt)=keys[1], in_key(decrypt)=keys[0]
//
// For server == true this is the exact mirror-opposite of the convention
// internal/tlscrypt.NewWrapper uses for the same boolean (server:
// encrypt=keys[0], decrypt=keys[1], tlscrypt.go:180-184). Copying
// tlscrypt's slot-assignment pattern here is a silent, hard-to-diagnose
// interop break that self-consistent round-trip tests between two
// instances of this package's own types will NOT catch — see
// TestKeyDirectionIsOppositeOfTLSCrypt and RESEARCH.md Pitfall 1's
// "Warning signs" paragraph.
func keyDirection(server bool) (encryptIdx, decryptIdx int) {
	if server {
		return 1, 0
	}
	return 0, 1
}

// DataKeys is the fully-sliced per-direction key material a
// internal/datachan.Wrapper needs: a 32-byte AES-256 cipher key and an
// 8-byte AEAD implicit IV for each of the encrypt and decrypt directions.
type DataKeys struct {
	EncryptCipher     [32]byte
	EncryptImplicitIV [8]byte
	DecryptCipher     [32]byte
	DecryptImplicitIV [8]byte
}

// slot returns the 64-byte cipher field and 64-byte hmac field for
// key2.keys[idx] (idx in {0,1}), per the layout k's own doc comment
// describes.
func (k *Key2) slot(idx int) (cipher, hmacField []byte) {
	base := idx * 128
	return k.raw[base : base+64], k.raw[base+64 : base+128]
}

// ServerSlots returns this Key2's per-direction key material from the
// server's own perspective (keyDirection(true)) — the encrypt slot is
// key2.keys[1], the decrypt slot is key2.keys[0], per
// key_ctx_update_implicit_iv (ssl.c:1556-1560):
//
//	key_ctx_update_implicit_iv(&key->encrypt, key2->keys[(int)server].hmac, …);
//	key_ctx_update_implicit_iv(&key->decrypt, key2->keys[1-(int)server].hmac, …);
func (k *Key2) ServerSlots() DataKeys {
	encIdx, decIdx := keyDirection(true)
	encCipher, encHMAC := k.slot(encIdx)
	decCipher, decHMAC := k.slot(decIdx)

	var out DataKeys
	copy(out.EncryptCipher[:], encCipher[:32])
	copy(out.EncryptImplicitIV[:], encHMAC[:8])
	copy(out.DecryptCipher[:], decCipher[:32])
	copy(out.DecryptImplicitIV[:], decHMAC[:8])
	return out
}

// DeriveKeys performs the two-stage OpenVPN key derivation
// (generate_key_expansion_openvpn_prf, ssl.c:1579-1630): a 48-byte master
// secret from the client's pre-master and both sides' random1, then a
// 256-byte key expansion from that master secret and both sides' random2
// plus the control-channel session IDs (server's own perspective:
// clientSID = the client's session ID we received, serverSID = our own —
// ssl.c:1586-1589). The intermediate master-secret buffer is zeroed before
// returning (threat T-02-03).
func DeriveKeys(src *KeySource2, clientSID, serverSID *[8]byte) (*Key2, error) {
	// Step 1 — master secret (ssl.c:1595-1608): secret is ALWAYS the
	// client's pre-master — the server never contributes pre-master
	// entropy, even server-side (the server has no pre_master field
	// populated at all, see ReadClientKeyMethod2 / WriteServerKeyMethod2).
	// No session IDs at this step.
	master := openvpnPRF(
		src.Client.PreMaster[:],
		masterSecretLabel,
		src.Client.Random1[:], src.Server.Random1[:],
		nil, nil,
		48,
	)
	defer zero(master)

	// Step 2 — key expansion (ssl.c:1611-1624): secret is the master
	// secret from step 1, seeded from both sides' random2 plus both
	// control-channel session IDs (server's own perspective:
	// clientSID = the client's session ID we received, serverSID = our
	// own — ssl.c:1586-1589).
	expansion := openvpnPRF(
		master,
		keyExpansionLabel,
		src.Client.Random2[:], src.Server.Random2[:],
		clientSID, serverSID,
		256,
	)

	return NewKey2(expansion)
}

const (
	// masterSecretLabel / keyExpansionLabel: ssl.h:49 (KEY_EXPANSION_ID ==
	// "OpenVPN"), combined with the fixed suffixes openvpn_PRF's two call
	// sites use (ssl.c:1595-1608, ssl.c:1611-1624).
	masterSecretLabel = "OpenVPN master secret"
	keyExpansionLabel = "OpenVPN key expansion"
)

// zero overwrites b's bytes in place.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
