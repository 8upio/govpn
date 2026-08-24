// Package keyderiv implements OpenVPN's Key Method 2 data-channel key
// derivation: the hand-rolled TLS 1.0 PRF (RFC 2246 §5.6.4.1) OpenVPN calls
// openvpn_PRF, the two-stage master-secret/key-expansion derivation that
// consumes it, the Key Method 2 wire message itself, and the per-direction
// key/implicit-IV slot assignment the data channel consumes.
//
// Byte layout, algorithms and line citations below are traceable to the
// pinned OpenVPN reference checkout (/Users/svenloth/dev/openvpn-reference,
// branch release/2.6, commit c9b790f5b9e8ebca5da38c22f479c31bb8d33686):
//
//   - PRF seed assembly: src/openvpn/ssl.c:1476-1517 (openvpn_PRF)
//   - P_hash / the TLS 1.0 PRF itself: src/openvpn/crypto_openssl.c:1467-1626
//     (tls1_P_hash, ssl_tls1_PRF)
//   - key expansion (master secret then key material, struct key_source2
//     seed layout): src/openvpn/ssl.c:1579-1630
//     (generate_key_expansion_openvpn_prf), src/openvpn/ssl_common.h:116-136
//   - Key Method 2 message layout: src/openvpn/ssl.c:1890-1905
//     (key_source2_read), src/openvpn/ssl.c:2387-2431 (key_method_2_read)
package keyderiv

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // G401: MD5 is a label-mixing component of OpenVPN's mandated RFC 2246 PRF (openvpn_PRF, ssl.c:1476-1517), not the security boundary — that is TLS plus AES-256-GCM. Wire compatibility with a real OpenVPN client requires it.
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is a label-mixing component of OpenVPN's mandated RFC 2246 PRF (openvpn_PRF, ssl.c:1476-1517), not the security boundary — that is TLS plus AES-256-GCM. Wire compatibility with a real OpenVPN client requires it.
	"hash"
)

// pHash implements RFC 2246 §5.6.4.1's P_hash construction into out:
//
//	A(0) = seed
//	A(i) = HMAC_h(secret, A(i-1))
//	P_hash(secret, seed) = HMAC_h(secret, A(1) || seed) ||
//	                       HMAC_h(secret, A(2) || seed) || ...
//
// truncated (or, for the last block, extended-then-truncated) to len(out)
// bytes. Source: crypto_openssl.c:1467-1565 (tls1_P_hash), read against the
// pinned reference this plan.
func pHash(h func() hash.Hash, secret, seed, out []byte) {
	mac := hmac.New(h, secret)
	mac.Write(seed)
	a := mac.Sum(nil) // A(1)

	pos := 0
	for pos < len(out) {
		mac = hmac.New(h, secret)
		mac.Write(a)
		mac.Write(seed)
		block := mac.Sum(nil)

		n := copy(out[pos:], block)
		pos += n

		mac = hmac.New(h, secret)
		mac.Write(a)
		a = mac.Sum(nil) // A(i+1)
	}
}

// PRF implements OpenVPN's own TLS 1.0 PRF (ssl_tls1_PRF,
// crypto_openssl.c:1586-1626): split secret into two halves (overlapping by
// one byte when secret has odd length — the reference's own construction,
// mirrored here even though every caller in this package uses an
// even-length 48-byte secret), run P_hash with MD5 over the first half and
// SHA-1 over the second, and XOR the two n-byte output streams together.
func PRF(secret, seed []byte, n int) []byte {
	slen := len(secret)
	half := slen / 2
	if slen%2 != 0 {
		half++
	}
	s1 := secret[:half]
	s2 := secret[slen-half:]

	out1 := make([]byte, n)
	out2 := make([]byte, n)
	pHash(md5.New, s1, seed, out1)
	pHash(sha1.New, s2, seed, out2)

	out := make([]byte, n)
	for i := range out {
		out[i] = out1[i] ^ out2[i]
	}
	return out
}

// openvpnPRF implements openvpn_PRF's own seed-assembly wrapper around PRF
// (ssl.c:1476-1517): seed = label || clientSeed || serverSeed ||
// [clientSID] || [serverSID], with the two 8-byte control-channel session
// IDs appended only when non-nil. Do not confuse this outer seed assembly
// with pHash's own internal A(i) || seed construction above — they are
// different concatenations at different layers.
func openvpnPRF(secret []byte, label string, clientSeed, serverSeed []byte, clientSID, serverSID *[8]byte, n int) []byte {
	seed := make([]byte, 0, len(label)+len(clientSeed)+len(serverSeed)+16)
	seed = append(seed, label...)
	seed = append(seed, clientSeed...)
	seed = append(seed, serverSeed...)
	if clientSID != nil {
		seed = append(seed, clientSID[:]...)
	}
	if serverSID != nil {
		seed = append(seed, serverSID[:]...)
	}
	return PRF(secret, seed, n)
}
