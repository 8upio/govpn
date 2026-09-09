// This file (cipher.go) implements Negotiable Crypto Parameters (NCP)
// cipher selection: the pure, unit-testable functions
// performKeyMethod2Exchange (ovpn.go) uses to choose this session's
// data-channel cipher from the client's advertised capabilities against
// the server's own configured, ordered allow-list — before any Key Method
// 2 key material is derived.
//
// Reference: /Users/svenloth/dev/openvpn-reference (release/2.6)
//   - ssl_ncp.c:55-92     tls_peer_info_ncp_ver, tls_peer_supports_ncp
//   - ssl_ncp.c:207-245   tls_item_in_cipher_list, tls_peer_ncp_list
//   - ssl_ncp.c:247-290   ncp_get_best_cipher
//   - ssl_ncp.c:1921-1929 the client-visible "no shared cipher" reason
//     string
//   - ssl_util.c:32-59    extract_var_peer_info (the IV_x= value runs to
//     the next newline)
//   - options.c:4380-4418 options_string's own cipher/keysize construction
//   - crypto_openssl.c:640-694 cipher_kt_key_size/cipher_kt_iv_size:
//     AES-128-GCM and AES-256-GCM differ ONLY in key length
package ovpn

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxCipherNameLen bounds any peer-supplied cipher token BEFORE it is even
// compared against supportedDataCiphers (T-05-04): no canonical name this
// milestone supports is anywhere close to this length, so a client sending
// something absurdly long is rejected up front rather than compared byte
// by byte.
const maxCipherNameLen = 63

// supportedDataCiphers is the single source of truth for every canonical
// data-channel cipher name this milestone supports, in the server's own
// default preference order (CONTEXT.md: a nil Config.DataCiphers resolves
// to a copy of this exact list). ChaCha20-Poly1305/AES-CBC are
// deliberately absent (CIPH-07/CIPH-08, deferred to v2 — see PROJECT.md
// Out of Scope).
var supportedDataCiphers = []string{"AES-256-GCM", "AES-128-GCM"}

// cipherNegotiationFailedReason is the reference's own client-visible
// AUTH_FAILED reason string for a no-shared-cipher rejection
// (auth_set_client_reason, ssl_ncp.c:1921-1929), quoted verbatim so a real
// client's log looks identical to a C server's own rejection — no
// server-side detail appended. Consumed by plan 05-03's rejection path.
const cipherNegotiationFailedReason = "Data channel cipher negotiation failed (no shared cipher)"

// errCipherNegotiationFailed is the sentinel selectCipher returns when no
// entry of the server's allow-list is acceptable to the peer.
var errCipherNegotiationFailed = errors.New("ovpn: no shared data-channel cipher")

// canonicalCipherName matches name against supportedDataCiphers under
// strings.EqualFold — ASCII case-insensitive EXACT matching against this
// milestone's fixed two-entry table, never a fuzzy/heuristic transform
// (RESEARCH.md Pitfall 6): a misspelled name (e.g. one missing its
// hyphens) is rejected outright, not "normalised" into something else.
// This is a deliberate divergence from the reference's own case-sensitive
// strcmp/streq comparisons (tls_item_in_cipher_list, ssl_ncp.c:207-224),
// locked by CONTEXT.md. The returned string is always the TABLE's own
// canonical upper-case spelling, never the caller's.
func canonicalCipherName(name string) (string, bool) {
	if len(name) == 0 || len(name) > maxCipherNameLen {
		return "", false
	}
	for _, candidate := range supportedDataCiphers {
		if strings.EqualFold(candidate, name) {
			return candidate, true
		}
	}
	return "", false
}

// cipherKeyLen returns the AEAD key length, in bytes, for canonicalName:
// 32 for AES-256-GCM, 16 for AES-128-GCM — the ONLY thing that varies
// between them (crypto_openssl.c:640-694: cipher_kt_key_size/
// cipher_kt_iv_size are EVP_CIPHER_key_length/EVP_CIPHER_iv_length; both
// ciphers share the same 12-byte nonce and 16-byte tag). Returns 0 for
// anything else, so a caller that skipped canonicalCipherName fails loudly
// downstream rather than silently defaulting to a key length that doesn't
// match the negotiated name.
func cipherKeyLen(canonicalName string) int {
	switch canonicalName {
	case "AES-256-GCM":
		return 32
	case "AES-128-GCM":
		return 16
	default:
		return 0
	}
}

// resolveDataCiphers resolves Config.DataCiphers (dataCiphers) and the
// deprecated Config.Cipher shorthand (cipher) into the server's own
// ordered allow-list, exactly once, at Serve time.
//
// An empty dataCiphers resolves to the one-element list [cipher] when
// cipher is non-empty (the deprecated shorthand, CONTEXT.md), or to a copy
// of supportedDataCiphers otherwise (today's default behaviour,
// unchanged). A non-empty dataCiphers is validated entry by entry: each
// name must match canonicalCipherName, and the canonical forms must be
// pairwise distinct — two entries differing only in case are a duplicate,
// rejected with an error, never silently deduplicated. The caller's order
// is preserved exactly: this function never sorts and never reorders
// around a rejected duplicate. The returned slice is freshly allocated so
// it can never alias the embedder's own Config.DataCiphers slice.
func resolveDataCiphers(dataCiphers []string, cipher string) ([]string, error) {
	if len(dataCiphers) == 0 {
		if cipher == "" {
			out := make([]string, len(supportedDataCiphers))
			copy(out, supportedDataCiphers)
			return out, nil
		}
		canonical, ok := canonicalCipherName(cipher)
		if !ok {
			return nil, fmt.Errorf("ovpn: Config.Cipher %q is not a supported data-channel cipher", cipher)
		}
		return []string{canonical}, nil
	}

	out := make([]string, 0, len(dataCiphers))
	seen := make(map[string]bool, len(dataCiphers))
	for _, name := range dataCiphers {
		canonical, ok := canonicalCipherName(name)
		if !ok {
			return nil, fmt.Errorf("ovpn: Config.DataCiphers entry %q is not a supported data-channel cipher", name)
		}
		if seen[canonical] {
			return nil, fmt.Errorf("ovpn: Config.DataCiphers contains %q more than once", canonical)
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	return out, nil
}

// peerInfoValue extracts the value of the first "\n"-delimited peerInfo
// line whose prefix is key (e.g. "IV_CIPHERS="), returning the remainder
// of that line. This is a deliberate hardening over the reference's own
// unanchored strstr (extract_var_peer_info, ssl_util.c:40-53): anchoring
// the match to the START of a line stops a crafted peer_info value from
// smuggling a second "IV_CIPHERS=" inside another variable's own value. A
// key present with an empty value returns ("", true) — a different
// outcome from the key being entirely absent (false).
func peerInfoValue(peerInfo []byte, key string) (string, bool) {
	for _, line := range strings.Split(string(peerInfo), "\n") {
		if rest, ok := strings.CutPrefix(line, key); ok {
			return rest, true
		}
	}
	return "", false
}

// peerNCPVersion parses the leading integer from peerInfo's "IV_NCP="
// value, mirroring tls_peer_info_ncp_ver (ssl_ncp.c:55-70). Returns 0 when
// the key is absent or the value does not parse as an integer.
func peerNCPVersion(peerInfo []byte) int {
	value, ok := peerInfoValue(peerInfo, "IV_NCP=")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return n
}

// peerSupportsNCP reports whether peerInfo signals NCP support, mirroring
// tls_peer_supports_ncp (ssl_ncp.c:76-92): true when IV_NCP>=2, or when
// IV_CIPHERS= is present at all (regardless of its value).
func peerSupportsNCP(peerInfo []byte) bool {
	if peerNCPVersion(peerInfo) >= 2 {
		return true
	}
	_, ok := peerInfoValue(peerInfo, "IV_CIPHERS=")
	return ok
}

// peerCipherList is the port of tls_peer_ncp_list (ssl_ncp.c:226-245): if
// IV_CIPHERS= is present, its value split on ":" (an empty value yields an
// empty, non-nil list — present but empty, which is NOT the IV_NCP
// fallback below); else, if IV_NCP>=2, the implied list [AES-256-GCM,
// AES-128-GCM]; else nil (no capability signal at all). The returned
// tokens are NOT canonicalised here — selectCipher compares them
// fold-insensitively against the already-canonical allow-list.
func peerCipherList(peerInfo []byte) []string {
	if value, ok := peerInfoValue(peerInfo, "IV_CIPHERS="); ok {
		if value == "" {
			return []string{}
		}
		return strings.Split(value, ":")
	}
	if peerNCPVersion(peerInfo) >= 2 {
		return []string{"AES-256-GCM", "AES-128-GCM"}
	}
	return nil
}

// containsFold reports whether list contains s under strings.EqualFold.
func containsFold(list []string, s string) bool {
	for _, item := range list {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

// selectCipher is the port of ncp_get_best_cipher (ssl_ncp.c:247-290): it
// iterates allowList — the SERVER's own ordered configuration — OUTERMOST,
// returning the first entry that either appears in peerCiphers (from
// IV_CIPHERS or the IV_NCP>=2 implied list) or equals occCipher, both
// under strings.EqualFold. This loop order is the whole point of success
// criterion 2: because the OUTER loop is over the server's list, the
// client's own ordering can never decide a tie (T-05-01). occCipher is
// always the empty string from this plan's own caller (performKeyMethod2
// Exchange) — the OCC fallback rules for a genuinely pre-NCP client land
// in plan 05-02/05-03.
func selectCipher(allowList, peerCiphers []string, occCipher string) (string, error) {
	for _, candidate := range allowList {
		if containsFold(peerCiphers, candidate) || strings.EqualFold(candidate, occCipher) {
			return candidate, nil
		}
	}
	return "", errCipherNegotiationFailed
}

// serverKM2Options builds this server's own Key Method 2 options string
// for the negotiated cipher, replacing the fixed cipher/keysize pair the
// old package-level serverKM2Options constant carried (formerly
// ovpn.go:474; removed by this plan). The identifier keeps its exact prior
// spelling so the netstack/*.go doc comments and ovpn_test.go's own
// comment that reference it by name stay truthful with no further edit.
// Every other token in the string stays byte-identical to the old
// constant; only "cipher <name>" and "keysize <bits>" change, where bits
// is cipherKeyLen(cipher)*8 (options.c:4380-4418).
func serverKM2Options(cipher string) string {
	return fmt.Sprintf(
		"V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher %s,auth SHA1,keysize %d,key-method 2,tls-server",
		cipher, cipherKeyLen(cipher)*8,
	)
}
