// Command gentestpki generates the throwaway CA/server/client certificate
// chain, a tls-crypt static key, and the client .conf that the
// test/interop Docker harness consumes.
//
// Everything is generated with crypto/x509 + crypto/rand (+ crypto/ecdsa or
// crypto/rsa, depending on -profile) + encoding/pem — no easy-rsa, no
// shelling out to the openvpn binary's --genkey. Every subject CommonName is
// namespaced with a "govpn-interop-" prefix so this material can never be
// mistaken for production credentials (RESEARCH threat T-01-09), and the
// output directory is regenerated fresh on every run into a gitignored
// path — nothing here is ever committed.
//
// -profile controls the server's certificate chain shape:
//
//   - "small" (default): the original single CA -> leaf chain with ECDSA
//     P-256 keys, kept fast for the clean-link scenario.
//   - "large": a three-level chain — root CA -> intermediate CA -> leaf —
//     with RSA-4096 keys, so the server's TLS Certificate message is several
//     kilobytes and necessarily spans multiple control packets at the
//     1150-byte fragmentation ceiling (01-04-PLAN.md Task 1). The server
//     presents the leaf plus the intermediate (server.crt + intermediate.crt);
//     the client trusts only the root (ca.crt).
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: used only as a non-cryptographic Subject/AuthorityKeyIdentifier derivation, mirroring RFC 5280 §4.2.1.2 method 1 (hash of the public key bits), not a security boundary.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8upio/govpn/internal/tlscrypt"
)

// staticKeyHead/staticKeyFoot mirror internal/tlscrypt/keyfile.go's parser
// exactly (crypto.c:1161-1163 static_key_head/static_key_foot) so the file
// this command writes round-trips through tlscrypt.ParseStaticKeyV1
// byte-for-byte.
const (
	staticKeyHead = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyFoot = "-----END OpenVPN Static key V1-----"

	// serverAlias is the compose network alias the generated client.conf's
	// `remote` directive targets — must match the alias
	// test/interop/docker-compose.yml assigns to the server service.
	serverAlias = "govpn-interop-server"
	serverPort  = 1194

	// pkiMountPoint is the absolute path both compose services mount the
	// generated PKI directory at, and therefore the path client.conf's
	// file references must use.
	pkiMountPoint = "/pki"

	certValidity = 24 * time.Hour

	profileSmall = "small"
	profileLarge = "large"

	// largePadding is deliberately verbose Subject/Issuer material applied
	// only to the "large" profile's intermediate and leaf certificates, on
	// top of the RSA-4096 key size itself, so the combined DER size of
	// server.crt+intermediate.crt comfortably and reliably clears the
	// acceptance threshold (>3000 bytes) rather than sitting right at the
	// edge of a rough estimate.
	largePadding = "large-certificate-profile-generated-for-govpn-interop-multi-packet-tls-fragmentation-verification-01-04-plan-task-1"
)

// clientDirectiveFlag collects a repeatable -client-directive flag into an
// ordered slice, so a scenario needing several extra client.conf lines (e.g.
// both `reneg-sec 15` and `explicit-exit-notify 2`, 04-03-PLAN.md) passes
// the flag more than once rather than needing its own comma-splitting
// convention. flag.Value's own String()/Set() contract, mirroring every
// other stdlib repeatable-flag implementation.
type clientDirectiveFlag []string

func (f *clientDirectiveFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *clientDirectiveFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	out := flag.String("out", filepath.Join("test", "interop", "pki"), "output directory for generated PKI material")
	profile := flag.String("profile", profileSmall, "certificate profile: small or large")
	var directives clientDirectiveFlag
	flag.Var(&directives, "client-directive", "extra client.conf directive to append verbatim (repeatable; e.g. -client-directive \"reneg-sec 15\"); default none, so the pre-existing clean-small/clean-large/lossy-large scenarios generate a byte-identical client.conf (04-03-PLAN.md Task 1)")
	flag.Parse()

	if err := run(*out, *profile, directives); err != nil {
		fmt.Fprintln(os.Stderr, "gentestpki:", err)
		os.Exit(1)
	}
}

func run(outDir, profile string, clientDirectives []string) error {
	if profile != profileSmall && profile != profileLarge {
		return fmt.Errorf("unknown -profile %q (want %q or %q)", profile, profileSmall, profileLarge)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	var (
		rootCert  *x509.Certificate
		serverDER []byte
		serverKey crypto.Signer
		intDER    []byte // empty for the small profile
		clientDER []byte
		clientKey crypto.Signer
	)

	switch profile {
	case profileSmall:
		caKey, caCert, caDER, err := generateECDSACA("govpn-interop-CA")
		if err != nil {
			return fmt.Errorf("generate CA: %w", err)
		}
		if err := writeCert(filepath.Join(outDir, "ca.crt"), caDER); err != nil {
			return err
		}
		rootCert = caCert

		serverKey, serverDER, err = generateECDSALeaf("govpn-interop-server", caCert, caKey, x509.ExtKeyUsageServerAuth)
		if err != nil {
			return fmt.Errorf("generate server cert: %w", err)
		}

		clientKey, clientDER, err = generateECDSALeaf("govpn-interop-client", caCert, caKey, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}

	case profileLarge:
		rootKey, caCert, caDER, err := generateRSACA("govpn-interop-root-ca")
		if err != nil {
			return fmt.Errorf("generate root CA: %w", err)
		}
		if err := writeCert(filepath.Join(outDir, "ca.crt"), caDER); err != nil {
			return err
		}
		rootCert = caCert

		// CommonName must stay short: a real OpenVPN client's CN
		// extraction from the X509 subject string is limited to 64
		// characters (verified empirically — a padded CN here produces
		// "VERIFY ERROR: could not extract CN ... field length is limited
		// to 64 characters" and a failed handshake). The size padding
		// lives in OrganizationalUnit (see generateRSAIntermediate/Leaf),
		// not here.
		intKey, intCert, intermediateDER, err := generateRSAIntermediate("govpn-interop-intermediate-ca", caCert, rootKey)
		if err != nil {
			return fmt.Errorf("generate intermediate CA: %w", err)
		}
		intDER = intermediateDER
		if err := writeCert(filepath.Join(outDir, "intermediate.crt"), intDER); err != nil {
			return err
		}

		serverKey, serverDER, err = generateRSALeaf("govpn-interop-server", intCert, intKey, x509.ExtKeyUsageServerAuth)
		if err != nil {
			return fmt.Errorf("generate server cert: %w", err)
		}

		// The client cert is issued directly by the root (not the
		// intermediate) — the large profile's point is fragmenting the
		// SERVER's TLS Certificate message; the client cert chain stays a
		// single hop in both profiles, and the client trusts only the root
		// either way (RESEARCH Pattern 4, plan Task 1 action text).
		clientKey, clientDER, err = generateRSALeaf("govpn-interop-client", caCert, rootKey, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return fmt.Errorf("generate client cert: %w", err)
		}
	}
	_ = rootCert

	if err := writeCert(filepath.Join(outDir, "server.crt"), serverDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outDir, "server.key"), serverKey); err != nil {
		return err
	}
	if err := writeCert(filepath.Join(outDir, "client.crt"), clientDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outDir, "client.key"), clientKey); err != nil {
		return err
	}

	if profile == profileSmall {
		// Ensure a stale intermediate.crt from a previous "large" run in
		// the same output directory is never silently reused.
		_ = os.Remove(filepath.Join(outDir, "intermediate.crt"))
	}

	tlsCryptKey := make([]byte, 256)
	if _, err := rand.Read(tlsCryptKey); err != nil {
		return fmt.Errorf("generate tls-crypt key: %w", err)
	}
	tlsCryptPath := filepath.Join(outDir, "tls-crypt.key")
	if err := writeStaticKeyV1(tlsCryptPath, tlsCryptKey); err != nil {
		return err
	}
	if err := verifyStaticKeyV1RoundTrip(tlsCryptPath, tlsCryptKey); err != nil {
		return fmt.Errorf("tls-crypt key self-check failed: %w", err)
	}

	if err := writeClientConf(filepath.Join(outDir, "client.conf"), clientDirectives); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------
// small profile: ECDSA P-256, single CA -> leaf chain (original behavior).
// ---------------------------------------------------------------------

func generateECDSACA(cn string) (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	tmpl.AuthorityKeyId = tmpl.SubjectKeyId

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, cert, der, nil
}

// generateECDSALeaf issues a certificate signed by ca/caKey for cn (already
// namespaced by the caller), with the given extended key usage.
func generateECDSALeaf(cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, eku x509.ExtKeyUsage) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyID(&key.PublicKey),
		AuthorityKeyId:        ca.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// ---------------------------------------------------------------------
// large profile: RSA-4096, root CA -> intermediate CA -> leaf chain.
// ---------------------------------------------------------------------

const rsaKeyBits = 4096

func generateRSACA(cn string) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"govpn interop testing harness"},
			OrganizationalUnit: []string{largePadding},
			Country:            []string{"US"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	tmpl.AuthorityKeyId = tmpl.SubjectKeyId

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, cert, der, nil
}

// generateRSAIntermediate issues an RSA-4096 intermediate CA certificate
// signed by the root, deliberately padded with verbose Subject fields (see
// largePadding) so the combined server.crt+intermediate.crt DER size
// comfortably clears the plan's >3000-byte acceptance threshold.
func generateRSAIntermediate(cn string, root *x509.Certificate, rootKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"govpn interop testing harness"},
			OrganizationalUnit: []string{largePadding},
			Country:            []string{"US"},
			Locality:           []string{"Testville"},
			Province:           []string{"Testland"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          keyID(&key.PublicKey),
		AuthorityKeyId:        root.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, cert, der, nil
}

// generateRSALeaf issues an RSA-4096 leaf certificate signed by parent,
// deliberately padded with verbose Subject fields (see largePadding).
func generateRSALeaf(cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey, eku x509.ExtKeyUsage) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"govpn interop testing harness"},
			OrganizationalUnit: []string{largePadding},
			Country:            []string{"US"},
			Locality:           []string{"Testville"},
			Province:           []string{"Testland"},
		},
		DNSNames:              []string{serverAlias, "govpn-interop-server.interop", "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          keyID(&key.PublicKey),
		AuthorityKeyId:        parent.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// keyID derives a RFC 5280 §4.2.1.2 method-1-style SubjectKeyIdentifier
// (SHA-1 of the DER-encoded SubjectPublicKeyInfo's BIT STRING contents) —
// standard practice for chain-building certs, not a security-relevant use
// of SHA-1 (see the file-level gosec suppression on the crypto/sha1 import).
func keyID(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha1.Sum(der) //nolint:gosec // G401: non-cryptographic identifier derivation only, see import comment.
	return sum[:]
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func writeCert(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
}

// writeKey PEM-encodes an ECDSA or RSA private key using the appropriate
// PKCS encoding for each.
func writeKey(path string, key crypto.Signer) error {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o644)
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0o644)
	default:
		return fmt.Errorf("gentestpki: unsupported key type %T", key)
	}
}

// writeStaticKeyV1 emits raw (must be exactly 256 bytes) as an OpenVPN
// "Static key V1" envelope: the exact header/footer strings and hex body
// format read from the pinned C reference (crypto.c:1161-1163,1189-1190),
// wrapped at 32 hex characters (16 bytes) per line to match the reference
// generator's own formatting.
func writeStaticKeyV1(path string, raw []byte) error {
	if len(raw) != 256 {
		return fmt.Errorf("tls-crypt key must be exactly 256 bytes, got %d", len(raw))
	}

	hexBody := hex.EncodeToString(raw)

	var b strings.Builder
	b.WriteString(staticKeyHead)
	b.WriteByte('\n')
	const lineWidth = 32 // 32 hex chars == 16 raw bytes per line
	for i := 0; i < len(hexBody); i += lineWidth {
		end := i + lineWidth
		if end > len(hexBody) {
			end = len(hexBody)
		}
		b.WriteString(hexBody[i:end])
		b.WriteByte('\n')
	}
	b.WriteString(staticKeyFoot)
	b.WriteByte('\n')

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// verifyStaticKeyV1RoundTrip is a build-time self-check: it re-reads the
// file this command just wrote through the actual production parser
// (internal/tlscrypt.ParseStaticKeyV1) the server and interop tests use, and
// confirms the recovered bytes match what was generated. This is a stronger
// check than re-implementing the parser here: it proves the real parser
// accepts the file this generator writes, not just a duplicate parser that
// could silently drift from it. A generator that writes a file its own
// project's parser can't read back correctly would be a silent,
// hard-to-diagnose harness bug.
func verifyStaticKeyV1RoundTrip(path string, want []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	got, err := tlscrypt.ParseStaticKeyV1(data)
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("round-trip length mismatch: wrote %d bytes, parsed back %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			return fmt.Errorf("round-trip byte mismatch at offset %d", i)
		}
	}
	return nil
}

// writeClientConf emits the client .conf the interop client container
// consumes. topology subnet and the explicit cipher are set from the very
// first run (RESEARCH: no reason to change this config when plan 01-03 and
// Phase 2 start relying on them). Identical across both profiles — only the
// underlying PKI material referenced by these same filenames changes shape.
//
// extraDirectives (04-03-PLAN.md Task 1) are appended verbatim, one per
// line, after the fixed lines above — e.g. "reneg-sec 15" or
// "explicit-exit-notify 2" for the renegotiation/exit-notify interop
// scenario. A nil/empty slice (every pre-existing scenario's call site)
// appends nothing, so clean-small/clean-large/lossy-large's generated
// client.conf stays byte-identical to before this flag existed.
func writeClientConf(path string, extraDirectives []string) error {
	conf := fmt.Sprintf(`client
dev tun
proto udp
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
ca %s/ca.crt
cert %s/client.crt
key %s/client.key
tls-crypt %s/tls-crypt.key
topology subnet
cipher AES-256-GCM
verb 4
`, serverAlias, serverPort, pkiMountPoint, pkiMountPoint, pkiMountPoint, pkiMountPoint)

	for _, d := range extraDirectives {
		conf += d + "\n"
	}

	return os.WriteFile(path, []byte(conf), 0o644)
}
