// Command gentestpki generates the throwaway CA/server/client certificate
// chain, a tls-crypt static key, and the client .conf that the
// test/interop Docker harness consumes.
//
// Everything is generated with crypto/x509 + crypto/rand + crypto/ecdsa +
// encoding/pem — no easy-rsa, no shelling out to the openvpn binary's
// --genkey. Every subject CommonName is namespaced with a "govpn-interop-"
// prefix so this material can never be mistaken for production credentials
// (RESEARCH threat T-01-09), and the output directory is regenerated fresh
// on every run into a gitignored path — nothing here is ever committed.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
)

func main() {
	out := flag.String("out", filepath.Join("test", "interop", "pki"), "output directory for generated PKI material")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "gentestpki:", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	caKey, caCert, caDER, err := generateCA()
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	if err := writeCert(filepath.Join(outDir, "ca.crt"), caDER); err != nil {
		return err
	}

	serverKey, serverDER, err := generateLeaf("govpn-interop-server", caCert, caKey, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return fmt.Errorf("generate server cert: %w", err)
	}
	if err := writeCert(filepath.Join(outDir, "server.crt"), serverDER); err != nil {
		return err
	}
	if err := writeECKey(filepath.Join(outDir, "server.key"), serverKey); err != nil {
		return err
	}

	clientKey, clientDER, err := generateLeaf("govpn-interop-client", caCert, caKey, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return fmt.Errorf("generate client cert: %w", err)
	}
	if err := writeCert(filepath.Join(outDir, "client.crt"), clientDER); err != nil {
		return err
	}
	if err := writeECKey(filepath.Join(outDir, "client.key"), clientKey); err != nil {
		return err
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

	if err := writeClientConf(filepath.Join(outDir, "client.conf")); err != nil {
		return err
	}

	return nil
}

// generateCA builds a self-signed CA suitable for signing the harness's
// server and client leaf certificates.
func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
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
		Subject:               pkix.Name{CommonName: "govpn-interop-CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

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

// generateLeaf issues a certificate signed by ca/caKey for cn (already
// namespaced by the caller), with the given extended key usage.
func generateLeaf(cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, eku x509.ExtKeyUsage) (*ecdsa.PrivateKey, []byte, error) {
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
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func writeCert(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
}

func writeECKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
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
// Phase 2 start relying on them).
func writeClientConf(path string) error {
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

	return os.WriteFile(path, []byte(conf), 0o644)
}
