package tlscrypt

import (
	"encoding/hex"
	"strings"
	"testing"
)

// validStaticKeyText builds a syntactically valid "Static key V1" envelope
// (256 distinguishable bytes, so slot-assignment tests can assert exact
// offsets) and returns both the PEM-style text and the raw bytes it encodes.
func validStaticKeyText(t testing.TB) (text string, raw []byte) {
	t.Helper()
	raw = make([]byte, staticKeyBodyLen)
	for i := range raw {
		raw[i] = byte(i)
	}

	hexBody := hex.EncodeToString(raw)
	var sb strings.Builder
	sb.WriteString(staticKeyHead)
	sb.WriteString("\n")
	for len(hexBody) > 0 {
		n := 32
		if n > len(hexBody) {
			n = len(hexBody)
		}
		sb.WriteString(hexBody[:n])
		sb.WriteString("\n")
		hexBody = hexBody[n:]
	}
	sb.WriteString(staticKeyFoot)
	sb.WriteString("\n")
	return sb.String(), raw
}

func TestParseStaticKeyV1(t *testing.T) {
	text, raw := validStaticKeyText(t)

	got, err := ParseStaticKeyV1([]byte(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("parsed bytes mismatch")
	}

	server, err := NewWrapper(got, true)
	if err != nil {
		t.Fatalf("new server wrapper: %v", err)
	}
	// Server encrypt uses slot 0: cipher = raw[0:32], hmac = raw[64:96].
	if string(server.encrypt.cipher[:]) != string(raw[0:32]) {
		t.Errorf("server encrypt cipher slot mismatch")
	}
	if string(server.encrypt.hmac[:]) != string(raw[64:96]) {
		t.Errorf("server encrypt hmac slot mismatch")
	}
	// Server decrypt uses slot 1: cipher = raw[128:160], hmac = raw[192:224].
	if string(server.decrypt.cipher[:]) != string(raw[128:160]) {
		t.Errorf("server decrypt cipher slot mismatch")
	}
	if string(server.decrypt.hmac[:]) != string(raw[192:224]) {
		t.Errorf("server decrypt hmac slot mismatch")
	}

	client, err := NewWrapper(got, false)
	if err != nil {
		t.Fatalf("new client wrapper: %v", err)
	}
	// Client is the mirror image: encrypt=slot1, decrypt=slot0.
	if string(client.encrypt.cipher[:]) != string(raw[128:160]) {
		t.Errorf("client encrypt cipher slot mismatch")
	}
	if string(client.decrypt.cipher[:]) != string(raw[0:32]) {
		t.Errorf("client decrypt cipher slot mismatch")
	}
}

func TestParseStaticKeyV1Errors(t *testing.T) {
	text, raw := validStaticKeyText(t)

	t.Run("255-byte body", func(t *testing.T) {
		short := hex.EncodeToString(raw[:255])
		bad := staticKeyHead + "\n" + short + "\n" + staticKeyFoot + "\n"
		if _, err := ParseStaticKeyV1([]byte(bad)); err == nil {
			t.Error("expected error for 255-byte body")
		}
	})

	t.Run("257-byte body", func(t *testing.T) {
		longRaw := append(append([]byte(nil), raw...), 0x00)
		long := hex.EncodeToString(longRaw)
		bad := staticKeyHead + "\n" + long + "\n" + staticKeyFoot + "\n"
		if _, err := ParseStaticKeyV1([]byte(bad)); err == nil {
			t.Error("expected error for 257-byte body")
		}
	})

	t.Run("missing footer", func(t *testing.T) {
		noFooter := strings.TrimSuffix(text, staticKeyFoot+"\n")
		if _, err := ParseStaticKeyV1([]byte(noFooter)); err == nil {
			t.Error("expected error for missing footer")
		}
	})

	t.Run("missing header", func(t *testing.T) {
		noHeader := strings.TrimPrefix(text, staticKeyHead+"\n")
		if _, err := ParseStaticKeyV1([]byte(noHeader)); err == nil {
			t.Error("expected error for missing header")
		}
	})

	t.Run("non-hex body", func(t *testing.T) {
		bad := staticKeyHead + "\n" + strings.Repeat("zz", 256) + "\n" + staticKeyFoot + "\n"
		if _, err := ParseStaticKeyV1([]byte(bad)); err == nil {
			t.Error("expected error for non-hex body")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if _, err := ParseStaticKeyV1(nil); err == nil {
			t.Error("expected error for empty input")
		}
	})
}
