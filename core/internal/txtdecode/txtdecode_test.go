package txtdecode

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/contract"
)

func has(problems []Problem, sev, substr string) bool {
	for _, p := range problems {
		if p.Severity == sev && strings.Contains(p.Message, substr) {
			return true
		}
	}
	return false
}

func TestSPF(t *testing.T) {
	s := DecodeSPF("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com a mx:mail.example.com ~all")
	if s.Kind != "spf" || len(s.Mechanisms) != 5 || s.LookupCount != 3 {
		t.Fatalf("%+v", s)
	}
	m := s.Mechanisms
	if m[0] != (Mechanism{"+", "ip4", "192.0.2.0/24"}) || m[1] != (Mechanism{"+", "include", "_spf.google.com"}) || m[2] != (Mechanism{"+", "a", ""}) || m[3] != (Mechanism{"+", "mx", "mail.example.com"}) || m[4] != (Mechanism{"~", "all", ""}) {
		t.Fatalf("%+v", m)
	}
	if len(s.Problems) != 0 {
		t.Fatalf("unexpected problems: %+v", s.Problems)
	}

	s = DecodeSPF("v=spf1 +all")
	if !has(s.Problems, SevError, "+all") {
		t.Fatalf("%+v", s.Problems)
	}
	s = DecodeSPF("v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all")
	if s.LookupCount != 11 || !has(s.Problems, SevError, "over the limit") {
		t.Fatalf("%d %+v", s.LookupCount, s.Problems)
	}
	s = DecodeSPF("v=spf1 ip4:192.0.2.1")
	if !has(s.Problems, SevWarning, "no \"all\"") {
		t.Fatalf("%+v", s.Problems)
	}
	s = DecodeSPF("v=spf1 redirect=_spf.example.com")
	if s.Modifiers.Redirect == nil || *s.Modifiers.Redirect != "_spf.example.com" || s.LookupCount != 1 || has(s.Problems, SevWarning, "no \"all\"") {
		t.Fatalf("%+v %+v", s.Modifiers, s.Problems)
	}
	s = DecodeSPF("v=spf1 ptr bogus:x -all foo")
	if !has(s.Problems, SevWarning, "ptr") || !has(s.Problems, SevError, "unknown mechanism bogus") || !has(s.Problems, SevWarning, "after \"all\"") {
		t.Fatalf("%+v", s.Problems)
	}
}

func TestDMARC(t *testing.T) {
	d := DecodeDMARC("v=DMARC1; p=reject; rua=mailto:a@x.test, mailto:b@x.test; pct=50; adkim=s")
	if d.Kind != "dmarc" || d.Tags.P == nil || *d.Tags.P != "reject" || len(d.Tags.RUA) != 2 || d.Tags.Pct != 50 || d.Tags.ADKIM != "s" || d.Tags.ASPF != "r" || d.Tags.RI != 86400 {
		t.Fatalf("%+v", d.Tags)
	}
	if !has(d.Problems, SevInfo, "50%") || has(d.Problems, SevError, "") {
		t.Fatalf("%+v", d.Problems)
	}
	d = DecodeDMARC("v=DMARC1; p=none")
	if !has(d.Problems, SevInfo, "p=none") || !has(d.Problems, SevWarning, "no rua") {
		t.Fatalf("%+v", d.Problems)
	}
	d = DecodeDMARC("v=DMARC1; sp=quarantine; pct=150; x=1")
	if !has(d.Problems, SevError, "p tag is required") || !has(d.Problems, SevError, "pct") || !has(d.Problems, SevWarning, "unknown tag x") {
		t.Fatalf("%+v", d.Problems)
	}
	d = DecodeDMARC("p=reject; v=DMARC1")
	if !has(d.Problems, SevError, "start with v=DMARC1") {
		t.Fatalf("%+v", d.Problems)
	}
	if d.Tags.RUF == nil {
		t.Fatal("ruf must be [] not null")
	}
}

// rsaKeyB64 builds a PKIX-encoded RSA public key of exactly bits bits. Go
// refuses to generate keys under 1024 bits, so the modulus is synthesised;
// only its length matters here.
func rsaKeyB64(t *testing.T, bits int) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestDKIM(t *testing.T) {
	d := DecodeDKIM("v=DKIM1; k=rsa; p=" + rsaKeyB64(t, 2048))
	if d.Kind != "dkim" || d.KeyType != "rsa" || d.KeyBits != 2048 || d.Revoked || len(d.Problems) != 0 {
		t.Fatalf("%+v", d)
	}
	d = DecodeDKIM("v=DKIM1; k=rsa; t=y; p=" + rsaKeyB64(t, 1024))
	if d.KeyBits != 1024 || !has(d.Problems, SevWarning, "1024 bits") || !has(d.Problems, SevInfo, "t=y") {
		t.Fatalf("%+v", d)
	}
	d = DecodeDKIM("v=DKIM1; k=rsa; p=" + rsaKeyB64(t, 512))
	if !has(d.Problems, SevError, "512 bits") {
		t.Fatalf("%+v", d.Problems)
	}
	d = DecodeDKIM("v=DKIM1; p=")
	if !d.Revoked || !has(d.Problems, SevInfo, "revoked") {
		t.Fatalf("%+v", d)
	}
	d = DecodeDKIM("k=ed25519; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if d.KeyType != "ed25519" || d.KeyBits != 256 || len(d.Problems) != 0 {
		t.Fatalf("%+v", d)
	}
	d = DecodeDKIM("v=DKIM1; k=rsa; p=!!!")
	if !has(d.Problems, SevError, "base64") {
		t.Fatalf("%+v", d.Problems)
	}
	d = DecodeDKIM("v=DKIM1; k=rsa")
	if !has(d.Problems, SevError, "p tag is required") {
		t.Fatalf("%+v", d.Problems)
	}
	// Multi-string records are joined before parsing.
	if got := Decode("s1._domainkey.example.test.", []string{"v=DKIM1; k=rsa; p=" + rsaKeyB64(t, 2048)[:40], rsaKeyB64(t, 2048)[40:]}); got == nil {
		t.Fatal("split record not decoded")
	}
}

func TestDecodeDispatch(t *testing.T) {
	if _, ok := Decode("x.", []string{"v=spf1 -all"}).(*SPF); !ok {
		t.Fatal("spf")
	}
	if _, ok := Decode("_dmarc.x.", []string{"v=DMARC1; p=reject"}).(*DMARC); !ok {
		t.Fatal("dmarc")
	}
	if _, ok := Decode("s._domainkey.x.", []string{"k=rsa; p=AAAA"}).(*DKIM); !ok {
		t.Fatal("dkim by name")
	}
	if Decode("x.", []string{"google-site-verification=abc"}) != nil {
		t.Fatal("unknown TXT must decode to nil")
	}
}

func TestDecorateFlagsDuplicateSPF(t *testing.T) {
	m := &contract.Message{Answer: []contract.Record{
		{Name: "x.", Type: "TXT", Fields: map[string]any{"strings": []string{"v=spf1 -all"}}},
		{Name: "x.", Type: "TXT", Fields: map[string]any{"strings": []string{"v=spf1 ip4:192.0.2.1 -all"}}},
		{Name: "x.", Type: "TXT", Fields: map[string]any{"strings": []string{"other"}}},
		{Name: "x.", Type: "A", Fields: map[string]any{"address": "192.0.2.1"}},
	}}
	Decorate(m)
	for i := 0; i < 2; i++ {
		s, ok := m.Answer[i].Decoded.(*SPF)
		if !ok || !has(s.Problems, SevError, "multiple SPF") {
			t.Fatalf("answer %d: %+v", i, m.Answer[i].Decoded)
		}
	}
	if m.Answer[2].Decoded != nil || m.Answer[3].Decoded != nil {
		t.Fatal("non-SPF records must stay undecoded")
	}
}
