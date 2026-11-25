package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/testdns"
)

// pki is a root, an intermediate and a leaf for example.test, with the
// intermediate's CRL published by the root.
type pki struct {
	root, inter, leaf *x509.Certificate
	rootKey, interKey crypto.Signer
	leafKey           crypto.Signer
	roots             *x509.CertPool
	crlURL            string
}

func key(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newPKI(t *testing.T, leafNames []string, leafNotAfter time.Time) *pki {
	t.Helper()
	p := &pki{rootKey: key(t), interKey: key(t), leafKey: key(t), crlURL: "http://crl.test/root.crl"}
	now := time.Now()
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root", Organization: []string{"Test CA"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	p.root = issue(t, rootT, rootT, p.rootKey.Public(), p.rootKey)
	interT := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Test Intermediate", Organization: []string{"Test CA"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, CRLDistributionPoints: []string{p.crlURL}}
	p.inter = issue(t, interT, p.root, p.interKey.Public(), p.rootKey)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: leafNames[0]}, DNSNames: leafNames,
		NotBefore: now.Add(-time.Hour), NotAfter: leafNotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	p.leaf = issue(t, leafT, p.inter, p.leafKey.Public(), p.interKey)
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.root)
	return p
}

// crl is the root's CRL, revoking the intermediate when revoke is set.
func (p *pki) crl(t *testing.T, revoke bool) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(24 * time.Hour)}
	if revoke {
		tmpl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: p.inter.SerialNumber, RevocationTime: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), ReasonCode: 2}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, p.root, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// serve runs a TLS server presenting leaf + intermediate.
func (p *pki) serve(t *testing.T) string {
	t.Helper()
	cert := tls.Certificate{Certificate: [][]byte{p.leaf.Raw, p.inter.Raw}, PrivateKey: p.leafKey, Leaf: p.leaf}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}(c)
		}
	}()
	return l.Addr().String()
}

func (p *pki) inspector(crl []byte) *Inspector {
	return &Inspector{Roots: p.roots, FetchCRL: func(_ context.Context, url string) ([]byte, error) {
		if url != p.crlURL || crl == nil {
			return nil, errors.New("not found")
		}
		return crl, nil
	}}
}

func run(t *testing.T, in *Inspector, addr, name string) Probe {
	t.Helper()
	st, err := in.Handshake(context.Background(), addr, name)
	if err != nil {
		t.Fatal(err)
	}
	return in.Inspect(context.Background(), st, name)
}

func TestValidChain(t *testing.T) {
	p := newPKI(t, []string{"example.test", "www.example.test"}, time.Now().Add(60*24*time.Hour))
	pr := run(t, p.inspector(p.crl(t, false)), p.serve(t), "www.example.test")
	if !pr.Trusted || !pr.NameMatch || len(pr.Chain) != 2 || pr.ExpiresInDays < 58 || !pr.RevocationChecked || len(pr.Revoked) != 0 {
		t.Fatalf("%+v", pr)
	}
	if pr.Chain[0].Issuer != "Test Intermediate (Test CA)" || pr.Chain[1].Subject != "Test Intermediate (Test CA)" {
		t.Fatalf("chain: %+v", pr.Chain)
	}
}

func TestNameMismatch(t *testing.T) {
	p := newPKI(t, []string{"other.test"}, time.Now().Add(60*24*time.Hour))
	pr := run(t, p.inspector(p.crl(t, false)), p.serve(t), "example.test")
	if pr.Trusted || pr.NameMatch || pr.TrustError == "" {
		t.Fatalf("%+v", pr)
	}
}

func TestExpired(t *testing.T) {
	p := newPKI(t, []string{"example.test"}, time.Now().Add(-24*time.Hour))
	pr := run(t, p.inspector(p.crl(t, false)), p.serve(t), "example.test")
	if pr.Trusted || pr.ExpiresInDays >= 0 {
		t.Fatalf("%+v", pr)
	}
}

func TestRevokedIntermediate(t *testing.T) {
	// The eMudhra case: a valid-looking chain whose intermediate the CA has
	// revoked for CA compromise, before any trust store has caught up.
	p := newPKI(t, []string{"example.test"}, time.Now().Add(60*24*time.Hour))
	pr := run(t, p.inspector(p.crl(t, true)), p.serve(t), "example.test")
	if pr.Trusted || len(pr.Revoked) != 1 || pr.Revoked[0].Reason != "CA compromise" || pr.Revoked[0].Subject != "Test Intermediate (Test CA)" {
		t.Fatalf("%+v", pr)
	}
	if !strings.Contains(pr.TrustError, "revoked") {
		t.Fatalf("trust error: %s", pr.TrustError)
	}
}

func TestCRLNotSignedByIssuerIsIgnored(t *testing.T) {
	// A CRL signed by someone else must not mark anything revoked.
	p := newPKI(t, []string{"example.test"}, time.Now().Add(60*24*time.Hour))
	other := newPKI(t, []string{"x.test"}, time.Now().Add(time.Hour))
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: p.inter.SerialNumber, RevocationTime: time.Now()}}}
	forged, err := x509.CreateRevocationList(rand.Reader, tmpl, other.root, other.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	pr := run(t, p.inspector(forged), p.serve(t), "example.test")
	if !pr.Trusted || len(pr.Revoked) != 0 || pr.RevocationChecked || !strings.Contains(pr.RevocationNote, "not signed by the issuing CA") {
		t.Fatalf("%+v", pr)
	}
}

func TestUnreachableCRLIsNotAFailure(t *testing.T) {
	p := newPKI(t, []string{"example.test"}, time.Now().Add(60*24*time.Hour))
	pr := run(t, p.inspector(nil), p.serve(t), "example.test")
	if !pr.Trusted || pr.RevocationChecked || pr.RevocationNote == "" {
		t.Fatalf("%+v", pr)
	}
}

func TestMatchTLSA(t *testing.T) {
	p := newPKI(t, []string{"example.test"}, time.Now().Add(60*24*time.Hour))
	chain := []*x509.Certificate{p.leaf, p.inter}
	spki := sha256.Sum256(p.leaf.RawSubjectPublicKeyInfo)
	good := &dns.TLSA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(spki[:])}
	if !MatchTLSA([]*dns.TLSA{good}, chain, false) {
		t.Fatal("DANE-EE SPKI SHA-256 should match the leaf")
	}
	ta := sha256.Sum256(p.inter.Raw)
	anchor := &dns.TLSA{Usage: 2, Selector: 0, MatchingType: 1, Certificate: hex.EncodeToString(ta[:])}
	if !MatchTLSA([]*dns.TLSA{anchor}, chain, false) {
		t.Fatal("DANE-TA should match the intermediate")
	}
	bad := &dns.TLSA{Usage: 3, Selector: 1, MatchingType: 1, Certificate: strings.Repeat("00", 32)}
	if MatchTLSA([]*dns.TLSA{bad}, chain, true) {
		t.Fatal("a wrong digest matched")
	}
	pkix := &dns.TLSA{Usage: 1, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(spki[:])}
	if MatchTLSA([]*dns.TLSA{pkix}, chain, false) {
		t.Fatal("PKIX-EE must not match an untrusted chain")
	}
}

func TestCAAIdentifiers(t *testing.T) {
	c := &x509.Certificate{Issuer: pkix.Name{CommonName: "R11", Organization: []string{"Let's Encrypt"}}}
	if ids := CAAIdentifiers(c); len(ids) != 1 || ids[0] != "letsencrypt.org" {
		t.Fatalf("%v", ids)
	}
	c = &x509.Certificate{Issuer: pkix.Name{CommonName: "emSign SSL CA - G3", Organization: []string{"eMudhra Inc"}}}
	if ids := CAAIdentifiers(c); len(ids) != 1 || ids[0] != "emudhra.com" {
		t.Fatalf("%v", ids)
	}
	if CAAIdentifiers(&x509.Certificate{Issuer: pkix.Name{CommonName: "Unknown CA"}}) != nil {
		t.Fatal("unknown issuer should give nil")
	}
}

func (p *pki) smtpServer(t *testing.T, starttls bool) string {
	t.Helper()
	return testdns.SMTP(t, tls.Certificate{Certificate: [][]byte{p.leaf.Raw, p.inter.Raw}, PrivateKey: p.leafKey, Leaf: p.leaf}, starttls)
}

func TestHandshakeSMTP(t *testing.T) {
	p := newPKI(t, []string{"mx.example.test"}, time.Now().Add(60*24*time.Hour))
	in := &Inspector{Timeout: time.Second}
	st, err := in.HandshakeSMTP(context.Background(), p.smtpServer(t, true), "mx.example.test")
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(p.leaf.RawSubjectPublicKeyInfo)
	if len(st.PeerCertificates) != 2 || !MatchTLSA([]*dns.TLSA{{Usage: 3, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(spki[:])}}, st.PeerCertificates, false) {
		t.Fatalf("chain %d", len(st.PeerCertificates))
	}
	if _, err := in.HandshakeSMTP(context.Background(), p.smtpServer(t, false), "mx.example.test"); !errors.Is(err, ErrNoSTARTTLS) {
		t.Fatalf("no starttls: %v", err)
	}
	var de *DialError
	if _, err := in.HandshakeSMTP(context.Background(), "127.0.0.1:1", "mx.example.test"); !errors.As(err, &de) {
		t.Fatalf("closed port: %v", err)
	}
}
