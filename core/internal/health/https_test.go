package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/certs"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// webServer runs a TLS listener with a self-signed certificate for names,
// issued in the name of org, and adds the certificate to roots.
func webServer(t *testing.T, roots *x509.CertPool, org string, notAfter time.Time, names ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0], Organization: []string{org}},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots.AddCert(leaf)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}})
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
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }(c)
		}
	}()
	return l.Addr().String()
}

func TestHTTPSHealthy(t *testing.T) {
	f := setup(t, nil)
	in := &certs.Inspector{Roots: x509.NewCertPool()}
	f.op.Certs = in
	addr := webServer(t, in.Roots, "Let's Encrypt", time.Now().Add(60*24*time.Hour), "good.test", "www.good.test")
	f.web["192.0.2.80"], f.web["192.0.2.81"] = addr, addr
	r := f.run(t, "good.test")
	h := r.HTTPS
	if h.Verdict.Status != OK || len(h.Hosts) != 2 || len(h.Hosts[1].Servers) != 2 {
		t.Fatalf("%+v\n%s", h.Verdict, dump(t, r))
	}
	if want := "good.test and www.good.test serve a valid certificate on every address, the soonest expiring in 59 days"; h.Verdict.Message != want {
		t.Fatalf("verdict %q", h.Verdict.Message)
	}
	if r.Overall.Status != OK {
		t.Fatalf("overall %+v", r.Overall)
	}
}

func TestHTTPSProblems(t *testing.T) {
	f := setup(t, nil)
	in := &certs.Inspector{Roots: x509.NewCertPool()}
	f.op.Certs = in
	// The apex serves a DigiCert certificate although CAA allows only Let's
	// Encrypt, and one www address serves a certificate for another name.
	f.web["192.0.2.80"] = webServer(t, in.Roots, "DigiCert Inc", time.Now().Add(5*24*time.Hour), "good.test", "www.good.test")
	f.web["192.0.2.81"] = webServer(t, in.Roots, "Let's Encrypt", time.Now().Add(60*24*time.Hour), "other.test")
	r := f.run(t, "good.test")
	h := r.HTTPS.Section
	for _, c := range []struct{ status, msg string }{
		{Fail, "www.good.test: 192.0.2.81 serves a certificate for other.test, which does not cover www.good.test"},
		{Warn, "good.test: 192.0.2.80 serves a certificate that expires in 4 days"},
		{Warn, "which the CAA record does not allow"},
		{Info, "www.good.test: the addresses serve 2 different certificates"},
	} {
		if !has(h, c.status, c.msg) {
			t.Errorf("missing %s %q\n%s", c.status, c.msg, dump(t, r))
		}
	}
	if h.Verdict.Status != Fail || r.Overall.Status != Fail {
		t.Fatalf("verdict %+v overall %+v", h.Verdict, r.Overall)
	}
}

func TestHTTPSNoWebsite(t *testing.T) {
	r := setup(t, nil).run(t, "good.test")
	if r.HTTPS.Verdict.Status != Info || !has(r.HTTPS.Section, Info, "good.test does not answer HTTPS") {
		t.Fatalf("%+v", r.HTTPS)
	}
	r = setup(t, nil).run(t, "bad.test")
	if r.HTTPS.Verdict.Status != Info || !has(r.HTTPS.Section, Info, "no website") {
		t.Fatalf("%+v", r.HTTPS)
	}
}

func TestHTTPSJudge(t *testing.T) {
	ok := certs.Probe{IP: "192.0.2.80", Connected: true, Trusted: true, NameMatch: true, ExpiresInDays: 30, Chain: []certs.Cert{{SHA256: "aa"}}}
	revoked := ok
	revoked.Trusted = false
	revoked.Revoked = []certs.Revocation{{Subject: "Example Intermediate", RevokedAt: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), Reason: "CA compromise"}}
	no := false
	sec := HTTPS{Hosts: []HTTPSHost{
		{Name: "example.com.", TLSA: []string{"3 1 1 00"}, TLSAStatus: dnssec.Secure, TLSAMatch: &no, Servers: []certs.Probe{ok}},
		{Name: "www.example.com.", TLSA: []string{"3 1 1 00"}, TLSAStatus: "insecure", Servers: []certs.Probe{revoked, {IP: "2001:db8::1", Skipped: true}}},
	}}
	judgeHTTPS(&sec, CAA{})
	for _, c := range []struct{ status, msg string }{
		{Fail, "example.com: the TLSA records match none of the certificates served"},
		{Warn, "www.example.com publishes TLSA records without DNSSEC"},
		{Fail, "www.example.com: 192.0.2.80 serves a chain through Example Intermediate, which its CA revoked on 18 Oct 2026 (CA compromise)"},
		{Info, "www.example.com: this Mac has no IPv6 route, so 1 IPv6 address could not be checked"},
	} {
		if !has(sec.Section, c.status, c.msg) {
			t.Errorf("missing %s %q in %+v", c.status, c.msg, sec.Findings)
		}
	}
	if sec.Verdict.Status != Fail {
		t.Fatalf("%+v", sec.Verdict)
	}
}

func TestWebAddrsFailedLookupIsNotNoWebsite(t *testing.T) {
	var aTries atomic.Int32
	srv := testdns.UDP(t, func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		qq := q.Question[0]
		switch {
		case qq.Name == "flaky.example." && qq.Qtype == dns.TypeA:
			aTries.Add(1)
			m.Rcode = dns.RcodeServerFailure
		case qq.Name == "flaky.example." && qq.Qtype == dns.TypeAAAA:
			m.Answer = []dns.RR{testdns.RR(t, "flaky.example. 300 IN AAAA 2001:db8::80")}
		case qq.Name == "none.example.":
			m.Rcode = dns.RcodeNameError
		}
		return m
	})
	r := &resolve.Resolver{Client: &transport.Client{}, Endpoint: contract.Endpoint{Transport: "udp", Address: srv}, Options: contract.Options{TimeoutMS: 300}.Resolve()}
	ips, failed := webAddrs(context.Background(), r, "flaky.example.")
	if len(ips) != 1 || len(failed) != 1 || failed[0] != "A" || aTries.Load() != 2 {
		t.Fatalf("ips %v failed %v after %d A tries", ips, failed, aTries.Load())
	}
	if ips, failed := webAddrs(context.Background(), r, "none.example."); len(ips) != 0 || len(failed) != 0 {
		t.Fatalf("NXDOMAIN is no address, not a failure: %v %v", ips, failed)
	}

	sec := HTTPS{Hosts: []HTTPSHost{
		{Name: "example.com.", LookupFailed: []string{"A", "AAAA"}, Servers: []certs.Probe{}},
		{Name: "www.example.com.", LookupFailed: []string{"A"}, Servers: []certs.Probe{
			{IP: "2001:db8::80", Connected: true, Trusted: true, NameMatch: true, ExpiresInDays: 30, Chain: []certs.Cert{{SHA256: "aa"}}}}},
	}}
	judgeHTTPS(&sec, CAA{})
	if !has(sec.Section, Warn, "example.com: the A and AAAA lookups failed through this resolver, so its website was not checked") ||
		!has(sec.Section, Warn, "www.example.com: the A lookup failed through this resolver, so its IPv4 addresses were not checked") ||
		sec.Verdict.Status != Warn {
		t.Fatalf("%+v", sec.Section)
	}
}
