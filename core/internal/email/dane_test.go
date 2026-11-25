package email

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// stubValidator reports status for every name, or the override for qtype.
type stubValidator struct {
	status string
	byType map[uint16]string
}

func (s stubValidator) Validate(_ context.Context, _ dnssec.Fetcher, _ string, qtype uint16, _ *dns.Msg) (*dnssec.Result, error) {
	if st, ok := s.byType[qtype]; ok {
		return &dnssec.Result{Status: st}, nil
	}
	return &dnssec.Result{Status: s.status}, nil
}

type daneFixture struct {
	op   *Op
	ep   contract.Endpoint
	smtp map[string]string
}

// newDANE serves dane.test: mx1 publishes the right TLSA record, mx2 one
// that matches no certificate. Both servers present the same certificate.
func newDANE(t *testing.T, v Validator) *daneFixture {
	t.Helper()
	cert := testdns.NewCert(t, "mx1.dane.test", "mx2.dane.test")
	spki := sha256.Sum256(cert.TLS.Leaf.RawSubjectPublicKeyInfo)
	zone := testdns.Zone(t,
		"dane.test. 300 IN MX 10 mx1.dane.test.",
		"dane.test. 300 IN MX 20 mx2.dane.test.",
		"mx1.dane.test. 300 IN A 192.0.2.91",
		"mx2.dane.test. 300 IN A 192.0.2.92",
		"_25._tcp.mx1.dane.test. 300 IN TLSA 3 1 1 "+hex.EncodeToString(spki[:]),
		"_25._tcp.mx2.dane.test. 300 IN TLSA 3 1 1 "+strings.Repeat("ab", 32),
		"plain.test. 300 IN MX 10 mx.plain.test.",
		"mx.plain.test. 300 IN A 192.0.2.93",
		"_25._tcp.mx.plain.test. 300 IN TLSA 1 1 1 "+hex.EncodeToString(spki[:]),
		"flaky.test. 300 IN MX 10 mx1.dane.test.",
		"flaky.test. 300 IN MX 20 mx.flaky.test.",
		"mx.flaky.test. 300 IN A 192.0.2.94",
	)
	// The TLSA lookup for mx.flaky.test always fails.
	addr := testdns.UDP(t, func(q *dns.Msg) *dns.Msg {
		if q.Question[0].Name == "_25._tcp.mx.flaky.test." {
			m := new(dns.Msg)
			m.SetRcode(q, dns.RcodeServerFailure)
			return m
		}
		return zone(q)
	})
	server := testdns.SMTP(t, cert.TLS, true)
	f := &daneFixture{ep: contract.Endpoint{Transport: "udp", Address: addr},
		smtp: map[string]string{"192.0.2.91": server, "192.0.2.92": server, "192.0.2.93": server}}
	f.op = &Op{Client: &transport.Client{}, Zones: []string{}, Validator: v, SMTPTimeout: time.Second,
		SMTPAddrFor: func(ip string) string {
			if a, ok := f.smtp[ip]; ok {
				return a
			}
			return "127.0.0.1:1"
		}}
	return f
}

func (f *daneFixture) run(t *testing.T, domain string) *Result {
	t.Helper()
	res, err := f.op.Run(context.Background(), Params{Domain: domain, Endpoint: f.ep, DKIMSelectors: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasFinding(s DANESection, status, substr string) bool {
	for _, f := range s.Findings {
		if f.Status == status && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestDANEMismatch(t *testing.T) {
	res := newDANE(t, stubValidator{status: dnssec.Secure}).run(t, "dane.test")
	d := res.DANE
	if d.MXStatus != dnssec.Secure || len(d.Hosts) != 2 || !d.Hosts[0].Servers[0].Match || d.Hosts[1].Servers[0].Match {
		t.Fatalf("%+v", d)
	}
	if d.Verdict.Status != Fail || !strings.Contains(d.Verdict.Message, "mx2.dane.test (192.0.2.92) presents a certificate that matches none of its TLSA records") {
		t.Fatalf("%+v", d.Verdict)
	}
	// MTA-STS is not configured (info), so the transport card is DANE's fail.
	if res.Transport != d.Verdict || res.Overall.Status != Fail {
		t.Fatalf("overall %+v", res.Overall)
	}
}

func TestDANEUnreachable(t *testing.T) {
	f := newDANE(t, stubValidator{status: dnssec.Secure})
	f.smtp = map[string]string{}
	d := f.run(t, "dane.test").DANE
	if d.Verdict.Status != OK || !strings.Contains(d.Verdict.Message, "Port 25 could not be reached from this network") {
		t.Fatalf("%+v", d)
	}
}

func TestDANEInsecureMX(t *testing.T) {
	d := newDANE(t, stubValidator{status: dnssec.Secure, byType: map[uint16]string{dns.TypeMX: dnssec.Insecure}}).run(t, "dane.test").DANE
	if d.Verdict.Status != Warn || !strings.Contains(d.Verdict.Message, "MX records are not DNSSEC-signed") || len(d.Hosts[0].Servers) != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestDANEBogusAndUnusable(t *testing.T) {
	d := newDANE(t, stubValidator{status: dnssec.Secure, byType: map[uint16]string{dns.TypeTLSA: dnssec.Bogus}}).run(t, "dane.test").DANE
	if d.Verdict.Status != Fail || !hasFinding(d, Fail, "mx1.dane.test: the TLSA records fail DNSSEC validation") {
		t.Fatalf("%+v", d)
	}
	d = newDANE(t, stubValidator{status: dnssec.Secure}).run(t, "plain.test").DANE
	if d.Verdict.Status != Warn || !hasFinding(d, Warn, "only TLSA usages 0 or 1") {
		t.Fatalf("%+v", d)
	}
}

func TestDANENotConfigured(t *testing.T) {
	op, ep := newOp(t)
	res, err := op.Run(context.Background(), Params{Domain: "good.test", Endpoint: ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.DANE.Verdict.Status != Info || !strings.HasPrefix(res.DANE.Verdict.Message, "not configured") || res.DANE.MXStatus != "" {
		t.Fatalf("%+v", res.DANE)
	}
	res, _ = op.Run(context.Background(), Params{Domain: "nomail.test", Endpoint: ep})
	if res.DANE.Verdict.Status != Info || !strings.Contains(res.DANE.Verdict.Message, "accepts no mail") {
		t.Fatalf("%+v", res.DANE)
	}
	if !strings.HasPrefix(res.Transport.Message, "neither MTA-STS nor DANE") {
		t.Fatalf("transport %+v", res.Transport)
	}
}

func TestDANEFailedLookupIsNotMissing(t *testing.T) {
	d := newDANE(t, stubValidator{status: dnssec.Secure}).run(t, "flaky.test").DANE
	if d.Hosts[1].Error == "" || hasFinding(d, Warn, "only 1 of 2") || !hasFinding(d, Warn, "mx.flaky.test: the TLSA lookup failed") {
		t.Fatalf("%+v", d)
	}
}
