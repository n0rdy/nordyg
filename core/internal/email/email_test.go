package email

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// goodKey is a 2048-bit RSA public key in PKIX form; only its size matters.
var goodKey = func() string {
	n := new(big.Int).Lsh(big.NewInt(1), 2047)
	n.Add(n, big.NewInt(1))
	der, _ := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	return base64.StdEncoding.EncodeToString(der)
}()

// good is a well-configured domain; the resolver fixture also holds the
// reverse zone, an SPF include target and a DNSBL zone.
var good = []string{
	"good.test. 300 IN MX 10 mx1.good.test.",
	"good.test. 300 IN MX 20 mx2.good.test.",
	"mx1.good.test. 300 IN A 192.0.2.10",
	"mx2.good.test. 300 IN A 192.0.2.11",
	"10.2.0.192.in-addr.arpa. 300 IN PTR mx1.good.test.",
	"11.2.0.192.in-addr.arpa. 300 IN PTR mail.good.test.",
	"mail.good.test. 300 IN A 192.0.2.11",
	"good.test. 300 IN TXT \"v=spf1 mx include:_spf.provider.test -all\"",
	"_spf.provider.test. 300 IN TXT \"v=spf1 ip4:198.51.100.0/24 include:_spf2.provider.test ~all\"",
	"_spf2.provider.test. 300 IN TXT \"v=spf1 a mx -all\"",
	"selector1._domainkey.good.test. 300 IN TXT \"v=DKIM1; k=rsa; p=" + goodKey + "\"",
	// A provider-hosted key behind a CNAME, and a bare p= record like Resend publishes.
	"protonmail._domainkey.good.test. 300 IN CNAME protonmail.domainkey.abc.provider.test.",
	"protonmail.domainkey.abc.provider.test. 300 IN TXT \"v=DKIM1;k=rsa;p=" + goodKey + "\"",
	"resend._domainkey.good.test. 300 IN TXT \"p=" + goodKey + "\"",
	"_dmarc.good.test. 300 IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@good.test\"",
	"_mta-sts.good.test. 300 IN TXT \"v=STSv1; id=20260905\"",
	"mta-sts.good.test. 300 IN A 192.0.2.50",
	"default._bimi.good.test. 300 IN TXT \"v=BIMI1; l=https://good.test/logo.svg; a=https://good.test/vmc.pem\"",
	// bad.test: two SPF records, +all, p=none, no MX PTR, listed MX, revoked DKIM
	"bad.test. 300 IN MX 10 mx.bad.test.",
	"mx.bad.test. 300 IN A 192.0.2.66",
	"bad.test. 300 IN TXT \"v=spf1 +all\"",
	"bad.test. 300 IN TXT \"v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test include:i.test include:j.test include:k.test ~all\"",
	"_dmarc.bad.test. 300 IN TXT \"v=DMARC1; p=none\"",
	"default._domainkey.bad.test. 300 IN TXT \"v=DKIM1; k=rsa; p=\"",
	// DNSBL zone: 192.0.2.66 listed, others clean; 192.0.2.10 blocked-style answer on one list
	"66.2.0.192.bl.test. 300 IN A 127.0.0.2",
	"10.2.0.192.bl2.test. 300 IN A 127.255.255.254",
	// nomail.test: null MX
	"nomail.test. 300 IN MX 0 .",
	// implicit.test: no MX, has A
	"implicit.test. 300 IN A 192.0.2.80",
	"80.2.0.192.in-addr.arpa. 300 IN PTR implicit.test.",
}

func newOp(t *testing.T) (*Op, contract.Endpoint) {
	t.Helper()
	addr := testdns.UDP(t, testdns.Zone(t, good...))
	op := &Op{
		Client: &transport.Client{},
		Zones:  []string{"bl.test.", "bl2.test."},
		FetchPolicy: func(_ context.Context, host string, ips []string) (string, error) {
			if host != "mta-sts.good.test" || len(ips) != 1 || ips[0] != "192.0.2.50" {
				return "", errors.New("unexpected policy host " + host)
			}
			return "version: STSv1\nmode: enforce\nmx: mx1.good.test\nmx: *.good.test\nmax_age: 604800\n", nil
		},
	}
	return op, contract.Endpoint{Transport: "udp", Address: addr}
}

func TestGoodDomain(t *testing.T) {
	op, ep := newOp(t)
	res, err := op.Run(context.Background(), Params{Domain: "good.test", Endpoint: ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall.Status != OK {
		t.Fatalf("overall %+v\nmx %+v\nspf %+v\ndkim %+v\ndmarc %+v\nsts %+v\nbimi %+v\ndnsbl %+v", res.Overall, res.MX.Verdict, res.SPF.Verdict, res.DKIM.Verdict, res.DMARC.Verdict, res.MTASTS.Verdict, res.BIMI.Verdict, res.DNSBL.Verdict)
	}
	// MX with PTR round trips: mx1 direct match, mx2 via forward-confirmed name.
	if len(res.MX.Hosts) != 2 || res.MX.Hosts[0].Exchange != "mx1.good.test." || !res.MX.Hosts[0].PTR[0].Matches || !res.MX.Hosts[1].PTR[0].Matches || res.MX.Hosts[1].PTR[0].Names[0] != "mail.good.test." {
		t.Fatalf("mx: %+v", res.MX)
	}
	// SPF: own record has mx + include = 2 lookups; provider has include = 1; provider2 has a + mx = 2 → 5.
	if res.SPF.TotalLookups != 5 || len(res.SPF.Includes) != 2 || res.SPF.Includes[1].Depth != 2 || res.SPF.Includes[1].Via != "_spf.provider.test." {
		t.Fatalf("spf: total=%d includes=%+v", res.SPF.TotalLookups, res.SPF.Includes)
	}
	if !strings.Contains(res.SPF.Verdict.Message, "5 of 10") {
		t.Fatal(res.SPF.Verdict.Message)
	}
	var found []string
	for _, s := range res.DKIM.Selectors {
		if s.Found {
			found = append(found, s.Selector)
			if s.Decoded.KeyBits != 2048 {
				t.Fatalf("dkim: %+v", s)
			}
		}
	}
	if strings.Join(found, ",") != "selector1,protonmail,resend" || res.DKIM.Verdict.Status != OK || !strings.Contains(res.DKIM.Verdict.Message, "3 DKIM keys") {
		t.Fatalf("dkim: found=%v %+v", found, res.DKIM.Verdict)
	}
	if res.DMARC.Verdict.Status != OK || res.DMARC.Decoded == nil || *res.DMARC.Decoded.Tags.P != "reject" {
		t.Fatalf("dmarc: %+v", res.DMARC)
	}
	if res.MTASTS.Policy == nil || res.MTASTS.Policy.Mode != "enforce" || len(res.MTASTS.Policy.MX) != 2 || res.MTASTS.Policy.MaxAge != 604800 || res.MTASTS.ID != "20260905" {
		t.Fatalf("mta-sts: %+v", res.MTASTS)
	}
	if res.BIMI.Logo != "https://good.test/logo.svg" || res.BIMI.Evidence == "" || res.BIMI.Verdict.Status != OK {
		t.Fatalf("bimi: %+v", res.BIMI)
	}
	// DNSBL: two IPs × two zones; 192.0.2.10 on bl2 is a "blocked" answer.
	if len(res.DNSBL.Checks) != 4 || res.DNSBL.Verdict.Status != OK || !strings.Contains(res.DNSBL.Verdict.Message, "1 list refused") {
		t.Fatalf("dnsbl: %+v", res.DNSBL)
	}
}

func TestBadDomain(t *testing.T) {
	op, ep := newOp(t)
	res, err := op.Run(context.Background(), Params{Domain: "bad.test", Endpoint: ep, DKIMSelectors: []string{"default"}, ExtraSelectors: []string{"nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall.Status != Fail {
		t.Fatalf("overall: %+v", res.Overall)
	}
	if res.SPF.Verdict.Status != Fail || !strings.Contains(res.SPF.Verdict.Message, "2 SPF records") || len(res.SPF.Records) != 2 {
		t.Fatalf("spf: %+v", res.SPF.Verdict)
	}
	if res.DMARC.Verdict.Status != Warn || !strings.Contains(res.DMARC.Verdict.Message, "p=none") {
		t.Fatalf("dmarc: %+v", res.DMARC.Verdict)
	}
	if res.DKIM.Verdict.Status != Fail || !strings.Contains(res.DKIM.Verdict.Message, "revoked") || len(res.DKIM.Selectors) != 2 {
		t.Fatalf("dkim: %+v", res.DKIM)
	}
	if res.MX.Verdict.Status != Warn || !strings.Contains(res.MX.Verdict.Message, "reverse") {
		t.Fatalf("mx: %+v", res.MX.Verdict)
	}
	if res.DNSBL.Verdict.Status != Fail || !res.DNSBL.Checks[0].Listed || res.DNSBL.Checks[0].Response != "127.0.0.2" {
		t.Fatalf("dnsbl: %+v", res.DNSBL)
	}
	if res.MTASTS.Verdict.Status != Info || res.BIMI.Verdict.Status != Info {
		t.Fatalf("optional sections: %+v %+v", res.MTASTS.Verdict, res.BIMI.Verdict)
	}
}

func TestSPFLookupLimit(t *testing.T) {
	op, ep := newOp(t)
	addr := testdns.UDP(t, testdns.Zone(t,
		"many.test. 300 IN TXT \"v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test include:i.test include:j.test include:k.test ~all\"",
	))
	_ = ep
	res, err := op.Run(context.Background(), Params{Domain: "many.test", Endpoint: contract.Endpoint{Transport: "udp", Address: addr}, DKIMSelectors: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	// Includes fail to resolve (NXDOMAIN): reported as fail on the first unresolved include.
	if res.SPF.Verdict.Status != Fail || len(res.SPF.Includes) != 11 {
		t.Fatalf("spf: %+v (%d includes)", res.SPF.Verdict, len(res.SPF.Includes))
	}
	if res.SPF.TotalLookups != 11 {
		t.Fatalf("total lookups %d", res.SPF.TotalLookups)
	}
}

func TestNullAndImplicitMX(t *testing.T) {
	op, ep := newOp(t)
	res, err := op.Run(context.Background(), Params{Domain: "nomail.test", Endpoint: ep, DKIMSelectors: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.MX.NullMX || res.MX.Verdict.Status != Info || res.DNSBL.Verdict.Status != Info {
		t.Fatalf("null mx: %+v %+v", res.MX, res.DNSBL.Verdict)
	}
	res, err = op.Run(context.Background(), Params{Domain: "implicit.test", Endpoint: ep, DKIMSelectors: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.MX.Implicit || res.MX.Verdict.Status != Warn || len(res.MX.Hosts) != 1 || !res.MX.Hosts[0].PTR[0].Matches {
		t.Fatalf("implicit mx: %+v", res.MX)
	}
}

func TestValidationAndEnvelope(t *testing.T) {
	op, ep := newOp(t)
	_, err := op.Run(context.Background(), Params{Domain: "", Endpoint: ep})
	var be *bridge.Error
	if !errors.As(err, &be) || be.Code != bridge.CodeBadRequest {
		t.Fatalf("empty domain: %v", err)
	}
	_, err = op.Run(context.Background(), Params{Domain: "x", Endpoint: contract.Endpoint{Transport: "dot"}})
	if !errors.As(err, &be) || be.Code != contract.CodeBadEndpoint {
		t.Fatalf("bad endpoint: %v", err)
	}

	d := bridge.New()
	op.Register(d)
	var resp bridge.Response
	_ = json.Unmarshal(d.Dispatch([]byte(`{"id":"e","op":"email","params":{"domain":"good.test","endpoint":{"transport":"udp","address":"`+ep.Address+`"},"dkim_selectors":["selector1"]}}`)), &resp)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var res Result
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Overall.Status != OK || res.MTASTS.Policy.Mode != "enforce" {
		t.Fatalf("%s", resp.Result)
	}
}

func TestCancel(t *testing.T) {
	op, _ := newOp(t)
	addr := testdns.UDP(t, testdns.Silent)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := op.Run(ctx, Params{Domain: "good.test", Endpoint: contract.Endpoint{Transport: "udp", Address: addr}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancelled, got %v", err)
	}
}
