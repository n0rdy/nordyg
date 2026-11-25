package health

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/certs"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/trace"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Fixture: root (192.0.2.1) → test. (192.0.2.2) which delegates
//
//	good.test   ns1/ns2.good.test, glued, both healthy, serial 7
//	bad.test    ns1.bad.test (serial 2, open AXFR, lists an extra ns3.bad.test),
//	            ns2.bad.test (serial 1, open resolver, glue 192.0.2.22 but the
//	            zone says 192.0.2.99), lame.other.test (REFUSED)
//	noglue.test ns.noglue.test with no glue
//	dead.test   ns.dead.test, silent
//	signed.test like good.test but with a DS at the parent and unsigned servers

type authOpts struct {
	apex      string
	serial    uint32
	ns        []string
	addrs     map[string]string // in-zone name → address the zone publishes
	aaaa      map[string]string // in-zone name → IPv6 address
	axfr      bool
	recursion bool
	extra     []string // other in-zone records
}

func authServer(t *testing.T, o authOpts) testdns.Answer {
	t.Helper()
	soa := testdns.RR(t, o.apex+" 300 IN SOA ns1."+o.apex+" hostmaster."+o.apex+" "+strconv.Itoa(int(o.serial))+" 7200 3600 1209600 300")
	var extra []dns.RR
	for _, s := range o.extra {
		extra = append(extra, testdns.RR(t, s))
	}
	return func(q *dns.Msg) *dns.Msg {
		m := testdns.Reply(q)
		qq := q.Question[0]
		name := strings.ToLower(qq.Name)
		if qq.Qtype == dns.TypeAXFR {
			if o.axfr {
				m.Answer = []dns.RR{soa, testdns.RR(t, o.apex+" 300 IN NS "+o.ns[0]), soa}
			} else {
				m.Rcode = dns.RcodeRefused
			}
			return m
		}
		if name == "a.root-servers.net." {
			if o.recursion && q.RecursionDesired {
				m.RecursionAvailable = true
				m.Answer = []dns.RR{testdns.RR(t, "a.root-servers.net. 300 IN A 198.41.0.4")}
			} else {
				m.Rcode = dns.RcodeRefused
			}
			return m
		}
		if !dns.IsSubDomain(o.apex, name) {
			m.Rcode = dns.RcodeRefused
			return m
		}
		m.Authoritative = true
		switch {
		case name == o.apex && qq.Qtype == dns.TypeSOA:
			m.Answer = []dns.RR{soa}
		case name == o.apex && qq.Qtype == dns.TypeNS:
			for _, n := range o.ns {
				m.Answer = append(m.Answer, testdns.RR(t, o.apex+" 300 IN NS "+n))
			}
		case qq.Qtype == dns.TypeA && o.addrs[name] != "":
			m.Answer = []dns.RR{testdns.RR(t, name+" 300 IN A "+o.addrs[name])}
		case qq.Qtype == dns.TypeAAAA && o.aaaa[name] != "":
			m.Answer = []dns.RR{testdns.RR(t, name+" 300 IN AAAA "+o.aaaa[name])}
		default:
			for _, e := range extra {
				if strings.EqualFold(e.Header().Name, name) && e.Header().Rrtype == qq.Qtype {
					m.Answer = append(m.Answer, e)
				}
			}
			if len(m.Answer) == 0 {
				exists := name == o.apex || o.addrs[name] != ""
				for _, e := range extra {
					exists = exists || strings.EqualFold(e.Header().Name, name)
				}
				if !exists {
					m.Rcode = dns.RcodeNameError
				}
				m.Ns = []dns.RR{soa}
			}
		}
		return m
	}
}

type fixture struct {
	op       *Op
	root     string
	resolver string
	web      map[string]string // web server IP → local TLS listener
}

func setup(t *testing.T, validator trace.Validator) *fixture {
	t.Helper()
	ports := map[string]string{}
	root := testdns.UDPTCP(t, func(q *dns.Msg) *dns.Msg {
		m := testdns.Reply(q)
		m.Ns = []dns.RR{testdns.RR(t, "test. 300 IN NS ns.test.")}
		m.Extra = []dns.RR{testdns.RR(t, "ns.test. 300 IN A 192.0.2.2")}
		return m
	})
	delegate := func(m *dns.Msg, zone string, glue map[string]string, ns ...string) {
		for _, n := range ns {
			m.Ns = append(m.Ns, testdns.RR(t, zone+" 300 IN NS "+n))
			if ip := glue[n]; ip != "" {
				m.Extra = append(m.Extra, testdns.RR(t, n+" 300 IN A "+ip))
			}
		}
	}
	// cohost.test is served by the .test server itself, like nic.cz by .cz.
	cohost := authServer(t, authOpts{apex: "cohost.test.", serial: 5, ns: []string{"ns.test."}})
	tld := testdns.UDPTCP(t, func(q *dns.Msg) *dns.Msg {
		m := testdns.Reply(q)
		name := strings.ToLower(q.Question[0].Name)
		switch {
		case dns.IsSubDomain("good.test.", name):
			delegate(m, "good.test.", map[string]string{"ns1.good.test.": "192.0.2.11", "ns2.good.test.": "198.51.100.12"}, "ns1.good.test.", "ns2.good.test.")
			m.Extra = append(m.Extra, testdns.RR(t, "ns2.good.test. 300 IN AAAA 2001:db8::12"))
		case dns.IsSubDomain("bad.test.", name):
			delegate(m, "bad.test.", map[string]string{"ns1.bad.test.": "192.0.2.21", "ns2.bad.test.": "192.0.2.22"}, "lame.other.test.", "ns1.bad.test.", "ns2.bad.test.")
		case dns.IsSubDomain("noglue.test.", name):
			delegate(m, "noglue.test.", nil, "ns.noglue.test.")
		case dns.IsSubDomain("dead.test.", name):
			delegate(m, "dead.test.", map[string]string{"ns.dead.test.": "192.0.2.41"}, "ns.dead.test.")
		case name == "cohost.test." && q.Question[0].Qtype == dns.TypeDS:
			m.Authoritative = true
			m.Answer = []dns.RR{testdns.RR(t, "cohost.test. 300 IN DS 4242 13 2 ABCDEF0123")}
		case dns.IsSubDomain("cohost.test.", name):
			return cohost(q)
		case dns.IsSubDomain("signed.test.", name):
			delegate(m, "signed.test.", map[string]string{"ns1.signed.test.": "192.0.2.51", "ns2.signed.test.": "198.51.100.52"}, "ns1.signed.test.", "ns2.signed.test.")
			m.Ns = append(m.Ns, testdns.RR(t, "signed.test. 300 IN DS 12345 13 1 ABCDEF0123"))
		default:
			m.Authoritative = true
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{testdns.RR(t, "test. 300 IN SOA ns.test. n. 1 7200 3600 1209600 300")}
		}
		return m
	})
	good := authServer(t, authOpts{apex: "good.test.", serial: 7, ns: []string{"ns1.good.test.", "ns2.good.test."},
		addrs: map[string]string{"ns1.good.test.": "192.0.2.11", "ns2.good.test.": "198.51.100.12", "www.good.test.": "192.0.2.80"},
		aaaa:  map[string]string{"ns2.good.test.": "2001:db8::12"}})
	bad1 := authServer(t, authOpts{apex: "bad.test.", serial: 2, axfr: true, ns: []string{"lame.other.test.", "ns1.bad.test.", "ns2.bad.test.", "ns3.bad.test."},
		addrs: map[string]string{"ns1.bad.test.": "192.0.2.21", "ns2.bad.test.": "192.0.2.99"}})
	bad2 := authServer(t, authOpts{apex: "bad.test.", serial: 1, recursion: true, ns: []string{"lame.other.test.", "ns1.bad.test.", "ns2.bad.test."},
		addrs: map[string]string{"ns1.bad.test.": "192.0.2.21", "ns2.bad.test.": "192.0.2.99"}})
	refused := func(q *dns.Msg) *dns.Msg { m := testdns.Reply(q); m.Rcode = dns.RcodeRefused; return m }
	noglue := authServer(t, authOpts{apex: "noglue.test.", serial: 3, ns: []string{"ns.noglue.test."},
		addrs: map[string]string{"ns.noglue.test.": "192.0.2.31"}})
	signed := authServer(t, authOpts{apex: "signed.test.", serial: 9, ns: []string{"ns1.signed.test.", "ns2.signed.test."},
		addrs: map[string]string{"ns1.signed.test.": "192.0.2.51", "ns2.signed.test.": "198.51.100.52"}})

	ports["192.0.2.1"] = root
	ports["192.0.2.2"] = tld
	ports["192.0.2.11"] = testdns.UDPTCP(t, good)
	ports["198.51.100.12"] = testdns.UDPTCP(t, good)
	ports["2001:db8::12"] = testdns.UDPTCP(t, good)
	ports["192.0.2.21"] = testdns.UDPTCP(t, bad1)
	b2 := testdns.UDPTCP(t, bad2)
	ports["192.0.2.22"], ports["192.0.2.99"] = b2, b2
	ports["192.0.2.23"] = testdns.UDPTCP(t, refused)
	ports["192.0.2.31"] = testdns.UDPTCP(t, noglue)
	ports["192.0.2.51"] = testdns.UDPTCP(t, signed)
	ports["198.51.100.52"] = testdns.UDPTCP(t, signed)
	silent := testdns.UDP(t, testdns.Silent)
	addrFor := func(ip string) string {
		if a, ok := ports[ip]; ok {
			return a
		}
		return silent
	}
	resolver := testdns.UDP(t, testdns.Zone(t,
		"ns1.good.test. 300 IN A 192.0.2.11",
		"ns2.good.test. 300 IN A 198.51.100.12",
		"ns2.good.test. 300 IN AAAA 2001:db8::12",
		"good.test. 300 IN CAA 0 issue \"letsencrypt.org\"",
		"ns1.bad.test. 300 IN A 192.0.2.21",
		"ns2.bad.test. 300 IN A 192.0.2.99",
		"lame.other.test. 300 IN A 192.0.2.23",
		"ns3.bad.test. 300 IN A 192.0.2.24",
		"ns.noglue.test. 300 IN A 192.0.2.31",
		"ns.dead.test. 300 IN A 192.0.2.41",
		"ns1.signed.test. 300 IN A 192.0.2.51",
		"ns.test. 300 IN A 192.0.2.2",
		"ns2.signed.test. 300 IN A 198.51.100.52",
		"good.test. 300 IN A 192.0.2.80",
		"www.good.test. 300 IN A 192.0.2.80",
		"www.good.test. 300 IN A 192.0.2.81",
	))
	tc := &transport.Client{}
	f := &fixture{root: root, resolver: resolver, web: map[string]string{}}
	f.op = &Op{Client: tc, Trace: &trace.Op{Client: tc, AddrFor: addrFor, Validator: validator}, AddrFor: addrFor,
		// No web server unless a test starts one: port 1 refuses at once.
		HTTPSAddrFor: func(ip string) string {
			if a, ok := f.web[ip]; ok {
				return a
			}
			return "127.0.0.1:1"
		},
		Certs: &certs.Inspector{Roots: x509.NewCertPool()}}
	return f
}

func (f *fixture) run(t *testing.T, domain string) *Result {
	t.Helper()
	res, err := f.op.Run(context.Background(), Params{
		Domain:    domain,
		Endpoint:  contract.Endpoint{Transport: "udp", Address: f.resolver},
		Options:   contract.Options{TimeoutMS: 300},
		RootHints: []string{f.root},
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func has(sec Section, status, substr string) bool {
	for _, f := range sec.Findings {
		if f.Status == status && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func dump(t *testing.T, r *Result) string {
	t.Helper()
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}

func TestHealthyZone(t *testing.T) {
	f := setup(t, nil)
	r := f.run(t, "good.test")
	testdns.Sample(t, "health", r)
	if r.Zone != "good.test." || r.Delegation.Parent != "test." {
		t.Fatalf("zone %s parent %s", r.Zone, r.Delegation.Parent)
	}
	for name, v := range map[string]Finding{"delegation": r.Delegation.Verdict, "nameservers": r.Nameservers.Verdict, "soa": r.SOA.Verdict, "glue": r.Glue.Verdict, "caa": r.CAA.Verdict} {
		if v.Status != OK {
			t.Errorf("%s: %+v", name, v)
		}
	}
	if r.Overall.Status != OK {
		t.Fatalf("overall %+v\n%s", r.Overall, dump(t, r))
	}
	if len(r.Nameservers.Servers) != 3 {
		t.Fatalf("servers: %+v", r.Nameservers.Servers)
	}
	for _, s := range r.Nameservers.Servers {
		if !s.Authoritative || !s.TCP || !s.EDNS || s.AXFR != AXFRRefused || s.Recursion || !s.AtParent || !s.AtChild || s.Serial == nil || *s.Serial != 7 {
			t.Errorf("server %+v", s)
		}
	}
	if r.SOA.Record == nil || r.SOA.Record.Type != "SOA" || len(r.SOA.Serials) != 1 {
		t.Fatalf("soa: %+v", r.SOA)
	}
	if !strings.Contains(r.CAA.Verdict.Message, "letsencrypt.org") || r.CAA.FoundAt != "good.test." {
		t.Fatalf("caa: %+v", r.CAA)
	}
	if r.DNSSEC.Verdict.Status != Info || !has(r.DNSSEC.Section, Info, "not validated") {
		t.Fatalf("dnssec without validator: %+v", r.DNSSEC)
	}
	// JSON keeps embedded section fields inline and empty lists as [].
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"delegation":{"parent":"test.","parent_ns":`) || strings.Contains(string(b), "null") {
		t.Fatalf("json shape: %s", b)
	}
}

func TestBrokenZone(t *testing.T) {
	f := setup(t, nil)
	r := f.run(t, "bad.test.")
	testdns.Sample(t, "health-broken", r)
	checks := []struct {
		name   string
		sec    Section
		status string
		substr string
	}{
		{"extra ns", r.Delegation.Section, Warn, "not delegated by the parent"},
		{"ns sets", r.Delegation.Section, Warn, "disagree on the zone's NS set"},
		{"same /24", r.Delegation.Section, Warn, "one /24"},
		{"lame", r.Nameservers.Section, Fail, "lame.other.test (192.0.2.23) answers REFUSED"},
		{"axfr", r.Nameservers.Section, Warn, "ns1.bad.test (192.0.2.21) allows a zone transfer"},
		{"recursion", r.Nameservers.Section, Warn, "ns2.bad.test (192.0.2.22) resolves names for anyone"},
		{"child-only silent", r.Nameservers.Section, Fail, "ns3.bad.test (192.0.2.24) does not answer"},
		{"serials", r.SOA.Section, Warn, "2 on ns1.bad.test (192.0.2.21) and 1 on"},
		{"glue mismatch", r.Glue.Section, Fail, "ns2.bad.test (192.0.2.22) has no address in common with the zone's own records (192.0.2.99)"},
		{"no caa", r.CAA.Section, Info, "any certificate authority may issue"},
	}
	for _, c := range checks {
		if !has(c.sec, c.status, c.substr) {
			t.Errorf("%s: no %s finding containing %q in %+v", c.name, c.status, c.substr, c.sec.Findings)
		}
	}
	if r.Overall.Status != Fail {
		t.Fatalf("overall: %+v", r.Overall)
	}
	// Both of ns2's addresses (glue and the zone's own) are probed.
	ips := map[string]bool{}
	for _, s := range r.Nameservers.Servers {
		if s.Name == "ns2.bad.test." {
			ips[s.IP] = true
		}
		if s.Name == "ns3.bad.test." && (s.AtParent || !s.AtChild) {
			t.Errorf("ns3 flags: %+v", s)
		}
	}
	if !ips["192.0.2.22"] || !ips["192.0.2.99"] {
		t.Fatalf("ns2 addresses: %v", ips)
	}
}

func TestMissingGlue(t *testing.T) {
	f := setup(t, nil)
	r := f.run(t, "noglue.test")
	if !has(r.Glue.Section, Fail, "ns.noglue.test is inside the zone but the parent has no glue") {
		t.Fatalf("%+v", r.Glue)
	}
	if !has(r.Delegation.Section, Warn, "only 1 nameserver") {
		t.Fatalf("%+v", r.Delegation)
	}
}

func TestDeadDelegation(t *testing.T) {
	f := setup(t, nil)
	r := f.run(t, "dead.test")
	if r.Zone != "dead.test." || len(r.Delegation.ParentNS) != 1 {
		t.Fatalf("%s", dump(t, r))
	}
	if !has(r.Delegation.Section, Fail, "SOA failed after the delegation: every nameserver for dead.test. failed") || !has(r.Delegation.Section, Fail, "no nameserver answers") {
		t.Fatalf("delegation: %+v", r.Delegation.Findings)
	}
	if !has(r.Nameservers.Section, Fail, "ns.dead.test (192.0.2.41) does not answer") {
		t.Fatalf("servers: %+v", r.Nameservers.Findings)
	}
	if r.SOA.Verdict.Status != Fail {
		t.Fatalf("soa: %+v", r.SOA.Verdict)
	}
}

func TestNotApexAndNXDOMAIN(t *testing.T) {
	f := setup(t, nil)
	r := f.run(t, "www.good.test")
	if r.Zone != "good.test." || !has(r.Delegation.Section, Info, "not a zone apex") {
		t.Fatalf("%s", dump(t, r))
	}
	if r.Nameservers.Verdict.Status != OK {
		t.Fatalf("servers: %+v", r.Nameservers.Verdict)
	}
	r = f.run(t, "nope.good.test")
	if !has(r.Delegation.Section, Fail, "does not exist") || r.Overall.Status != Fail || r.Nameservers.Verdict.Status != Info {
		t.Fatalf("%s", dump(t, r))
	}
}

// stubValidator returns a fixed DNSSEC verdict.
type stubValidator struct{ r *dnssec.Result }

func (s stubValidator) Validate(context.Context, contract.Resolved, contract.Effective, map[string]string, *dns.Msg) (any, error) {
	return s.r, nil
}

func TestDNSSEC(t *testing.T) {
	soon := &dnssec.Result{Status: dnssec.Secure, Chain: []dnssec.Link{}, AnswerSignatures: []dnssec.Signature{
		{Signer: "signed.test.", Valid: true, ExpiresInMS: 5 * 3600 * 1000},
	}}
	f := setup(t, stubValidator{soon})
	r := f.run(t, "signed.test")
	if r.DNSSEC.Status != dnssec.Secure || len(r.DNSSEC.DS) != 1 {
		t.Fatalf("%+v", r.DNSSEC)
	}
	for _, want := range []struct{ status, substr string }{
		{Fail, "serves the zone without signatures"},
		{Warn, "expire in 5 h"},
		{Warn, "SHA-1 digest"},
	} {
		if !has(r.DNSSEC.Section, want.status, want.substr) {
			t.Errorf("no %s %q in %+v", want.status, want.substr, r.DNSSEC.Findings)
		}
	}
	bogus := &dnssec.Result{Status: dnssec.Bogus, Reason: "DS matches no DNSKEY", Chain: []dnssec.Link{}, AnswerSignatures: []dnssec.Signature{}}
	f = setup(t, stubValidator{bogus})
	if r := f.run(t, "good.test"); !has(r.DNSSEC.Section, Fail, "DS matches no DNSKEY") {
		t.Fatalf("%+v", r.DNSSEC)
	}
	unsigned := &dnssec.Result{Status: dnssec.Insecure, Chain: []dnssec.Link{}, AnswerSignatures: []dnssec.Signature{}}
	f = setup(t, stubValidator{unsigned})
	if r := f.run(t, "good.test"); r.DNSSEC.Verdict.Status != Info || !has(r.DNSSEC.Section, Info, "not signed") {
		t.Fatalf("%+v", r.DNSSEC)
	}
}

func TestBadRequests(t *testing.T) {
	f := setup(t, nil)
	for _, d := range []string{"", ".", "bad..name"} {
		_, err := f.op.Run(context.Background(), Params{Domain: d, Endpoint: contract.Endpoint{Transport: "udp", Address: f.resolver}})
		var be *bridge.Error
		if !errors.As(err, &be) || be.Code != bridge.CodeBadRequest {
			t.Errorf("%q: %v", d, err)
		}
	}
}

func TestNameserverWithoutAddress(t *testing.T) {
	op := &Op{}
	servers := op.probeAll(context.Background(), "x.test.",
		map[string][]string{"gone.x.test.": nil, "unknown.x.test.": nil},
		map[string]error{"unknown.x.test.": errors.New("SERVFAIL")}, contract.Options{}.Resolve())
	sec := checkServers(servers)
	// No address is the zone's problem. A lookup that failed is not.
	if !has(sec.Section, Fail, "gone.x.test has no A or AAAA records") {
		t.Errorf("no address: %+v", sec.Findings)
	}
	if !has(sec.Section, Warn, "unknown.x.test could not be checked, because its address lookup failed") || has(sec.Section, Fail, "unknown.x.test") {
		t.Errorf("failed lookup: %+v", sec.Findings)
	}
}

func TestCancel(t *testing.T) {
	f := setup(t, nil)
	// dead.test has a nameserver that never answers, so the run is still
	// probing when the cancel lands.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	_, err := f.op.Run(ctx, Params{Domain: "dead.test", Endpoint: contract.Endpoint{Transport: "udp", Address: f.resolver}, RootHints: []string{f.root}})
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Fatalf("want context.Canceled soon after the cancel, got %v after %s", err, time.Since(start))
	}
}

func TestSOATimers(t *testing.T) {
	soa := testdns.RR(t, "x. 300 IN SOA ns.x. h.x. 1 3600 7200 86400 172800").(*dns.SOA)
	serial := uint32(1)
	r := checkSOA([]Server{{Name: "ns.x.", IP: "192.0.2.1", Authoritative: true, Serial: &serial, soa: soa}}, "x.")
	for _, want := range []string{"retry (2 h) should be shorter than refresh (1 h)", "expire is 1 d", "cached for 2 d"} {
		if !has(r.Section, Warn, want) {
			t.Errorf("no %q in %+v", want, r.Findings)
		}
	}
}

func TestCohostedParent(t *testing.T) {
	f := setup(t, nil)
	r := f.run(t, "cohost.test")
	if r.Delegation.Parent != "test." || len(r.Delegation.ParentNS) != 1 || r.Delegation.ParentNS[0] != "ns.test." {
		t.Fatalf("%s", dump(t, r))
	}
	if !has(r.Delegation.Section, Info, "the servers of the .test zone also serve cohost.test") {
		t.Fatalf("delegation: %+v", r.Delegation.Findings)
	}
	if r.Nameservers.Verdict.Status != OK || len(r.DNSSEC.DS) != 1 {
		t.Fatalf("servers %+v ds %+v", r.Nameservers.Verdict, r.DNSSEC.DS)
	}
}

func TestSerialsByProvider(t *testing.T) {
	one, two := uint32(1), uint32(2)
	soa := testdns.RR(t, "x. 300 IN SOA ns.x. h.x. 1 7200 3600 1209600 300").(*dns.SOA)
	multi := checkSOA([]Server{
		{Name: "dns1.p08.nsone.net.", IP: "192.0.2.1", Authoritative: true, Serial: &one, soa: soa},
		{Name: "ns-1.awsdns-01.net.", IP: "192.0.2.2", Authoritative: true, Serial: &two, soa: soa},
	}, "x.")
	if !has(multi.Section, Info, "differs between DNS providers") || multi.Verdict.Status != Info {
		t.Fatalf("multi-provider: %+v", multi.Section)
	}
	lag := checkSOA([]Server{
		{Name: "ns1.example.com.", IP: "192.0.2.1", Authoritative: true, Serial: &one, soa: soa},
		{Name: "ns2.example.com.", IP: "192.0.2.2", Authoritative: true, Serial: &two, soa: soa},
	}, "x.")
	if !has(lag.Section, Warn, "different versions of the zone") {
		t.Fatalf("lagging secondary: %+v", lag.Section)
	}
}

func TestIPv6SkipsCollapse(t *testing.T) {
	serial := uint32(1)
	ok := Server{Name: "ns.x.", IP: "192.0.2.1", Answered: true, Authoritative: true, Rcode: "NOERROR", Serial: &serial, TCP: true, EDNS: true, AXFR: AXFRRefused}
	sec := checkServers([]Server{ok,
		{Name: "ns.x.", IP: "2001:db8::1", Skipped: true, Error: "this Mac has no IPv6 route, so the address was not checked"},
		{Name: "ns2.x.", IP: "2001:db8::2", Skipped: true, Error: "this Mac has no IPv6 route, so the address was not checked"},
	})
	if len(sec.Findings) != 1 || !strings.Contains(sec.Findings[0].Message, "2 IPv6 addresses could not be checked") {
		t.Fatalf("findings: %+v", sec.Findings)
	}
	if sec.Verdict.Status != Info || !strings.HasPrefix(sec.Verdict.Message, "the only address answers") {
		t.Fatalf("verdict: %+v", sec.Verdict)
	}
}

func TestShortLivedSignaturesDoNotWarn(t *testing.T) {
	now := time.Now()
	fresh := &dnssec.Result{Status: dnssec.Secure, Chain: []dnssec.Link{}, AnswerSignatures: []dnssec.Signature{
		// Cloudflare style: valid 25 h, 24 h left.
		{Signer: "good.test.", Valid: true, Inception: now.Add(-time.Hour), Expiration: now.Add(24 * time.Hour), ExpiresInMS: 24 * 3600 * 1000},
	}}
	f := setup(t, stubValidator{fresh})
	if r := f.run(t, "good.test"); r.DNSSEC.Verdict.Status != OK {
		t.Fatalf("%+v", r.DNSSEC.Section)
	}
	stale := &dnssec.Result{Status: dnssec.Secure, Chain: []dnssec.Link{}, AnswerSignatures: []dnssec.Signature{
		// Two-week signature with 30 h left.
		{Signer: "good.test.", Valid: true, Inception: now.Add(-13 * 24 * time.Hour), Expiration: now.Add(30 * time.Hour), ExpiresInMS: 30 * 3600 * 1000},
	}}
	f = setup(t, stubValidator{stale})
	if r := f.run(t, "good.test"); !has(r.DNSSEC.Section, Warn, "expire in 30 h, near the end") {
		t.Fatalf("%+v", r.DNSSEC.Section)
	}
}
