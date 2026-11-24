package trace

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// setup builds the fixture: root (192.0.2.1) delegates test. to ns.test
// (192.0.2.2), which delegates example.test to ns.example.test (192.0.2.3,
// glued), noglue.test to ns.example.test (no glue) and dead.test to
// ns.dead.test (192.0.2.9, silent).
func setup(t *testing.T) (*Op, string) {
	t.Helper()
	root := testdns.UDP(t, func(q *dns.Msg) *dns.Msg {
		m := testdns.Reply(q)
		name := strings.ToLower(q.Question[0].Name)
		switch {
		case name == ".":
			m.Authoritative = true
			m.Answer = []dns.RR{testdns.RR(t, ". 300 IN NS root-hint.")}
		case dns.IsSubDomain("test.", name):
			m.Ns = []dns.RR{testdns.RR(t, "test. 300 IN NS ns.test."), testdns.RR(t, "test. 300 IN DS 12345 13 2 ABCDEF")}
			m.Extra = append(m.Extra, testdns.RR(t, "ns.test. 300 IN A 192.0.2.2"), testdns.RR(t, "ns.test. 300 IN AAAA 2001:db8::2"))
		default:
			m.Authoritative = true
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{testdns.RR(t, ". 300 IN SOA a.root. n. 1 1 1 1 1")}
		}
		return m
	})
	tld := testdns.UDP(t, func(q *dns.Msg) *dns.Msg {
		m := testdns.Reply(q)
		name := strings.ToLower(q.Question[0].Name)
		switch {
		case dns.IsSubDomain("example.test.", name):
			m.Ns = []dns.RR{testdns.RR(t, "example.test. 300 IN NS ns.example.test.")}
			m.Extra = append(m.Extra, testdns.RR(t, "ns.example.test. 300 IN A 192.0.2.3"))
		case dns.IsSubDomain("noglue.test.", name):
			m.Ns = []dns.RR{testdns.RR(t, "noglue.test. 300 IN NS ns.example.test.")}
		case dns.IsSubDomain("dead.test.", name):
			m.Ns = []dns.RR{testdns.RR(t, "dead.test. 300 IN NS ns.dead.test.")}
			m.Extra = append(m.Extra, testdns.RR(t, "ns.dead.test. 300 IN A 192.0.2.9"))
		case dns.IsSubDomain("lame.test.", name):
			m.Rcode = dns.RcodeRefused
		default:
			m.Authoritative = true
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{testdns.RR(t, "test. 300 IN SOA ns.test. n. 1 1 1 1 1")}
		}
		return m
	})
	auth := testdns.UDP(t, func(q *dns.Msg) *dns.Msg {
		m := testdns.Reply(q)
		m.Authoritative = true
		name := strings.ToLower(q.Question[0].Name)
		qt := q.Question[0].Qtype
		switch {
		case name == "example.test." && qt == dns.TypeA:
			m.Answer = []dns.RR{testdns.RR(t, "example.test. 300 IN A 192.0.2.10")}
		case name == "ns.example.test." && qt == dns.TypeA:
			m.Answer = []dns.RR{testdns.RR(t, "ns.example.test. 300 IN A 192.0.2.3")}
		case name == "www.example.test.":
			m.Answer = []dns.RR{testdns.RR(t, "www.example.test. 300 IN CNAME example.test.")}
		case name == "noglue.test." && qt == dns.TypeA:
			m.Answer = []dns.RR{testdns.RR(t, "noglue.test. 300 IN A 192.0.2.11")}
		case name == "example.test." && qt == dns.TypeMX:
			m.Ns = []dns.RR{testdns.RR(t, "example.test. 300 IN SOA ns.example.test. n. 1 1 1 1 1")}
		default:
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{testdns.RR(t, "example.test. 300 IN SOA ns.example.test. n. 1 1 1 1 1")}
		}
		return m
	})
	silent := testdns.UDP(t, testdns.Silent)
	ports := map[string]string{"192.0.2.1": root, "192.0.2.2": tld, "192.0.2.3": auth, "192.0.2.9": silent}
	op := &Op{Client: &transport.Client{}, AddrFor: func(ip string) string {
		if a, ok := ports[ip]; ok {
			return a
		}
		return silent
	}}
	return op, root
}

func params(root, name, typ string) Params {
	return Params{Question: contract.Question{Name: name, Type: typ}, Options: contract.Options{TimeoutMS: 300}, RootHints: []string{root}}
}

func TestTraceFollowsReferrals(t *testing.T) {
	op, root := setup(t)
	res, err := op.Run(context.Background(), params(root, "example.test", "A"))
	if err != nil {
		t.Fatal(err)
	}
	testdns.Sample(t, "trace", res)
	if len(res.Hops) != 3 {
		t.Fatalf("hops: %d", len(res.Hops))
	}
	h := res.Hops
	if h[0].Zone != "." || h[0].Server.Name != "root-hint" || h[0].Referral == nil || h[0].Referral.Zone != "test." || h[0].Referral.Nameservers[0] != "ns.test." || len(h[0].Referral.DS) != 1 {
		t.Fatalf("hop 0: %+v", h[0])
	}
	if g := h[0].Referral.Glue["ns.test."]; len(g) != 2 || g[0] != "192.0.2.2" {
		t.Fatalf("glue: %v", h[0].Referral.Glue)
	}
	if h[1].Zone != "test." || h[1].Server.Name != "ns.test." || h[1].Referral == nil || h[1].Referral.Zone != "example.test." || len(h[1].Referral.DS) != 0 {
		t.Fatalf("hop 1: %+v", h[1])
	}
	if h[2].Zone != "example.test." || h[2].Server.Name != "ns.example.test." || h[2].Referral != nil || !h[2].Message.Flags.AA {
		t.Fatalf("hop 2: %+v", h[2])
	}
	if res.Final.Rcode != "NOERROR" || len(res.Final.Answer) != 1 || res.Final.Answer[0].Fields["address"] != "192.0.2.10" {
		t.Fatalf("final: %+v", res.Final)
	}
	if !res.Hops[0].Message.Flags.RD == false {
		t.Fatal("trace queries must not set RD")
	}
	if res.QuestionSent.Name != "example.test." {
		t.Fatalf("question_sent: %+v", res.QuestionSent)
	}
}

func TestTraceFollowsCNAMEByRestarting(t *testing.T) {
	op, root := setup(t)
	res, err := op.Run(context.Background(), params(root, "www.example.test", "A"))
	if err != nil {
		t.Fatal(err)
	}
	// root, tld, auth (CNAME), root, tld, auth (A)
	if len(res.Hops) != 6 || res.Hops[2].Message.Answer[0].Type != "CNAME" || res.Hops[3].Zone != "." || res.Final.Answer[0].Fields["address"] != "192.0.2.10" {
		t.Fatalf("hops=%d final=%+v", len(res.Hops), res.Final)
	}
}

func TestCNAMETarget(t *testing.T) {
	answer := func(records ...string) *dns.Msg {
		m := new(dns.Msg)
		for _, r := range records {
			m.Answer = append(m.Answer, testdns.RR(t, r))
		}
		return m
	}
	for name, tc := range map[string]struct {
		m    *dns.Msg
		want string
	}{
		"chain listed out of order": {answer("b.test. 60 IN CNAME c.test.", "A.test. 60 IN CNAME b.test."), "c.test."},
		"no CNAME for the name":     {answer("other.test. 60 IN CNAME c.test."), "a.test."},
		"points at itself":          {answer("a.test. 60 IN CNAME a.test."), "a.test."},
		"two names in a loop":       {answer("a.test. 60 IN CNAME b.test.", "b.test. 60 IN CNAME a.test."), "a.test."},
	} {
		if got := cnameTarget(tc.m, "a.test."); got != tc.want {
			t.Errorf("%s: got %s, want %s", name, got, tc.want)
		}
	}
}

func TestTraceResolvesUngluedNameserver(t *testing.T) {
	op, root := setup(t)
	res, err := op.Run(context.Background(), params(root, "noglue.test", "A"))
	if err != nil {
		t.Fatal(err)
	}
	// The nested lookup for ns.example.test is not part of the main chain.
	if len(res.Hops) != 3 || res.Hops[2].Server.Address == "" || res.Final.Answer[0].Fields["address"] != "192.0.2.11" {
		t.Fatalf("hops=%d final=%+v", len(res.Hops), res.Final)
	}
	if len(res.Hops[1].Referral.Glue) != 0 {
		t.Fatalf("glue should be empty: %+v", res.Hops[1].Referral)
	}
}

func TestTraceNegativeAnswers(t *testing.T) {
	op, root := setup(t)
	res, err := op.Run(context.Background(), params(root, "nope.example.test", "A"))
	if err != nil || res.Final.Rcode != "NXDOMAIN" || len(res.Hops) != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = op.Run(context.Background(), params(root, "example.test", "MX"))
	if err != nil || res.Final.Rcode != "NOERROR" || len(res.Final.Answer) != 0 || len(res.Final.Authority) != 1 {
		t.Fatalf("nodata: %+v %v", res, err)
	}
	res, err = op.Run(context.Background(), params(root, "other.", "A"))
	if err != nil || res.Final.Rcode != "NXDOMAIN" || len(res.Hops) != 1 {
		t.Fatalf("root nxdomain: %+v %v", res, err)
	}
}

func TestTraceDeadEndKeepsHops(t *testing.T) {
	op, root := setup(t)
	_, err := op.Run(context.Background(), params(root, "dead.test", "A"))
	var be *bridge.Error
	if !errors.As(err, &be) || be.Code != contract.CodeTraceDeadEnd {
		t.Fatalf("want trace_dead_end, got %v", err)
	}
	hops, _ := be.Details["hops"].([]Hop)
	if len(hops) != 2 || hops[1].Referral.Zone != "dead.test." {
		t.Fatalf("details: %+v", be.Details)
	}
	if !strings.Contains(be.Message, "dead.test.") {
		t.Fatal(be.Message)
	}

	_, err = op.Run(context.Background(), params(root, "lame.test", "A"))
	if !errors.As(err, &be) || be.Code != contract.CodeTraceDeadEnd || !strings.Contains(be.Message, "REFUSED") {
		t.Fatalf("lame: %v", err)
	}
}

func TestTraceValidation(t *testing.T) {
	op, _ := setup(t)
	_, err := op.Run(context.Background(), Params{Question: contract.Question{Name: "x", Type: "A"}, RootHints: []string{"192.0.2.1"}})
	if testdns.Code(err) != bridge.CodeBadRequest {
		t.Fatalf("root hint without port: %v", err)
	}
	_, err = op.Run(context.Background(), Params{Question: contract.Question{Name: "x", Type: "ZZ"}})
	if testdns.Code(err) != contract.CodeUnknownType {
		t.Fatal(err)
	}
}

func TestTraceCancel(t *testing.T) {
	op, root := setup(t)
	// The nameserver of dead.test never answers, so the trace is waiting on
	// it when the cancel lands.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	_, err := op.Run(ctx, params(root, "dead.test", "A"))
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Fatalf("want context.Canceled soon after the cancel, got %v after %s", err, time.Since(start))
	}
}

func TestTraceThroughEnvelope(t *testing.T) {
	op, root := setup(t)
	d := bridge.New()
	op.Register(d)
	var resp bridge.Response
	_ = json.Unmarshal(d.Dispatch([]byte(`{"id":"t","op":"trace","params":{"question":{"name":"example.test","type":"A"},"options":{"timeout_ms":300},"root_hints":["`+root+`"]}}`)), &resp)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var res Result
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Hops) != 3 || res.Hops[0].Referral.Glue["ns.test."] == nil {
		t.Fatalf("%s", resp.Result)
	}
	// The dead-end error carries hops as JSON too.
	_ = json.Unmarshal(d.Dispatch([]byte(`{"id":"t2","op":"trace","params":{"question":{"name":"dead.test","type":"A"},"options":{"timeout_ms":300},"root_hints":["`+root+`"]}}`)), &resp)
	if resp.OK || resp.Error.Code != contract.CodeTraceDeadEnd || resp.Error.Details["hops"] == nil {
		t.Fatalf("%+v", resp)
	}
}

func TestDefaultRootsAreValidEndpoints(t *testing.T) {
	if len(rootHints) != 13 {
		t.Fatal("expected 13 root servers")
	}
	for _, c := range rootHints {
		for _, ip := range c.IPs {
			if err := (contract.Endpoint{Transport: "udp", Address: contract.JoinHostPort(ip, 53)}).Validate(); err != nil {
				t.Errorf("%s %s: %v", c.Name, ip, err)
			}
		}
	}
}
