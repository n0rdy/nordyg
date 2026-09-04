package compare

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/query"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

func newOp() *Op { return &Op{Query: &query.Op{Client: &transport.Client{}}} }

func TestGroupsAgreeingAndDisagreeingResolvers(t *testing.T) {
	// Two resolvers agree (different TTL and order), one differs, one fails.
	a := testdns.UDP(t, testdns.Zone(t, "example.test. 300 IN A 192.0.2.1", "example.test. 300 IN A 192.0.2.2"))
	b := testdns.UDP(t, testdns.Zone(t, "example.test. 60 IN A 192.0.2.2", "example.test. 60 IN A 192.0.2.1"))
	c := testdns.UDP(t, testdns.Zone(t, "example.test. 300 IN A 192.0.2.9"))
	d := testdns.UDP(t, testdns.Silent)

	res, err := newOp().Run(context.Background(), Params{
		Question: contract.Question{Name: "example.test", Type: "A"},
		Endpoints: []contract.Endpoint{
			{Transport: "udp", Address: a, Label: "A"},
			{Transport: "udp", Address: b, Label: "B"},
			{Transport: "udp", Address: c, Label: "C"},
			{Transport: "udp", Address: d, Label: "D"},
		},
		Options: contract.Options{TimeoutMS: 300},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Consistent || len(res.Results) != 4 || len(res.Groups) != 3 {
		t.Fatalf("%+v", res)
	}
	g := res.Groups
	if g[0].Rcode != "NOERROR" || len(g[0].Members) != 2 || g[0].Members[0] != 0 || g[0].Members[1] != 1 || len(g[0].Answers) != 2 || g[0].Answers[0] != "192.0.2.1" {
		t.Fatalf("group 0: %+v", g[0])
	}
	if len(g[1].Members) != 1 || g[1].Members[0] != 2 || g[1].Answers[0] != "192.0.2.9" {
		t.Fatalf("group 1: %+v", g[1])
	}
	if g[2].Key != ErrorKey || g[2].Members[0] != 3 || res.Results[3].OK || res.Results[3].Error.Code != contract.CodeTimeout {
		t.Fatalf("group 2: %+v %+v", g[2], res.Results[3])
	}
	if res.Results[0].Endpoint.Label != "A" || res.Results[0].Message == nil || res.Results[0].Exchange == nil {
		t.Fatalf("entry: %+v", res.Results[0])
	}
}

func TestConsistentWhenAllAgree(t *testing.T) {
	z := testdns.Zone(t, "example.test. 300 IN A 192.0.2.1")
	a, b := testdns.UDP(t, z), testdns.TCP(t, z)
	res, err := newOp().Run(context.Background(), Params{
		Question:  contract.Question{Name: "example.test", Type: "A"},
		Endpoints: []contract.Endpoint{{Transport: "udp", Address: a}, {Transport: "tcp", Address: b}},
	})
	if err != nil || !res.Consistent || len(res.Groups) != 1 || len(res.Groups[0].Members) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestNXDOMAINGroupsSeparatelyFromAnswers(t *testing.T) {
	a := testdns.UDP(t, testdns.Zone(t, "example.test. 300 IN A 192.0.2.1"))
	b := testdns.UDP(t, testdns.Zone(t))
	res, err := newOp().Run(context.Background(), Params{
		Question:  contract.Question{Name: "example.test", Type: "A"},
		Endpoints: []contract.Endpoint{{Transport: "udp", Address: a}, {Transport: "udp", Address: b}},
	})
	if err != nil || res.Consistent || len(res.Groups) != 2 || res.Groups[1].Rcode != "NXDOMAIN" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestValidation(t *testing.T) {
	op := newOp()
	_, err := op.Run(context.Background(), Params{Question: contract.Question{Name: "x", Type: "A"}})
	if code(err) != bridge.CodeBadRequest {
		t.Fatalf("empty endpoints: %v", err)
	}
	_, err = op.Run(context.Background(), Params{Question: contract.Question{Name: "x", Type: "A"}, Endpoints: []contract.Endpoint{{Transport: "udp", Address: "1.1.1.1:53"}, {Transport: "dot"}}})
	var be *bridge.Error
	if !errors.As(err, &be) || be.Code != contract.CodeBadEndpoint || be.Message[:13] != "endpoints[1]:" {
		t.Fatalf("bad endpoint: %v", err)
	}
}

func TestCancelPropagates(t *testing.T) {
	d := testdns.UDP(t, testdns.Silent)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newOp().Run(ctx, Params{Question: contract.Question{Name: "x", Type: "A"}, Endpoints: []contract.Endpoint{{Transport: "udp", Address: d}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancelled, got %v", err)
	}
}

func TestKeyIgnoresTTLAndOrder(t *testing.T) {
	mk := func(rrs ...string) *contract.Message {
		m := &contract.Message{Rcode: "NOERROR"}
		for _, s := range rrs {
			rr, _ := dns.NewRR(s)
			m.Answer = append(m.Answer, contract.Record{Type: dns.TypeToString[rr.Header().Rrtype], Rdata: rr.String()[len(rr.Header().String()):]})
		}
		return m
	}
	k1, _ := Key(mk("x. 1 IN A 192.0.2.1", "x. 1 IN A 192.0.2.2"))
	k2, _ := Key(mk("x. 999 IN A 192.0.2.2", "x. 999 IN A 192.0.2.1"))
	k3, _ := Key(mk("x. 1 IN A 192.0.2.1"))
	if k1 != k2 || k1 == k3 {
		t.Fatalf("%s %s %s", k1, k2, k3)
	}
}

func TestThroughEnvelope(t *testing.T) {
	a := testdns.UDP(t, testdns.Zone(t, "example.test. 300 IN A 192.0.2.1"))
	d := bridge.New()
	newOp().Register(d)
	var resp bridge.Response
	_ = json.Unmarshal(d.Dispatch([]byte(`{"id":"c","op":"compare","params":{"question":{"name":"example.test","type":"A"},"endpoints":[{"transport":"udp","address":"`+a+`"}]}}`)), &resp)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var res Result
	_ = json.Unmarshal(resp.Result, &res)
	if !res.Consistent || res.Groups[0].Answers[0] != "192.0.2.1" {
		t.Fatalf("%s", resp.Result)
	}
}

func code(err error) string {
	var e *bridge.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}
