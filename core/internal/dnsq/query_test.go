package dnsq

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
)

// startServer runs an in-process authoritative server on a random port. It
// answers example.test with a fixed A record and refuses everything else.
// No test in this package touches the public internet.
func startServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func fixture(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	q := r.Question[0]
	if q.Name == "example.test." && q.Qtype == dns.TypeA {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		})
	} else {
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

func TestQueryReturnsAnswer(t *testing.T) {
	addr := startServer(t, fixture)
	res, err := Query(context.Background(), Params{Name: "example.test", Type: "a", Server: addr})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rcode != "NOERROR" || len(res.Answers) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	a := res.Answers[0]
	if a.Name != "example.test." || a.Type != "A" || a.TTL != 300 || a.Data != "192.0.2.1" {
		t.Fatalf("unexpected record: %+v", a)
	}
}

func TestQueryNXDOMAINIsNotAnError(t *testing.T) {
	addr := startServer(t, fixture)
	res, err := Query(context.Background(), Params{Name: "missing.test", Type: "A", Server: addr})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rcode != "NXDOMAIN" || len(res.Answers) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestQueryValidation(t *testing.T) {
	cases := []struct {
		name string
		p    Params
		code string
	}{
		{"no name", Params{Type: "A", Server: "127.0.0.1:53"}, bridge.CodeBadRequest},
		{"bad type", Params{Name: "x", Type: "NOPE", Server: "127.0.0.1:53"}, CodeUnknownType},
		{"no port", Params{Name: "x", Type: "A", Server: "127.0.0.1"}, CodeBadServer},
	}
	for _, c := range cases {
		_, err := Query(context.Background(), c.p)
		var e *bridge.Error
		if !errors.As(err, &e) || e.Code != c.code {
			t.Errorf("%s: want %s, got %v", c.name, c.code, err)
		}
	}
}

func TestQueryTimeout(t *testing.T) {
	// A server that never answers.
	addr := startServer(t, func(dns.ResponseWriter, *dns.Msg) {})
	_, err := Query(context.Background(), Params{Name: "example.test", Type: "A", Server: addr, TimeoutMS: 100})
	var e *bridge.Error
	if !errors.As(err, &e) || e.Code != CodeTimeout {
		t.Fatalf("want timeout, got %v", err)
	}
}

func TestQueryCancel(t *testing.T) {
	addr := startServer(t, func(dns.ResponseWriter, *dns.Msg) {})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := Query(ctx, Params{Name: "example.test", Type: "A", Server: addr})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestQueryThroughBridge(t *testing.T) {
	addr := startServer(t, fixture)
	d := bridge.New()
	Register(d)
	req, _ := json.Marshal(bridge.Request{ID: "q1", Op: "query", Params: mustJSON(Params{Name: "example.test", Type: "A", Server: addr})})
	var resp bridge.Response
	if err := json.Unmarshal(d.Dispatch(req), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.ID != "q1" {
		t.Fatalf("unexpected: %+v", resp)
	}
	var res Result
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Answers) != 1 || res.Answers[0].Data != "192.0.2.1" {
		t.Fatalf("unexpected: %+v", res)
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
