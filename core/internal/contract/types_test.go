package contract

import (
	"errors"
	"testing"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
)

func code(err error) string {
	var e *bridge.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "<" + err.Error() + ">"
}

func TestEndpointValidate(t *testing.T) {
	cases := []struct {
		name string
		ep   Endpoint
		want string
	}{
		{"udp ok", Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, ""},
		{"tcp v6 ok", Endpoint{Transport: "tcp", Address: "[2606:4700::1111]:53"}, ""},
		{"udp no address", Endpoint{Transport: "udp"}, CodeBadEndpoint},
		{"udp hostname", Endpoint{Transport: "udp", Address: "dns.google:53"}, CodeBadEndpoint},
		{"udp no port", Endpoint{Transport: "udp", Address: "1.1.1.1"}, CodeBadEndpoint},
		{"dot ok", Endpoint{Transport: "dot", Address: "9.9.9.9:853", TLSName: "dns.quad9.net"}, ""},
		{"dot no tls name", Endpoint{Transport: "dot", Address: "9.9.9.9:853"}, CodeBadEndpoint},
		{"doq no tls name", Endpoint{Transport: "doq", Address: "9.9.9.9:853"}, CodeBadEndpoint},
		{"doh ok", Endpoint{Transport: "doh", URL: "https://cloudflare-dns.com/dns-query"}, ""},
		{"doh pinned ok", Endpoint{Transport: "doh", URL: "https://cloudflare-dns.com/dns-query", Address: "1.1.1.1:443", Method: "get"}, ""},
		{"doh http", Endpoint{Transport: "doh", URL: "http://x/dns-query"}, CodeBadEndpoint},
		{"doh no url", Endpoint{Transport: "doh"}, CodeBadEndpoint},
		{"doh bad method", Endpoint{Transport: "doh", URL: "https://x/q", Method: "put"}, CodeBadEndpoint},
		{"no transport", Endpoint{Address: "1.1.1.1:53"}, CodeBadEndpoint},
		{"bad transport", Endpoint{Transport: "smtp", Address: "1.1.1.1:53"}, CodeBadEndpoint},
	}
	for _, c := range cases {
		if got := code(c.ep.Validate()); got != c.want {
			t.Errorf("%s: want %q, got %q", c.name, c.want, got)
		}
	}
}

func TestParseType(t *testing.T) {
	cases := map[string]uint16{"a": 1, "MX": 15, "https": 65, "TYPE65534": 65534, " caa ": 257}
	for in, want := range cases {
		got, err := ParseType(in)
		if err != nil || got != want {
			t.Errorf("%q: got %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "NOPE", "TYPE", "TYPE70000", "TYPEx"} {
		if _, err := ParseType(bad); code(err) != CodeUnknownType {
			t.Errorf("%q: want unknown_type, got %v", bad, err)
		}
	}
	if TypeToString(65534) != "TYPE65534" || TypeToString(1) != "A" {
		t.Error("TypeToString")
	}
}

func TestQuestionResolve(t *testing.T) {
	r, err := Question{Name: "n0rdy.foo", Type: "a"}.Resolve()
	if err != nil || r.Name != "n0rdy.foo." || r.Type != dns.TypeA || r.Class != dns.ClassINET {
		t.Fatalf("got %+v, %v", r, err)
	}
	if q := r.Question(); q.Name != "n0rdy.foo." || q.Type != "A" || q.Class != "IN" {
		t.Fatalf("question_sent: %+v", q)
	}

	r, err = Question{Name: "1.1.1.1", Type: "PTR"}.Resolve()
	if err != nil || r.Name != "1.1.1.1.in-addr.arpa." {
		t.Fatalf("ptr v4: %+v, %v", r, err)
	}
	r, err = Question{Name: "2606:4700:4700::1111", Type: "ptr"}.Resolve()
	if err != nil || r.Name != "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa." {
		t.Fatalf("ptr v6: %+v, %v", r, err)
	}
	// An IP with a non-PTR type is sent as a name, not reversed.
	r, err = Question{Name: "1.1.1.1", Type: "A"}.Resolve()
	if err != nil || r.Name != "1.1.1.1." {
		t.Fatalf("ip as name: %+v, %v", r, err)
	}
	r, err = Question{Name: "example.com.", Type: "TXT", Class: "ch"}.Resolve()
	if err != nil || r.Class != dns.ClassCHAOS {
		t.Fatalf("class: %+v, %v", r, err)
	}

	for name, q := range map[string]Question{
		"no name":   {Type: "A"},
		"no type":   {Name: "x"},
		"bad type":  {Name: "x", Type: "ZZZ"},
		"bad class": {Name: "x", Type: "A", Class: "XX"},
		"bad name":  {Name: "a..b", Type: "A"},
	} {
		if _, err := q.Resolve(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestOptionsDefaults(t *testing.T) {
	e := Options{}.Resolve()
	if !e.RecursionDesired || !e.DNSSECOK || e.CheckingDisabled || !e.EDNS || e.UDPSize != 1232 || !e.TCPFallback || e.Timeout != DefaultTimeout {
		t.Fatalf("defaults: %+v", e)
	}
	f := false
	e = Options{EDNS: &f, DNSSECOK: nil, NSID: true, TimeoutMS: 250, UDPSize: 512}.Resolve()
	if e.EDNS || e.DNSSECOK || e.NSID || e.Timeout.Milliseconds() != 250 || e.UDPSize != 512 {
		t.Fatalf("edns off must clear DO/NSID: %+v", e)
	}

	m := Options{NSID: true, Cookie: true}.Resolve().Build(Resolved{Name: "x.", Type: dns.TypeA, Class: dns.ClassINET})
	opt := m.IsEdns0()
	if opt == nil || !opt.Do() || opt.UDPSize() != 1232 || len(opt.Option) != 2 || !m.RecursionDesired {
		t.Fatalf("built query: %v", m)
	}
	if (Options{EDNS: &f}).Resolve().Build(Resolved{Name: "x.", Type: 1, Class: 1}).IsEdns0() != nil {
		t.Fatal("edns=false must not add OPT")
	}
}
