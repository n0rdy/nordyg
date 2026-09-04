package export

import (
	"errors"
	"strings"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
)

func ptr(b bool) *bool { return &b }

func run(t *testing.T, p Params) string {
	t.Helper()
	cmd, err := Command(p)
	if err != nil {
		t.Fatalf("%+v: %v", p, err)
	}
	return cmd
}

func TestDig(t *testing.T) {
	q := contract.Question{Name: "n0rdy.foo", Type: "a"}
	cases := []struct {
		name string
		p    Params
		want string
	}{
		{"udp defaults", Params{Question: q, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Format: "dig"}, "dig @1.1.1.1 n0rdy.foo A +dnssec"},
		{"udp custom port, no dnssec, norecurse", Params{Question: q, Endpoint: contract.Endpoint{Transport: "udp", Address: "127.0.0.1:5353"}, Options: contract.Options{DNSSECOK: ptr(false), RecursionDesired: ptr(false)}, Format: "dig"}, "dig @127.0.0.1 -p 5353 n0rdy.foo A +norecurse"},
		{"tcp", Params{Question: q, Endpoint: contract.Endpoint{Transport: "tcp", Address: "8.8.8.8:53"}, Format: "dig"}, "dig @8.8.8.8 n0rdy.foo A +tcp +dnssec"},
		{"dot", Params{Question: q, Endpoint: contract.Endpoint{Transport: "dot", Address: "9.9.9.9:853", TLSName: "dns.quad9.net"}, Format: "dig"}, "dig @9.9.9.9 n0rdy.foo A +tls +tls-hostname=dns.quad9.net +dnssec"},
		{"doh", Params{Question: q, Endpoint: contract.Endpoint{Transport: "doh", URL: "https://cloudflare-dns.com/dns-query"}, Format: "dig"}, "dig @cloudflare-dns.com n0rdy.foo A +https +dnssec"},
		{"doh custom path get", Params{Question: q, Endpoint: contract.Endpoint{Transport: "doh", URL: "https://dns.nextdns.io/abc123", Method: "get"}, Format: "dig"}, "dig @dns.nextdns.io n0rdy.foo A +https=/abc123 +https-get +dnssec"},
		{"no edns", Params{Question: q, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Options: contract.Options{EDNS: ptr(false)}, Format: "dig"}, "dig @1.1.1.1 n0rdy.foo A +noedns"},
		{"knobs", Params{Question: q, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Options: contract.Options{UDPSize: 4096, NSID: true, Cookie: true, CheckingDisabled: ptr(true), TimeoutMS: 2000}, Format: "dig"}, "dig @1.1.1.1 n0rdy.foo A +dnssec +bufsize=4096 +nsid +cookie +cdflag +timeout=2"},
		{"ptr from ip", Params{Question: contract.Question{Name: "1.1.1.1", Type: "PTR"}, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Format: "dig"}, "dig @1.1.1.1 1.1.1.1.in-addr.arpa PTR +dnssec"},
		{"chaos", Params{Question: contract.Question{Name: "version.bind", Type: "TXT", Class: "CH"}, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Format: "dig"}, "dig @1.1.1.1 version.bind TXT -c CH +dnssec"},
	}
	for _, c := range cases {
		if got := run(t, c.p); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	_, err := Command(Params{Question: q, Endpoint: contract.Endpoint{Transport: "doq", Address: "94.140.14.14:853", TLSName: "dns.adguard-dns.com"}, Format: "dig"})
	if code(err) != contract.CodeExportUnsupported {
		t.Fatalf("doq via dig: %v", err)
	}
}

func TestNslookup(t *testing.T) {
	q := contract.Question{Name: "n0rdy.foo", Type: "MX"}
	if got := run(t, Params{Question: q, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Format: "nslookup"}); got != "nslookup -type=MX n0rdy.foo 1.1.1.1" {
		t.Fatal(got)
	}
	if got := run(t, Params{Question: q, Endpoint: contract.Endpoint{Transport: "tcp", Address: "127.0.0.1:5353"}, Format: "nslookup"}); got != "nslookup -type=MX -port=5353 -vc n0rdy.foo 127.0.0.1" {
		t.Fatal(got)
	}
	_, err := Command(Params{Question: q, Endpoint: contract.Endpoint{Transport: "dot", Address: "9.9.9.9:853", TLSName: "dns.quad9.net"}, Format: "nslookup"})
	if code(err) != contract.CodeExportUnsupported {
		t.Fatal(err)
	}
}

func TestDoggo(t *testing.T) {
	q := contract.Question{Name: "n0rdy.foo", Type: "A"}
	cases := map[string]string{
		"udp": "doggo n0rdy.foo A @udp://1.1.1.1:53",
		"tcp": "doggo n0rdy.foo A @tcp://1.1.1.1:53",
		"dot": "doggo n0rdy.foo A @tls://9.9.9.9:853 --tls-hostname=dns.quad9.net",
		"doh": "doggo n0rdy.foo A @https://cloudflare-dns.com/dns-query",
		"doq": "doggo n0rdy.foo A @quic://94.140.14.14:853 --tls-hostname=dns.adguard-dns.com",
	}
	eps := map[string]contract.Endpoint{
		"udp": {Transport: "udp", Address: "1.1.1.1:53"},
		"tcp": {Transport: "tcp", Address: "1.1.1.1:53"},
		"dot": {Transport: "dot", Address: "9.9.9.9:853", TLSName: "dns.quad9.net"},
		"doh": {Transport: "doh", URL: "https://cloudflare-dns.com/dns-query"},
		"doq": {Transport: "doq", Address: "94.140.14.14:853", TLSName: "dns.adguard-dns.com"},
	}
	for k, want := range cases {
		if got := run(t, Params{Question: q, Endpoint: eps[k], Format: "doggo"}); got != want {
			t.Errorf("%s:\n got %s\nwant %s", k, got, want)
		}
	}
}

func TestCurl(t *testing.T) {
	q := contract.Question{Name: "n0rdy.foo", Type: "A"}
	got := run(t, Params{Question: q, Endpoint: contract.Endpoint{Transport: "doh", URL: "https://cloudflare-dns.com/dns-query", Address: "1.1.1.1:443"}, Format: "curl"})
	if !strings.HasPrefix(got, "curl -s -H 'accept: application/dns-message' --resolve cloudflare-dns.com:443:1.1.1.1 'https://cloudflare-dns.com/dns-query?dns=") || !strings.HasSuffix(got, " -o dns-response.bin") {
		t.Fatal(got)
	}
	// The dns parameter must be stable for the same question and options.
	if again := run(t, Params{Question: q, Endpoint: contract.Endpoint{Transport: "doh", URL: "https://cloudflare-dns.com/dns-query", Address: "1.1.1.1:443"}, Format: "curl"}); again != got {
		t.Fatal("curl export is not deterministic")
	}
	_, err := Command(Params{Question: q, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Format: "curl"})
	if code(err) != contract.CodeExportUnsupported {
		t.Fatal(err)
	}
}

func TestBadFormatAndQuoting(t *testing.T) {
	_, err := Command(Params{Question: contract.Question{Name: "x", Type: "A"}, Endpoint: contract.Endpoint{Transport: "udp", Address: "1.1.1.1:53"}, Format: "xlsx"})
	if code(err) != bridge.CodeBadRequest {
		t.Fatal(err)
	}
	if quote("it's") != `'it'\''s'` || quote("plain") != "plain" || quote("a b") != "'a b'" {
		t.Fatal("quoting")
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
