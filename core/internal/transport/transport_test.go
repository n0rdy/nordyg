package transport

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/testdns"
)

var zone = []string{
	"example.test. 300 IN A 192.0.2.1",
	"example.test. 300 IN AAAA 2001:db8::1",
	"doh.test. 300 IN A 127.0.0.1",
}

func query(name string, t uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), t)
	m.SetEdns0(1232, true)
	return m
}

func opts(ms int) contract.Effective {
	return contract.Options{TimeoutMS: ms}.Resolve()
}

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

func port(t *testing.T, addr string) string {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertAnswer(t *testing.T, res *Result, proto string) {
	t.Helper()
	if res.Msg.Rcode != dns.RcodeSuccess || len(res.Msg.Answer) != 1 {
		t.Fatalf("unexpected message: %v", res.Msg)
	}
	if a, ok := res.Msg.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.1" {
		t.Fatalf("unexpected answer: %v", res.Msg.Answer[0])
	}
	if res.Exchange.Protocol != proto || res.Size == 0 || res.Exchange.RTTms <= 0 || res.Exchange.StartedAt.IsZero() {
		t.Fatalf("exchange: %+v", res.Exchange)
	}
}

func TestUDPAndTCP(t *testing.T) {
	z := testdns.Zone(t, zone...)
	c := &Client{}
	udp := testdns.UDP(t, z)
	res, err := c.Exchange(context.Background(), contract.Endpoint{Transport: "udp", Address: udp}, query("example.test", dns.TypeA), opts(2000), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, res, "udp")
	if res.Exchange.TruncatedRetry || res.Exchange.TLS != nil || res.Exchange.Endpoint.Address != udp {
		t.Fatalf("exchange: %+v", res.Exchange)
	}

	tcp := testdns.TCP(t, z)
	res, err = c.Exchange(context.Background(), contract.Endpoint{Transport: "tcp", Address: tcp}, query("example.test", dns.TypeA), opts(2000), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, res, "tcp")
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	z := testdns.Zone(t, zone...)
	truncating := func(q *dns.Msg) *dns.Msg {
		m := z(q)
		m.Truncated = true
		m.Answer = nil
		return m
	}
	// Same port for UDP and TCP so the fallback hits the honest TCP server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	us := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { _ = w.WriteMsg(truncating(r)) })}
	ts := &dns.Server{Listener: l, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { _ = w.WriteMsg(z(r)) })}
	go func() { _ = us.ActivateAndServe() }()
	go func() { _ = ts.ActivateAndServe() }()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })

	c := &Client{}
	res, err := c.Exchange(context.Background(), contract.Endpoint{Transport: "udp", Address: addr}, query("example.test", dns.TypeA), opts(2000), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, res, "tcp")
	if !res.Exchange.TruncatedRetry {
		t.Fatal("expected truncated_retry")
	}

	f := false
	o := contract.Options{TimeoutMS: 2000, TCPFallback: &f}.Resolve()
	res, err = c.Exchange(context.Background(), contract.Endpoint{Transport: "udp", Address: addr}, query("example.test", dns.TypeA), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Msg.Truncated || res.Exchange.Protocol != "udp" {
		t.Fatalf("fallback disabled: %+v", res.Exchange)
	}
}

func TestDoT(t *testing.T) {
	cert := testdns.NewCert(t, "dns.test")
	addr := testdns.DoT(t, cert, testdns.Zone(t, zone...))
	c := &Client{RootCAs: cert.Pool}
	res, err := c.Exchange(context.Background(), contract.Endpoint{Transport: "dot", Address: addr, TLSName: "dns.test"}, query("example.test", dns.TypeA), opts(3000), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, res, "dot")
	tl := res.Exchange.TLS
	if tl == nil || tl.Version != "TLS 1.3" || tl.ServerName != "dns.test" || tl.ALPN != "dot" || tl.Certificate == nil || tl.Certificate.DNSNames[0] != "dns.test" || len(tl.Certificate.SHA256) != 64 {
		t.Fatalf("tls: %+v", tl)
	}

	// Wrong name must be a tls error, not network.
	_, err = c.Exchange(context.Background(), contract.Endpoint{Transport: "dot", Address: addr, TLSName: "wrong.test"}, query("example.test", dns.TypeA), opts(3000), nil)
	if code(err) != contract.CodeTLS {
		t.Fatalf("want tls error, got %v", err)
	}
	// Untrusted CA too.
	_, err = (&Client{}).Exchange(context.Background(), contract.Endpoint{Transport: "dot", Address: addr, TLSName: "dns.test"}, query("example.test", dns.TypeA), opts(3000), nil)
	if code(err) != contract.CodeTLS {
		t.Fatalf("want tls error, got %v", err)
	}
}

func TestDoHPostAndGet(t *testing.T) {
	cert := testdns.NewCert(t, "doh.test")
	addr := testdns.DoH(t, cert, testdns.Zone(t, zone...))
	c := &Client{RootCAs: cert.Pool}
	url := "https://doh.test:" + port(t, addr) + "/dns-query"

	for _, method := range []string{"", "get"} {
		res, err := c.Exchange(context.Background(), contract.Endpoint{Transport: "doh", URL: url, Address: addr, Method: method}, query("example.test", dns.TypeA), opts(3000), nil)
		if err != nil {
			t.Fatalf("%q: %v", method, err)
		}
		assertAnswer(t, res, "doh")
		if res.Exchange.HTTP == nil || res.Exchange.HTTP.Status != 200 || res.Exchange.HTTP.Version != "HTTP/2.0" || !strings.HasPrefix(res.Exchange.HTTP.ContentType, "application/dns-message") {
			t.Fatalf("%q http: %+v", method, res.Exchange.HTTP)
		}
		if res.Exchange.TLS == nil || res.Exchange.TLS.ALPN != "h2" || res.Exchange.TLS.ServerName != "doh.test" {
			t.Fatalf("%q tls: %+v", method, res.Exchange.TLS)
		}
	}
}

func TestDoHBootstrap(t *testing.T) {
	cert := testdns.NewCert(t, "doh.test")
	z := testdns.Zone(t, zone...)
	addr := testdns.DoH(t, cert, z)
	boot := testdns.UDP(t, z)
	c := &Client{RootCAs: cert.Pool}
	url := "https://doh.test:" + port(t, addr) + "/dns-query"
	ep := contract.Endpoint{Transport: "doh", URL: url}

	_, err := c.Exchange(context.Background(), ep, query("example.test", dns.TypeA), opts(3000), nil)
	if code(err) != contract.CodeBootstrapRequired {
		t.Fatalf("want bootstrap_required, got %v", err)
	}

	res, err := c.Exchange(context.Background(), ep, query("example.test", dns.TypeA), opts(3000), []contract.Endpoint{{Transport: "udp", Address: boot}})
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, res, "doh")

	// Bootstrap that cannot resolve the host.
	empty := testdns.UDP(t, testdns.Zone(t))
	_, err = c.Exchange(context.Background(), ep, query("example.test", dns.TypeA), opts(3000), []contract.Endpoint{{Transport: "udp", Address: empty}})
	if code(err) != contract.CodeBootstrapFailed {
		t.Fatalf("want bootstrap_failed, got %v", err)
	}
}

func TestDoHErrors(t *testing.T) {
	cert := testdns.NewCert(t, "doh.test")
	addr := testdns.DoH(t, cert, testdns.Zone(t, zone...))
	c := &Client{RootCAs: cert.Pool}
	// Wrong path → 404 → http error with status in details.
	url := "https://doh.test:" + port(t, addr) + "/nope"
	_, err := c.Exchange(context.Background(), contract.Endpoint{Transport: "doh", URL: url, Address: addr}, query("example.test", dns.TypeA), opts(3000), nil)
	var be *bridge.Error
	if !errors.As(err, &be) || be.Code != contract.CodeHTTP || be.Details["status"] != 404 {
		t.Fatalf("want http 404, got %v", err)
	}
	// Name mismatch → tls.
	url = "https://other.test:" + port(t, addr) + "/dns-query"
	_, err = c.Exchange(context.Background(), contract.Endpoint{Transport: "doh", URL: url, Address: addr}, query("example.test", dns.TypeA), opts(3000), nil)
	if code(err) != contract.CodeTLS {
		t.Fatalf("want tls, got %v", err)
	}
}

func TestDoQ(t *testing.T) {
	cert := testdns.NewCert(t, "doq.test")
	addr := testdns.DoQ(t, cert, testdns.Zone(t, zone...))
	c := &Client{RootCAs: cert.Pool}
	res, err := c.Exchange(context.Background(), contract.Endpoint{Transport: "doq", Address: addr, TLSName: "doq.test"}, query("example.test", dns.TypeA), opts(3000), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertAnswer(t, res, "doq")
	if res.Exchange.TLS == nil || res.Exchange.TLS.ALPN != "doq" || res.Exchange.TLS.Version != "TLS 1.3" {
		t.Fatalf("tls: %+v", res.Exchange.TLS)
	}
	if res.Msg.Id != 0 {
		t.Fatalf("doq reply id must be 0, got %d", res.Msg.Id)
	}

	_, err = c.Exchange(context.Background(), contract.Endpoint{Transport: "doq", Address: addr, TLSName: "wrong.test"}, query("example.test", dns.TypeA), opts(3000), nil)
	if code(err) != contract.CodeTLS {
		t.Fatalf("want tls, got %v", err)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	addr := testdns.UDP(t, testdns.Silent)
	c := &Client{}
	_, err := c.Exchange(context.Background(), contract.Endpoint{Transport: "udp", Address: addr}, query("example.test", dns.TypeA), opts(150), nil)
	if code(err) != contract.CodeTimeout {
		t.Fatalf("want timeout, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err = c.Exchange(ctx, contract.Endpoint{Transport: "udp", Address: addr}, query("example.test", dns.TypeA), opts(5000), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}

	tcp := testdns.TCP(t, testdns.Silent)
	ctx, cancel = context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err = c.Exchange(ctx, contract.Endpoint{Transport: "tcp", Address: tcp}, query("example.test", dns.TypeA), opts(5000), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("tcp: want context.Canceled, got %v", err)
	}
}

func TestConnectionRefusedIsNetwork(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	_, err := (&Client{}).Exchange(context.Background(), contract.Endpoint{Transport: "tcp", Address: addr}, query("example.test", dns.TypeA), opts(1000), nil)
	if code(err) != contract.CodeNetwork {
		t.Fatalf("want network, got %v", err)
	}
}

func TestInvalidEndpointRejected(t *testing.T) {
	_, err := (&Client{}).Exchange(context.Background(), contract.Endpoint{Transport: "dot", Address: "1.1.1.1:853"}, query("x", dns.TypeA), opts(1000), nil)
	if code(err) != contract.CodeBadEndpoint {
		t.Fatalf("want bad_endpoint, got %v", err)
	}
}
