// Package testdns runs in-process DNS servers for tests: UDP, TCP, DoT, DoH
// and DoQ, all backed by one handler, plus a throwaway certificate. It is only
// imported from _test files, so it never ends up in the archive.
package testdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Answer builds the reply for a query.
type Answer func(q *dns.Msg) *dns.Msg

// Cert is a self-signed certificate valid for the given names and 127.0.0.1.
type Cert struct {
	TLS  tls.Certificate
	Pool *x509.CertPool
}

// NewCert generates an ECDSA self-signed certificate.
func NewCert(t testing.TB, names ...string) *Cert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nordyg test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              names,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &Cert{TLS: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, Pool: pool}
}

func handler(a Answer) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if resp := a(r); resp != nil {
			_ = w.WriteMsg(resp)
		}
	}
}

// UDP starts a UDP server and returns its ip:port.
func UDP(t testing.TB, a Answer) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler(a)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TCP starts a TCP server and returns its ip:port.
func TCP(t testing.TB, a Answer) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: l, Handler: handler(a)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return l.Addr().String()
}

// DoT starts a DNS-over-TLS server with the given certificate.
func DoT(t testing.TB, c *Cert, a Answer) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{c.TLS}, NextProtos: []string{"dot"}})
	srv := &dns.Server{Listener: tl, Net: "tcp-tls", Handler: handler(a)}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return l.Addr().String()
}

// DoH starts an RFC 8484 server. It returns the ip:port; build the URL with
// the certificate's name and that port. Requests is incremented per request
// if non-nil.
func DoH(t testing.TB, c *Cert, a Answer) string {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" {
			http.NotFound(w, r)
			return
		}
		var body []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			body, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		case http.MethodPost:
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/dns-message") {
				http.Error(w, "content type", http.StatusUnsupportedMediaType)
				return
			}
			body, err = io.ReadAll(r.Body)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := a(q)
		if resp == nil {
			http.Error(w, "no answer", http.StatusInternalServerError)
			return
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{c.TLS}, NextProtos: []string{"h2", "http/1.1"}}
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	return s.Listener.Addr().String()
}

// DoQ starts an RFC 9250 server.
func DoQ(t testing.TB, c *Cert, a Answer) string {
	t.Helper()
	l, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{c.TLS}, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept(ctx)
			if err != nil {
				return
			}
			go serveDoQConn(ctx, conn, a)
		}
	}()
	return l.Addr().String()
}

func serveDoQConn(ctx context.Context, conn *quic.Conn, a Answer) {
	defer func() { _ = conn.CloseWithError(0, "") }()
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = st.Close() }()
			var lenBuf [2]byte
			if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
				return
			}
			body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
			if _, err := io.ReadFull(st, body); err != nil {
				return
			}
			q := new(dns.Msg)
			if err := q.Unpack(body); err != nil {
				return
			}
			resp := a(q)
			if resp == nil {
				return
			}
			out, _ := resp.Pack()
			binary.BigEndian.PutUint16(lenBuf[:], uint16(len(out)))
			_, _ = st.Write(append(lenBuf[:], out...))
		}()
	}
}

// Zone is a tiny fixture: name → records, answered authoritatively; anything
// else is NXDOMAIN. Records are given in presentation format.
func Zone(t testing.TB, records ...string) Answer {
	t.Helper()
	rrs := make([]dns.RR, 0, len(records))
	for _, s := range records {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("bad fixture %q: %v", s, err)
		}
		rrs = append(rrs, rr)
	}
	return func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		if len(q.Question) == 0 {
			m.Rcode = dns.RcodeFormatError
			return m
		}
		qq := q.Question[0]
		found := false
		for _, rr := range rrs {
			h := rr.Header()
			if strings.EqualFold(h.Name, qq.Name) {
				found = true
				if h.Rrtype == qq.Qtype || qq.Qtype == dns.TypeANY {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if !found {
			m.Rcode = dns.RcodeNameError
		}
		if opt := q.IsEdns0(); opt != nil {
			m.SetEdns0(1232, opt.Do())
		}
		return m
	}
}

// Silent never answers, for timeout tests.
func Silent(*dns.Msg) *dns.Msg { return nil }
