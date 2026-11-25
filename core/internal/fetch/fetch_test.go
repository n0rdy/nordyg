package fetch

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/testdns"
)

// site serves h over HTTPS as fetch.test and returns its base URL, a resolver
// that maps every host to the server, and the roots that trust it.
func site(t *testing.T, h http.Handler) (base string, r Resolver, roots *tls.Config) {
	t.Helper()
	cert := testdns.NewCert(t, "fetch.test")
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert.TLS}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	r = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	return "https://fetch.test:" + port, r, &tls.Config{RootCAs: cert.Pool}
}

func TestGetRefusesPlainHTTP(t *testing.T) {
	resolved := false
	r := func(context.Context, string) ([]string, error) { resolved = true; return nil, nil }
	_, err := Get(context.Background(), "http://fetch.test/", "", r, nil)
	if err == nil || !strings.Contains(err.Error(), "non-https") || resolved {
		t.Fatalf("want a refusal before any lookup, got %v (resolved %v)", err, resolved)
	}
}

func TestGetRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/end", http.StatusFound) })
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("arrived")) })
	mux.HandleFunc("/downgrade", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://fetch.test/end", http.StatusFound)
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	base, r, roots := site(t, mux)

	resp, err := Get(context.Background(), base+"/start", "", r, roots)
	if err != nil || resp.Status != http.StatusOK || string(resp.Body) != "arrived" {
		t.Fatalf("redirect within https: %+v, %v", resp, err)
	}
	if _, err := Get(context.Background(), base+"/downgrade", "", r, roots); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("a redirect to http must be refused, got %v", err)
	}
	if _, err := Get(context.Background(), base+"/loop", "", r, roots); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("a redirect loop must end, got %v", err)
	}
}

func TestGetRejectsUntrustedCertificate(t *testing.T) {
	base, r, _ := site(t, http.NotFoundHandler())
	if _, err := Get(context.Background(), base+"/", "", r, nil); err == nil {
		t.Fatal("a certificate the system does not trust must fail the fetch")
	}
}
