// Package fetch does HTTPS GETs and raw TCP exchanges for hosts resolved
// through the user's chosen DNS resolver, never the system one. Used by the
// rdap, health and email ops.
package fetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Resolver returns the addresses for a host.
type Resolver func(ctx context.Context, host string) ([]string, error)

// NewResolver resolves A and AAAA through the given endpoint.
func NewResolver(c *transport.Client, ep contract.Endpoint, o contract.Effective, boot []contract.Endpoint) Resolver {
	o.RecursionDesired = true
	r := &resolve.Resolver{Client: c, Endpoint: ep, Options: o, Bootstrap: boot}
	return func(ctx context.Context, host string) ([]string, error) {
		if ip := net.ParseIP(host); ip != nil {
			return []string{host}, nil
		}
		addrs, err := r.Addrs(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, errors.New("no address for " + host)
		}
		return addrs, nil
	}
}

// Response is a completed GET.
type Response struct {
	Status      int
	ContentType string
	Body        []byte
}

const (
	maxRedirects = 5
	maxBody      = 2 << 20
)

// Get fetches an https URL, following redirects, dialing pinned addresses.
// Only RootCAs is read from roots, and nil means the system pool.
func Get(ctx context.Context, rawURL, accept string, r Resolver, roots *tls.Config) (*Response, error) {
	cur := rawURL
	for hop := 0; hop <= maxRedirects; hop++ {
		u, err := url.Parse(cur)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "https" {
			return nil, fmt.Errorf("refusing non-https URL %s", cur)
		}
		ips, err := r(ctx, u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", u.Hostname(), err)
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		resp, err := getOnce(ctx, u, ips, port, accept, roots)
		if err != nil {
			return nil, err
		}
		if resp.Status >= 300 && resp.Status < 400 && resp.location != "" {
			next, err := u.Parse(resp.location)
			if err != nil {
				return nil, err
			}
			cur = next.String()
			continue
		}
		return &resp.Response, nil
	}
	return nil, errors.New("too many redirects")
}

// GetPinned fetches an https URL from addresses the caller already resolved
// and follows no redirect, so a 3xx comes back as the response.
func GetPinned(ctx context.Context, rawURL string, ips []string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("refusing non-https URL %s", rawURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	resp, err := getOnce(ctx, u, ips, port, "", nil)
	if err != nil {
		return nil, err
	}
	return &resp.Response, nil
}

// GetSigned fetches an object that carries its own signature, such as a
// certificate revocation list. CAs publish those over plain HTTP by design,
// so http is allowed here, unlike Get; the caller must verify the signature
// before trusting a single byte. No redirects are followed.
func GetSigned(ctx context.Context, rawURL string, r Resolver) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL %s", rawURL)
	}
	ips, err := r(ctx, u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", u.Hostname(), err)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	resp, err := getOnce(ctx, u, ips, port, "", nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", u.Hostname(), resp.Status)
	}
	return resp.Body, nil
}

type rawResponse struct {
	Response
	location string
}

func getOnce(ctx context.Context, u *url.URL, ips []string, port, accept string, roots *tls.Config) (*rawResponse, error) {
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, port)
		tlsConf := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
		if roots != nil {
			tlsConf.RootCAs = roots.RootCAs
		}
		tr := &http.Transport{
			TLSClientConfig: tlsConf,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			},
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
		}
		client := &http.Client{Transport: tr, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.Header.Set("User-Agent", "nordyg")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			tr.CloseIdleConnections()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		if err != nil {
			lastErr = err
			continue
		}
		return &rawResponse{
			Response: Response{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: body},
			location: resp.Header.Get("Location"),
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses to connect to")
	}
	return nil, lastErr
}

// TCPQuery connects to host:port, writes the query and reads until EOF or
// the deadline. WHOIS (RFC 3912) is exactly this.
func TCPQuery(ctx context.Context, host string, port int, query string, r Resolver) (string, error) {
	ips, err := r(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
		if err != nil {
			lastErr = err
			continue
		}
		dl := time.Now().Add(10 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(dl) {
			dl = d
		}
		_ = conn.SetDeadline(dl)
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		_, err = io.WriteString(conn, strings.TrimSpace(query)+"\r\n")
		if err == nil {
			var b []byte
			b, err = io.ReadAll(io.LimitReader(conn, maxBody))
			// WHOIS has no framing: what arrived before a timeout or a reset
			// is still the answer, from a server that did not close cleanly.
			if err == nil || len(b) > 0 {
				stop()
				_ = conn.Close()
				return string(b), nil
			}
		}
		stop()
		_ = conn.Close()
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses to connect to")
	}
	return "", lastErr
}
