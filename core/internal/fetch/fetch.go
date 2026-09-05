// Package fetch does HTTPS GETs and raw TCP exchanges for hosts resolved
// through the user's chosen DNS resolver, never the system one. Used by the
// email (MTA-STS) and rdap ops.
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

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Resolver returns the addresses for a host.
type Resolver func(ctx context.Context, host string) ([]string, error)

// NewResolver resolves A and AAAA through the given endpoint.
func NewResolver(c *transport.Client, ep contract.Endpoint, o contract.Effective, boot []contract.Endpoint) Resolver {
	o.RecursionDesired = true
	return func(ctx context.Context, host string) ([]string, error) {
		if ip := net.ParseIP(host); ip != nil {
			return []string{host}, nil
		}
		var out []string
		var firstErr error
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			q := o.Build(contract.Resolved{Name: dns.Fqdn(host), Type: t, Class: dns.ClassINET})
			res, err := c.Exchange(ctx, ep, q, o, boot)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			for _, rr := range res.Msg.Answer {
				switch a := rr.(type) {
				case *dns.A:
					out = append(out, a.A.String())
				case *dns.AAAA:
					out = append(out, a.AAAA.String())
				}
			}
		}
		if len(out) == 0 {
			if firstErr != nil {
				return nil, firstErr
			}
			return nil, errors.New("no address for " + host)
		}
		return out, nil
	}
}

// Response is a completed GET.
type Response struct {
	Status      int
	ContentType string
	Body        []byte
	FinalURL    string
}

const (
	maxRedirects = 5
	maxBody      = 2 << 20
)

// Get fetches an https URL, following redirects, dialing pinned addresses.
// Tests may set RootCAs on the client used to build the resolver; here the
// TLS config takes the optional pool.
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
		resp.FinalURL = cur
		return &resp.Response, nil
	}
	return nil, errors.New("too many redirects")
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
