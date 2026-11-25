package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
)

func (c *Client) doh(ctx context.Context, ep contract.Endpoint, q *dns.Msg, o contract.Effective, bootstrap []contract.Endpoint) (*Result, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil, err
	}
	dialAddr := ep.Address
	if dialAddr == "" {
		ip, err := c.resolveHost(ctx, u.Hostname(), o, bootstrap)
		if err != nil {
			return nil, err
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		dialAddr = net.JoinHostPort(ip, port)
	}
	tlsName := ep.TLSName
	if tlsName == "" {
		tlsName = u.Hostname()
	}

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: tlsName, RootCAs: c.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, dialAddr)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// RFC 8484 §4.1: id 0 for cache friendliness.
	sendq := q.Copy()
	sendq.Id = 0
	packed, err := sendq.Pack()
	if err != nil {
		return nil, err
	}

	var req *http.Request
	if ep.Method == "get" {
		gu := *u
		qs := gu.Query()
		qs.Set("dns", base64.RawURLEncoding.EncodeToString(packed))
		gu.RawQuery = qs.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, gu.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(packed))
		if err == nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "nordyg")

	var hsStart time.Time
	var hs time.Duration
	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeStart: func() { hsStart = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { hs = time.Since(hsStart) },
	}))

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage))
	if err != nil {
		return nil, err
	}
	info := &contract.HTTPInfo{Status: resp.StatusCode, Version: resp.Proto, ContentType: resp.Header.Get("Content-Type")}
	if resp.StatusCode != http.StatusOK {
		return nil, &bridge.Error{Code: contract.CodeHTTP, Message: fmt.Sprintf("DoH server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(truncate(body, 200)))), Details: map[string]any{"status": resp.StatusCode}}
	}
	if ct := strings.ToLower(info.ContentType); !strings.HasPrefix(ct, "application/dns-message") {
		return nil, &bridge.Error{Code: contract.CodeHTTP, Message: "DoH server returned content type " + info.ContentType, Details: map[string]any{"status": resp.StatusCode}}
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, malformed(err)
	}
	res := &Result{Msg: r, Size: len(body)}
	res.Exchange.Protocol = contract.DoH
	res.Exchange.HTTP = info
	if resp.TLS != nil {
		res.Exchange.TLS = tlsInfo(*resp.TLS, hs)
	}
	return res, nil
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// resolveHost turns a DoH hostname into an IP using the bootstrap endpoints.
func (c *Client) resolveHost(ctx context.Context, host string, o contract.Effective, bootstrap []contract.Endpoint) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	if len(bootstrap) == 0 {
		return "", &bridge.Error{Code: contract.CodeBootstrapRequired, Message: "DoH host " + host + " needs an address or bootstrap resolvers"}
	}
	var lastErr error
	for _, b := range bootstrap {
		if b.Transport != contract.UDP && b.Transport != contract.TCP {
			continue
		}
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(host), t)
			m.SetEdns0(contract.DefaultUDPSize, false)
			res, err := c.Exchange(ctx, b, m, o, nil)
			if err != nil {
				lastErr = err
				continue
			}
			for _, rr := range res.Msg.Answer {
				switch a := rr.(type) {
				case *dns.A:
					return a.A.String(), nil
				case *dns.AAAA:
					return a.AAAA.String(), nil
				}
			}
		}
	}
	msg := "no address for " + host + " from bootstrap resolvers"
	if lastErr != nil {
		msg += ": " + lastErr.Error()
	}
	return "", &bridge.Error{Code: contract.CodeBootstrapFailed, Message: msg}
}
