package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// fetchPolicyHTTPS downloads the MTA-STS policy (RFC 8461 §3.3). The host is
// resolved by the caller through the chosen resolver; we dial one of those
// IPs directly so the system resolver stays out of the path.
func fetchPolicyHTTPS(ctx context.Context, host string, ips []string) (string, error) {
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, "443")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			},
			DisableKeepAlives: true,
		}
		client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("policy must not redirect")
		}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/.well-known/mta-sts.txt", nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "nordyg")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			tr.CloseIdleConnections()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, host)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "text/plain") {
			return "", fmt.Errorf("policy served as %s, must be text/plain", ct)
		}
		return string(body), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses to connect to")
	}
	return "", lastErr
}
