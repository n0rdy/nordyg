package email

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/n0rdy/nordyg/core/internal/fetch"
)

// maxPolicySize is the most RFC 8461 asks senders to read of a policy.
const maxPolicySize = 64 * 1024

// fetchPolicyHTTPS downloads the MTA-STS policy (RFC 8461 §3.3). The host is
// resolved by the caller through the chosen resolver, and one of those IPs is
// dialed directly so the system resolver stays out of the path.
func fetchPolicyHTTPS(ctx context.Context, host string, ips []string) (string, error) {
	resp, err := fetch.GetPinned(ctx, "https://"+host+"/.well-known/mta-sts.txt", ips)
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status >= 300 && resp.Status < 400:
		return "", errors.New("policy must not redirect")
	case resp.Status != http.StatusOK:
		return "", fmt.Errorf("HTTP %d from %s", resp.Status, host)
	}
	if ct := resp.ContentType; ct != "" && !strings.HasPrefix(ct, "text/plain") {
		return "", fmt.Errorf("policy served as %s, must be text/plain", ct)
	}
	return string(resp.Body[:min(len(resp.Body), maxPolicySize)]), nil
}
