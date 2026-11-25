package email

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/n0rdy/nordyg/core/internal/prose"
	"github.com/n0rdy/nordyg/core/internal/resolve"
)

// MTASTSPolicy is the policy file as parsed.
type MTASTSPolicy struct {
	Version string   `json:"version"`
	Mode    string   `json:"mode"`
	MX      []string `json:"mx"`
	MaxAge  int      `json:"max_age"`
}

// MTASTSSection is the MTA-STS record and the policy file it announces.
type MTASTSSection struct {
	Name       string        `json:"name"`
	Record     string        `json:"record,omitempty"`
	ID         string        `json:"id,omitempty"`
	PolicyURL  string        `json:"policy_url,omitempty"`
	PolicyText string        `json:"policy_text,omitempty"`
	Policy     *MTASTSPolicy `json:"policy,omitempty"`
	Error      string        `json:"error,omitempty"`
	Verdict    Verdict       `json:"verdict"`

	off bool // no MTA-STS record is published
}

// humanSeconds renders a policy lifetime: "1 week", "2 days", "3600 s".
func humanSeconds(s int) string {
	switch {
	case s >= 7*86400 && s%(7*86400) == 0:
		n := s / (7 * 86400)
		return fmt.Sprintf("%d week%s", n, prose.Plural(n))
	case s >= 86400 && s%86400 == 0:
		n := s / 86400
		return fmt.Sprintf("%d day%s", n, prose.Plural(n))
	case s >= 3600 && s%3600 == 0:
		n := s / 3600
		return fmt.Sprintf("%d hour%s", n, prose.Plural(n))
	}
	return fmt.Sprintf("%d s", s)
}

func (op *Op) checkMTASTS(ctx context.Context, r *resolve.Resolver, domain string) MTASTSSection {
	sec := MTASTSSection{Name: "_mta-sts." + domain}
	txts, err := txt(ctx, r, sec.Name)
	if err != nil {
		sec.Verdict = Verdict{Status: Fail, Message: "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if hasVersion(t, "v=stsv1") {
			sec.Record = t
			break
		}
	}
	if sec.Record == "" {
		sec.off = true
		sec.Verdict = Verdict{Status: Info, Message: "not configured. MTA-STS is optional and tells senders to require TLS to your MX hosts"}
		return sec
	}
	for _, part := range strings.Split(sec.Record, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(strings.TrimSpace(k), "id") {
			sec.ID = strings.TrimSpace(v)
		}
	}
	host := "mta-sts." + strings.TrimSuffix(domain, ".")
	sec.PolicyURL = "https://" + host + "/.well-known/mta-sts.txt"
	ips, err := r.Addrs(ctx, host)
	if err != nil {
		sec.Error = "the lookup of policy host " + host + " failed: " + err.Error()
		sec.Verdict = Verdict{Status: Fail, Message: sec.Error}
		return sec
	}
	if len(ips) == 0 {
		sec.Error = "policy host " + host + " does not resolve"
		sec.Verdict = Verdict{Status: Fail, Message: sec.Error}
		return sec
	}
	fetch := op.FetchPolicy
	if fetch == nil {
		fetch = fetchPolicyHTTPS
	}
	text, err := fetch(ctx, host, ips)
	if err != nil {
		sec.Error = err.Error()
		sec.Verdict = Verdict{Status: Fail, Message: "policy file could not be fetched: " + err.Error()}
		return sec
	}
	sec.PolicyText = text
	sec.Policy = parsePolicy(text)
	switch {
	case sec.Policy.Version != "STSv1":
		sec.Verdict = Verdict{Status: Fail, Message: "policy file has no version: STSv1 line"}
	case sec.Policy.MaxAge <= 0:
		sec.Verdict = Verdict{Status: Fail, Message: "policy file has no valid max_age line, which every policy needs (RFC 8461)"}
	case sec.Policy.Mode == "enforce":
		sec.Verdict = Verdict{Status: OK, Message: fmt.Sprintf("enforce mode, %d MX pattern%s, cached by senders for %s", len(sec.Policy.MX), prose.Plural(len(sec.Policy.MX)), humanSeconds(sec.Policy.MaxAge))}
	case sec.Policy.Mode == "testing":
		sec.Verdict = Verdict{Status: Warn, Message: "testing mode: senders report failures but still deliver over plain text"}
	case sec.Policy.Mode == "none":
		sec.Verdict = Verdict{Status: Info, Message: "mode none: policy published but switched off"}
	default:
		sec.Verdict = Verdict{Status: Fail, Message: "policy file has no valid mode"}
	}
	return sec
}

func parsePolicy(text string) *MTASTSPolicy {
	p := &MTASTSPolicy{MX: []string{}}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "version":
			p.Version = v
		case "mode":
			p.Mode = strings.ToLower(v)
		case "mx":
			p.MX = append(p.MX, v)
		case "max_age":
			p.MaxAge, _ = strconv.Atoi(v)
		}
	}
	return p
}
