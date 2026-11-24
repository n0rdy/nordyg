package email

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/prose"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/txtdecode"
)

// SPFInclude is one record pulled in by an include or redirect, with the lookups it costs.
type SPFInclude struct {
	Name    string         `json:"name"`
	Via     string         `json:"via"`
	Depth   int            `json:"depth"`
	Record  string         `json:"record,omitempty"`
	Decoded *txtdecode.SPF `json:"decoded,omitempty"`
	Lookups int            `json:"lookups"`
	Error   string         `json:"error,omitempty"`
}

// SPFSection is the SPF record and its include chain, counted against the limit of 10 lookups.
type SPFSection struct {
	Records      []string       `json:"records"`
	Decoded      *txtdecode.SPF `json:"decoded,omitempty"`
	Includes     []SPFInclude   `json:"includes"`
	TotalLookups int            `json:"total_lookups"`
	Verdict      Verdict        `json:"verdict"`
}

const maxSPFDepth = 10

func checkSPF(ctx context.Context, r *resolve.Resolver, domain string) SPFSection {
	sec := SPFSection{Records: []string{}, Includes: []SPFInclude{}}
	txts, err := txt(ctx, r, domain)
	if err != nil {
		sec.Verdict = Verdict{Status: Fail, Message: "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if hasVersion(t, "v=spf1") {
			sec.Records = append(sec.Records, t)
		}
	}
	if len(sec.Records) == 0 {
		sec.Verdict = Verdict{Status: Fail, Message: "no SPF record, so receivers cannot tell which servers may send mail for the domain"}
		return sec
	}
	sec.Decoded = txtdecode.DecodeSPF(sec.Records[0])
	visited := map[string]bool{strings.ToLower(domain): true}
	sec.TotalLookups = sec.Decoded.LookupCount + followIncludes(ctx, r, sec.Decoded, domain, 1, visited, &sec.Includes)

	if len(sec.Records) > 1 {
		sec.Verdict = Verdict{Status: Fail, Message: fmt.Sprintf("%d SPF records, which receivers treat as a permanent error (RFC 7208 §3.2)", len(sec.Records))}
		return sec
	}
	for _, p := range sec.Decoded.Problems {
		if p.Severity == txtdecode.SevError {
			sec.Verdict = Verdict{Status: Fail, Message: p.Message}
			return sec
		}
	}
	for _, inc := range sec.Includes {
		if inc.Error != "" {
			sec.Verdict = Verdict{Status: Fail, Message: "include:" + prose.Name(inc.Name) + " could not be resolved: " + inc.Error}
			return sec
		}
	}
	switch {
	case sec.TotalLookups > 10:
		sec.Verdict = Verdict{Status: Fail, Message: fmt.Sprintf("%d DNS lookups across the include chain, over the limit of 10, so receivers return permerror", sec.TotalLookups)}
	case sec.TotalLookups > 8:
		sec.Verdict = Verdict{Status: Warn, Message: fmt.Sprintf("%d of 10 allowed DNS lookups used across the include chain, so one more sender may break SPF", sec.TotalLookups)}
	case lastAll(sec.Decoded) == "?" || (lastAll(sec.Decoded) == "" && sec.Decoded.Modifiers.Redirect == nil):
		sec.Verdict = Verdict{Status: Warn, Message: "record ends without -all or ~all, so unauthorised senders get a neutral result"}
	case len(sec.Decoded.Mechanisms) == 1 && lastAll(sec.Decoded) == "-":
		sec.Verdict = Verdict{Status: OK, Message: "no server may send mail for the domain (v=spf1 -all)"}
	case lastAll(sec.Decoded) == "" && sec.Decoded.Modifiers.Redirect != nil:
		sec.Verdict = Verdict{Status: OK, Message: fmt.Sprintf("valid, %d of 10 lookups used, hands the rest to %s (redirect)", sec.TotalLookups, prose.Name(*sec.Decoded.Modifiers.Redirect))}
	default:
		sec.Verdict = Verdict{Status: OK, Message: fmt.Sprintf("valid, %d of 10 lookups used, ends with %sall", sec.TotalLookups, lastAll(sec.Decoded))}
	}
	return sec
}

func lastAll(s *txtdecode.SPF) string {
	for _, m := range s.Mechanisms {
		if m.Kind == "all" {
			return m.Qualifier
		}
	}
	return ""
}

// followIncludes resolves include: and redirect= targets recursively and
// returns the lookups they add.
func followIncludes(ctx context.Context, r *resolve.Resolver, s *txtdecode.SPF, via string, depth int, visited map[string]bool, out *[]SPFInclude) int {
	if depth > maxSPFDepth {
		return 0
	}
	total := 0
	var targets []string
	for _, m := range s.Mechanisms {
		if m.Kind == "include" && m.Value != "" {
			targets = append(targets, m.Value)
		}
	}
	if s.Modifiers.Redirect != nil && *s.Modifiers.Redirect != "" {
		targets = append(targets, *s.Modifiers.Redirect)
	}
	for _, t := range targets {
		name := strings.ToLower(dns.Fqdn(strings.TrimSpace(t)))
		inc := SPFInclude{Name: name, Via: via, Depth: depth}
		if visited[name] {
			inc.Error = "already included higher up (loop)"
			*out = append(*out, inc)
			continue
		}
		visited[name] = true
		txts, err := txt(ctx, r, name)
		if err != nil {
			inc.Error = err.Error()
			*out = append(*out, inc)
			continue
		}
		for _, x := range txts {
			if hasVersion(x, "v=spf1") {
				inc.Record = x
				break
			}
		}
		if inc.Record == "" {
			inc.Error = "no SPF record at the include target"
			*out = append(*out, inc)
			continue
		}
		inc.Decoded = txtdecode.DecodeSPF(inc.Record)
		inc.Lookups = inc.Decoded.LookupCount
		total += inc.Lookups
		*out = append(*out, inc)
		total += followIncludes(ctx, r, inc.Decoded, name, depth+1, visited, out)
	}
	return total
}
