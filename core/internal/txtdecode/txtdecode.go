// Package txtdecode parses SPF, DMARC and DKIM TXT records into readable
// fields and flags problems.
package txtdecode

import (
	"strings"

	"github.com/n0rdy/nordyg/core/internal/contract"
)

// Problem is one flagged issue.
type Problem struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

const (
	SevError   = "error"
	SevWarning = "warning"
	SevInfo    = "info"
)

// Decode returns the decoded form of a TXT record, or nil if it is none of
// the known kinds. name is the owner name, strings the character-strings.
func Decode(name string, strings_ []string) any {
	txt := strings.Join(strings_, "")
	lower := strings.ToLower(strings.TrimSpace(txt))
	switch {
	case strings.HasPrefix(lower, "v=spf1"):
		return DecodeSPF(txt)
	case strings.HasPrefix(lower, "v=dmarc1"):
		return DecodeDMARC(txt)
	case strings.HasPrefix(lower, "v=dkim1"), isDKIMName(name) && strings.Contains(lower, "p="):
		return DecodeDKIM(txt)
	}
	return nil
}

func isDKIMName(name string) bool {
	return strings.Contains(strings.ToLower(name), "._domainkey.")
}

// Decorate attaches decoded forms to every TXT record in the message and
// flags duplicate SPF records per name.
func Decorate(m *contract.Message) {
	spfCount := map[string]int{}
	sections := [][]contract.Record{m.Answer, m.Authority, m.Additional}
	for _, sec := range sections {
		for i := range sec {
			rec := &sec[i]
			if rec.Type != "TXT" {
				continue
			}
			strs, _ := rec.Fields["strings"].([]string)
			if strs == nil {
				continue
			}
			rec.Decoded = Decode(rec.Name, strs)
			if _, ok := rec.Decoded.(*SPF); ok {
				spfCount[strings.ToLower(rec.Name)]++
			}
		}
	}
	for _, sec := range sections {
		for i := range sec {
			if s, ok := sec[i].Decoded.(*SPF); ok && spfCount[strings.ToLower(sec[i].Name)] > 1 {
				s.Problems = append(s.Problems, Problem{SevError, "multiple SPF records for this name, which receivers treat as a permanent error (RFC 7208 §3.2)"})
			}
		}
	}
}

// parseTags splits "k=v; k2=v2" into a map and the order the keys appeared.
func parseTags(txt string) (map[string]string, []string) {
	tags := map[string]string{}
	var order []string
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := tags[k]; !dup {
			order = append(order, k)
		}
		tags[k] = strings.TrimSpace(v)
	}
	return tags, order
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func ptr(s string) *string { return &s }
