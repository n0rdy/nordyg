package txtdecode

import (
	"strconv"
	"strings"
)

// Mechanism is one SPF term.
type Mechanism struct {
	Qualifier string `json:"qualifier"`
	Kind      string `json:"kind"`
	Value     string `json:"value,omitempty"`
}

// SPFModifiers are the two standard modifiers.
type SPFModifiers struct {
	Redirect *string `json:"redirect"`
	Exp      *string `json:"exp"`
}

// SPF is a decoded v=spf1 record.
type SPF struct {
	Kind        string       `json:"kind"`
	Mechanisms  []Mechanism  `json:"mechanisms"`
	Modifiers   SPFModifiers `json:"modifiers"`
	LookupCount int          `json:"lookup_count"`
	Problems    []Problem    `json:"problems"`
}

var spfMechanisms = map[string]bool{"all": true, "include": true, "a": true, "mx": true, "ptr": true, "ip4": true, "ip6": true, "exists": true}

// DecodeSPF parses a v=spf1 record.
func DecodeSPF(txt string) *SPF {
	out := &SPF{Kind: "spf", Mechanisms: []Mechanism{}, Problems: []Problem{}}
	terms := strings.Fields(txt)
	if len(terms) == 0 || !strings.EqualFold(terms[0], "v=spf1") {
		out.Problems = append(out.Problems, Problem{SevError, "record does not start with v=spf1"})
		return out
	}
	sawAll := false
	for _, term := range terms[1:] {
		if sawAll {
			out.Problems = append(out.Problems, Problem{SevWarning, "terms after \"all\" are ignored: " + term})
			continue
		}
		if eq := strings.IndexByte(term, '='); eq > 0 && !strings.ContainsAny(term[:eq], ":/") {
			// modifier
			k, v := strings.ToLower(term[:eq]), term[eq+1:]
			switch k {
			case "redirect":
				out.Modifiers.Redirect = &v
				out.LookupCount++
			case "exp":
				out.Modifiers.Exp = &v
			default:
				out.Problems = append(out.Problems, Problem{SevInfo, "unknown modifier " + k})
			}
			continue
		}
		q := "+"
		if strings.ContainsRune("+-~?", rune(term[0])) {
			q, term = term[:1], term[1:]
		}
		kind, value := term, ""
		if i := strings.IndexAny(term, ":/"); i >= 0 {
			kind, value = term[:i], term[i:]
			if value[0] == ':' {
				value = value[1:]
			}
		}
		kind = strings.ToLower(kind)
		if !spfMechanisms[kind] {
			out.Problems = append(out.Problems, Problem{SevError, "unknown mechanism " + kind})
			continue
		}
		out.Mechanisms = append(out.Mechanisms, Mechanism{Qualifier: q, Kind: kind, Value: value})
		switch kind {
		case "include", "a", "mx", "exists":
			out.LookupCount++
		case "ptr":
			out.LookupCount++
			out.Problems = append(out.Problems, Problem{SevWarning, "ptr mechanism is deprecated and slow (RFC 7208 §5.5)"})
		case "all":
			sawAll = true
			if q == "+" {
				out.Problems = append(out.Problems, Problem{SevError, "+all allows any sender, so the record provides no protection"})
			}
		}
	}
	if !sawAll && out.Modifiers.Redirect == nil {
		out.Problems = append(out.Problems, Problem{SevWarning, "no \"all\" mechanism, so unmatched senders get a neutral result"})
	}
	switch {
	case out.LookupCount > 10:
		out.Problems = append(out.Problems, Problem{SevError, "record needs " + strconv.Itoa(out.LookupCount) + " DNS lookups in this record alone, over the limit of 10 (RFC 7208 §4.6.4)"})
	case out.LookupCount > 6:
		out.Problems = append(out.Problems, Problem{SevWarning, "record uses " + strconv.Itoa(out.LookupCount) + " of 10 allowed DNS lookups before following includes"})
	}
	return out
}
