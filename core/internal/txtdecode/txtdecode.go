// Package txtdecode parses SPF, DMARC and DKIM TXT records into readable
// fields and flags problems (contract §2.8).
package txtdecode

import (
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strconv"
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

// DMARCTags are the parsed tags with defaults applied.
type DMARCTags struct {
	V     string   `json:"v"`
	P     *string  `json:"p"`
	SP    *string  `json:"sp"`
	RUA   []string `json:"rua"`
	RUF   []string `json:"ruf"`
	Pct   int      `json:"pct"`
	ADKIM string   `json:"adkim"`
	ASPF  string   `json:"aspf"`
	FO    string   `json:"fo"`
	RF    string   `json:"rf"`
	RI    int      `json:"ri"`
}

// DMARC is a decoded v=DMARC1 record.
type DMARC struct {
	Kind     string    `json:"kind"`
	Tags     DMARCTags `json:"tags"`
	Problems []Problem `json:"problems"`
}

// DKIMTags are the parsed tags.
type DKIMTags struct {
	V *string `json:"v"`
	K *string `json:"k"`
	H *string `json:"h"`
	T *string `json:"t"`
	S *string `json:"s"`
	N *string `json:"n"`
}

// DKIM is a decoded DKIM public key record.
type DKIM struct {
	Kind     string    `json:"kind"`
	Tags     DKIMTags  `json:"tags"`
	KeyType  string    `json:"key_type"`
	KeyBits  int       `json:"key_bits"`
	Revoked  bool      `json:"revoked"`
	Problems []Problem `json:"problems"`
}

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
				s.Problems = append(s.Problems, Problem{SevError, "multiple SPF records for this name; receivers treat that as a permanent error (RFC 7208 §3.2)"})
			}
		}
	}
}

// --- SPF -------------------------------------------------------------------

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
				out.Problems = append(out.Problems, Problem{SevError, "+all allows any sender; the record provides no protection"})
			}
		}
	}
	if !sawAll && out.Modifiers.Redirect == nil {
		out.Problems = append(out.Problems, Problem{SevWarning, "no \"all\" mechanism; unmatched senders get neutral"})
	}
	switch {
	case out.LookupCount > 10:
		out.Problems = append(out.Problems, Problem{SevError, "record needs " + strconv.Itoa(out.LookupCount) + " DNS lookups in this record alone, over the limit of 10 (RFC 7208 §4.6.4)"})
	case out.LookupCount > 6:
		out.Problems = append(out.Problems, Problem{SevWarning, "record uses " + strconv.Itoa(out.LookupCount) + " of 10 allowed DNS lookups before following includes"})
	}
	return out
}

// --- DMARC -----------------------------------------------------------------

// DecodeDMARC parses a v=DMARC1 record.
func DecodeDMARC(txt string) *DMARC {
	out := &DMARC{Kind: "dmarc", Problems: []Problem{}, Tags: DMARCTags{V: "DMARC1", RUA: []string{}, RUF: []string{}, Pct: 100, ADKIM: "r", ASPF: "r", FO: "0", RF: "afrf", RI: 86400}}
	tags, order := parseTags(txt)
	if len(order) == 0 || order[0] != "v" || !strings.EqualFold(tags["v"], "DMARC1") {
		out.Problems = append(out.Problems, Problem{SevError, "record must start with v=DMARC1"})
	}
	for _, k := range order {
		v := tags[k]
		switch k {
		case "v":
		case "p", "sp":
			lv := strings.ToLower(v)
			if lv != "none" && lv != "quarantine" && lv != "reject" {
				out.Problems = append(out.Problems, Problem{SevError, k + "=" + v + " is not none, quarantine or reject"})
			}
			if k == "p" {
				out.Tags.P = &lv
			} else {
				out.Tags.SP = &lv
			}
		case "rua", "ruf":
			uris := splitList(v)
			if k == "rua" {
				out.Tags.RUA = uris
			} else {
				out.Tags.RUF = uris
			}
			for _, u := range uris {
				if !strings.HasPrefix(strings.ToLower(u), "mailto:") {
					out.Problems = append(out.Problems, Problem{SevWarning, k + " URI is not mailto: " + u})
				}
			}
		case "pct":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 100 {
				out.Problems = append(out.Problems, Problem{SevError, "pct must be 0-100, got " + v})
			} else {
				out.Tags.Pct = n
				if n < 100 {
					out.Problems = append(out.Problems, Problem{SevInfo, "policy applies to " + v + "% of messages only"})
				}
			}
		case "adkim", "aspf":
			lv := strings.ToLower(v)
			if lv != "r" && lv != "s" {
				out.Problems = append(out.Problems, Problem{SevError, k + " must be r or s, got " + v})
			} else if k == "adkim" {
				out.Tags.ADKIM = lv
			} else {
				out.Tags.ASPF = lv
			}
		case "fo":
			out.Tags.FO = v
		case "rf":
			out.Tags.RF = v
		case "ri":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				out.Problems = append(out.Problems, Problem{SevError, "ri must be a non-negative integer, got " + v})
			} else {
				out.Tags.RI = n
			}
		default:
			out.Problems = append(out.Problems, Problem{SevWarning, "unknown tag " + k})
		}
	}
	if out.Tags.P == nil {
		out.Problems = append(out.Problems, Problem{SevError, "p tag is required"})
	} else if *out.Tags.P == "none" {
		out.Problems = append(out.Problems, Problem{SevInfo, "p=none only monitors; failing mail is still delivered"})
	}
	if len(out.Tags.RUA) == 0 {
		out.Problems = append(out.Problems, Problem{SevWarning, "no rua address; aggregate reports are not collected"})
	}
	return out
}

// --- DKIM ------------------------------------------------------------------

// DecodeDKIM parses a DKIM key record (RFC 6376 §3.6.1).
func DecodeDKIM(txt string) *DKIM {
	out := &DKIM{Kind: "dkim", Problems: []Problem{}, KeyType: "rsa"}
	tags, order := parseTags(txt)
	var pubB64 string
	hasP := false
	for _, k := range order {
		v := tags[k]
		switch k {
		case "v":
			out.Tags.V = ptr(v)
			if !strings.EqualFold(v, "DKIM1") {
				out.Problems = append(out.Problems, Problem{SevError, "v must be DKIM1, got " + v})
			}
		case "k":
			out.Tags.K = ptr(v)
			out.KeyType = strings.ToLower(v)
		case "h":
			out.Tags.H = ptr(v)
		case "t":
			out.Tags.T = ptr(v)
			for _, flag := range splitList(v) {
				switch strings.ToLower(flag) {
				case "y":
					out.Problems = append(out.Problems, Problem{SevInfo, "t=y marks the domain as testing; verifiers treat failures leniently"})
				case "s":
				default:
					out.Problems = append(out.Problems, Problem{SevWarning, "unknown t flag " + flag})
				}
			}
		case "s":
			out.Tags.S = ptr(v)
		case "n":
			out.Tags.N = ptr(v)
		case "p":
			hasP = true
			pubB64 = strings.Join(strings.Fields(v), "")
		default:
			out.Problems = append(out.Problems, Problem{SevWarning, "unknown tag " + k})
		}
	}
	if len(order) > 0 && order[0] == "v" {
		// fine
	} else if out.Tags.V != nil {
		out.Problems = append(out.Problems, Problem{SevWarning, "v tag must be first when present"})
	}
	if !hasP {
		out.Problems = append(out.Problems, Problem{SevError, "p tag is required"})
		return out
	}
	if pubB64 == "" {
		out.Revoked = true
		out.Problems = append(out.Problems, Problem{SevInfo, "empty p= means the key is revoked"})
		return out
	}
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		out.Problems = append(out.Problems, Problem{SevError, "p is not valid base64: " + err.Error()})
		return out
	}
	switch out.KeyType {
	case "rsa":
		bitsN := rsaBits(raw)
		if bitsN == 0 {
			out.Problems = append(out.Problems, Problem{SevError, "p does not decode as an RSA public key"})
			return out
		}
		out.KeyBits = bitsN
		switch {
		case bitsN < 1024:
			out.Problems = append(out.Problems, Problem{SevError, "RSA key is " + strconv.Itoa(bitsN) + " bits; verifiers reject keys under 1024 (RFC 8301)"})
		case bitsN < 2048:
			out.Problems = append(out.Problems, Problem{SevWarning, "RSA key is " + strconv.Itoa(bitsN) + " bits; 2048 is recommended"})
		}
	case "ed25519":
		if len(raw) != ed25519.PublicKeySize {
			out.Problems = append(out.Problems, Problem{SevError, "ed25519 key must be 32 bytes, got " + strconv.Itoa(len(raw))})
			return out
		}
		out.KeyBits = 256
	default:
		out.Problems = append(out.Problems, Problem{SevError, "unknown key type " + out.KeyType})
	}
	return out
}

// rsaBits reads the modulus size from a PKIX (SubjectPublicKeyInfo) or PKCS#1
// encoded RSA key. It parses the ASN.1 directly so keys Go's crypto package
// rejects as too small are still measured; that is exactly the case worth
// reporting.
func rsaBits(der []byte) int {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	pkcs1 := der
	if rest, err := asn1.Unmarshal(der, &spki); err == nil && len(rest) == 0 {
		pkcs1 = spki.PublicKey.RightAlign()
	}
	var key struct {
		N *big.Int
		E int
	}
	if rest, err := asn1.Unmarshal(pkcs1, &key); err != nil || len(rest) != 0 || key.N == nil {
		return 0
	}
	return key.N.BitLen()
}

// --- helpers ---------------------------------------------------------------

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
