package txtdecode

import (
	"strconv"
	"strings"
)

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
		out.Problems = append(out.Problems, Problem{SevInfo, "p=none only monitors, so failing mail is still delivered"})
	}
	if len(out.Tags.RUA) == 0 {
		out.Problems = append(out.Problems, Problem{SevWarning, "no rua address, so aggregate reports are not collected"})
	}
	return out
}
