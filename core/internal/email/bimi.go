package email

import (
	"context"
	"strings"

	"github.com/n0rdy/nordyg/core/internal/resolve"
)

// BIMISection is the record at default._bimi.<domain>.
type BIMISection struct {
	Name     string  `json:"name"`
	Record   string  `json:"record,omitempty"`
	Logo     string  `json:"logo,omitempty"`
	Evidence string  `json:"evidence,omitempty"`
	Verdict  Verdict `json:"verdict"`
}

func checkBIMI(ctx context.Context, r *resolve.Resolver, domain string) BIMISection {
	sec := BIMISection{Name: "default._bimi." + domain}
	txts, err := txt(ctx, r, sec.Name)
	if err != nil {
		sec.Verdict = Verdict{Status: Fail, Message: "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if hasVersion(t, "v=bimi1") {
			sec.Record = t
			break
		}
	}
	if sec.Record == "" {
		sec.Verdict = Verdict{Status: Info, Message: "not configured. BIMI shows your logo in supporting inboxes and needs DMARC at quarantine or reject"}
		return sec
	}
	for _, part := range strings.Split(sec.Record, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "l":
			sec.Logo = strings.TrimSpace(v)
		case "a":
			sec.Evidence = strings.TrimSpace(v)
		}
	}
	switch {
	case sec.Logo == "" && sec.Evidence == "":
		// "v=BIMI1; l=; a=;" is the BIMI spec's declination record.
		sec.Verdict = Verdict{Status: Info, Message: "declined: the record says this domain shows no logo (empty l= and a=)"}
	case sec.Logo == "":
		sec.Verdict = Verdict{Status: Fail, Message: "BIMI record without a logo URL (l=)"}
	case !strings.HasPrefix(sec.Logo, "https://"):
		sec.Verdict = Verdict{Status: Fail, Message: "BIMI logo URL must be https"}
	case sec.Evidence == "":
		sec.Verdict = Verdict{Status: OK, Message: "logo published without a VMC/CMC certificate (a=), so Gmail and Apple Mail will not show it"}
	default:
		sec.Verdict = Verdict{Status: OK, Message: "logo and evidence certificate published"}
	}
	return sec
}
