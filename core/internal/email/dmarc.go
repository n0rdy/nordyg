package email

import (
	"context"
	"fmt"

	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/txtdecode"
)

// DMARCSection is the record at _dmarc.<domain> and the policy it sets.
type DMARCSection struct {
	Name    string           `json:"name"`
	Records []string         `json:"records"`
	Decoded *txtdecode.DMARC `json:"decoded,omitempty"`
	Verdict Verdict          `json:"verdict"`

	rejectNoRUA bool // p=reject at 100% with no aggregate report address
}

func checkDMARC(ctx context.Context, r *resolve.Resolver, domain string) DMARCSection {
	sec := DMARCSection{Name: "_dmarc." + domain, Records: []string{}}
	txts, err := txt(ctx, r, sec.Name)
	if err != nil {
		sec.Verdict = Verdict{Status: Fail, Message: "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if hasVersion(t, "v=dmarc1") {
			sec.Records = append(sec.Records, t)
		}
	}
	if len(sec.Records) == 0 {
		sec.Verdict = Verdict{Status: Fail, Message: "no DMARC record, so SPF and DKIM results are not enforced and no reports are sent"}
		return sec
	}
	sec.Decoded = txtdecode.DecodeDMARC(sec.Records[0])
	if len(sec.Records) > 1 {
		sec.Verdict = Verdict{Status: Fail, Message: "multiple DMARC records, and receivers ignore all of them"}
		return sec
	}
	for _, p := range sec.Decoded.Problems {
		if p.Severity == txtdecode.SevError {
			sec.Verdict = Verdict{Status: Fail, Message: p.Message}
			return sec
		}
	}
	policy := ""
	if sec.Decoded.Tags.P != nil {
		policy = *sec.Decoded.Tags.P
	}
	switch policy {
	case "none":
		sec.Verdict = Verdict{Status: Warn, Message: "p=none only monitors, so spoofed mail is still delivered. Move to quarantine or reject once reports look clean."}
	case "quarantine":
		if sec.Decoded.Tags.Pct < 100 {
			sec.Verdict = Verdict{Status: Warn, Message: fmt.Sprintf("p=quarantine applied to %d%% of failing mail", sec.Decoded.Tags.Pct)}
		} else {
			sec.Verdict = Verdict{Status: OK, Message: "p=quarantine, failing mail goes to spam"}
		}
	case "reject":
		if sec.Decoded.Tags.Pct < 100 {
			sec.Verdict = Verdict{Status: Warn, Message: fmt.Sprintf("p=reject applied to %d%% of failing mail", sec.Decoded.Tags.Pct)}
		} else if len(sec.Decoded.Tags.RUA) == 0 {
			sec.rejectNoRUA = true
			sec.Verdict = Verdict{Status: Warn, Message: "p=reject but no rua address, so you will not see what is being rejected"}
		} else {
			sec.Verdict = Verdict{Status: OK, Message: "p=reject with aggregate reporting"}
		}
	default:
		sec.Verdict = Verdict{Status: Fail, Message: "no valid p= policy"}
	}
	return sec
}
