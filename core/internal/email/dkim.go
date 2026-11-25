package email

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/n0rdy/nordyg/core/internal/prose"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/txtdecode"
)

// DKIMSelector is one selector that was tried and the key found there, if any.
type DKIMSelector struct {
	Selector string          `json:"selector"`
	Name     string          `json:"name"`
	Found    bool            `json:"found"`
	Record   string          `json:"record,omitempty"`
	Decoded  *txtdecode.DKIM `json:"decoded,omitempty"`
}

// DKIMSection is the outcome of trying a list of selectors.
type DKIMSection struct {
	Selectors []DKIMSelector `json:"selectors"`
	// Wildcard: every selector tried returned the same revoked key.
	Wildcard bool    `json:"wildcard"`
	Verdict  Verdict `json:"verdict"`
}

// DefaultSelectors are tried when the caller gives none. Grouped by who uses
// them; providers with random or date-based selectors (Amazon SES, Postmark)
// cannot be guessed and need the selector from a real message header.
var DefaultSelectors = []string{
	// generic
	"default", "dkim", "mail", "email", "smtp", "selector", "s", "key1", "key2", "sig1",
	// Google, Microsoft 365, iCloud (sig1 above)
	"google", "selector1", "selector2",
	// mailbox providers
	"protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3", "zmail", "zoho",
	// transactional and marketing senders
	"resend", "s1", "s2", "sendgrid", "k1", "k2", "k3", "mandrill", "mg", "mailgun", "mailo", "pic",
	"brevo1", "brevo2", "sib", "mailjet", "postmark", "pm", "smtpcom", "smtp2go", "sparkpost", "turbo-smtp",
	"amazonses", "ses", "cm", "krs", "mesmtp", "mxvault",
	// CRM, support and security gateways
	"hs1", "hs2", "hubspot", "zendesk1", "zendesk2", "freshdesk", "ctct1", "ctct2", "everlytickey1", "everlytickey2",
	"mimecast", "pp1", "barracuda",
}

// dkimLookups is how many selector lookups run at once. The default list is
// long, and a resolver may throttle a client that asks for all of it at once.
const dkimLookups = 8

func checkDKIM(ctx context.Context, r *resolve.Resolver, domain string, selectors []string) DKIMSection {
	sec := DKIMSection{Selectors: make([]DKIMSelector, len(selectors))}
	lookupErrs := make([]error, len(selectors))
	sem := make(chan struct{}, dkimLookups)
	var wg sync.WaitGroup
	for i, sel := range selectors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := sel + "._domainkey." + domain
			s := DKIMSelector{Selector: sel, Name: name}
			txts, err := txt(ctx, r, name)
			lookupErrs[i] = err
			for _, t := range txts {
				lower := strings.ToLower(t)
				if strings.Contains(lower, "p=") || strings.HasPrefix(lower, "v=dkim1") {
					s.Found, s.Record = true, t
					s.Decoded = txtdecode.DecodeDKIM(t)
					break
				}
			}
			sec.Selectors[i] = s
		}()
	}
	wg.Wait()

	found := 0
	weak := 0
	revoked := 0
	for _, s := range sec.Selectors {
		if !s.Found {
			continue
		}
		found++
		if s.Decoded != nil {
			if s.Decoded.Revoked {
				revoked++
			}
			for _, p := range s.Decoded.Problems {
				if p.Severity == txtdecode.SevError {
					weak++
					break
				}
			}
		}
	}
	switch {
	case found == 0 && !slices.Contains(lookupErrs, nil):
		sec.Verdict = Verdict{Status: Fail, Message: "TXT lookup failed: " + lookupErrs[0].Error()}
	case found == 0:
		// Not finding a key proves little: many providers use dated or random
		// selectors (Google: 20230601) that no list can guess.
		sec.Verdict = Verdict{Status: Info, Message: fmt.Sprintf("no key at the %d common selectors. Many providers use dated or random selectors, so enter yours to check", len(selectors))}
	case found == revoked && found == len(selectors):
		// Every guess answers with the same revoked key: a wildcard, the way a
		// domain says it signs no mail. Run judges it against the MX section.
		sec.Wildcard = true
		sec.Verdict = Verdict{Status: Fail, Message: "every selector returns a revoked key (a wildcard), so mail from this domain carries no valid signature"}
	case found == revoked:
		sec.Verdict = Verdict{Status: Fail, Message: "the only DKIM keys found are revoked (empty p=)"}
	case weak > 0:
		sec.Verdict = Verdict{Status: Fail, Message: fmt.Sprintf("%d DKIM key%s with errors (see the selector details)", weak, prose.Plural(weak))}
	default:
		sec.Verdict = Verdict{Status: OK, Message: fmt.Sprintf("%d DKIM key%s found", found, prose.Plural(found))}
	}
	return sec
}
