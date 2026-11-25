// Package email implements the "email" op: everything a mail admin checks
// about a domain, in one call, each part with a plain verdict.
package email

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/transport"
	"github.com/n0rdy/nordyg/core/internal/verdict"
)

// Params is the op input.
type Params struct {
	Domain    string              `json:"domain"`
	Endpoint  contract.Endpoint   `json:"endpoint"`
	Options   contract.Options    `json:"options"`
	Bootstrap []contract.Endpoint `json:"bootstrap"`
	// DKIMSelectors replaces the default selector list; ExtraSelectors are
	// added to whichever list is in use.
	DKIMSelectors  []string `json:"dkim_selectors"`
	ExtraSelectors []string `json:"extra_dkim_selectors"`
}

// Verdict statuses.
const (
	OK   = verdict.OK
	Info = verdict.Info
	Warn = verdict.Warn
	Fail = verdict.Fail
)

// Verdict is the one-line judgement for a section.
type Verdict = verdict.Finding

// Result is the op output.
type Result struct {
	Domain string        `json:"domain"`
	MX     MXSection     `json:"mx"`
	SPF    SPFSection    `json:"spf"`
	DKIM   DKIMSection   `json:"dkim"`
	DMARC  DMARCSection  `json:"dmarc"`
	MTASTS MTASTSSection `json:"mta_sts"`
	DANE   DANESection   `json:"dane"`
	// Transport is the transport security card's verdict: MTA-STS and DANE
	// together, counted once in the overall.
	Transport Verdict      `json:"transport"`
	BIMI      BIMISection  `json:"bimi"`
	DNSBL     DNSBLSection `json:"dnsbl"`
	Overall   Verdict      `json:"overall"`
}

// Op is the configured handler.
type Op struct {
	Client *transport.Client
	// FetchPolicy retrieves the MTA-STS policy text for host, connecting to
	// one of ips. Defaults to an HTTPS GET; tests replace it.
	FetchPolicy func(ctx context.Context, host string, ips []string) (string, error)
	// Zones overrides DNSBLZones (tests).
	Zones []string
	// SMTPAddrFor maps an MX address to ip:port for the DANE check.
	// Defaults to port 25; tests replace it.
	SMTPAddrFor func(ip string) string
	// SMTPTimeout bounds each port 25 connect (default 3 s).
	SMTPTimeout time.Duration
	// Validator validates TLSA and MX records for DANE; nil means the
	// embedded root anchors.
	Validator Validator
}

// Register attaches the op to d.
func (op *Op) Register(d *bridge.Dispatcher) {
	d.Register("email", bridge.Typed(op.Run))
}

// Run performs every check concurrently.
func (op *Op) Run(ctx context.Context, p Params) (*Result, error) {
	domain := strings.ToLower(strings.TrimSpace(p.Domain))
	if domain == "" {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "domain is required"}
	}
	if _, ok := dns.IsDomainName(domain); !ok {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "invalid domain name " + p.Domain}
	}
	if err := p.Endpoint.Validate(); err != nil {
		return nil, err
	}
	domain = dns.Fqdn(domain)
	r := &resolve.Resolver{Client: op.Client, Endpoint: p.Endpoint, Options: p.Options.Resolve(), Bootstrap: p.Bootstrap}
	r.Options.RecursionDesired = true
	if err := op.Client.CheckResolver(ctx, p.Endpoint, r.Options, p.Bootstrap); err != nil {
		return nil, err
	}

	res := &Result{Domain: domain}
	selectors := p.DKIMSelectors
	if len(selectors) == 0 {
		selectors = DefaultSelectors
	}
	for _, extra := range p.ExtraSelectors {
		if extra = strings.TrimSpace(extra); extra != "" && !contains(selectors, extra) {
			selectors = append([]string{extra}, selectors...)
		}
	}
	zones := op.Zones
	if zones == nil {
		zones = DNSBLZones
	}

	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	// DANE and the blocklists need the MX hosts, so they start once those
	// are known and then run side by side.
	run(func() {
		res.MX = checkMX(ctx, r, domain)
		var dane sync.WaitGroup
		dane.Add(1)
		go func() { defer dane.Done(); res.DANE = op.checkDANE(ctx, r, domain, res.MX) }()
		res.DNSBL = checkDNSBL(ctx, r, res.MX, zones)
		dane.Wait()
	})
	run(func() { res.SPF = checkSPF(ctx, r, domain) })
	run(func() { res.DKIM = checkDKIM(ctx, r, domain, selectors) })
	run(func() { res.DMARC = checkDMARC(ctx, r, domain) })
	run(func() { res.MTASTS = op.checkMTASTS(ctx, r, domain) })
	run(func() { res.BIMI = checkBIMI(ctx, r, domain) })
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// A domain that accepts no mail and sends none has nothing to report on.
	if res.MX.NullMX && res.DMARC.rejectNoRUA {
		res.DMARC.Verdict = Verdict{Status: Info, Message: "p=reject without reporting, which is fine for a domain that sends no mail"}
	}
	if res.MX.NullMX && res.DKIM.Wildcard {
		res.DKIM.Verdict = Verdict{Status: OK, Message: "signs no mail: every selector returns a revoked key, as a domain that sends none should"}
	}
	res.Transport = transportVerdict(res.MTASTS, res.DANE)
	res.Overall = overall(res)
	return res, nil
}

// transportVerdict joins MTA-STS and DANE: the worse of the two, except that
// either one set up correctly is enough and both missing is one sentence.
func transportVerdict(sts MTASTSSection, dane DANESection) Verdict {
	switch {
	case sts.off && dane.off:
		return Verdict{Status: Info, Message: "neither MTA-STS nor DANE is set up. Both are optional and make senders require TLS to your MX hosts"}
	case sts.off:
		return dane.Verdict
	case dane.off:
		return sts.Verdict
	case verdict.Rank(dane.Verdict.Status) > verdict.Rank(sts.Verdict.Status):
		return dane.Verdict
	}
	return sts.Verdict
}

func overall(r *Result) Verdict {
	if v, bad := verdict.Tally(r.MX.Verdict, r.SPF.Verdict, r.DKIM.Verdict, r.DMARC.Verdict, r.Transport, r.BIMI.Verdict, r.DNSBL.Verdict); bad {
		return v
	}
	if r.MX.NullMX {
		return Verdict{Status: OK, Message: "accepts no mail (null MX) and the sending side is locked down"}
	}
	return Verdict{Status: OK, Message: "mail authentication looks complete"}
}

// txt returns each TXT record the resolver answered with for name, joined
// into one string. Records are taken from the whole answer section, not only
// those owned by name, because providers publish DKIM keys and DMARC records
// behind CNAMEs (Proton, Mailchimp, many DMARC services) and the resolver
// returns the chased TXT under the target's name.
func txt(ctx context.Context, r *resolve.Resolver, name string) ([]string, error) {
	m, err := r.Answer(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

// hasVersion reports whether a TXT record opens with the version tag that
// marks its kind, such as "v=spf1".
func hasVersion(txt, tag string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), tag)
}

func contains(list []string, s string) bool {
	return slices.ContainsFunc(list, func(v string) bool { return strings.EqualFold(v, s) })
}
