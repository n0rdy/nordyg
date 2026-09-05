// Package email implements the "email" op: everything a mail admin checks
// about a domain, in one call, each part with a plain verdict.
package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/transport"
	"github.com/n0rdy/nordyg/core/internal/txtdecode"
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
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
	Info = "info"
)

// Verdict is the one-line judgement for a section.
type Verdict struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type PTRCheck struct {
	IP      string   `json:"ip"`
	Names   []string `json:"names"`
	Matches bool     `json:"matches"`
	Error   string   `json:"error,omitempty"`
}

type MXHost struct {
	Preference uint16     `json:"preference"`
	Exchange   string     `json:"exchange"`
	Addresses  []string   `json:"addresses"`
	PTR        []PTRCheck `json:"ptr"`
	Error      string     `json:"error,omitempty"`
}

type MXSection struct {
	Hosts    []MXHost `json:"hosts"`
	NullMX   bool     `json:"null_mx"`
	Implicit bool     `json:"implicit"`
	Verdict  Verdict  `json:"verdict"`
}

type SPFInclude struct {
	Name    string         `json:"name"`
	Via     string         `json:"via"`
	Depth   int            `json:"depth"`
	Record  string         `json:"record,omitempty"`
	Decoded *txtdecode.SPF `json:"decoded,omitempty"`
	Lookups int            `json:"lookups"`
	Error   string         `json:"error,omitempty"`
}

type SPFSection struct {
	Records      []string       `json:"records"`
	Decoded      *txtdecode.SPF `json:"decoded,omitempty"`
	Includes     []SPFInclude   `json:"includes"`
	TotalLookups int            `json:"total_lookups"`
	Verdict      Verdict        `json:"verdict"`
}

type DKIMSelector struct {
	Selector string          `json:"selector"`
	Name     string          `json:"name"`
	Found    bool            `json:"found"`
	Record   string          `json:"record,omitempty"`
	Decoded  *txtdecode.DKIM `json:"decoded,omitempty"`
}

type DKIMSection struct {
	Selectors []DKIMSelector `json:"selectors"`
	Verdict   Verdict        `json:"verdict"`
}

type DMARCSection struct {
	Name    string           `json:"name"`
	Records []string         `json:"records"`
	Decoded *txtdecode.DMARC `json:"decoded,omitempty"`
	Verdict Verdict          `json:"verdict"`
}

type MTASTSPolicy struct {
	Version string   `json:"version"`
	Mode    string   `json:"mode"`
	MX      []string `json:"mx"`
	MaxAge  int      `json:"max_age"`
}

type MTASTSSection struct {
	Name       string        `json:"name"`
	Record     string        `json:"record,omitempty"`
	ID         string        `json:"id,omitempty"`
	PolicyURL  string        `json:"policy_url,omitempty"`
	PolicyText string        `json:"policy_text,omitempty"`
	Policy     *MTASTSPolicy `json:"policy,omitempty"`
	Error      string        `json:"error,omitempty"`
	Verdict    Verdict       `json:"verdict"`
}

type BIMISection struct {
	Name     string  `json:"name"`
	Record   string  `json:"record,omitempty"`
	Logo     string  `json:"logo,omitempty"`
	Evidence string  `json:"evidence,omitempty"`
	Verdict  Verdict `json:"verdict"`
}

type DNSBLCheck struct {
	IP       string `json:"ip"`
	Zone     string `json:"zone"`
	Listed   bool   `json:"listed"`
	Blocked  bool   `json:"blocked"`
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

type DNSBLSection struct {
	Checks  []DNSBLCheck `json:"checks"`
	Verdict Verdict      `json:"verdict"`
}

// Result is the op output.
type Result struct {
	Domain  string        `json:"domain"`
	MX      MXSection     `json:"mx"`
	SPF     SPFSection    `json:"spf"`
	DKIM    DKIMSection   `json:"dkim"`
	DMARC   DMARCSection  `json:"dmarc"`
	MTASTS  MTASTSSection `json:"mta_sts"`
	BIMI    BIMISection   `json:"bimi"`
	DNSBL   DNSBLSection  `json:"dnsbl"`
	Overall Verdict       `json:"overall"`
}

// DefaultSelectors are tried when the caller gives none.
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

// DNSBLZones are queried for every MX IPv4 address.
var DNSBLZones = []string{"zen.spamhaus.org.", "bl.spamcop.net.", "b.barracudacentral.org."}

const maxSPFDepth = 10

// Op is the configured handler.
type Op struct {
	Client *transport.Client
	// FetchPolicy retrieves the MTA-STS policy text for host, connecting to
	// one of ips. Defaults to an HTTPS GET; tests replace it.
	FetchPolicy func(ctx context.Context, host string, ips []string) (string, error)
	// Zones overrides DNSBLZones (tests).
	Zones []string
}

// Register attaches the op to d.
func (op *Op) Register(d *bridge.Dispatcher) {
	d.Register("email", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p Params
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
		}
		return op.Run(ctx, p)
	})
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
	r := &resolver{client: op.Client, ep: p.Endpoint, o: p.Options.Resolve(), boot: p.Bootstrap}
	r.o.RecursionDesired = true

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
	run(func() {
		res.MX = checkMX(ctx, r, domain)
		res.DNSBL = checkDNSBL(ctx, r, res.MX, zones)
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
	res.Overall = overall(res)
	return res, nil
}

func overall(r *Result) Verdict {
	fails, warns := 0, 0
	for _, v := range []Verdict{r.MX.Verdict, r.SPF.Verdict, r.DKIM.Verdict, r.DMARC.Verdict, r.MTASTS.Verdict, r.BIMI.Verdict, r.DNSBL.Verdict} {
		switch v.Status {
		case Fail:
			fails++
		case Warn:
			warns++
		}
	}
	switch {
	case fails > 0:
		return Verdict{Fail, fmt.Sprintf("%d check%s failing, %d warning%s", fails, plural(fails), warns, plural(warns))}
	case warns > 0:
		return Verdict{Warn, fmt.Sprintf("no failures, %d warning%s", warns, plural(warns))}
	}
	return Verdict{OK, "mail authentication looks complete"}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// --- resolver ----------------------------------------------------------------

type resolver struct {
	client *transport.Client
	ep     contract.Endpoint
	o      contract.Effective
	boot   []contract.Endpoint
}

func (r *resolver) lookup(ctx context.Context, name string, t uint16) (*dns.Msg, error) {
	q := r.o.Build(contract.Resolved{Name: dns.Fqdn(name), Type: t, Class: dns.ClassINET})
	res, err := r.client.Exchange(ctx, r.ep, q, r.o, r.boot)
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// txt returns each TXT record the resolver answered with for name, joined
// into one string. Records are taken from the whole answer section, not only
// those owned by name, because providers publish DKIM keys and DMARC records
// behind CNAMEs (Proton, Mailchimp, many DMARC services) and the resolver
// returns the chased TXT under the target's name.
func (r *resolver) txt(ctx context.Context, name string) ([]string, error) {
	m, err := r.lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return nil, errors.New(dns.RcodeToString[m.Rcode])
	}
	var out []string
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

func (r *resolver) addrs(ctx context.Context, name string) ([]string, error) {
	var out []string
	var firstErr error
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m, err := r.lookup(ctx, name, t)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, rr := range m.Answer {
			switch a := rr.(type) {
			case *dns.A:
				out = append(out, a.A.String())
			case *dns.AAAA:
				out = append(out, a.AAAA.String())
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// --- MX + PTR ----------------------------------------------------------------

func checkMX(ctx context.Context, r *resolver, domain string) MXSection {
	sec := MXSection{Hosts: []MXHost{}}
	m, err := r.lookup(ctx, domain, dns.TypeMX)
	if err != nil {
		sec.Verdict = Verdict{Fail, "MX lookup failed: " + err.Error()}
		return sec
	}
	var mxs []*dns.MX
	for _, rr := range m.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			mxs = append(mxs, mx)
		}
	}
	sort.Slice(mxs, func(a, b int) bool { return mxs[a].Preference < mxs[b].Preference })
	if len(mxs) == 1 && mxs[0].Mx == "." {
		sec.NullMX = true
		sec.Hosts = append(sec.Hosts, MXHost{Preference: 0, Exchange: ".", Addresses: []string{}, PTR: []PTRCheck{}})
		sec.Verdict = Verdict{Info, "null MX: the domain declares it does not accept mail (RFC 7505)"}
		return sec
	}
	if len(mxs) == 0 {
		sec.Implicit = true
		addrs, _ := r.addrs(ctx, domain)
		if len(addrs) == 0 {
			sec.Verdict = Verdict{Fail, "no MX records and no address records; the domain cannot receive mail"}
			return sec
		}
		host := MXHost{Preference: 0, Exchange: domain, Addresses: addrs}
		host.PTR = ptrChecks(ctx, r, addrs, domain)
		sec.Hosts = append(sec.Hosts, host)
		sec.Verdict = Verdict{Warn, "no MX records; mail falls back to the domain's own address (implicit MX). Publish MX records explicitly."}
		return sec
	}

	var wg sync.WaitGroup
	hosts := make([]MXHost, len(mxs))
	for i, mx := range mxs {
		wg.Add(1)
		go func(i int, mx *dns.MX) {
			defer wg.Done()
			h := MXHost{Preference: mx.Preference, Exchange: mx.Mx, Addresses: []string{}, PTR: []PTRCheck{}}
			addrs, err := r.addrs(ctx, mx.Mx)
			if err != nil {
				h.Error = err.Error()
			} else if len(addrs) == 0 {
				h.Error = "host has no address records"
			}
			h.Addresses = addrs
			if h.Addresses == nil {
				h.Addresses = []string{}
			}
			h.PTR = ptrChecks(ctx, r, addrs, mx.Mx)
			hosts[i] = h
		}(i, mx)
	}
	wg.Wait()
	sec.Hosts = hosts

	broken, ptrMiss := 0, 0
	for _, h := range hosts {
		if h.Error != "" {
			broken++
		}
		for _, p := range h.PTR {
			if !p.Matches {
				ptrMiss++
			}
		}
	}
	switch {
	case broken == len(hosts):
		sec.Verdict = Verdict{Fail, "none of the MX hosts resolve to an address"}
	case broken > 0:
		sec.Verdict = Verdict{Warn, fmt.Sprintf("%d of %d MX hosts do not resolve", broken, len(hosts))}
	case ptrMiss > 0:
		sec.Verdict = Verdict{Warn, fmt.Sprintf("%d MX address%s without a matching reverse (PTR) record; some receivers score this against the sender", ptrMiss, pluralEs(ptrMiss))}
	default:
		sec.Verdict = Verdict{OK, fmt.Sprintf("%d MX host%s, all resolve with matching reverse records", len(hosts), plural(len(hosts)))}
	}
	return sec
}

func pluralEs(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// ptrChecks does the forward-confirmed reverse DNS round trip for each address.
func ptrChecks(ctx context.Context, r *resolver, addrs []string, expect string) []PTRCheck {
	out := make([]PTRCheck, 0, len(addrs))
	for _, ip := range addrs {
		c := PTRCheck{IP: ip, Names: []string{}}
		rev, err := dns.ReverseAddr(ip)
		if err != nil {
			c.Error = err.Error()
			out = append(out, c)
			continue
		}
		m, err := r.lookup(ctx, rev, dns.TypePTR)
		if err != nil {
			c.Error = err.Error()
			out = append(out, c)
			continue
		}
		for _, rr := range m.Answer {
			if p, ok := rr.(*dns.PTR); ok {
				c.Names = append(c.Names, strings.ToLower(p.Ptr))
			}
		}
		// Forward-confirm: any PTR name that resolves back to the IP counts,
		// and a PTR equal to the MX name is the ideal.
		for _, n := range c.Names {
			if strings.EqualFold(n, expect) {
				c.Matches = true
				break
			}
			fwd, err := r.addrs(ctx, n)
			if err == nil && contains(fwd, ip) {
				c.Matches = true
				break
			}
		}
		out = append(out, c)
	}
	return out
}

// --- SPF -----------------------------------------------------------------------

func checkSPF(ctx context.Context, r *resolver, domain string) SPFSection {
	sec := SPFSection{Records: []string{}, Includes: []SPFInclude{}}
	txts, err := r.txt(ctx, domain)
	if err != nil {
		sec.Verdict = Verdict{Fail, "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			sec.Records = append(sec.Records, t)
		}
	}
	if len(sec.Records) == 0 {
		sec.Verdict = Verdict{Fail, "no SPF record; receivers cannot tell which servers may send mail for the domain"}
		return sec
	}
	sec.Decoded = txtdecode.DecodeSPF(sec.Records[0])
	visited := map[string]bool{strings.ToLower(domain): true}
	sec.TotalLookups = sec.Decoded.LookupCount + followIncludes(ctx, r, sec.Decoded, domain, 1, visited, &sec.Includes)

	if len(sec.Records) > 1 {
		sec.Verdict = Verdict{Fail, fmt.Sprintf("%d SPF records; receivers treat multiple records as a permanent error (RFC 7208 §3.2)", len(sec.Records))}
		return sec
	}
	for _, p := range sec.Decoded.Problems {
		if p.Severity == txtdecode.SevError {
			sec.Verdict = Verdict{Fail, p.Message}
			return sec
		}
	}
	for _, inc := range sec.Includes {
		if inc.Error != "" {
			sec.Verdict = Verdict{Fail, "include:" + prose(inc.Name) + " could not be resolved: " + inc.Error}
			return sec
		}
	}
	switch {
	case sec.TotalLookups > 10:
		sec.Verdict = Verdict{Fail, fmt.Sprintf("%d DNS lookups across the include chain, over the limit of 10; receivers return permerror", sec.TotalLookups)}
	case sec.TotalLookups > 8:
		sec.Verdict = Verdict{Warn, fmt.Sprintf("%d of 10 allowed DNS lookups used across the include chain; one more sender may break SPF", sec.TotalLookups)}
	case lastAll(sec.Decoded) == "?" || (lastAll(sec.Decoded) == "" && sec.Decoded.Modifiers.Redirect == nil):
		sec.Verdict = Verdict{Warn, "record ends without -all or ~all, so unauthorised senders get a neutral result"}
	default:
		sec.Verdict = Verdict{OK, fmt.Sprintf("valid, %d of 10 lookups used, ends with %sall", sec.TotalLookups, lastAll(sec.Decoded))}
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
func followIncludes(ctx context.Context, r *resolver, s *txtdecode.SPF, via string, depth int, visited map[string]bool, out *[]SPFInclude) int {
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
		txts, err := r.txt(ctx, name)
		if err != nil {
			inc.Error = err.Error()
			*out = append(*out, inc)
			continue
		}
		for _, x := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(x)), "v=spf1") {
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

// --- DKIM ----------------------------------------------------------------------

func checkDKIM(ctx context.Context, r *resolver, domain string, selectors []string) DKIMSection {
	sec := DKIMSection{Selectors: make([]DKIMSelector, len(selectors))}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, sel := range selectors {
		wg.Add(1)
		go func(i int, sel string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := sel + "._domainkey." + domain
			s := DKIMSelector{Selector: sel, Name: name}
			txts, err := r.txt(ctx, name)
			if err == nil {
				for _, t := range txts {
					lower := strings.ToLower(t)
					if strings.Contains(lower, "p=") || strings.HasPrefix(lower, "v=dkim1") {
						s.Found, s.Record = true, t
						s.Decoded = txtdecode.DecodeDKIM(t)
						break
					}
				}
			}
			sec.Selectors[i] = s
		}(i, sel)
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
	case found == 0:
		sec.Verdict = Verdict{Warn, fmt.Sprintf("no DKIM key at %d common selectors; if the domain sends mail, enter the selector your provider uses", len(selectors))}
	case found == revoked:
		sec.Verdict = Verdict{Fail, "the only DKIM keys found are revoked (empty p=)"}
	case weak > 0:
		sec.Verdict = Verdict{Fail, fmt.Sprintf("%d DKIM key%s with errors (see the selector details)", weak, plural(weak))}
	default:
		sec.Verdict = Verdict{OK, fmt.Sprintf("%d DKIM key%s found", found, plural(found))}
	}
	return sec
}

// --- DMARC ----------------------------------------------------------------------

func checkDMARC(ctx context.Context, r *resolver, domain string) DMARCSection {
	sec := DMARCSection{Name: "_dmarc." + domain, Records: []string{}}
	txts, err := r.txt(ctx, sec.Name)
	if err != nil {
		sec.Verdict = Verdict{Fail, "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			sec.Records = append(sec.Records, t)
		}
	}
	if len(sec.Records) == 0 {
		sec.Verdict = Verdict{Fail, "no DMARC record; SPF and DKIM results are not enforced and no reports are sent"}
		return sec
	}
	sec.Decoded = txtdecode.DecodeDMARC(sec.Records[0])
	if len(sec.Records) > 1 {
		sec.Verdict = Verdict{Fail, "multiple DMARC records; receivers ignore all of them"}
		return sec
	}
	for _, p := range sec.Decoded.Problems {
		if p.Severity == txtdecode.SevError {
			sec.Verdict = Verdict{Fail, p.Message}
			return sec
		}
	}
	policy := ""
	if sec.Decoded.Tags.P != nil {
		policy = *sec.Decoded.Tags.P
	}
	switch policy {
	case "none":
		sec.Verdict = Verdict{Warn, "p=none only monitors; spoofed mail is still delivered. Move to quarantine or reject once reports look clean."}
	case "quarantine":
		if sec.Decoded.Tags.Pct < 100 {
			sec.Verdict = Verdict{Warn, fmt.Sprintf("p=quarantine applied to %d%% of failing mail", sec.Decoded.Tags.Pct)}
		} else {
			sec.Verdict = Verdict{OK, "p=quarantine, failing mail goes to spam"}
		}
	case "reject":
		if sec.Decoded.Tags.Pct < 100 {
			sec.Verdict = Verdict{Warn, fmt.Sprintf("p=reject applied to %d%% of failing mail", sec.Decoded.Tags.Pct)}
		} else if len(sec.Decoded.Tags.RUA) == 0 {
			sec.Verdict = Verdict{Warn, "p=reject but no rua address; you will not see what is being rejected"}
		} else {
			sec.Verdict = Verdict{OK, "p=reject with aggregate reporting"}
		}
	default:
		sec.Verdict = Verdict{Fail, "no valid p= policy"}
	}
	return sec
}

// --- MTA-STS -----------------------------------------------------------------

func (op *Op) checkMTASTS(ctx context.Context, r *resolver, domain string) MTASTSSection {
	sec := MTASTSSection{Name: "_mta-sts." + domain}
	txts, err := r.txt(ctx, sec.Name)
	if err != nil {
		sec.Verdict = Verdict{Fail, "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=stsv1") {
			sec.Record = t
			break
		}
	}
	if sec.Record == "" {
		sec.Verdict = Verdict{Info, "not configured; MTA-STS is optional and tells senders to require TLS to your MX hosts"}
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
	ips, err := r.addrs(ctx, host)
	if err != nil || len(ips) == 0 {
		sec.Error = "policy host " + host + " does not resolve"
		sec.Verdict = Verdict{Fail, sec.Error}
		return sec
	}
	fetch := op.FetchPolicy
	if fetch == nil {
		fetch = fetchPolicyHTTPS
	}
	text, err := fetch(ctx, host, ips)
	if err != nil {
		sec.Error = err.Error()
		sec.Verdict = Verdict{Fail, "policy file could not be fetched: " + err.Error()}
		return sec
	}
	sec.PolicyText = text
	sec.Policy = parsePolicy(text)
	switch {
	case sec.Policy.Version != "STSv1":
		sec.Verdict = Verdict{Fail, "policy file has no version: STSv1 line"}
	case sec.Policy.Mode == "enforce":
		sec.Verdict = Verdict{OK, fmt.Sprintf("enforce mode, %d MX pattern%s, max_age %d s", len(sec.Policy.MX), plural(len(sec.Policy.MX)), sec.Policy.MaxAge)}
	case sec.Policy.Mode == "testing":
		sec.Verdict = Verdict{Warn, "testing mode: senders report failures but still deliver over plain text"}
	case sec.Policy.Mode == "none":
		sec.Verdict = Verdict{Info, "mode none: policy published but switched off"}
	default:
		sec.Verdict = Verdict{Fail, "policy file has no valid mode"}
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

// --- BIMI --------------------------------------------------------------------

func checkBIMI(ctx context.Context, r *resolver, domain string) BIMISection {
	sec := BIMISection{Name: "default._bimi." + domain}
	txts, err := r.txt(ctx, sec.Name)
	if err != nil {
		sec.Verdict = Verdict{Fail, "TXT lookup failed: " + err.Error()}
		return sec
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=bimi1") {
			sec.Record = t
			break
		}
	}
	if sec.Record == "" {
		sec.Verdict = Verdict{Info, "not configured; BIMI shows your logo in supporting inboxes and needs DMARC at quarantine or reject"}
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
	case sec.Logo == "":
		sec.Verdict = Verdict{Fail, "BIMI record without a logo URL (l=)"}
	case !strings.HasPrefix(sec.Logo, "https://"):
		sec.Verdict = Verdict{Fail, "BIMI logo URL must be https"}
	case sec.Evidence == "":
		sec.Verdict = Verdict{OK, "logo published; no VMC/CMC certificate (a=), so Gmail and Apple Mail will not show it"}
	default:
		sec.Verdict = Verdict{OK, "logo and evidence certificate published"}
	}
	return sec
}

// --- DNSBL --------------------------------------------------------------------

func checkDNSBL(ctx context.Context, r *resolver, mx MXSection, zones []string) DNSBLSection {
	sec := DNSBLSection{Checks: []DNSBLCheck{}}
	var ips []string
	for _, h := range mx.Hosts {
		for _, ip := range h.Addresses {
			if net.ParseIP(ip).To4() != nil && !contains(ips, ip) {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		sec.Verdict = Verdict{Info, "no IPv4 MX addresses to check"}
		return sec
	}
	type key struct{ ip, zone string }
	results := map[key]DNSBLCheck{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		for _, zone := range zones {
			wg.Add(1)
			go func(ip, zone string) {
				defer wg.Done()
				c := DNSBLCheck{IP: ip, Zone: strings.TrimSuffix(zone, ".")}
				rev := reverse4(ip) + "." + dns.Fqdn(zone)
				m, err := r.lookup(ctx, rev, dns.TypeA)
				if err != nil {
					c.Error = err.Error()
				} else {
					for _, rr := range m.Answer {
						if a, ok := rr.(*dns.A); ok {
							c.Response = a.A.String()
							// 127.255.255.x: the list refuses to answer this resolver (open/public resolver, over quota).
							if strings.HasPrefix(c.Response, "127.255.") {
								c.Blocked = true
							} else if strings.HasPrefix(c.Response, "127.") {
								c.Listed = true
							}
						}
					}
				}
				mu.Lock()
				results[key{ip, zone}] = c
				mu.Unlock()
			}(ip, zone)
		}
	}
	wg.Wait()
	for _, ip := range ips {
		for _, zone := range zones {
			sec.Checks = append(sec.Checks, results[key{ip, zone}])
		}
	}
	listed, blocked := 0, 0
	for _, c := range sec.Checks {
		if c.Listed {
			listed++
		}
		if c.Blocked {
			blocked++
		}
	}
	switch {
	case listed > 0:
		sec.Verdict = Verdict{Fail, fmt.Sprintf("%d listing%s on blocklists; receivers using them will refuse mail from these MX hosts", listed, plural(listed))}
	case blocked == len(sec.Checks):
		sec.Verdict = Verdict{Info, "the blocklists refuse queries from this resolver (public resolvers are blocked); use your ISP or system resolver to check"}
	case blocked > 0:
		sec.Verdict = Verdict{OK, fmt.Sprintf("not listed where the lists answered; %d list%s refused this resolver", blocked, plural(blocked))}
	default:
		sec.Verdict = Verdict{OK, fmt.Sprintf("%d address%s clean on %d blocklists", len(ips), pluralEs(len(ips)), len(zones))}
	}
	return sec
}

func reverse4(ip string) string {
	p := strings.Split(ip, ".")
	for i, j := 0, len(p)-1; i < j; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}
	return strings.Join(p, ".")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func prose(name string) string { return strings.TrimSuffix(name, ".") }
