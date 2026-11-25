// Package health implements the "health" op, a lightweight Zonemaster: it
// walks the delegation from the root, asks every nameserver of the zone
// directly, and reports each check with a plain verdict.
package health

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/certs"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/prose"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/trace"
	"github.com/n0rdy/nordyg/core/internal/transport"
	"github.com/n0rdy/nordyg/core/internal/verdict"
)

// Params is the op input. Endpoint is the resolver used for nameserver
// addresses and CAA; everything about the zone itself is asked of the
// zone's own servers.
type Params struct {
	Domain    string              `json:"domain"`
	Endpoint  contract.Endpoint   `json:"endpoint"`
	Options   contract.Options    `json:"options"`
	Bootstrap []contract.Endpoint `json:"bootstrap"`
	// RootHints overrides the root servers (ip:port), for tests.
	RootHints []string `json:"root_hints"`
}

// Finding statuses, worst last.
const (
	OK   = verdict.OK
	Info = verdict.Info
	Warn = verdict.Warn
	Fail = verdict.Fail
)

// Finding is one observation with its severity.
type Finding = verdict.Finding

// Section carries the verdict and the findings behind it. It is embedded in
// every section, so its fields appear inline in the JSON.
type Section struct {
	Verdict  Finding   `json:"verdict"`
	Findings []Finding `json:"findings"`
}

func (s *Section) add(status, format string, args ...any) {
	s.Findings = append(s.Findings, Finding{Status: status, Message: fmt.Sprintf(format, args...)})
}

// settle sets the verdict to the worst finding, or to ok with okMsg.
func (s *Section) settle(okMsg string) {
	s.Verdict = verdict.Worst(s.Findings, okMsg)
}

// Delegation compares what the parent says with what the zone says.
type Delegation struct {
	Parent   string   `json:"parent"`
	ParentNS []string `json:"parent_ns"`
	ChildNS  []string `json:"child_ns"`
	Section
}

// Server is one nameserver address and what it answered.
type Server struct {
	Name          string    `json:"name"`
	IP            string    `json:"ip"`
	AtParent      bool      `json:"at_parent"`
	AtChild       bool      `json:"at_child"`
	Answered      bool      `json:"answered"`
	Skipped       bool      `json:"skipped"`
	Authoritative bool      `json:"authoritative"`
	Rcode         string    `json:"rcode,omitempty"`
	Serial        *uint32   `json:"serial,omitempty"`
	NS            []string  `json:"ns"`
	TCP           bool      `json:"tcp"`
	EDNS          bool      `json:"edns"`
	Signed        bool      `json:"signed"`
	AXFR          string    `json:"axfr"`
	Recursion     bool      `json:"recursion"`
	RTTms         float64   `json:"rtt_ms"`
	Error         string    `json:"error,omitempty"`
	Status        string    `json:"status"`
	Problems      []Finding `json:"problems"`

	soa        *dns.SOA // the full record, for the SOA section
	unresolved bool     // the address lookup failed, so nothing is known about it
}

// AXFR outcomes.
const (
	AXFRRefused    = "refused"
	AXFRAllowed    = "allowed"
	AXFRNoAnswer   = "no_answer"
	AXFRNotChecked = "not_checked"
)

// Nameservers is the per-address table.
type Nameservers struct {
	Servers []Server `json:"servers"`
	Section
}

// SerialGroup is one SOA serial and the servers serving it.
type SerialGroup struct {
	Serial  uint32   `json:"serial"`
	Servers []string `json:"servers"`

	names []string // the servers' names without their addresses
}

// SOA reports the zone's SOA and serial agreement.
type SOA struct {
	Record  *contract.Record `json:"record,omitempty"`
	Serials []SerialGroup    `json:"serials"`
	Section
}

// GlueEntry compares the parent's glue for one nameserver name with the
// zone's own address records for it.
type GlueEntry struct {
	Name        string   `json:"name"`
	InBailiwick bool     `json:"in_bailiwick"`
	Parent      []string `json:"parent"`
	Child       []string `json:"child"`
	Match       bool     `json:"match"`
}

// Glue is the glue check.
type Glue struct {
	Entries []GlueEntry `json:"entries"`
	Section
}

// DNSSEC is the chain verdict plus per-server signing and DS hygiene.
type DNSSEC struct {
	Status string            `json:"status"`
	DS     []contract.Record `json:"ds"`
	Result *dnssec.Result    `json:"result,omitempty"`
	Section
}

// CAARecord is one CAA record.
type CAARecord struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// CAA is the CAA check, with RFC 8659 tree climbing.
type CAA struct {
	FoundAt string      `json:"found_at,omitempty"`
	Records []CAARecord `json:"records"`
	Section
}

// Result is the op output.
type Result struct {
	Domain      string      `json:"domain"`
	Zone        string      `json:"zone"`
	Delegation  Delegation  `json:"delegation"`
	Nameservers Nameservers `json:"nameservers"`
	SOA         SOA         `json:"soa"`
	Glue        Glue        `json:"glue"`
	DNSSEC      DNSSEC      `json:"dnssec"`
	CAA         CAA         `json:"caa"`
	HTTPS       HTTPS       `json:"https"`
	Overall     Finding     `json:"overall"`

	skippedRest bool // the delegation was too broken to check the sections after it
}

const notChecked = "not checked: the delegation is broken"

// Op is the configured handler.
type Op struct {
	Client *transport.Client
	Trace  *trace.Op
	// AddrFor maps a nameserver IP to ip:port. Defaults to port 53; tests
	// remap to local ports.
	AddrFor func(ip string) string
	// HTTPSAddrFor maps a web server IP to ip:port. Defaults to port 443.
	HTTPSAddrFor func(ip string) string
	// Certs inspects TLS certificates; nil means the system trust store and
	// CRLs fetched through the chosen resolver.
	Certs *certs.Inspector
}

// Register attaches the op to d.
func (op *Op) Register(d *bridge.Dispatcher) {
	d.Register("health", bridge.Typed(op.Run))
}

// Run performs the checks.
func (op *Op) Run(ctx context.Context, p Params) (*Result, error) {
	domain := strings.ToLower(strings.TrimSpace(p.Domain))
	if domain == "" {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "domain is required"}
	}
	if _, ok := dns.IsDomainName(domain); !ok {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "invalid domain name " + p.Domain}
	}
	domain = dns.Fqdn(domain)
	if domain == "." {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "the root zone has no parent to check against"}
	}
	if err := p.Endpoint.Validate(); err != nil {
		return nil, err
	}
	o := p.Options.Resolve()
	r := &resolve.Resolver{Client: op.Client, Endpoint: p.Endpoint, Options: o, Bootstrap: p.Bootstrap}
	if err := op.Client.CheckResolver(ctx, p.Endpoint, o, p.Bootstrap); err != nil {
		return nil, err
	}
	r.Options.RecursionDesired = true

	res := &Result{Domain: domain, Zone: domain}
	res.Delegation.ParentNS, res.Delegation.ChildNS = []string{}, []string{}
	res.Nameservers.Servers = []Server{}
	res.SOA.Serials = []SerialGroup{}
	res.Glue.Entries = []GlueEntry{}
	res.DNSSEC.DS = []contract.Record{}
	res.CAA.Records = []CAARecord{}
	res.HTTPS.Hosts = []HTTPSHost{}

	// CAA depends only on the resolver; run it alongside everything else.
	// HTTPS needs CAA (issuer check) and the apex, so it waits for both.
	var wg sync.WaitGroup
	caaDone := make(chan struct{})
	wg.Add(1)
	go func() { defer wg.Done(); defer close(caaDone); res.CAA = checkCAA(ctx, r, domain) }()
	// The goroutines write into res, so no return path may leave one behind.
	defer wg.Wait()

	tr, hops, traceErr := op.trace(ctx, p, domain)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	apex, exists := zoneApex(tr, hops, domain)
	res.Zone = apex
	ref, parent := referralFor(hops, apex)

	d := &res.Delegation
	if ref == nil && traceErr == nil && exists && len(hops) > 0 {
		// The parent's servers may host the zone too (.cz and nic.cz), so
		// the trace got an answer instead of a referral.
		if last := hops[len(hops)-1]; !strings.EqualFold(last.Zone, apex) && dns.IsSubDomain(last.Zone, apex) {
			if ref = op.cohosted(ctx, last.Server.Address, apex, o); ref != nil {
				parent = last.Zone
				d.add(Info, "the servers of %s also serve %s, so the delegation was read from them directly", prose.Zone(parent), prose.Name(apex))
			}
		}
	}
	d.Parent = parent
	switch {
	case !exists:
		d.add(Fail, "%s does not exist (NXDOMAIN from the authoritative servers)", prose.Name(domain))
	case ref == nil && traceErr != nil:
		d.add(Fail, "the delegation from the root breaks before reaching %s: %s", prose.Name(apex), bridge.Message(traceErr))
	case ref == nil:
		d.add(Fail, "no referral to %s was seen on the way down from the root", prose.Name(apex))
	}
	if apex != domain && exists {
		d.add(Info, "%s is not a zone apex, so the zone %s that contains it was checked", prose.Name(domain), prose.Name(apex))
	}
	if ref == nil || !exists {
		wg.Wait()
		res.HTTPS.Verdict = Finding{Status: Info, Message: notChecked}
		res.skipAfterDelegation()
		res.finish()
		return res, nil
	}
	if traceErr != nil {
		d.add(Fail, "the trace to %s's SOA failed after the delegation: %s", prose.Name(apex), bridge.Message(traceErr))
	}
	d.ParentNS = append(d.ParentNS, ref.Nameservers...)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-caaDone
		res.HTTPS = op.checkHTTPS(ctx, p, r, o, apex, res.CAA)
	}()

	// A name whose lookup failed is kept apart from one that has no
	// addresses: the first says something about the resolver, the second
	// about the zone.
	lookupErrs := map[string]error{}
	resolveNS := func(name string, glue []string) []string {
		found, err := r.Addrs(ctx, name)
		all := union(glue, found)
		if len(all) == 0 && err != nil {
			lookupErrs[name] = err
		}
		return all
	}
	// Round one: every name the parent delegates to.
	addrs := map[string][]string{}
	for _, name := range ref.Nameservers {
		addrs[name] = resolveNS(name, ref.Glue[name])
	}
	servers := op.probeAll(ctx, apex, addrs, lookupErrs, o)
	for i := range servers {
		servers[i].AtParent = true
	}
	childNS := nsUnion(servers)
	// Round two: names only the zone itself lists.
	extra := map[string][]string{}
	for _, name := range childNS {
		if !contains(ref.Nameservers, name) {
			extra[name] = resolveNS(name, nil)
		}
	}
	servers = append(servers, op.probeAll(ctx, apex, extra, lookupErrs, o)...)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	for i := range servers {
		servers[i].AtChild = contains(childNS, servers[i].Name)
	}
	sort.SliceStable(servers, func(a, b int) bool {
		if servers[a].Name != servers[b].Name {
			return servers[a].Name < servers[b].Name
		}
		return ipLess(servers[a].IP, servers[b].IP)
	})
	d.ChildNS = childNS

	checkDelegation(d, apex, servers, extra)
	res.Nameservers = checkServers(servers)
	res.SOA = checkSOA(servers, apex)
	res.Glue = op.checkGlue(ctx, apex, ref, servers, o)
	res.DNSSEC = checkDNSSEC(tr, ref, servers, apex)
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	res.finish()
	return res, nil
}

// trace runs the trace op for the domain's SOA. On a dead end it returns the
// hops collected so far, which still carry the parent's referral.
func (op *Op) trace(ctx context.Context, p Params, domain string) (*trace.Result, []trace.Hop, error) {
	tr, err := op.Trace.Run(ctx, trace.Params{
		Question:  contract.Question{Name: domain, Type: "SOA"},
		Options:   p.Options,
		Validate:  true,
		Bootstrap: p.Bootstrap,
		RootHints: p.RootHints,
	})
	if err == nil {
		return tr, tr.Hops, nil
	}
	var be *bridge.Error
	if errors.As(err, &be) && be.Details != nil {
		if hops, ok := be.Details["hops"].([]trace.Hop); ok {
			return nil, hops, be
		}
	}
	return nil, nil, err
}

// zoneApex finds the zone that holds domain from the SOA the trace ended
// with, or from the deepest referral when the trace failed. exists is false
// for NXDOMAIN.
func zoneApex(tr *trace.Result, hops []trace.Hop, domain string) (string, bool) {
	if tr != nil {
		for _, sec := range [][]contract.Record{tr.Final.Answer, tr.Final.Authority} {
			for _, rec := range sec {
				if rec.Type == "SOA" && dns.IsSubDomain(strings.ToLower(rec.Name), domain) {
					return dns.Fqdn(strings.ToLower(rec.Name)), tr.Final.Rcode != "NXDOMAIN"
				}
			}
		}
		if tr.Final.Rcode == "NXDOMAIN" {
			return domain, false
		}
	}
	best := ""
	for _, h := range hops {
		if h.Referral != nil && dns.IsSubDomain(h.Referral.Zone, domain) && dns.CountLabel(h.Referral.Zone) > dns.CountLabel(best) {
			best = h.Referral.Zone
		}
	}
	if best == "" {
		return domain, true
	}
	return best, true
}

// referralFor returns the parent's referral to apex and the parent zone.
func referralFor(hops []trace.Hop, apex string) (*trace.Referral, string) {
	for i := len(hops) - 1; i >= 0; i-- {
		if ref := hops[i].Referral; ref != nil && strings.EqualFold(ref.Zone, apex) {
			return ref, hops[i].Zone
		}
	}
	return nil, ""
}

// skipAfterDelegation settles every later section when the delegation is
// too broken to check anything else.
func (r *Result) skipAfterDelegation() {
	r.skippedRest = true
	r.Nameservers.Verdict = Finding{Status: Info, Message: notChecked}
	r.SOA.Verdict = Finding{Status: Info, Message: notChecked}
	r.Glue.Verdict = Finding{Status: Info, Message: notChecked}
	r.DNSSEC.Verdict = Finding{Status: Info, Message: notChecked}
	r.DNSSEC.Status = ""
}

func (r *Result) finish() {
	if r.Delegation.Verdict.Status == "" {
		r.Delegation.settle("")
	}
	for _, s := range []*Section{&r.Delegation.Section, &r.Nameservers.Section, &r.SOA.Section, &r.Glue.Section, &r.DNSSEC.Section, &r.CAA.Section, &r.HTTPS.Section} {
		if s.Findings == nil {
			s.Findings = []Finding{}
		}
	}
	tally, bad := verdict.Tally(r.Delegation.Verdict, r.Nameservers.Verdict, r.SOA.Verdict, r.Glue.Verdict, r.DNSSEC.Verdict, r.CAA.Verdict, r.HTTPS.Verdict)
	switch {
	case r.Delegation.Verdict.Status == Fail && r.skippedRest:
		// Nothing past the delegation could be checked, so its reason is the story.
		r.Overall = r.Delegation.Verdict
	case bad:
		r.Overall = tally
	default:
		r.Overall = Finding{Status: OK, Message: "the zone " + prose.Name(r.Zone) + " looks healthy"}
	}
}

// addresses extracts A/AAAA values, only for owner when it is not empty.
func addresses(rrs []dns.RR, owner string) []string {
	var out []string
	for _, rr := range rrs {
		if owner != "" && !strings.EqualFold(rr.Header().Name, owner) {
			continue
		}
		switch a := rr.(type) {
		case *dns.A:
			out = append(out, a.A.String())
		case *dns.AAAA:
			out = append(out, a.AAAA.String())
		}
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i], out[j]) })
	return out
}

func contains(list []string, s string) bool {
	return slices.ContainsFunc(list, func(v string) bool { return strings.EqualFold(v, s) })
}

// ipLess orders IPv4 before IPv6, then lexically.
func ipLess(a, b string) bool {
	a6, b6 := strings.Contains(a, ":"), strings.Contains(b, ":")
	if a6 != b6 {
		return !a6
	}
	return a < b
}

// label names a server in a finding: "ns1.example.com (192.0.2.1)", or the
// bare name when it has no address.
func label(s Server) string {
	if s.IP == "" {
		return prose.Name(s.Name)
	}
	return prose.Name(s.Name) + " (" + s.IP + ")"
}
