// Package health implements the "health" op, a lightweight Zonemaster: it
// walks the delegation from the root, asks every nameserver of the zone
// directly, and reports each check with a plain verdict.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/certs"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/trace"
	"github.com/n0rdy/nordyg/core/internal/transport"
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
	OK   = "ok"
	Info = "info"
	Warn = "warn"
	Fail = "fail"
)

// Finding is one observation with its severity.
type Finding struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Section carries the verdict and the findings behind it. It is embedded in
// every section, so its fields appear inline in the JSON.
type Section struct {
	Verdict  Finding   `json:"verdict"`
	Findings []Finding `json:"findings"`
}

func (s *Section) add(status, format string, args ...any) {
	s.Findings = append(s.Findings, Finding{status, fmt.Sprintf(format, args...)})
}

// settle sets the verdict to the worst finding, or to ok with okMsg.
func (s *Section) settle(okMsg string) {
	worst, first, more := OK, "", 0
	for _, f := range s.Findings {
		switch {
		case rank(f.Status) > rank(worst):
			worst, first, more = f.Status, f.Message, 0
		case rank(f.Status) == rank(worst) && worst != OK:
			more++
		}
	}
	if worst == OK {
		s.Verdict = Finding{OK, okMsg}
		return
	}
	if more > 0 {
		first += fmt.Sprintf(" (and %d more)", more)
	}
	s.Verdict = Finding{worst, first}
}

func rank(s string) int {
	switch s {
	case Info:
		return 1
	case Warn:
		return 2
	case Fail:
		return 3
	}
	return 0
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

	soa *dns.SOA // the full record, for the SOA section
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
}

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
	d.Register("health", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p Params
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
		}
		return op.Run(ctx, p)
	})
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
	r := &resolver{client: op.Client, ep: p.Endpoint, o: o, boot: p.Bootstrap}
	r.o.RecursionDesired = true

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
				d.add(Info, "the servers of %s also serve %s, so the delegation was read from them directly", proseZone(parent), prose(apex))
			}
		}
	}
	d.Parent = parent
	switch {
	case !exists:
		d.add(Fail, "%s does not exist (NXDOMAIN from the authoritative servers)", prose(domain))
	case ref == nil && traceErr != nil:
		d.add(Fail, "the delegation from the root breaks before reaching %s: %s", prose(apex), traceErr.Error())
	case ref == nil:
		d.add(Fail, "no referral to %s was seen on the way down from the root", prose(apex))
	}
	if apex != domain && exists {
		d.add(Info, "%s is not a zone apex, so the zone %s that contains it was checked", prose(domain), prose(apex))
	}
	if ref == nil || !exists {
		wg.Wait()
		res.HTTPS.Verdict = Finding{Info, "not checked: the delegation is broken"}
		res.skipAfterDelegation()
		res.finish()
		return res, nil
	}
	if traceErr != nil {
		d.add(Fail, "the trace to %s's SOA failed after the delegation: %s", prose(apex), traceErr.Error())
	}
	d.ParentNS = append(d.ParentNS, ref.Nameservers...)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-caaDone
		res.HTTPS = op.checkHTTPS(ctx, p, r, o, apex, res.CAA)
	}()

	// Round one: every name the parent delegates to.
	addrs := map[string][]string{}
	for _, name := range ref.Nameservers {
		addrs[name] = union(ref.Glue[name], r.addrs(ctx, name))
	}
	servers := op.probeAll(ctx, apex, addrs, o)
	for i := range servers {
		servers[i].AtParent = true
	}
	childNS := nsUnion(servers)
	// Round two: names only the zone itself lists.
	extra := map[string][]string{}
	for _, name := range childNS {
		if !contains(ref.Nameservers, name) {
			extra[name] = r.addrs(ctx, name)
		}
	}
	servers = append(servers, op.probeAll(ctx, apex, extra, o)...)
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
	const msg = "not checked: the delegation is broken"
	r.Nameservers.Verdict = Finding{Info, msg}
	r.SOA.Verdict = Finding{Info, msg}
	r.Glue.Verdict = Finding{Info, msg}
	r.DNSSEC.Verdict = Finding{Info, msg}
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
	fails, warns := 0, 0
	for _, v := range []Finding{r.Delegation.Verdict, r.Nameservers.Verdict, r.SOA.Verdict, r.Glue.Verdict, r.DNSSEC.Verdict, r.CAA.Verdict, r.HTTPS.Verdict} {
		switch v.Status {
		case Fail:
			fails++
		case Warn:
			warns++
		}
	}
	switch {
	case r.Delegation.Verdict.Status == Fail && strings.HasPrefix(r.Nameservers.Verdict.Message, "not checked"):
		// Nothing past the delegation could be checked, so its reason is the story.
		r.Overall = r.Delegation.Verdict
	case fails > 0:
		msg := fmt.Sprintf("%d check%s failing", fails, plural(fails))
		if warns > 0 {
			msg += fmt.Sprintf(", %d warning%s", warns, plural(warns))
		}
		r.Overall = Finding{Fail, msg}
	case warns > 0:
		r.Overall = Finding{Warn, fmt.Sprintf("no failures, %d warning%s", warns, plural(warns))}
	default:
		r.Overall = Finding{OK, "the zone " + prose(r.Zone) + " looks healthy"}
	}
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

// addrs returns the A and AAAA addresses of name, or nil when it has none
// or the lookups fail.
func (r *resolver) addrs(ctx context.Context, name string) []string {
	var out []string
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m, err := r.lookup(ctx, name, t)
		if err != nil {
			continue
		}
		out = append(out, addresses(m.Answer, "")...)
	}
	return out
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

// --- helpers -----------------------------------------------------------------

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
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// ipLess orders IPv4 before IPv6, then lexically.
func ipLess(a, b string) bool {
	a6, b6 := strings.Contains(a, ":"), strings.Contains(b, ":")
	if a6 != b6 {
		return !a6
	}
	return a < b
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func prose(name string) string {
	if name == "." {
		return "the root"
	}
	return strings.TrimSuffix(name, ".")
}

func label(s Server) string { return prose(s.Name) + " (" + s.IP + ")" }

// proseZone renders a zone for prose: "the .cz zone", "the zone example.com".
func proseZone(zone string) string {
	switch dns.CountLabel(zone) {
	case 0:
		return "the root zone"
	case 1:
		return "the ." + strings.TrimSuffix(zone, ".") + " zone"
	}
	return "the zone " + strings.TrimSuffix(zone, ".")
}
