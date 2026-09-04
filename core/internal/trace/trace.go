// Package trace implements the "trace" op (contract §6): iterative resolution
// from the root, reporting every hop like dig +trace.
package trace

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/msg"
	"github.com/n0rdy/nordyg/core/internal/query"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Params is the op input.
type Params struct {
	Question  contract.Question   `json:"question"`
	Options   contract.Options    `json:"options"`
	Validate  bool                `json:"validate"`
	Bootstrap []contract.Endpoint `json:"bootstrap"`
	RootHints []string            `json:"root_hints"`
}

// Server is the nameserver a hop used.
type Server struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// Referral is where a hop pointed next.
type Referral struct {
	Zone        string              `json:"zone"`
	Nameservers []string            `json:"nameservers"`
	Glue        map[string][]string `json:"glue"`
	DS          []contract.Record   `json:"ds"`
}

// Hop is one query in the chain.
type Hop struct {
	Zone       string            `json:"zone"`
	Server     Server            `json:"server"`
	Candidates []string          `json:"candidates"`
	Message    contract.Message  `json:"message"`
	Exchange   contract.Exchange `json:"exchange"`
	Referral   *Referral         `json:"referral"`
}

// Result is the op output.
type Result struct {
	QuestionSent contract.Question `json:"question_sent"`
	Hops         []Hop             `json:"hops"`
	Final        contract.Message  `json:"final"`
	DNSSEC       any               `json:"dnssec,omitempty"`
}

// Validator produces the DNSSEC verdict for the final answer, fetching keys
// from the servers the trace discovered (zone → address).
type Validator interface {
	Validate(ctx context.Context, r contract.Resolved, o contract.Effective, servers map[string]string, final *dns.Msg) (any, error)
}

// Op is the configured handler.
type Op struct {
	Client    *transport.Client
	Validator Validator
	Decorate  query.Decorator
	// AddrFor maps a nameserver IP to an endpoint address. Defaults to
	// ip:53; tests remap to local ports.
	AddrFor func(ip string) string
}

const (
	maxHops       = 30
	maxCNAME      = 8
	maxNestDepth  = 4
	maxGlueLookup = 3
)

type candidate struct {
	Name string
	IPs  []string // ip literals, or ip:port for root hint overrides
	full bool     // IPs already carry a port
}

// Register attaches the op to d.
func (op *Op) Register(d *bridge.Dispatcher) {
	d.Register("trace", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p Params
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
		}
		return op.Run(ctx, p)
	})
}

func (op *Op) addr(c candidate, ip string) string {
	if c.full {
		return ip
	}
	if op.AddrFor != nil {
		return op.AddrFor(ip)
	}
	return net.JoinHostPort(ip, "53")
}

func (op *Op) roots(p Params) ([]candidate, error) {
	if len(p.RootHints) == 0 {
		return rootHints, nil
	}
	for _, h := range p.RootHints {
		if _, _, err := net.SplitHostPort(h); err != nil {
			return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "root_hints entries must be ip:port: " + h}
		}
	}
	return []candidate{{Name: "root-hint", IPs: p.RootHints, full: true}}, nil
}

type run struct {
	op    *Op
	p     Params
	o     contract.Effective
	roots []candidate
	hops  []Hop
	raw   []*dns.Msg
}

// Run performs the trace.
func (op *Op) Run(ctx context.Context, p Params) (*Result, error) {
	r, err := p.Question.Resolve()
	if err != nil {
		return nil, err
	}
	roots, err := op.roots(p)
	if err != nil {
		return nil, err
	}
	o := p.Options.Resolve()
	o.RecursionDesired = false

	s := &run{op: op, p: p, o: o, roots: roots, hops: []Hop{}}
	final, err := s.trace(ctx, r.Name, r.Type, r.Class, 0, 0)
	if err != nil {
		return nil, s.fail(ctx, err)
	}
	out := &Result{QuestionSent: r.Question(), Hops: s.hops, Final: final}
	if p.Validate && op.Validator != nil {
		servers := map[string]string{}
		for _, h := range s.hops {
			servers[strings.ToLower(h.Zone)] = h.Server.Address
		}
		v, err := op.Validator.Validate(ctx, r, o, servers, s.raw[len(s.raw)-1])
		if err != nil {
			return nil, err
		}
		out.DNSSEC = v
	}
	return out, nil
}

// fail wraps a dead end with the hops collected so far.
func (s *run) fail(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return context.Canceled
	}
	var be *bridge.Error
	if !errors.As(err, &be) {
		be = &bridge.Error{Code: contract.CodeTraceDeadEnd, Message: err.Error()}
	}
	if be.Code == contract.CodeTraceDeadEnd {
		if be.Details == nil {
			be.Details = map[string]any{}
		}
		be.Details["hops"] = s.hops
	}
	return be
}

type kind int

const (
	kindLame kind = iota
	kindAnswer
	kindCNAME
	kindReferral
	kindNegative
)

// trace resolves qname/qtype iteratively from the root, appending hops.
func (s *run) trace(ctx context.Context, qname string, qtype, qclass uint16, cnameDepth, nestDepth int) (contract.Message, error) {
	zone := "."
	cands := s.roots
	for i := 0; i < maxHops; i++ {
		if err := ctx.Err(); err != nil {
			return contract.Message{}, err
		}
		hop, resp, k, referral, err := s.step(ctx, zone, cands, qname, qtype, qclass, nestDepth)
		if err != nil {
			return contract.Message{}, err
		}
		s.hops = append(s.hops, *hop)
		s.raw = append(s.raw, resp)
		switch k {
		case kindAnswer, kindNegative:
			return hop.Message, nil
		case kindCNAME:
			if cnameDepth >= maxCNAME {
				return contract.Message{}, &bridge.Error{Code: contract.CodeTraceDeadEnd, Message: "CNAME chain longer than " + itoa(maxCNAME)}
			}
			target := cnameTarget(resp, qname)
			return s.trace(ctx, target, qtype, qclass, cnameDepth+1, nestDepth)
		case kindReferral:
			zone = referral.Zone
			cands, err = s.candidatesFor(ctx, referral, nestDepth)
			if err != nil {
				return contract.Message{}, err
			}
		}
	}
	return contract.Message{}, &bridge.Error{Code: contract.CodeTraceDeadEnd, Message: "more than " + itoa(maxHops) + " hops"}
}

// step queries the candidates for zone one by one until a usable response.
func (s *run) step(ctx context.Context, zone string, cands []candidate, qname string, qtype, qclass uint16, nestDepth int) (*Hop, *dns.Msg, kind, *Referral, error) {
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.Name)
	}
	var failures []string
	for _, c := range cands {
		for _, ip := range c.IPs {
			if err := ctx.Err(); err != nil {
				return nil, nil, kindLame, nil, err
			}
			ep := contract.Endpoint{Transport: contract.UDP, Address: s.op.addr(c, ip)}
			if err := ep.Validate(); err != nil {
				failures = append(failures, c.Name+" ("+ip+"): "+err.Error())
				continue
			}
			q := s.o.Build(contract.Resolved{Name: qname, Type: qtype, Class: qclass})
			res, err := s.op.Client.Exchange(ctx, ep, q, s.o, nil)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil, nil, kindLame, nil, err
				}
				failures = append(failures, c.Name+" ("+ip+"): "+err.Error())
				continue
			}
			k, referral := classify(res.Msg, zone, qname, qtype)
			if k == kindLame {
				failures = append(failures, c.Name+" ("+ip+"): no usable answer, rcode "+dns.RcodeToString[res.Msg.Rcode])
				continue
			}
			hop := &Hop{
				Zone:       zone,
				Server:     Server{Name: c.Name, Address: ep.Address},
				Candidates: names,
				Message:    msg.Convert(res.Msg, res.Size),
				Exchange:   res.Exchange,
				Referral:   referral,
			}
			hop.Message.Text += query.Footer(res.Exchange, res.Size)
			if s.op.Decorate != nil {
				s.op.Decorate(&hop.Message)
			}
			return hop, res.Msg, k, referral, nil
		}
	}
	msgText := "every nameserver for " + zone + " failed: " + strings.Join(failures, "; ")
	if len(failures) == 0 {
		msgText = "no addresses known for the nameservers of " + zone
	}
	return nil, nil, kindLame, nil, &bridge.Error{Code: contract.CodeTraceDeadEnd, Message: msgText}
}

// classify decides what a response means for the trace.
func classify(m *dns.Msg, zone, qname string, qtype uint16) (kind, *Referral) {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return kindLame, nil
	}
	hasType, hasCNAME := false, false
	for _, rr := range m.Answer {
		h := rr.Header()
		if !strings.EqualFold(h.Name, qname) {
			continue
		}
		switch h.Rrtype {
		case qtype:
			hasType = true
		case dns.TypeCNAME:
			hasCNAME = true
		}
	}
	if hasType {
		return kindAnswer, nil
	}
	if hasCNAME && qtype != dns.TypeCNAME {
		return kindCNAME, nil
	}
	if len(m.Answer) > 0 {
		return kindAnswer, nil
	}
	// Referral: NS records in authority for a zone below the current one
	// that contains the qname, and the answer was not authoritative.
	if ref := referralOf(m, zone, qname); ref != nil && !m.Authoritative {
		return kindReferral, ref
	}
	if m.Rcode == dns.RcodeNameError {
		return kindNegative, nil
	}
	for _, rr := range m.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			return kindNegative, nil
		}
	}
	if m.Authoritative {
		return kindNegative, nil
	}
	return kindLame, nil
}

func referralOf(m *dns.Msg, zone, qname string) *Referral {
	var ref *Referral
	for _, rr := range m.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := strings.ToLower(ns.Hdr.Name)
		if !dns.IsSubDomain(zone, owner) || strings.EqualFold(owner, zone) || !dns.IsSubDomain(owner, qname) {
			continue
		}
		if ref == nil {
			ref = &Referral{Zone: owner, Glue: map[string][]string{}, DS: []contract.Record{}}
		} else if ref.Zone != owner {
			continue
		}
		ref.Nameservers = append(ref.Nameservers, strings.ToLower(ns.Ns))
	}
	if ref == nil {
		return nil
	}
	sort.Strings(ref.Nameservers)
	for _, rr := range m.Extra {
		name := strings.ToLower(rr.Header().Name)
		switch a := rr.(type) {
		case *dns.A:
			if contains(ref.Nameservers, name) {
				ref.Glue[name] = append(ref.Glue[name], a.A.String())
			}
		case *dns.AAAA:
			if contains(ref.Nameservers, name) {
				ref.Glue[name] = append(ref.Glue[name], a.AAAA.String())
			}
		}
	}
	for _, rr := range m.Ns {
		if ds, ok := rr.(*dns.DS); ok && strings.EqualFold(ds.Hdr.Name, ref.Zone) {
			ref.DS = append(ref.DS, msg.Record(ds))
		}
	}
	return ref
}

// candidatesFor turns a referral into servers to try: glued ones first, IPv4
// before IPv6; unglued names are resolved with a nested trace only if no
// glue exists at all.
func (s *run) candidatesFor(ctx context.Context, ref *Referral, nestDepth int) ([]candidate, error) {
	var out []candidate
	for _, ns := range ref.Nameservers {
		if ips := ref.Glue[ns]; len(ips) > 0 {
			out = append(out, candidate{Name: ns, IPs: sortIPs(ips)})
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if nestDepth >= maxNestDepth {
		return nil, &bridge.Error{Code: contract.CodeTraceDeadEnd, Message: "no glue for " + ref.Zone + " and nested lookup depth exceeded"}
	}
	// Resolve a few nameserver names out of band with a nested trace.
	sub := &run{op: s.op, p: s.p, o: s.o, roots: s.roots}
	looked := 0
	for _, ns := range ref.Nameservers {
		if looked >= maxGlueLookup {
			break
		}
		looked++
		final, err := sub.trace(ctx, ns, dns.TypeA, dns.ClassINET, 0, nestDepth+1)
		if err != nil {
			continue
		}
		var ips []string
		for _, rr := range final.Answer {
			if rr.Type == "A" || rr.Type == "AAAA" {
				ips = append(ips, rr.Fields["address"].(string))
			}
		}
		if len(ips) > 0 {
			out = append(out, candidate{Name: ns, IPs: sortIPs(ips)})
		}
	}
	// Nested hops are not part of the main chain; keep only the main hops.
	if len(out) == 0 {
		return nil, &bridge.Error{Code: contract.CodeTraceDeadEnd, Message: "could not find an address for any nameserver of " + ref.Zone}
	}
	return out, nil
}

func cnameTarget(m *dns.Msg, qname string) string {
	name := qname
	for changed := true; changed; {
		changed = false
		for _, rr := range m.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, name) {
				name = strings.ToLower(c.Target)
				changed = true
			}
		}
	}
	return dns.Fqdn(name)
}

func sortIPs(ips []string) []string {
	out := append([]string(nil), ips...)
	sort.SliceStable(out, func(a, b int) bool {
		a4, b4 := net.ParseIP(out[a]).To4() != nil, net.ParseIP(out[b]).To4() != nil
		return a4 && !b4
	})
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func itoa(i int) string { return strconv.Itoa(i) }
