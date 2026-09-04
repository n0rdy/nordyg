package dnssec

import (
	"context"
	"errors"
	"strings"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Recursive fetches through a recursive resolver with CD set, so a
// validating resolver still returns data it considers bogus.
type Recursive struct {
	Client    *transport.Client
	Endpoint  contract.Endpoint
	Options   contract.Effective
	Bootstrap []contract.Endpoint
}

// Fetch implements Fetcher.
func (r *Recursive) Fetch(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	o := r.Options
	o.EDNS, o.DNSSECOK, o.CheckingDisabled, o.RecursionDesired = true, true, true, true
	q := o.Build(contract.Resolved{Name: dns.Fqdn(name), Type: qtype, Class: dns.ClassINET})
	res, err := r.Client.Exchange(ctx, r.Endpoint, q, o, r.Bootstrap)
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// Authoritative fetches from the servers a trace discovered, keyed by zone.
// DS records are asked from the parent zone's server, everything else from
// the closest enclosing zone's server.
type Authoritative struct {
	Client  *transport.Client
	Options contract.Effective
	Servers map[string]string // zone (fqdn, lowercase) → ip:port
}

// Fetch implements Fetcher.
func (a *Authoritative) Fetch(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	name = dns.Fqdn(strings.ToLower(name))
	zone := a.zoneFor(name, qtype == dns.TypeDS)
	addr, ok := a.Servers[zone]
	if !ok {
		return nil, errors.New("no server known for zone " + zone)
	}
	o := a.Options
	o.EDNS, o.DNSSECOK, o.RecursionDesired = true, true, false
	q := o.Build(contract.Resolved{Name: name, Type: qtype, Class: dns.ClassINET})
	res, err := a.Client.Exchange(ctx, contract.Endpoint{Transport: contract.UDP, Address: addr}, q, o, nil)
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func (a *Authoritative) zoneFor(name string, parent bool) string {
	best := "."
	for zone := range a.Servers {
		if !dns.IsSubDomain(zone, name) {
			continue
		}
		if parent && strings.EqualFold(zone, name) {
			continue
		}
		if dns.CountLabel(zone) > dns.CountLabel(best) {
			best = zone
		}
	}
	return best
}

// QueryHook adapts the validator to the query op's Validator interface.
type QueryHook struct {
	V      *Validator
	Client *transport.Client
}

// Validate implements query.Validator.
func (h QueryHook) Validate(ctx context.Context, r contract.Resolved, res *transport.Result, ep contract.Endpoint, o contract.Effective, bootstrap []contract.Endpoint) (any, error) {
	f := &Recursive{Client: h.Client, Endpoint: ep, Options: o, Bootstrap: bootstrap}
	return h.V.Validate(ctx, f, r.Name, r.Type, res.Msg)
}

// TraceHook adapts the validator to the trace op's Validator interface.
type TraceHook struct {
	V      *Validator
	Client *transport.Client
}

// Validate implements trace.Validator.
func (h TraceHook) Validate(ctx context.Context, r contract.Resolved, o contract.Effective, servers map[string]string, final *dns.Msg) (any, error) {
	f := &Authoritative{Client: h.Client, Options: o, Servers: servers}
	return h.V.Validate(ctx, f, r.Name, r.Type, final)
}
