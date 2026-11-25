// Package resolve asks the user's chosen resolver for records, for the ops
// that need a lookup on the way to their own result.
package resolve

import (
	"context"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Resolver is one endpoint and the options to ask it with.
type Resolver struct {
	Client    *transport.Client
	Endpoint  contract.Endpoint
	Options   contract.Effective
	Bootstrap []contract.Endpoint
}

// Lookup asks for name and type in class IN and returns the reply as it
// came, whatever its rcode.
func (r *Resolver) Lookup(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	q := r.Options.Build(contract.Resolved{Name: dns.Fqdn(name), Type: qtype, Class: dns.ClassINET})
	res, err := r.Client.Exchange(ctx, r.Endpoint, q, r.Options, r.Bootstrap)
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// Answer is Lookup for callers that only read the records: a reply the
// resolver could not answer (anything but NOERROR and NXDOMAIN) comes back
// as an Rcode error.
func (r *Resolver) Answer(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m, err := r.Lookup(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return nil, Rcode(m.Rcode)
	}
	return m, nil
}

// Addrs returns the A and AAAA addresses in the answers for name. The error
// is set only when there are no addresses and a lookup failed, so "has none"
// and "could not find out" stay apart.
func (r *Resolver) Addrs(ctx context.Context, name string) ([]string, error) {
	var out []string
	var firstErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m, err := r.Answer(ctx, name, qtype)
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

// Rcode is a reply whose rcode says the resolver could not answer, such as
// SERVFAIL or REFUSED. NXDOMAIN is an answer, not one of these.
type Rcode int

func (e Rcode) Error() string { return dns.RcodeToString[int(e)] }
