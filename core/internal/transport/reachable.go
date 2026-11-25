package transport

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
)

// CheckResolver asks ep one cheap question (the root's NS set) before an op
// that sends it dozens. A resolver that does not answer would otherwise turn
// every check into its own timeout: a long wait, then a page of identical
// errors. Any DNS answer counts, whatever its rcode. It returns a
// resolver_unreachable error naming the resolver, with the underlying code
// and message in details, and passes cancellation and bad endpoints through.
func (c *Client) CheckResolver(ctx context.Context, ep contract.Endpoint, o contract.Effective, bootstrap []contract.Endpoint) error {
	o.RecursionDesired = true
	q := o.Build(contract.Resolved{Name: ".", Type: dns.TypeNS, Class: dns.ClassINET})
	_, err := c.Exchange(ctx, ep, q, o, bootstrap)
	if err == nil || ctx.Err() != nil {
		return err
	}
	code := contract.CodeNetwork
	var be *bridge.Error
	if errors.As(err, &be) {
		if be.Code == contract.CodeBadEndpoint || be.Code == bridge.CodeBadRequest {
			return err
		}
		code = be.Code
	}
	name := ResolverName(ep)
	var msg string
	switch code {
	case contract.CodeTimeout:
		msg = name + " did not answer in time, so nothing was checked"
	case contract.CodeTLS:
		msg = "the secure connection to " + name + " failed, so nothing was checked"
	case contract.CodeNetwork:
		msg = name + " could not be reached, so nothing was checked"
	default:
		msg = name + " did not give a usable answer, so nothing was checked"
	}
	return &bridge.Error{Code: contract.CodeResolverUnreachable, Message: msg,
		Details: map[string]any{"cause": code, "reason": err.Error()}}
}

// ResolverName renders an endpoint for prose: "Quad9 (9.9.9.9:853)", or just
// the address or URL when it has no label.
func ResolverName(ep contract.Endpoint) string {
	where := ep.Address
	if ep.URL != "" {
		where = ep.URL
	}
	switch {
	case ep.Label == "":
		return where
	case where == "":
		return ep.Label
	}
	return fmt.Sprintf("%s (%s)", ep.Label, where)
}
