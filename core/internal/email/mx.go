package email

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/prose"
	"github.com/n0rdy/nordyg/core/internal/resolve"
)

// PTRCheck is the reverse DNS round trip for one address: the names it points to and whether one of them leads back.
type PTRCheck struct {
	IP      string   `json:"ip"`
	Names   []string `json:"names"`
	Matches bool     `json:"matches"`
	Error   string   `json:"error,omitempty"`
}

// MXHost is one mail exchange with its addresses and their reverse DNS.
type MXHost struct {
	Preference uint16     `json:"preference"`
	Exchange   string     `json:"exchange"`
	Addresses  []string   `json:"addresses"`
	PTR        []PTRCheck `json:"ptr"`
	Error      string     `json:"error,omitempty"`

	noAddress bool // resolved fine and has no A or AAAA, unlike a failed lookup
}

// MXSection is where the domain receives mail: its MX hosts, or the absence of them.
type MXSection struct {
	Hosts    []MXHost `json:"hosts"`
	NullMX   bool     `json:"null_mx"`
	Implicit bool     `json:"implicit"`
	Verdict  Verdict  `json:"verdict"`
}

func checkMX(ctx context.Context, r *resolve.Resolver, domain string) MXSection {
	sec := MXSection{Hosts: []MXHost{}}
	m, err := r.Answer(ctx, domain, dns.TypeMX)
	if err != nil {
		sec.Verdict = Verdict{Status: Fail, Message: "MX lookup failed: " + err.Error()}
		return sec
	}
	var mxs []*dns.MX
	for _, rr := range m.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			mxs = append(mxs, mx)
		}
	}
	sort.Slice(mxs, func(a, b int) bool {
		if mxs[a].Preference != mxs[b].Preference {
			return mxs[a].Preference < mxs[b].Preference
		}
		return mxs[a].Mx < mxs[b].Mx
	})
	if len(mxs) == 1 && mxs[0].Mx == "." {
		sec.NullMX = true
		sec.Hosts = append(sec.Hosts, MXHost{Preference: 0, Exchange: ".", Addresses: []string{}, PTR: []PTRCheck{}})
		sec.Verdict = Verdict{Status: Info, Message: "null MX: the domain declares it does not accept mail (RFC 7505)"}
		return sec
	}
	if len(mxs) == 0 {
		sec.Implicit = true
		addrs, err := r.Addrs(ctx, domain)
		if err != nil {
			sec.Verdict = Verdict{Status: Fail, Message: "no MX records, and the address lookup failed: " + err.Error()}
			return sec
		}
		if len(addrs) == 0 {
			sec.Verdict = Verdict{Status: Fail, Message: "no MX records and no address records, so the domain cannot receive mail"}
			return sec
		}
		host := MXHost{Preference: 0, Exchange: domain, Addresses: addrs}
		host.PTR = ptrChecks(ctx, r, addrs, domain)
		sec.Hosts = append(sec.Hosts, host)
		sec.Verdict = Verdict{Status: Warn, Message: "no MX records, so mail falls back to the domain's own address (implicit MX). Publish MX records explicitly."}
		return sec
	}

	var wg sync.WaitGroup
	hosts := make([]MXHost, len(mxs))
	for i, mx := range mxs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := MXHost{Preference: mx.Preference, Exchange: mx.Mx, Addresses: []string{}, PTR: []PTRCheck{}}
			addrs, err := r.Addrs(ctx, mx.Mx)
			if err != nil {
				h.Error = err.Error()
			} else if len(addrs) == 0 {
				h.Error, h.noAddress = "host has no address records", true
			}
			h.Addresses = addrs
			if h.Addresses == nil {
				h.Addresses = []string{}
			}
			h.PTR = ptrChecks(ctx, r, addrs, mx.Mx)
			hosts[i] = h
		}()
	}
	wg.Wait()
	sec.Hosts = hosts

	broken, unchecked, ptrMiss := 0, 0, 0
	for _, h := range hosts {
		switch {
		case h.noAddress:
			broken++
		case h.Error != "":
			// The lookup itself failed (a timeout, a SERVFAIL): that says
			// nothing about the host, so it is not counted as broken.
			unchecked++
		}
		for _, p := range h.PTR {
			if !p.Matches {
				ptrMiss++
			}
		}
	}
	switch {
	case broken == len(hosts):
		sec.Verdict = Verdict{Status: Fail, Message: "none of the MX hosts resolve to an address"}
	case broken > 0:
		sec.Verdict = Verdict{Status: Warn, Message: fmt.Sprintf("%d of %d MX hosts do not resolve", broken, len(hosts))}
	case unchecked == len(hosts):
		sec.Verdict = Verdict{Status: Warn, Message: "the MX hosts could not be looked up through this resolver. Run the check again"}
	case unchecked > 0:
		sec.Verdict = Verdict{Status: Warn, Message: fmt.Sprintf("%d of %d MX hosts could not be looked up through this resolver. Run the check again", unchecked, len(hosts))}
	case ptrMiss > 0:
		// Receivers check the reverse record of the server that connects to
		// them, the sender; MX hosts receive. It matters only if they also send.
		verb := "resolve"
		if len(hosts) == 1 {
			verb = "resolves"
		}
		sec.Verdict = Verdict{Status: Info, Message: fmt.Sprintf("%d MX host%s %s. Reverse (PTR) records are missing for %d address%s, which matters only if these servers also send mail", len(hosts), prose.Plural(len(hosts)), verb, ptrMiss, prose.PluralEs(ptrMiss))}
	default:
		sec.Verdict = Verdict{Status: OK, Message: fmt.Sprintf("%d MX host%s, all resolve with matching reverse records", len(hosts), prose.Plural(len(hosts)))}
	}
	return sec
}

// ptrChecks does the forward-confirmed reverse DNS round trip for each address.
func ptrChecks(ctx context.Context, r *resolve.Resolver, addrs []string, expect string) []PTRCheck {
	out := make([]PTRCheck, 0, len(addrs))
	for _, ip := range addrs {
		c := PTRCheck{IP: ip, Names: []string{}}
		rev, err := dns.ReverseAddr(ip)
		if err != nil {
			c.Error = err.Error()
			out = append(out, c)
			continue
		}
		m, err := r.Lookup(ctx, rev, dns.TypePTR)
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
			fwd, err := r.Addrs(ctx, n)
			if err == nil && contains(fwd, ip) {
				c.Matches = true
				break
			}
		}
		out = append(out, c)
	}
	return out
}
