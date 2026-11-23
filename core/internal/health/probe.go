package health

import (
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/msg"
	"github.com/n0rdy/nordyg/core/internal/trace"
)

// maxProbes bounds how many servers are probed at once.
const maxProbes = 8

// recursionProbe is a name outside any zone under test; a server that
// resolves it for us is an open recursive resolver.
const recursionProbe = "a.root-servers.net."

func (op *Op) addr(ip string) string {
	if op.AddrFor != nil {
		return op.AddrFor(ip)
	}
	return net.JoinHostPort(ip, "53")
}

// probeAll probes every (name, address) pair concurrently. A name without
// addresses yields one entry with an error, so it shows up in the table.
func (op *Op) probeAll(ctx context.Context, apex string, addrs map[string][]string, o contract.Effective) []Server {
	names := make([]string, 0, len(addrs))
	for n := range addrs {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Server
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxProbes)
	for _, name := range names {
		if len(addrs[name]) == 0 {
			out = append(out, Server{Name: name, NS: []string{}, AXFR: AXFRNotChecked, Error: "the name has no A or AAAA records", Problems: []Finding{}})
			continue
		}
		for _, ip := range addrs[name] {
			wg.Add(1)
			go func(name, ip string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				s := op.probe(ctx, apex, name, ip, o)
				mu.Lock()
				out = append(out, s)
				mu.Unlock()
			}(name, ip)
		}
	}
	wg.Wait()
	return out
}

// probe asks one server about the zone. If the server does not answer over
// UDP, only TCP is tried; the remaining probes would just time out too.
func (op *Op) probe(ctx context.Context, apex, name, ip string, o contract.Effective) Server {
	s := Server{Name: name, IP: ip, NS: []string{}, AXFR: AXFRNotChecked, Problems: []Finding{}}
	addr := op.addr(ip)
	auth := o
	auth.RecursionDesired, auth.EDNS, auth.DNSSECOK, auth.TCPFallback = false, true, true, true

	res, err := op.exchange(ctx, "udp", addr, apex, dns.TypeSOA, auth)
	if err != nil {
		if strings.Contains(ip, ":") && noRoute(err) {
			s.Skipped = true
			s.Error = "this Mac has no IPv6 route, so the address was not checked"
			return s
		}
		s.Error = err.Error()
		s.TCP = op.tcpWorks(ctx, addr, apex, auth)
		return s
	}
	m := res.Msg
	s.Answered = true
	s.RTTms = res.Exchange.RTTms
	s.Rcode = dns.RcodeToString[m.Rcode]
	s.Authoritative = m.Authoritative && m.Rcode == dns.RcodeSuccess
	s.EDNS = m.IsEdns0() != nil
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.SOA:
			if strings.EqualFold(v.Hdr.Name, apex) {
				serial := v.Serial
				s.Serial, s.soa = &serial, v
			}
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeSOA {
				s.Signed = true
			}
		}
	}
	if nsRes, err := op.exchange(ctx, "udp", addr, apex, dns.TypeNS, auth); err == nil {
		for _, rr := range nsRes.Msg.Answer {
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, apex) {
				s.NS = append(s.NS, strings.ToLower(ns.Ns))
			}
		}
		sort.Strings(s.NS)
	}
	s.TCP = op.tcpWorks(ctx, addr, apex, auth)
	s.Recursion = op.recursive(ctx, addr, o)
	s.AXFR = op.axfr(ctx, addr, apex, o.Timeout)
	return s
}

func (op *Op) exchange(ctx context.Context, transportName, addr, name string, t uint16, o contract.Effective) (*exchangeResult, error) {
	q := o.Build(contract.Resolved{Name: name, Type: t, Class: dns.ClassINET})
	res, err := op.Client.Exchange(ctx, contract.Endpoint{Transport: transportName, Address: addr}, q, o, nil)
	if err != nil {
		return nil, err
	}
	return &exchangeResult{Msg: res.Msg, Exchange: res.Exchange}, nil
}

type exchangeResult struct {
	Msg      *dns.Msg
	Exchange contract.Exchange
}

func (op *Op) tcpWorks(ctx context.Context, addr, apex string, o contract.Effective) bool {
	res, err := op.exchange(ctx, "tcp", addr, apex, dns.TypeSOA, o)
	return err == nil && res.Msg.Rcode == dns.RcodeSuccess
}

// recursive reports whether the server resolves a name it cannot be
// authoritative for.
func (op *Op) recursive(ctx context.Context, addr string, o contract.Effective) bool {
	rd := o
	rd.RecursionDesired, rd.EDNS, rd.DNSSECOK = true, true, false
	res, err := op.exchange(ctx, "udp", addr, recursionProbe, dns.TypeA, rd)
	if err != nil {
		return false
	}
	m := res.Msg
	return m.RecursionAvailable && m.Rcode == dns.RcodeSuccess && !m.Authoritative && len(m.Answer) > 0
}

// axfr asks for a zone transfer and reads only the first message, so an open
// server never streams the whole zone at us.
func (op *Op) axfr(ctx context.Context, addr, apex string, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return AXFRNoAnswer
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(timeout))
	co := &dns.Conn{Conn: c}
	q := new(dns.Msg)
	q.SetAxfr(apex)
	if err := co.WriteMsg(q); err != nil {
		return AXFRNoAnswer
	}
	m, err := co.ReadMsg()
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return AXFRNoAnswer
		}
		// Closing or resetting the connection is a common way to refuse.
		if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "closed") {
			return AXFRRefused
		}
		return AXFRNoAnswer
	}
	if m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 {
		if _, ok := m.Answer[0].(*dns.SOA); ok {
			return AXFRAllowed
		}
	}
	return AXFRRefused
}

// noRoute is true when the local machine cannot reach the address family at
// all, as opposed to the server not answering.
func noRoute(err error) bool {
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "no route to host") || strings.Contains(s, "network is unreachable")
}

// nsUnion is the zone's own NS set: every name an authoritative server
// listed for the apex.
func nsUnion(servers []Server) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range servers {
		if !s.Authoritative {
			continue
		}
		for _, n := range s.NS {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// askAuth asks one server for name/type without recursion.
func (op *Op) askAuth(ctx context.Context, ip, name string, t uint16, o contract.Effective) (*dns.Msg, error) {
	auth := o
	auth.RecursionDesired, auth.EDNS, auth.TCPFallback = false, true, true
	res, err := op.exchange(ctx, "udp", op.addr(ip), name, t, auth)
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// cohosted reads the delegation of apex from a parent server that also
// serves apex: the NS set and glue from an NS query, and the DS set, which
// a server always answers from the parent side (RFC 4035 §3.1.4.1).
func (op *Op) cohosted(ctx context.Context, addr, apex string, o contract.Effective) *trace.Referral {
	auth := o
	auth.RecursionDesired, auth.EDNS, auth.DNSSECOK, auth.TCPFallback = false, true, true, true
	res, err := op.exchange(ctx, "udp", addr, apex, dns.TypeNS, auth)
	if err != nil {
		return nil
	}
	ref := &trace.Referral{Zone: apex, Glue: map[string][]string{}, DS: []contract.Record{}}
	for _, rr := range append(append([]dns.RR{}, res.Msg.Answer...), res.Msg.Ns...) {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, apex) {
			if n := strings.ToLower(ns.Ns); !contains(ref.Nameservers, n) {
				ref.Nameservers = append(ref.Nameservers, n)
			}
		}
	}
	if len(ref.Nameservers) == 0 {
		return nil
	}
	sort.Strings(ref.Nameservers)
	for _, n := range ref.Nameservers {
		if ips := addresses(res.Msg.Extra, n); len(ips) > 0 {
			ref.Glue[n] = ips
		}
	}
	if dsRes, err := op.exchange(ctx, "udp", addr, apex, dns.TypeDS, auth); err == nil {
		for _, rr := range dsRes.Msg.Answer {
			if ds, ok := rr.(*dns.DS); ok && strings.EqualFold(ds.Hdr.Name, apex) {
				ref.DS = append(ref.DS, msg.Record(ds))
			}
		}
	}
	return ref
}
