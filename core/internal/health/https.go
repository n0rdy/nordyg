package health

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/certs"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/fetch"
)

// HTTPSHost is one web name (the zone, or www) and what each of its
// addresses serves on port 443.
type HTTPSHost struct {
	Name string `json:"name"`
	// TLSA records at _443._tcp.<name>, their DNSSEC status as Nordyg
	// validated it, and whether any server's certificate matches them.
	TLSA       []string      `json:"tlsa"`
	TLSAStatus string        `json:"tlsa_status,omitempty"`
	TLSAMatch  *bool         `json:"tlsa_match,omitempty"`
	TLSAError  string        `json:"tlsa_error,omitempty"`
	Servers    []certs.Probe `json:"servers"`
}

// HTTPS is the certificate check.
type HTTPS struct {
	Hosts []HTTPSHost `json:"hosts"`
	Section
}

func (op *Op) httpsAddr(ip string) string {
	if op.HTTPSAddrFor != nil {
		return op.HTTPSAddrFor(ip)
	}
	return net.JoinHostPort(ip, "443")
}

func (op *Op) inspector(p Params, o contract.Effective) *certs.Inspector {
	if op.Certs != nil {
		return op.Certs
	}
	resolve := fetch.NewResolver(op.Client, p.Endpoint, o, p.Bootstrap)
	return &certs.Inspector{FetchCRL: func(ctx context.Context, url string) ([]byte, error) {
		return fetch.GetSigned(ctx, url, resolve)
	}}
}

// checkHTTPS looks at the zone and www: every address, port 443.
func (op *Op) checkHTTPS(ctx context.Context, p Params, r *resolver, o contract.Effective, apex string, caa CAA) HTTPS {
	sec := HTTPS{Hosts: []HTTPSHost{}}
	in := op.inspector(p, o)
	f := dnssec.Shared(&dnssec.Recursive{Client: op.Client, Endpoint: p.Endpoint, Options: o, Bootstrap: p.Bootstrap})
	names := []string{apex}
	if apex != "." {
		names = append(names, "www."+apex)
	}
	for _, name := range names {
		ips := r.addrs(ctx, name)
		if len(ips) == 0 {
			continue
		}
		sort.Slice(ips, func(a, b int) bool { return ipLess(ips[a], ips[b]) })
		host := HTTPSHost{Name: name, TLSA: []string{}, Servers: make([]certs.Probe, len(ips))}
		var wg sync.WaitGroup
		sem := make(chan struct{}, maxProbes)
		for i, ip := range ips {
			wg.Add(1)
			go func(i int, ip string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				host.Servers[i] = op.probeHTTPS(ctx, in, name, ip)
			}(i, ip)
		}
		checkTLSA(ctx, f, &host)
		wg.Wait()
		if host.TLSAStatus == dnssec.Secure {
			m := false
			for _, s := range host.Servers {
				if s.Connected && certs.MatchTLSA(host.tlsaRecords(), s.Certificates(), s.Trusted) {
					m = true
				}
			}
			host.TLSAMatch = &m
		}
		sec.Hosts = append(sec.Hosts, host)
	}
	judgeHTTPS(&sec, caa)
	return sec
}

func (op *Op) probeHTTPS(ctx context.Context, in *certs.Inspector, name, ip string) certs.Probe {
	st, err := in.Handshake(ctx, op.httpsAddr(ip), strings.TrimSuffix(name, "."))
	if err != nil {
		pr := certs.Probe{Name: name, IP: ip, Port: 443, Chain: []certs.Cert{}, Revoked: []certs.Revocation{}}
		if strings.Contains(ip, ":") && noRoute(err) {
			pr.Skipped = true
			pr.Error = "this Mac has no IPv6 route, so the address was not checked"
		} else {
			pr.Error = err.Error()
		}
		return pr
	}
	pr := in.Inspect(ctx, st, name)
	pr.Name, pr.IP, pr.Port = name, ip, 443
	return pr
}

// checkTLSA reads _443._tcp.<name> and validates its DNSSEC status itself;
// TLSA without DNSSEC carries no weight.
func checkTLSA(ctx context.Context, f dnssec.Fetcher, host *HTTPSHost) {
	qname := "_443._tcp." + dns.Fqdn(host.Name)
	m, err := dnssec.FetchRRset(ctx, f, qname, dns.TypeTLSA)
	if err != nil {
		host.TLSAError = err.Error()
		return
	}
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			host.TLSA = append(host.TLSA, strings.TrimPrefix(t.String(), t.Hdr.String()))
		}
	}
	if len(host.TLSA) == 0 {
		return
	}
	res, err := dnssec.New().Validate(ctx, f, qname, dns.TypeTLSA, m)
	if err == nil && res != nil {
		host.TLSAStatus = res.Status
	}
}

func (h *HTTPSHost) tlsaRecords() []*dns.TLSA {
	var out []*dns.TLSA
	for _, s := range h.TLSA {
		if rr, err := dns.NewRR("x. 300 IN TLSA " + s); err == nil {
			out = append(out, rr.(*dns.TLSA))
		}
	}
	return out
}

// judgeHTTPS turns probes into findings, one line per problem with the
// addresses it applies to.
func judgeHTTPS(sec *HTTPS, caa CAA) {
	if len(sec.Hosts) == 0 {
		sec.add(Info, "neither the zone nor www has an address, so there is no website to check")
		sec.settle("")
		return
	}
	allowed := caaIssuers(caa)
	minDays, served := -1, 0
	var working []string
	scope := "every address"
	for _, h := range sec.Hosts {
		problems := map[string][]string{} // message → addresses
		status := map[string]string{}
		add := func(st, msg, ip string) { problems[msg] = append(problems[msg], ip); status[msg] = st }
		connected, skipped := 0, 0
		fingerprints := map[string]bool{}
		for _, s := range h.Servers {
			switch {
			case s.Skipped:
				skipped++
				continue
			case !s.Connected:
				add(Warn, "does not answer HTTPS on port 443", s.IP)
				continue
			}
			connected++
			served++
			if len(s.Chain) > 0 {
				fingerprints[s.Chain[0].SHA256] = true
			}
			if minDays < 0 || s.ExpiresInDays < minDays {
				minDays = s.ExpiresInDays
			}
			switch {
			case len(s.Revoked) > 0:
				r := s.Revoked[0]
				add(Fail, fmt.Sprintf("serves a chain through %s, which its CA revoked on %s (%s)", r.Subject, r.RevokedAt.Format("2 Jan 2006"), r.Reason), s.IP)
			case !s.NameMatch && len(s.Chain) > 0:
				add(Fail, fmt.Sprintf("serves a certificate for %s, which does not cover %s", strings.Join(firstN(s.Chain[0].Names, 3), ", "), prose(h.Name)), s.IP)
			case s.ExpiresInDays < 0:
				add(Fail, "serves an expired certificate", s.IP)
			case !s.Trusted:
				add(Fail, "serves a certificate macOS does not trust: "+s.TrustError, s.IP)
			case s.ExpiresInDays < 14:
				add(Warn, fmt.Sprintf("serves a certificate that expires in %d day%s", s.ExpiresInDays, plural(s.ExpiresInDays)), s.IP)
			}
			if chain := s.Certificates(); len(allowed) > 0 && s.Trusted && len(chain) > 0 {
				if ids := certs.CAAIdentifiers(chain[0]); ids != nil && !overlaps(ids, allowed) {
					add(Warn, fmt.Sprintf("serves a certificate from %s, which the CAA record does not allow, so renewing it there will fail", s.Chain[0].Issuer), s.IP)
				}
			}
		}
		if connected == 0 && skipped < len(h.Servers) {
			sec.add(Info, "%s does not answer HTTPS on port 443", prose(h.Name))
			continue
		}
		if connected > 0 {
			working = append(working, prose(h.Name))
		}
		msgs := make([]string, 0, len(problems))
		for m := range problems {
			msgs = append(msgs, m)
		}
		sort.Strings(msgs)
		for _, m := range msgs {
			ips := problems[m]
			who := strings.Join(ips, ", ")
			if len(ips) == connected && connected > 1 {
				who = "every address"
			}
			sec.add(status[m], "%s: %s %s", prose(h.Name), who, m)
		}
		if len(fingerprints) > 1 {
			sec.add(Info, "%s: the addresses serve %d different certificates", prose(h.Name), len(fingerprints))
		}
		switch {
		case h.TLSAError != "":
			sec.add(Info, "%s: the TLSA lookup failed through this resolver, so DANE was not checked", prose(h.Name))
		case len(h.TLSA) > 0 && h.TLSAStatus == dnssec.Bogus:
			sec.add(Fail, "%s: the TLSA records fail DNSSEC validation, so DANE clients refuse to connect", prose(h.Name))
		case len(h.TLSA) > 0 && h.TLSAStatus == dnssec.Insecure:
			sec.add(Warn, "%s publishes TLSA records without DNSSEC, so clients ignore them", prose(h.Name))
		case len(h.TLSA) > 0 && h.TLSAStatus != dnssec.Secure:
			sec.add(Info, "%s: the TLSA records could not be DNSSEC-validated through this resolver, so DANE was not checked", prose(h.Name))
		case h.TLSAMatch != nil && !*h.TLSAMatch:
			sec.add(Fail, "%s: the TLSA records match none of the certificates served, so DANE clients refuse to connect", prose(h.Name))
		}
		if skipped > 0 {
			scope = "every IPv4 address"
			sec.add(Info, "%s: this Mac has no IPv6 route, so %d IPv6 address%s could not be checked", prose(h.Name), skipped, pluralEs(skipped))
		}
	}
	if served == 0 {
		sec.settle("")
		return
	}
	okMsg := fmt.Sprintf("%s serves a valid certificate on %s, expiring in %d day%s", working[0], scope, minDays, plural(minDays))
	if len(working) > 1 {
		okMsg = fmt.Sprintf("%s serve a valid certificate on %s, the soonest expiring in %d day%s", strings.Join(working, " and "), scope, minDays, plural(minDays))
	}
	sec.settle(okMsg)
	// Notes (another certificate per address, an IPv6 address not reached)
	// do not outweigh a working site.
	if sec.Verdict.Status == Info {
		sec.Verdict = Finding{OK, okMsg}
	}
}

// caaIssuers is the set of CA names the CAA record lets issue (issue tags).
func caaIssuers(caa CAA) []string {
	var out []string
	for _, r := range caa.Records {
		if r.Tag != "issue" {
			continue
		}
		if ca := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Value, ";", 2)[0])); ca != "" {
			out = append(out, ca)
		}
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "…")
	}
	return s
}
