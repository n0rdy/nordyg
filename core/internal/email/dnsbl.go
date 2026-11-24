package email

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/prose"
	"github.com/n0rdy/nordyg/core/internal/resolve"
)

// DNSBLCheck is one address looked up in one blocklist.
type DNSBLCheck struct {
	IP       string `json:"ip"`
	Zone     string `json:"zone"`
	Listed   bool   `json:"listed"`
	Blocked  bool   `json:"blocked"`
	Response string `json:"response,omitempty"`
	Error    string `json:"error,omitempty"`
}

// DNSBLSection is every MX address against every blocklist.
type DNSBLSection struct {
	Checks  []DNSBLCheck `json:"checks"`
	Verdict Verdict      `json:"verdict"`
}

// DNSBLZones are queried for every MX IPv4 address.
var DNSBLZones = []string{"zen.spamhaus.org.", "bl.spamcop.net.", "b.barracudacentral.org."}

func checkDNSBL(ctx context.Context, r *resolve.Resolver, mx MXSection, zones []string) DNSBLSection {
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
		sec.Verdict = Verdict{Status: Info, Message: "no IPv4 MX addresses to check"}
		return sec
	}
	type key struct{ ip, zone string }
	results := map[key]DNSBLCheck{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		for _, zone := range zones {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := DNSBLCheck{IP: ip, Zone: strings.TrimSuffix(zone, ".")}
				rev := reverse4(ip) + "." + dns.Fqdn(zone)
				m, err := r.Lookup(ctx, rev, dns.TypeA)
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
			}()
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
		sec.Verdict = Verdict{Status: Fail, Message: fmt.Sprintf("%d listing%s on blocklists, so receivers using them will refuse mail from these MX hosts", listed, prose.Plural(listed))}
	case blocked == len(sec.Checks):
		sec.Verdict = Verdict{Status: Info, Message: "the blocklists refuse queries from this resolver (public resolvers are blocked). Use your ISP or system resolver to check"}
	case blocked > 0:
		sec.Verdict = Verdict{Status: OK, Message: fmt.Sprintf("not listed where the lists answered, and %d list%s refused this resolver", blocked, prose.Plural(blocked))}
	default:
		sec.Verdict = Verdict{Status: OK, Message: fmt.Sprintf("%d address%s clean on %d blocklists", len(ips), prose.PluralEs(len(ips)), len(zones))}
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
