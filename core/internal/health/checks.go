package health

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/msg"
	"github.com/n0rdy/nordyg/core/internal/prose"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/trace"
	"github.com/n0rdy/nordyg/core/internal/verdict"
)

func checkDelegation(d *Delegation, apex string, servers []Server, extra map[string][]string) {
	if n := len(d.ParentNS); n < 2 {
		d.add(Warn, "the parent lists only %d nameserver, but RFC 1034 asks for at least two, on separate networks", n)
	}
	authoritative := 0
	sets := map[string][]string{}
	for _, s := range servers {
		if s.Authoritative {
			authoritative++
			// An empty set means the NS query to this server failed, which
			// is not a disagreement.
			if len(s.NS) > 0 {
				key := strings.Join(s.NS, " ")
				sets[key] = append(sets[key], label(s))
			}
		}
	}
	if authoritative == 0 {
		d.add(Fail, "no nameserver answers authoritatively for %s", prose.Name(apex))
	}
	if len(d.ChildNS) > 0 {
		var onlyParent []string
		for _, n := range d.ParentNS {
			if !contains(d.ChildNS, n) {
				onlyParent = append(onlyParent, prose.Name(n))
			}
		}
		if len(onlyParent) > 0 {
			d.add(Warn, "delegated by the parent but missing from the zone's own NS set: %s", strings.Join(onlyParent, ", "))
		}
	}
	if len(extra) > 0 {
		var onlyChild []string
		for n := range extra {
			onlyChild = append(onlyChild, prose.Name(n))
		}
		sort.Strings(onlyChild)
		d.add(Warn, "in the zone's own NS set but not delegated by the parent, so resolvers coming from the parent never use them: %s", strings.Join(onlyChild, ", "))
	}
	if len(sets) > 1 {
		d.add(Warn, "the nameservers disagree on the zone's NS set")
	}

	var v4, v6 []string
	for _, s := range servers {
		if s.IP == "" {
			continue
		}
		if strings.Contains(s.IP, ":") {
			v6 = append(v6, s.IP)
		} else {
			v4 = append(v4, s.IP)
		}
	}
	if len(v4) >= 2 && sameNet(v4) {
		d.add(Warn, "every nameserver IPv4 address is in one /24, so one network outage takes the whole zone down")
	}
	if len(v4) > 0 && len(v6) == 0 {
		d.add(Info, "no nameserver has an IPv6 address, so IPv6-only resolvers cannot reach the zone")
	}
	d.settle(fmt.Sprintf("the parent delegates to %d nameserver%s and the zone lists the same set", len(d.ParentNS), prose.Plural(len(d.ParentNS))))
}

func sameNet(ips []string) bool {
	nets := map[string]bool{}
	for _, s := range ips {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			continue
		}
		nets[ip.Mask(net.CIDRMask(24, 32)).String()] = true
	}
	return len(nets) == 1
}

func checkServers(servers []Server) Nameservers {
	sec := Nameservers{Servers: servers}
	answering := 0
	for i := range servers {
		s := &servers[i]
		p := func(status, format string, args ...any) {
			s.Problems = append(s.Problems, Finding{Status: status, Message: fmt.Sprintf(format, args...)})
		}
		switch {
		case s.Skipped:
			p(Info, "%s", s.Error)
		case s.unresolved:
			p(Warn, "could not be checked, because its address lookup failed through this resolver")
		case s.IP == "":
			p(Fail, "has no A or AAAA records")
		case !s.Answered && s.TCP:
			p(Fail, "answers over TCP but not over UDP: %s", s.Error)
		case !s.Answered:
			p(Fail, "does not answer: %s", s.Error)
		case s.Rcode != "NOERROR":
			p(Fail, "answers %s for the zone's SOA: a lame delegation", s.Rcode)
		case !s.Authoritative:
			p(Fail, "answers without the AA flag, so it is not authoritative for the zone: a lame delegation")
		}
		if s.Answered && s.Authoritative {
			answering++
			if s.Serial == nil {
				p(Warn, "is authoritative but returned no SOA record")
			}
			if !s.TCP {
				p(Fail, "does not answer over TCP, which every nameserver must (RFC 7766)")
			}
			if !s.EDNS {
				p(Warn, "ignores EDNS, so large answers fall back to TCP (RFC 6891)")
			}
		}
		if s.AXFR == AXFRAllowed {
			p(Warn, "allows a zone transfer (AXFR) to anyone, which publishes every name in the zone")
		}
		if s.Recursion {
			p(Warn, "resolves names for anyone: an open resolver can be abused for amplification attacks")
		}
		s.Status = OK
		for _, f := range s.Problems {
			if verdict.Rank(f.Status) > verdict.Rank(s.Status) {
				s.Status = f.Status
			}
			if !s.Skipped {
				sec.add(f.Status, "%s %s", label(*s), f.Message)
			}
		}
	}
	skipped := 0
	for _, s := range servers {
		if s.Skipped {
			skipped++
		}
	}
	if skipped > 0 {
		sec.add(Info, "this Mac has no IPv6 route, so %d IPv6 address%s could not be checked", skipped, prose.PluralEs(skipped))
	}
	okMsg := fmt.Sprintf("all %d addresses answer authoritatively over UDP and TCP", answering)
	if answering == 1 {
		okMsg = "the only address answers authoritatively over UDP and TCP"
	}
	sec.settle(okMsg)
	if sec.Verdict.Status == Info {
		// Only notes, no problems: keep the good news in the verdict.
		sec.Verdict.Message = okMsg + ". " + strings.ToUpper(sec.Verdict.Message[:1]) + sec.Verdict.Message[1:]
	}
	return sec
}

func checkSOA(servers []Server, apex string) SOA {
	sec := SOA{Serials: []SerialGroup{}}
	idx := map[uint32]int{}
	var soa *dns.SOA
	for _, s := range servers {
		if !s.Authoritative || s.Serial == nil {
			continue
		}
		if soa == nil {
			soa = s.soa
		}
		i, ok := idx[*s.Serial]
		if !ok {
			i = len(sec.Serials)
			idx[*s.Serial] = i
			sec.Serials = append(sec.Serials, SerialGroup{Serial: *s.Serial})
		}
		sec.Serials[i].Servers = append(sec.Serials[i].Servers, label(s))
		sec.Serials[i].names = append(sec.Serials[i].names, s.Name)
	}
	sort.Slice(sec.Serials, func(a, b int) bool { return sec.Serials[a].Serial > sec.Serials[b].Serial })
	if soa == nil {
		sec.add(Fail, "no nameserver returned the SOA record of %s", prose.Name(apex))
		sec.settle("")
		return sec
	}
	rec := msg.Record(soa)
	sec.Record = &rec
	if len(sec.Serials) > 1 {
		parts := make([]string, 0, len(sec.Serials))
		for _, g := range sec.Serials {
			parts = append(parts, fmt.Sprintf("%d on %s", g.Serial, strings.Join(g.Servers, ", ")))
		}
		if byProvider(sec.Serials) {
			sec.add(Info, "the serial differs between DNS providers, which is normal when several providers serve the zone, each with its own serial: %s", strings.Join(parts, " and "))
		} else {
			sec.add(Warn, "the nameservers serve different versions of the zone (a change still propagating, or a broken transfer): %s", strings.Join(parts, " and "))
		}
	}
	if soa.Retry >= soa.Refresh {
		sec.add(Warn, "retry (%s) should be shorter than refresh (%s)", dur(soa.Retry), dur(soa.Refresh))
	}
	if soa.Expire < 7*86400 {
		sec.add(Warn, "expire is %s, so secondaries stop serving the zone that soon after losing the primary. A week or more is usual", dur(soa.Expire))
	}
	if soa.Expire <= soa.Refresh {
		sec.add(Warn, "expire (%s) is not longer than refresh (%s), so secondaries can expire the zone between refreshes", dur(soa.Expire), dur(soa.Refresh))
	}
	if soa.Minttl > 86400 {
		sec.add(Warn, "negative answers are cached for %s (the SOA minimum), so new names take that long to appear for resolvers that asked before (RFC 2308)", dur(soa.Minttl))
	}
	n := 0
	for _, g := range sec.Serials {
		n += len(g.Servers)
	}
	if n == 1 {
		sec.settle(fmt.Sprintf("the only address serves serial %d", sec.Serials[0].Serial))
	} else {
		sec.settle(fmt.Sprintf("all %d addresses serve serial %d", n, sec.Serials[0].Serial))
	}
	return sec
}

// byProvider reports whether the serial groups split cleanly by the
// nameservers' parent domains (nsone.net vs awsdns-*), the signature of a
// multi-provider setup rather than a lagging secondary.
func byProvider(groups []SerialGroup) bool {
	owner := map[string]int{}
	for i, g := range groups {
		for _, name := range g.names {
			p := provider(name)
			if j, ok := owner[p]; ok && j != i {
				return false
			}
			owner[p] = i
		}
	}
	return true
}

// provider is the last two labels of a nameserver's name.
func provider(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.ToLower(strings.Join(parts, "."))
}

// dur renders seconds the way people read timers: exact for round SOA
// values, approximate otherwise.
func dur(s uint32) string {
	switch {
	case s >= 86400 && s%86400 == 0:
		return fmt.Sprintf("%d d", s/86400)
	case s >= 3600 && s%3600 == 0:
		return fmt.Sprintf("%d h", s/3600)
	case s >= 60 && s%60 == 0:
		return fmt.Sprintf("%d min", s/60)
	case s >= 2*86400:
		return fmt.Sprintf("about %d d", s/86400)
	case s >= 3600:
		return fmt.Sprintf("about %d h", s/3600)
	case s >= 60:
		return fmt.Sprintf("about %d min", s/60)
	}
	return fmt.Sprintf("%d s", s)
}

func (op *Op) checkGlue(ctx context.Context, apex string, ref *trace.Referral, servers []Server, o contract.Effective) Glue {
	sec := Glue{Entries: []GlueEntry{}}
	var authIP string
	for _, s := range servers {
		if s.Authoritative {
			authIP = s.IP
			break
		}
	}
	inside := 0
	for _, name := range ref.Nameservers {
		e := GlueEntry{Name: name, InBailiwick: dns.IsSubDomain(apex, name), Parent: union(ref.Glue[name], nil), Child: []string{}}
		if e.Parent == nil {
			e.Parent = []string{}
		}
		if !e.InBailiwick {
			e.Match = true
			sec.Entries = append(sec.Entries, e)
			continue
		}
		inside++
		if authIP != "" {
			var child []string
			for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if m, err := op.askAuth(ctx, authIP, name, t, o); err == nil {
					child = append(child, addresses(m.Answer, name)...)
				}
			}
			e.Child = union(child, nil)
			if e.Child == nil {
				e.Child = []string{}
			}
		}
		e.Match = equalSets(e.Parent, e.Child)
		switch {
		case len(e.Parent) == 0:
			sec.add(Fail, "%s is inside the zone but the parent has no glue for it, so resolvers cannot reach it", prose.Name(name))
		case authIP == "":
			sec.add(Info, "the zone's own records for %s could not be read, so its glue was not compared", prose.Name(name))
		case len(e.Child) == 0:
			sec.add(Warn, "the zone has no A or AAAA record for its own nameserver %s, so only the parent's glue points at it", prose.Name(name))
		case !e.Match && !overlaps(e.Parent, e.Child):
			sec.add(Fail, "the parent's glue for %s (%s) has no address in common with the zone's own records (%s)", prose.Name(name), strings.Join(e.Parent, ", "), strings.Join(e.Child, ", "))
		case !e.Match:
			sec.add(Warn, "the parent's glue for %s (%s) differs from the zone's own records (%s)", prose.Name(name), strings.Join(e.Parent, ", "), strings.Join(e.Child, ", "))
		}
		sec.Entries = append(sec.Entries, e)
	}
	if inside == 0 {
		sec.settle("no nameserver is inside the zone, so no glue is needed")
		return sec
	}
	sec.settle(fmt.Sprintf("the parent's glue matches the zone's own records for %d nameserver%s", inside, prose.Plural(inside)))
	return sec
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, s := range a {
		if !contains(b, s) {
			return false
		}
	}
	return true
}

func overlaps(a, b []string) bool {
	for _, s := range a {
		if contains(b, s) {
			return true
		}
	}
	return false
}

func checkDNSSEC(tr *trace.Result, ref *trace.Referral, servers []Server, apex string) DNSSEC {
	sec := DNSSEC{DS: ref.DS}
	if sec.DS == nil {
		sec.DS = []contract.Record{}
	}
	if tr != nil {
		sec.Result, _ = tr.DNSSEC.(*dnssec.Result)
	}
	r := sec.Result
	if r == nil {
		sec.add(Info, "the chain of trust was not validated")
	} else {
		sec.Status = r.Status
		switch r.Status {
		case dnssec.Insecure:
			if len(sec.DS) == 0 {
				sec.add(Info, "the zone is not signed: the parent publishes no DS record for it")
			} else {
				sec.add(Warn, "%s", r.Reason)
			}
		case dnssec.Bogus:
			sec.add(Fail, "validation fails: %s", r.Reason)
		case dnssec.Indeterminate:
			sec.add(Warn, "validation could not finish: %s", r.Reason)
		}
	}
	if len(sec.DS) > 0 {
		for _, s := range servers {
			if s.Authoritative && !s.Signed {
				sec.add(Fail, "%s serves the zone without signatures although the parent publishes a DS, so validating resolvers that ask it fail", label(s))
			}
		}
		dsHygiene(&sec)
	}
	if r != nil && r.Status == dnssec.Secure {
		// On-the-fly signers (Cloudflare, NS1) issue signatures valid for a
		// day or so, so only a signature near the end of its own validity
		// period is a sign of a stuck signer.
		if sig, ok := soonestExpiry(r, apex); ok {
			left := sig.ExpiresInMS
			period := sig.Expiration.Sub(sig.Inception).Milliseconds()
			if left < 3*86400*1000 && (period <= 0 || left*5 < period) {
				sec.add(Warn, "the zone's signatures expire in %s, near the end of their validity. If re-signing has stopped, the zone turns bogus then", dur(uint32(max(left, 0)/1000)))
			}
		}
	}
	sec.settle("the chain of trust validates from the root to " + prose.Name(apex))
	return sec
}

// soonestExpiry is the valid signature made by the zone with the least
// time left.
func soonestExpiry(r *dnssec.Result, apex string) (dnssec.Signature, bool) {
	var best dnssec.Signature
	found := false
	consider := func(sigs []dnssec.Signature) {
		for _, s := range sigs {
			if strings.EqualFold(s.Signer, apex) && s.Valid && (!found || s.ExpiresInMS < best.ExpiresInMS) {
				best, found = s, true
			}
		}
	}
	for _, l := range r.Chain {
		if strings.EqualFold(l.Zone, apex) {
			consider(l.Signatures)
		}
	}
	consider(r.AnswerSignatures)
	return best, found
}

// dsHygiene flags DS digests and algorithms RFC 8624 retires.
func dsHygiene(sec *DNSSEC) {
	sha1Only := true
	weakAlg := map[uint8]bool{}
	for _, rec := range sec.DS {
		algorithm, _ := rec.Fields["algorithm"].(uint8)
		if digest, _ := rec.Fields["digest_type"].(uint8); digest != dns.SHA1 {
			sha1Only = false
		}
		switch algorithm {
		case dns.RSAMD5, dns.DSA, dns.DSANSEC3SHA1, dns.ECCGOST, dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
			weakAlg[algorithm] = true
		}
	}
	if sha1Only {
		sec.add(Warn, "every DS record uses a SHA-1 digest, which RFC 8624 retires. Publish a SHA-256 DS")
	}
	for _, a := range slices.Sorted(maps.Keys(weakAlg)) {
		sec.add(Warn, "the zone signs with %s, an algorithm RFC 8624 retires. ECDSAP256SHA256 or ED25519 are the usual choices", dns.AlgorithmToString[a])
	}
}

var caaTags = map[string]bool{"issue": true, "issuewild": true, "iodef": true, "issuemail": true, "issuevmc": true, "contactemail": true, "contactphone": true}

// checkCAA finds the relevant CAA set by climbing from domain towards the
// root (RFC 8659 §3), stopping below the root.
func checkCAA(ctx context.Context, r *resolve.Resolver, domain string) CAA {
	sec := CAA{Records: []CAARecord{}}
	labels := dns.SplitDomainName(domain)
	for i := range labels {
		name := strings.Join(labels[i:], ".") + "."
		m, err := r.Lookup(ctx, name, dns.TypeCAA)
		if err != nil {
			sec.add(Warn, "the CAA lookup for %s failed: %s", prose.Name(name), err.Error())
			sec.settle("")
			return sec
		}
		if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
			hint := ""
			if m.Rcode == dns.RcodeServerFailure {
				hint = " (a validating resolver answers SERVFAIL when the zone's DNSSEC is broken)"
			}
			sec.add(Warn, "the CAA lookup for %s returned %s, so CAs may refuse to issue%s", prose.Name(name), dns.RcodeToString[m.Rcode], hint)
			sec.settle("")
			return sec
		}
		for _, rr := range m.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				sec.Records = append(sec.Records, CAARecord{Flags: c.Flag, Tag: strings.ToLower(c.Tag), Value: c.Value})
			}
		}
		if len(sec.Records) > 0 {
			sec.FoundAt = name
			break
		}
	}
	if len(sec.Records) == 0 {
		sec.add(Info, "no CAA record at %s or above it, so any certificate authority may issue for it", prose.Name(domain))
		sec.settle("")
		return sec
	}
	var issue, wild []string
	issueSeen, wildSeen := false, false
	for _, c := range sec.Records {
		if !caaTags[c.Tag] && c.Flags&128 != 0 {
			sec.add(Warn, "a critical CAA tag %q is not one CAs know, so they must refuse to issue (RFC 8659 §4.1)", c.Tag)
		}
		ca := strings.TrimSpace(strings.SplitN(c.Value, ";", 2)[0])
		switch c.Tag {
		case "issue":
			issueSeen = true
			if ca != "" {
				issue = append(issue, ca)
			}
		case "issuewild":
			wildSeen = true
			if ca != "" {
				wild = append(wild, ca)
			}
		}
	}
	where := "CAA at " + prose.Name(sec.FoundAt)
	var okMsg string
	switch {
	case issueSeen && len(issue) == 0:
		okMsg = where + " forbids every CA from issuing"
	case issueSeen:
		okMsg = where + " lets " + strings.Join(issue, ", ") + " issue certificates"
	default:
		okMsg = where + " sets no issue rule, so any CA may issue"
	}
	if wildSeen {
		if len(wild) == 0 {
			okMsg += ", but no CA may issue wildcards"
		} else {
			okMsg += ", and for wildcards " + strings.Join(wild, ", ")
		}
	}
	sec.settle(okMsg)
	return sec
}
