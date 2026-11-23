package dnssec

import (
	"bytes"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// proofKind is what a set of NSEC/NSEC3 records proves about a name.
type proofKind int

const (
	proofNone     proofKind = iota // nothing usable
	proofBogus                     // records present but their signatures fail
	proofNoData                    // name exists, type does not
	proofNXDomain                  // name does not exist
	proofOptOut                    // name is inside an NSEC3 opt-out span
)

type proof struct {
	kind       proofKind
	delegation bool // NoData at a delegation point (NS set, SOA clear)
	reason     string
	signatures []Signature
}

// denial examines the authority section of m for a proof about (name, qtype),
// accepting only records validly signed by keys of zone.
func denial(m *dns.Msg, name string, qtype uint16, keys []*dns.DNSKEY, zone string, now time.Time) proof {
	p := proof{kind: proofNone}
	nsecs, nsec3s, sigs, sawBad := denialSets(m, keys, zone, now)
	p.signatures = sigs
	name = dns.Fqdn(strings.ToLower(name))
	if len(nsecs) > 0 {
		return nsecProof(p, nsecs, name, qtype)
	}
	if len(nsec3s) > 0 {
		return nsec3Proof(p, nsec3s, name, qtype)
	}
	if sawBad {
		p.kind = proofBogus
		p.reason = "NSEC/NSEC3 records for " + name + " are not validly signed by " + zone
		return p
	}
	p.reason = "no NSEC or NSEC3 records prove anything about " + name
	return p
}

// denialSets collects the NSEC and NSEC3 records in m's authority section
// that are validly signed by zone. bad is true when some were present but
// failed verification.
func denialSets(m *dns.Msg, keys []*dns.DNSKEY, zone string, now time.Time) (nsecs []*dns.NSEC, nsec3s []*dns.NSEC3, sigs []Signature, bad bool) {
	for _, s := range rrsets(m.Ns) {
		if s.typ != dns.TypeNSEC && s.typ != dns.TypeNSEC3 {
			continue
		}
		ss, ok := verifySet(s, keys, zone, now)
		sigs = append(sigs, ss...)
		if !ok {
			bad = true
			continue
		}
		for _, rr := range s.rrs {
			switch v := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, v)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, v)
			}
		}
	}
	return nsecs, nsec3s, sigs, bad
}

// wildcardProof checks that m's authority section proves name itself does
// not exist, so expanding wild for it was legitimate (RFC 4035 §5.3.4,
// RFC 5155 §8.8). Without that proof a signed wildcard answer could be
// replayed for a name that has records of its own. It returns Secure, Bogus
// (no proof), or Indeterminate (NSEC3 present but unusable).
func wildcardProof(m *dns.Msg, name, wild string, keys []*dns.DNSKEY, zone string, now time.Time) (string, string, []Signature) {
	nsecs, nsec3s, sigs, _ := denialSets(m, keys, zone, now)
	name = dns.Fqdn(strings.ToLower(name))
	ce := strings.TrimPrefix(strings.ToLower(wild), "*.")
	if ce == "" {
		ce = "."
	}
	for _, n := range nsecs {
		if nsecCovers(n, name) && strings.EqualFold(closestEncloser(name, n), ce) {
			return Secure, "", sigs
		}
	}
	if len(nsec3s) > 0 {
		for _, n := range nsec3s {
			if n.Iterations > 150 {
				return Indeterminate, "NSEC3 iterations " + itoa(int(n.Iterations)) + " exceed the limit; cannot check the wildcard expansion for " + prose(name) + " (RFC 9276)", sigs
			}
		}
		// The closest encloser is implied by the RRSIG labels; only the next
		// closer name needs a covering NSEC3.
		labels := dns.SplitDomainName(name)
		if k := dns.CountLabel(ce) + 1; k <= len(labels) {
			nc := strings.Join(labels[len(labels)-k:], ".") + "."
			if nsec3Cover(nsec3s, nc) != nil {
				return Secure, "", sigs
			}
		}
	}
	return Bogus, prose(name) + " was answered from the wildcard " + prose(wild) + ", but the response does not prove that " + prose(name) + " itself does not exist (RFC 4035 §5.3.4)", sigs
}

// --- NSEC --------------------------------------------------------------------

func nsecProof(p proof, nsecs []*dns.NSEC, name string, qtype uint16) proof {
	for _, n := range nsecs {
		if strings.EqualFold(n.Hdr.Name, name) {
			if hasType(n.TypeBitMap, qtype) || hasType(n.TypeBitMap, dns.TypeCNAME) {
				p.kind = proofBogus
				p.reason = "NSEC for " + name + " claims the type exists"
				return p
			}
			p.kind = proofNoData
			p.delegation = hasType(n.TypeBitMap, dns.TypeNS) && !hasType(n.TypeBitMap, dns.TypeSOA)
			return p
		}
	}
	var covering *dns.NSEC
	for _, n := range nsecs {
		if nsecCovers(n, name) {
			covering = n
			break
		}
	}
	if covering == nil {
		p.reason = "no NSEC matches or covers " + name
		return p
	}
	ce := closestEncloser(name, covering)
	wild := "*." + ce
	if ce == "." {
		wild = "*."
	}
	for _, n := range nsecs {
		if strings.EqualFold(n.Hdr.Name, wild) {
			p.kind = proofBogus
			p.reason = "wildcard " + wild + " exists but was not expanded"
			return p
		}
		if nsecCovers(n, wild) {
			p.kind = proofNXDomain
			return p
		}
	}
	p.reason = "NSEC covers " + name + " but nothing denies the wildcard " + wild
	return p
}

// nsecCovers reports whether name falls strictly between owner and next in
// canonical order, handling the last NSEC that wraps to the apex.
func nsecCovers(n *dns.NSEC, name string) bool {
	owner, next := strings.ToLower(n.Hdr.Name), strings.ToLower(n.NextDomain)
	if canonicalCompare(owner, name) == 0 {
		return false
	}
	if canonicalCompare(owner, next) < 0 {
		return canonicalCompare(owner, name) < 0 && canonicalCompare(name, next) < 0
	}
	// Wrap-around: next is the apex, so everything after owner or before next.
	return canonicalCompare(owner, name) < 0 || canonicalCompare(name, next) < 0
}

// closestEncloser is the longest common ancestor of name and the NSEC's
// owner or next name.
func closestEncloser(name string, n *dns.NSEC) string {
	a := commonAncestor(name, strings.ToLower(n.Hdr.Name))
	b := commonAncestor(name, strings.ToLower(n.NextDomain))
	if dns.CountLabel(b) > dns.CountLabel(a) {
		return b
	}
	return a
}

func commonAncestor(a, b string) string {
	la, lb := dns.SplitDomainName(a), dns.SplitDomainName(b)
	var common []string
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if !strings.EqualFold(la[i], lb[j]) {
			break
		}
		common = append([]string{la[i]}, common...)
	}
	if len(common) == 0 {
		return "."
	}
	return strings.Join(common, ".") + "."
}

// canonicalCompare orders names per RFC 4034 §6.1.
func canonicalCompare(a, b string) int {
	la, lb := dns.SplitDomainName(a), dns.SplitDomainName(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(bytes.ToLower([]byte(la[i])), bytes.ToLower([]byte(lb[j]))); c != 0 {
			return c
		}
	}
	switch {
	case len(la) < len(lb):
		return -1
	case len(la) > len(lb):
		return 1
	}
	return 0
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, v := range bitmap {
		if v == t {
			return true
		}
	}
	return false
}

// --- NSEC3 -------------------------------------------------------------------

func nsec3Proof(p proof, nsec3s []*dns.NSEC3, name string, qtype uint16) proof {
	for _, n := range nsec3s {
		if n.Iterations > 150 {
			p.reason = "NSEC3 iterations " + itoa(int(n.Iterations)) + " exceed the limit; treating as unusable (RFC 9276)"
			return p
		}
	}
	if n := nsec3Match(nsec3s, name); n != nil {
		if hasType(n.TypeBitMap, qtype) || hasType(n.TypeBitMap, dns.TypeCNAME) {
			p.kind = proofBogus
			p.reason = "NSEC3 for " + name + " claims the type exists"
			return p
		}
		p.kind = proofNoData
		p.delegation = hasType(n.TypeBitMap, dns.TypeNS) && !hasType(n.TypeBitMap, dns.TypeSOA)
		return p
	}
	// Closest encloser proof: walk up until an NSEC3 matches an ancestor.
	labels := dns.SplitDomainName(name)
	for i := 1; i <= len(labels); i++ {
		ce := "."
		if i < len(labels) {
			ce = strings.Join(labels[i:], ".") + "."
		}
		if nsec3Match(nsec3s, ce) == nil {
			continue
		}
		nc := strings.Join(labels[i-1:], ".") + "."
		cover := nsec3Cover(nsec3s, nc)
		if cover == nil {
			p.reason = "closest encloser " + ce + " proven but nothing covers " + nc
			return p
		}
		if qtype == dns.TypeDS && cover.Flags&1 != 0 {
			p.kind = proofOptOut
			p.reason = "opt-out span covers " + nc
			return p
		}
		wild := "*." + ce
		if ce == "." {
			wild = "*."
		}
		if nsec3Match(nsec3s, wild) != nil {
			p.kind = proofBogus
			p.reason = "wildcard " + wild + " exists but was not expanded"
			return p
		}
		if nsec3Cover(nsec3s, wild) == nil {
			p.reason = "nothing covers the wildcard " + wild
			return p
		}
		p.kind = proofNXDomain
		return p
	}
	p.reason = "no NSEC3 matches " + name + " or any ancestor"
	return p
}

func nsec3Match(set []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range set {
		if n.Match(name) {
			return n
		}
	}
	return nil
}

func nsec3Cover(set []*dns.NSEC3, name string) *dns.NSEC3 {
	for _, n := range set {
		if n.Cover(name) {
			return n
		}
	}
	return nil
}
