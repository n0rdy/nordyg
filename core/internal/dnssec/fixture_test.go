package dnssec

import (
	"context"
	"crypto"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// zone is a signed test zone with an in-memory authoritative server.
type zone struct {
	t        *testing.T
	apex     string
	rrsets   map[string]map[uint16][]dns.RR // lowercase owner → type → records
	children map[string]*zone
	parent   *zone

	signed     bool
	nsec3      bool
	optout     bool
	ksk, zsk   *dns.DNSKEY
	kpriv      crypto.Signer
	zpriv      crypto.Signer
	inception  time.Time
	expiration time.Time
	corruptSig bool
	stripSigs  bool

	nsecs  map[string]dns.RR // owner → NSEC or NSEC3 record (by hashed owner for NSEC3)
	sigs   map[string]map[uint16][]dns.RR
	params *dns.NSEC3PARAM
}

type zoneOpt func(*zone)

func withNSEC3(optout bool) zoneOpt { return func(z *zone) { z.nsec3, z.optout = true, optout } }
func unsigned() zoneOpt             { return func(z *zone) { z.signed = false } }
func expired() zoneOpt {
	return func(z *zone) {
		z.inception = time.Now().Add(-48 * time.Hour)
		z.expiration = time.Now().Add(-24 * time.Hour)
	}
}
func corrupt() zoneOpt  { return func(z *zone) { z.corruptSig = true } }
func stripped() zoneOpt { return func(z *zone) { z.stripSigs = true } }
func rsaKeys() zoneOpt {
	return func(z *zone) { z.ksk.Algorithm, z.zsk.Algorithm = dns.RSASHA256, dns.RSASHA256 }
}

func newZone(t *testing.T, apex string, opts ...zoneOpt) *zone {
	t.Helper()
	z := &zone{
		t: t, apex: dns.Fqdn(apex), rrsets: map[string]map[uint16][]dns.RR{}, children: map[string]*zone{},
		signed: true, inception: time.Now().Add(-time.Hour), expiration: time.Now().Add(24 * time.Hour),
		sigs: map[string]map[uint16][]dns.RR{}, nsecs: map[string]dns.RR{},
	}
	z.ksk = &dns.DNSKEY{Hdr: dns.RR_Header{Name: z.apex, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	z.zsk = &dns.DNSKEY{Hdr: dns.RR_Header{Name: z.apex, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 256, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	for _, o := range opts {
		o(z)
	}
	ns := "ns." + z.apex
	if z.apex == "." {
		ns = "ns."
	}
	z.add(z.apex + " 300 IN SOA " + ns + " hostmaster." + strings.TrimPrefix(z.apex, ".") + " 1 7200 3600 1209600 300")
	z.add(z.apex + " 300 IN NS " + ns)
	z.add(ns + " 300 IN A 192.0.2.1")
	if z.signed {
		bits := 256
		if z.ksk.Algorithm == dns.RSASHA256 {
			bits = 2048
		}
		kp, err := z.ksk.Generate(bits)
		if err != nil {
			t.Fatal(err)
		}
		zp, err := z.zsk.Generate(bits)
		if err != nil {
			t.Fatal(err)
		}
		z.kpriv, z.zpriv = kp.(crypto.Signer), zp.(crypto.Signer)
		z.addRR(z.ksk)
		z.addRR(z.zsk)
	}
	return z
}

func (z *zone) add(s string) {
	rr, err := dns.NewRR(s)
	if err != nil {
		z.t.Fatalf("bad RR %q: %v", s, err)
	}
	z.addRR(rr)
}

func (z *zone) addRR(rr dns.RR) {
	h := rr.Header()
	name := strings.ToLower(h.Name)
	if z.rrsets[name] == nil {
		z.rrsets[name] = map[uint16][]dns.RR{}
	}
	z.rrsets[name][h.Rrtype] = append(z.rrsets[name][h.Rrtype], rr)
}

// delegate adds child's NS + glue to z and a DS if the child is signed and
// publishDS is true.
func (z *zone) delegate(child *zone, publishDS bool) {
	child.parent = z
	z.children[child.apex] = child
	for _, rr := range child.rrsets[child.apex][dns.TypeNS] {
		ns := rr.(*dns.NS)
		z.addRR(&dns.NS{Hdr: dns.RR_Header{Name: child.apex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: ns.Ns})
		for _, g := range child.rrsets[strings.ToLower(ns.Ns)][dns.TypeA] {
			z.addRR(g)
		}
	}
	if publishDS && child.signed {
		ds := child.ksk.ToDS(dns.SHA256)
		ds.Hdr.Ttl = 300
		z.addRR(ds)
	}
}

// delegateBogusDS publishes a DS that matches no key of the child.
func (z *zone) delegateBogusDS(child *zone) {
	z.delegate(child, false)
	other := &dns.DNSKEY{Hdr: dns.RR_Header{Name: child.apex, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := other.Generate(256); err != nil {
		z.t.Fatal(err)
	}
	ds := other.ToDS(dns.SHA256)
	ds.Hdr.Ttl = 300
	z.addRR(ds)
}

func (z *zone) isDelegation(name string) bool {
	_, ok := z.children[name]
	return ok
}

// sign builds the NSEC/NSEC3 chain and signs every RRset that belongs to z.
func (z *zone) sign() {
	if !z.signed {
		return
	}
	names := make([]string, 0, len(z.rrsets))
	for n := range z.rrsets {
		if z.belowDelegation(n) {
			continue
		}
		names = append(names, n)
	}
	if z.nsec3 {
		z.buildNSEC3(names)
	} else {
		z.buildNSEC(names)
	}
	for name, types := range z.rrsets {
		if z.belowDelegation(name) {
			continue
		}
		for typ, rrs := range types {
			if z.isDelegation(name) && typ != dns.TypeDS && typ != dns.TypeNSEC && typ != dns.TypeNSEC3 {
				continue // parent does not sign NS or glue at a delegation
			}
			z.signSet(name, typ, rrs)
		}
	}
}

// belowDelegation is true for glue names strictly under a delegation.
func (z *zone) belowDelegation(name string) bool {
	for child := range z.children {
		if dns.IsSubDomain(child, name) && !strings.EqualFold(child, name) {
			return true
		}
	}
	return false
}

func (z *zone) signSet(name string, typ uint16, rrs []dns.RR) {
	key, priv := z.zsk, z.zpriv
	if typ == dns.TypeDNSKEY {
		key, priv = z.ksk, z.kpriv
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrs[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrs[0].Header().Ttl},
		TypeCovered: typ, Algorithm: key.Algorithm, Labels: uint8(dns.CountLabel(rrs[0].Header().Name)),
		OrigTtl: rrs[0].Header().Ttl, Expiration: uint32(z.expiration.Unix()), Inception: uint32(z.inception.Unix()),
		KeyTag: key.KeyTag(), SignerName: z.apex,
	}
	if strings.HasPrefix(rrs[0].Header().Name, "*.") {
		sig.Labels--
	}
	if err := sig.Sign(priv, rrs); err != nil {
		z.t.Fatal(err)
	}
	if z.corruptSig && typ != dns.TypeDNSKEY {
		b := []byte(sig.Signature)
		b[len(b)/2] ^= 'A' ^ 'B'
		sig.Signature = string(b)
	}
	if z.sigs[name] == nil {
		z.sigs[name] = map[uint16][]dns.RR{}
	}
	z.sigs[name][typ] = []dns.RR{sig}
}

func (z *zone) typesAt(name string) []uint16 {
	var types []uint16
	for t := range z.rrsets[name] {
		types = append(types, t)
	}
	if z.isDelegation(name) {
		// Only NS and DS (and NSEC) are visible at the parent side of a cut.
		types = types[:0]
		for t := range z.rrsets[name] {
			if t == dns.TypeNS || t == dns.TypeDS {
				types = append(types, t)
			}
		}
	}
	if z.nsec3 {
		types = append(types, dns.TypeRRSIG)
		if strings.EqualFold(name, z.apex) {
			types = append(types, dns.TypeNSEC3PARAM)
		}
	} else {
		types = append(types, dns.TypeRRSIG, dns.TypeNSEC)
	}
	if z.isDelegation(name) && z.rrsets[name][dns.TypeDS] == nil {
		types = filter(types, dns.TypeRRSIG)
	}
	sort.Slice(types, func(a, b int) bool { return types[a] < types[b] })
	return types
}

func filter(types []uint16, drop uint16) []uint16 {
	out := types[:0]
	for _, t := range types {
		if t != drop {
			out = append(out, t)
		}
	}
	return out
}

func (z *zone) buildNSEC(names []string) {
	sort.Slice(names, func(a, b int) bool { return canonicalCompare(names[a], names[b]) < 0 })
	for i, name := range names {
		next := names[(i+1)%len(names)]
		n := &dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: next, TypeBitMap: z.typesAt(name)}
		z.nsecs[name] = n
		z.addRR(n)
	}
}

func (z *zone) buildNSEC3(names []string) {
	flags := uint8(0)
	if z.optout {
		flags = 1
	}
	z.params = &dns.NSEC3PARAM{Hdr: dns.RR_Header{Name: z.apex, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0}, Hash: dns.SHA1, Flags: 0, Iterations: 0, SaltLength: 0, Salt: ""}
	z.addRR(z.params)
	type hashed struct{ hash, name string }
	var list []hashed
	for _, name := range names {
		if z.optout && z.isDelegation(name) && z.rrsets[name][dns.TypeDS] == nil {
			continue // opt-out: insecure delegations are not in the chain
		}
		list = append(list, hashed{strings.ToLower(dns.HashName(name, dns.SHA1, 0, "")), name})
	}
	sort.Slice(list, func(a, b int) bool { return list[a].hash < list[b].hash })
	for i, h := range list {
		next := list[(i+1)%len(list)]
		n := &dns.NSEC3{
			Hdr:  dns.RR_Header{Name: h.hash + "." + z.apex, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
			Hash: dns.SHA1, Flags: flags, Iterations: 0, SaltLength: 0, Salt: "", HashLength: 20,
			NextDomain: strings.ToUpper(next.hash), TypeBitMap: z.typesAt(h.name),
		}
		z.nsecs[h.hash] = n
		z.addRR(n)
	}
}

// --- serving ---------------------------------------------------------------

func (z *zone) rrsWithSigs(name string, typ uint16) []dns.RR {
	out := append([]dns.RR{}, z.rrsets[name][typ]...)
	// stripSigs simulates a middlebox dropping RRSIGs from ordinary answers
	// while the key and denial infrastructure stays intact.
	infra := typ == dns.TypeDNSKEY || typ == dns.TypeDS || typ == dns.TypeNSEC || typ == dns.TypeNSEC3 || typ == dns.TypeSOA
	if !z.stripSigs || infra {
		out = append(out, z.sigs[name][typ]...)
	}
	return out
}

// answer serves z authoritatively.
func (z *zone) answer(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.Authoritative = true
	if opt := q.IsEdns0(); opt != nil {
		m.SetEdns0(4096, opt.Do())
	}
	qq := q.Question[0]
	name := strings.ToLower(qq.Name)

	// Referral for names in a child zone (DS at the cut stays with us).
	for apex := range z.children {
		if dns.IsSubDomain(apex, name) && (qq.Qtype != dns.TypeDS || !strings.EqualFold(apex, name)) {
			m.Authoritative = false
			m.Ns = append(m.Ns, z.rrsets[apex][dns.TypeNS]...)
			m.Ns = append(m.Ns, z.rrsWithSigs(apex, dns.TypeDS)...)
			if z.rrsets[apex][dns.TypeDS] == nil && z.signed {
				m.Ns = append(m.Ns, z.denial(apex, dns.TypeDS)...)
			}
			for _, rr := range z.rrsets[apex][dns.TypeNS] {
				m.Extra = append(m.Extra, z.rrsets[strings.ToLower(rr.(*dns.NS).Ns)][dns.TypeA]...)
			}
			return m
		}
	}

	if types, exists := z.rrsets[name]; exists {
		if rrs := types[qq.Qtype]; len(rrs) > 0 {
			m.Answer = z.rrsWithSigs(name, qq.Qtype)
			return m
		}
		if cn := types[dns.TypeCNAME]; len(cn) > 0 && qq.Qtype != dns.TypeCNAME {
			m.Answer = z.rrsWithSigs(name, dns.TypeCNAME)
			return m
		}
		// NODATA
		m.Ns = append(m.Ns, z.rrsWithSigs(z.apex, dns.TypeSOA)...)
		m.Ns = append(m.Ns, z.denial(name, qq.Qtype)...)
		return m
	}
	// Wildcard synthesis.
	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels); i++ {
		wild := "*." + strings.Join(labels[i:], ".") + "."
		if rrs := z.rrsets[wild][qq.Qtype]; len(rrs) > 0 {
			for _, rr := range rrs {
				c := dns.Copy(rr)
				c.Header().Name = qq.Name
				m.Answer = append(m.Answer, c)
			}
			for _, rr := range z.sigs[wild][qq.Qtype] {
				c := dns.Copy(rr)
				c.Header().Name = qq.Name
				m.Answer = append(m.Answer, c)
			}
			return m
		}
	}
	m.Rcode = dns.RcodeNameError
	m.Ns = append(m.Ns, z.rrsWithSigs(z.apex, dns.TypeSOA)...)
	m.Ns = append(m.Ns, z.denial(name, qq.Qtype)...)
	return m
}

// denial returns the NSEC/NSEC3 records (with RRSIGs) that prove the
// non-existence of name or of the type at name.
func (z *zone) denial(name string, qtype uint16) []dns.RR {
	if !z.signed {
		return nil
	}
	var out []dns.RR
	emit := func(rr dns.RR) {
		if rr == nil {
			return
		}
		owner := strings.ToLower(rr.Header().Name)
		out = append(out, rr)
		out = append(out, z.sigs[owner][rr.Header().Rrtype]...)
	}
	if !z.nsec3 {
		if n := z.nsecs[name]; n != nil {
			emit(n)
			return out
		}
		cover := z.nsecCovering(name)
		emit(cover)
		if cover != nil {
			ce := closestEncloser(name, cover.(*dns.NSEC))
			wild := "*." + ce
			if w := z.nsecCovering(wild); w != nil && w != cover {
				emit(w)
			}
		}
		return out
	}
	// NSEC3
	if n := z.nsec3Matching(name); n != nil {
		emit(n)
		return out
	}
	labels := dns.SplitDomainName(name)
	for i := 1; i <= len(labels); i++ {
		ce := "."
		if i < len(labels) {
			ce = strings.Join(labels[i:], ".") + "."
		}
		m := z.nsec3Matching(ce)
		if m == nil {
			continue
		}
		emit(m)
		nc := strings.Join(labels[i-1:], ".") + "."
		c := z.nsec3Covering(nc)
		if c != nil && c != m {
			emit(c)
		}
		w := z.nsec3Covering("*." + ce)
		if w != nil && w != m && w != c {
			emit(w)
		}
		return out
	}
	return out
}

func (z *zone) nsecCovering(name string) dns.RR {
	for _, rr := range z.nsecs {
		if nsecCovers(rr.(*dns.NSEC), name) {
			return rr
		}
	}
	return nil
}

func (z *zone) nsec3Matching(name string) dns.RR {
	for _, rr := range z.nsecs {
		if rr.(*dns.NSEC3).Match(name) {
			return rr
		}
	}
	return nil
}

func (z *zone) nsec3Covering(name string) dns.RR {
	for _, rr := range z.nsecs {
		if rr.(*dns.NSEC3).Cover(name) {
			return rr
		}
	}
	return nil
}

// recursive resolves like a resolver would, by asking the deepest zone that
// contains the name (the parent for DS at a cut). It never validates.
func recursive(root *zone) func(*dns.Msg) *dns.Msg {
	return func(q *dns.Msg) *dns.Msg {
		qq := q.Question[0]
		name := strings.ToLower(qq.Name)
		z := root
		for {
			var next *zone
			for apex, c := range z.children {
				if dns.IsSubDomain(apex, name) && (qq.Qtype != dns.TypeDS || !strings.EqualFold(apex, name)) {
					next = c
				}
			}
			if next == nil {
				break
			}
			z = next
		}
		m := z.answer(q)
		m.Authoritative = false
		m.RecursionAvailable = true
		return m
	}
}

// memFetcher serves Fetch straight from the fixture, no sockets.
type memFetcher struct {
	answer func(*dns.Msg) *dns.Msg
	fail   map[string]bool // "name/TYPE" → simulate fetch failure
}

func (f *memFetcher) Fetch(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if f.fail[strings.ToLower(name)+"/"+dns.TypeToString[qtype]] {
		return nil, errTimeout
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.SetEdns0(4096, true)
	return f.answer(q), nil
}
