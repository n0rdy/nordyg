package dnssec

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/testdns"
)

var errTimeout = errors.New("i/o timeout")

// world builds root → test. → several children covering every verdict.
type world struct {
	root, tld, example, unsigned, bogus, expiredZ, badsig, strippedZ, n3, n3optoutChild, n3signedChild, rsa *zone
	fetch                                                                                                   *memFetcher
	v                                                                                                       *Validator
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{}
	w.root = newZone(t, ".")
	w.tld = newZone(t, "test.")
	w.example = newZone(t, "example.test.")
	w.example.add("example.test. 300 IN A 192.0.2.10")
	w.example.add("example.test. 300 IN TXT \"v=spf1 -all\"")
	w.example.add("www.example.test. 300 IN CNAME example.test.")
	w.example.add("*.wild.example.test. 300 IN A 192.0.2.99")
	w.example.add("real.wild.example.test. 300 IN A 192.0.2.98")
	w.example.add("old.example.test. 300 IN DNAME example.test.")
	w.example.add("alias.example.test. 300 IN CNAME target.other.test.")
	other := newZone(t, "other.test.")
	other.add("target.other.test. 300 IN A 192.0.2.77")
	w.unsigned = newZone(t, "unsigned.test.", unsigned())
	w.unsigned.add("unsigned.test. 300 IN A 192.0.2.20")
	w.bogus = newZone(t, "bogus.test.")
	w.bogus.add("bogus.test. 300 IN A 192.0.2.30")
	w.expiredZ = newZone(t, "expired.test.", expired())
	w.expiredZ.add("expired.test. 300 IN A 192.0.2.40")
	future := newZone(t, "future.test.", notYetValid())
	future.add("future.test. 300 IN A 192.0.2.41")
	newAlg := newZone(t, "newalg.test.")
	newAlg.add("newalg.test. 300 IN A 192.0.2.42")
	w.badsig = newZone(t, "badsig.test.", corrupt())
	w.badsig.add("badsig.test. 300 IN A 192.0.2.50")
	w.strippedZ = newZone(t, "stripped.test.", stripped())
	w.strippedZ.add("stripped.test. 300 IN A 192.0.2.60")
	w.rsa = newZone(t, "rsa.test.", rsaKeys())
	w.rsa.add("rsa.test. 300 IN A 192.0.2.70")
	w.n3 = newZone(t, "nsec3.test.", withNSEC3(true))
	w.n3.add("nsec3.test. 300 IN A 192.0.2.80")
	w.n3.add("a.nsec3.test. 300 IN A 192.0.2.81")
	w.n3.add("*.w.nsec3.test. 300 IN A 192.0.2.84")
	w.n3optoutChild = newZone(t, "optout.nsec3.test.", unsigned())
	w.n3optoutChild.add("optout.nsec3.test. 300 IN A 192.0.2.82")
	w.n3signedChild = newZone(t, "signed.nsec3.test.")
	w.n3signedChild.add("signed.nsec3.test. 300 IN A 192.0.2.83")

	w.tld.delegate(w.example, true)
	w.tld.delegate(other, true)
	w.tld.delegate(w.unsigned, false)
	w.tld.delegateBogusDS(w.bogus)
	w.tld.delegate(w.expiredZ, true)
	w.tld.delegate(future, true)
	w.tld.delegateUnsupportedDS(newAlg)
	w.tld.delegate(w.badsig, true)
	w.tld.delegate(w.strippedZ, true)
	w.tld.delegate(w.rsa, true)
	w.tld.delegate(w.n3, true)
	w.n3.delegate(w.n3optoutChild, false)
	w.n3.delegate(w.n3signedChild, true)
	// An unsigned delegation below an empty non-terminal (ent.example.test
	// has no records), the shape of reverse DNS: 1.1.in-addr.arpa above a
	// delegated 1.1.1.in-addr.arpa.
	deep := newZone(t, "sub.ent.example.test.", unsigned())
	deep.add("sub.ent.example.test. 300 IN A 192.0.2.91")
	w.example.delegate(deep, false)
	w.root.delegate(w.tld, true)

	for _, z := range []*zone{deep, future, newAlg, w.root, w.tld, w.example, other, w.unsigned, w.bogus, w.expiredZ, w.badsig, w.strippedZ, w.rsa, w.n3, w.n3optoutChild, w.n3signedChild} {
		z.sign()
	}
	w.fetch = &memFetcher{answer: recursive(w.root), fail: map[string]bool{}}
	anchor := w.root.ksk.ToDS(dns.SHA256)
	w.v = &Validator{Anchors: []*dns.DS{anchor}}
	return w
}

func (w *world) query(t *testing.T, name string, qtype uint16) *Result {
	t.Helper()
	m, err := w.fetch.Fetch(context.Background(), name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.v.Validate(context.Background(), w.fetch, name, qtype, m)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func zones(res *Result) []string {
	out := make([]string, 0, len(res.Chain))
	for _, l := range res.Chain {
		out = append(out, l.Zone+":"+l.Status)
	}
	return out
}

func TestSecurePositive(t *testing.T) {
	w := newWorld(t)
	res := w.query(t, "example.test.", dns.TypeA)
	testdns.Sample(t, "dnssec", res)
	if res.Status != Secure {
		t.Fatalf("%s: %s\n%v", res.Status, res.Reason, zones(res))
	}
	if got := strings.Join(zones(res), " "); got != ".:secure test.:secure example.test.:secure" {
		t.Fatal(got)
	}
	if res.TrustAnchor == nil || !res.TrustAnchor.TrustAnchor || res.TrustAnchor.KeyTag != w.root.ksk.KeyTag() {
		t.Fatalf("trust anchor: %+v", res.TrustAnchor)
	}
	if len(res.AnswerSignatures) != 1 || !res.AnswerSignatures[0].Valid || res.AnswerSignatures[0].Signer != "example.test." || res.AnswerSignatures[0].ExpiresInMS <= 0 {
		t.Fatalf("answer sigs: %+v", res.AnswerSignatures)
	}
	link := res.Chain[2]
	if len(link.DS) != 1 || !link.DS[0].MatchesDNSKEY || len(link.DNSKeys) != 2 || len(link.Signatures) != 2 {
		t.Fatalf("link: %+v", link)
	}
	ksk := 0
	for _, k := range link.DNSKeys {
		if k.Role == "ksk" && k.TrustAnchor {
			t.Fatal("child KSK must not be marked trust anchor")
		}
		if k.Role == "ksk" {
			ksk++
		}
	}
	if ksk != 1 {
		t.Fatal("expected one ksk")
	}
	// Root link: the anchor key is marked.
	found := false
	for _, k := range res.Chain[0].DNSKeys {
		found = found || k.TrustAnchor
	}
	if !found {
		t.Fatal("root anchor key not marked")
	}
}

func TestSecureWildcardAndCNAME(t *testing.T) {
	w := newWorld(t)
	if res := w.query(t, "anything.wild.example.test.", dns.TypeA); res.Status != Secure {
		t.Fatalf("wildcard: %s %s", res.Status, res.Reason)
	}
	// CNAME within the zone: the fixture returns only the CNAME.
	if res := w.query(t, "www.example.test.", dns.TypeA); res.Status != Secure {
		t.Fatalf("cname: %s %s", res.Status, res.Reason)
	}
	// CNAME into another zone with both RRsets in one answer, signed by two zones.
	m, _ := w.fetch.Fetch(context.Background(), "alias.example.test.", dns.TypeA)
	tgt, _ := w.fetch.Fetch(context.Background(), "target.other.test.", dns.TypeA)
	m.Answer = append(m.Answer, tgt.Answer...)
	res, err := w.v.Validate(context.Background(), w.fetch, "alias.example.test.", dns.TypeA, m)
	if err != nil || res.Status != Secure || len(res.AnswerSignatures) != 2 {
		t.Fatalf("cross-zone cname: %+v %v", res, err)
	}
	// The primary chain ends at the queried name's zone; the target's zone
	// is reported as a related chain of its own.
	if got := strings.Join(zones(res), " "); got != ".:secure test.:secure example.test.:secure" {
		t.Fatalf("primary chain: %s", got)
	}
	if len(res.Related) != 1 {
		t.Fatalf("related: %+v", res.Related)
	}
	rel := res.Related[0]
	if rel.Name != "target.other.test." || rel.Type != "A" || rel.Signer != "other.test." || rel.Status != Secure {
		t.Fatalf("related: %+v", rel)
	}
	if got := strings.Join(zones(&Result{Chain: rel.Chain}), " "); got != ".:secure test.:secure other.test.:secure" {
		t.Fatalf("related chain: %s", got)
	}
	// Same-zone answers have no related chains.
	if res := w.query(t, "www.example.test.", dns.TypeA); len(res.Related) != 0 {
		t.Fatalf("same-zone related: %+v", res.Related)
	}
}

func TestRelatedChainCarriesVerdict(t *testing.T) {
	w := newWorld(t)
	// CNAME from a secure zone into one with a DS that matches no key.
	m, _ := w.fetch.Fetch(context.Background(), "alias.example.test.", dns.TypeA)
	tgt, _ := w.fetch.Fetch(context.Background(), "bogus.test.", dns.TypeA)
	m.Answer = append(m.Answer, tgt.Answer...)
	res, err := w.v.Validate(context.Background(), w.fetch, "alias.example.test.", dns.TypeA, m)
	if err != nil || res.Status != Bogus || len(res.Related) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	rel := res.Related[0]
	if rel.Status != Bogus || rel.Reason == "" || rel.Chain[len(rel.Chain)-1].Zone != "bogus.test." {
		t.Fatalf("related: %+v", rel)
	}
	if !strings.HasPrefix(res.Reason, "bogus.test.: ") {
		t.Fatalf("reason: %s", res.Reason)
	}
}

func TestWildcardProof(t *testing.T) {
	w := newWorld(t)
	validate := func(name string, m *dns.Msg) *Result {
		t.Helper()
		res, err := w.v.Validate(context.Background(), w.fetch, name, dns.TypeA, m)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	fetch := func(name string) *dns.Msg {
		t.Helper()
		m, err := w.fetch.Fetch(context.Background(), name, dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("nsec3 wildcard is secure", func(t *testing.T) {
		if res := w.query(t, "x.w.nsec3.test.", dns.TypeA); res.Status != Secure {
			t.Fatalf("%s: %s", res.Status, res.Reason)
		}
	})
	t.Run("proof includes its signatures", func(t *testing.T) {
		res := w.query(t, "anything.wild.example.test.", dns.TypeA)
		nsec := false
		for _, s := range res.AnswerSignatures {
			nsec = nsec || (s.TypeCovered == "NSEC" && s.Valid)
		}
		if !nsec {
			t.Fatalf("no NSEC signature reported: %+v", res.AnswerSignatures)
		}
	})
	for _, name := range []string{"anything.wild.example.test.", "x.w.nsec3.test."} {
		t.Run("missing proof is bogus "+name, func(t *testing.T) {
			m := fetch(name)
			m.Ns = nil
			if res := validate(name, m); res.Status != Bogus || !strings.Contains(res.Reason, "does not prove") {
				t.Fatalf("%s: %s", res.Status, res.Reason)
			}
		})
	}
	t.Run("wildcard replayed onto an existing name is bogus", func(t *testing.T) {
		// Take the signed wildcard expansion and its proof for one name and
		// present them as the answer for a name that has its own records.
		m := fetch("anything.wild.example.test.")
		for _, rr := range m.Answer {
			rr.Header().Name = "real.wild.example.test."
		}
		if res := validate("real.wild.example.test.", m); res.Status != Bogus || !strings.Contains(res.Reason, "does not prove") {
			t.Fatalf("%s: %s", res.Status, res.Reason)
		}
	})
	t.Run("labels above owner count is bogus", func(t *testing.T) {
		m := fetch("example.test.")
		for _, rr := range m.Answer {
			if sig, ok := rr.(*dns.RRSIG); ok {
				sig.Labels = 5
			}
		}
		if res := validate("example.test.", m); res.Status != Bogus || !strings.Contains(res.Reason, "labels field") {
			t.Fatalf("%s: %s", res.Status, res.Reason)
		}
	})
}

func TestDNAME(t *testing.T) {
	w := newWorld(t)
	dname, err := w.fetch.Fetch(context.Background(), "old.example.test.", dns.TypeDNAME)
	if err != nil {
		t.Fatal(err)
	}
	build := func(target string) *dns.Msg {
		m := dname.Copy()
		cn, _ := dns.NewRR("www.old.example.test. 300 IN CNAME " + target)
		m.Answer = append(m.Answer, cn)
		tgt, _ := w.fetch.Fetch(context.Background(), "www.example.test.", dns.TypeA)
		m.Answer = append(m.Answer, tgt.Answer...)
		return m
	}
	t.Run("synthesised CNAME is accepted", func(t *testing.T) {
		res, err := w.v.Validate(context.Background(), w.fetch, "www.old.example.test.", dns.TypeA, build("www.example.test."))
		if err != nil || res.Status != Secure {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("CNAME that does not follow from the DNAME is bogus", func(t *testing.T) {
		res, err := w.v.Validate(context.Background(), w.fetch, "www.old.example.test.", dns.TypeA, build("evil.example.test."))
		if err != nil || res.Status != Bogus || !strings.Contains(res.Reason, "has no RRSIG") {
			t.Fatalf("%+v %v", res, err)
		}
	})
}

func TestSecureNegativeNSEC(t *testing.T) {
	w := newWorld(t)
	if res := w.query(t, "nope.example.test.", dns.TypeA); res.Status != Secure {
		t.Fatalf("nxdomain: %s %s", res.Status, res.Reason)
	}
	if res := w.query(t, "example.test.", dns.TypeMX); res.Status != Secure {
		t.Fatalf("nodata: %s %s", res.Status, res.Reason)
	}
}

func TestSecureNSEC3(t *testing.T) {
	w := newWorld(t)
	if res := w.query(t, "a.nsec3.test.", dns.TypeA); res.Status != Secure {
		t.Fatalf("positive: %s %s", res.Status, res.Reason)
	}
	if res := w.query(t, "zzz.nsec3.test.", dns.TypeA); res.Status != Secure {
		t.Fatalf("nxdomain: %s %s", res.Status, res.Reason)
	}
	if res := w.query(t, "a.nsec3.test.", dns.TypeMX); res.Status != Secure {
		t.Fatalf("nodata: %s %s", res.Status, res.Reason)
	}
	if res := w.query(t, "signed.nsec3.test.", dns.TypeA); res.Status != Secure {
		t.Fatalf("signed child: %s %s\n%v", res.Status, res.Reason, zones(res))
	}
	res := w.query(t, "optout.nsec3.test.", dns.TypeA)
	if res.Status != Insecure || !strings.Contains(res.Reason, "opt-out") {
		t.Fatalf("opt-out child: %s %s", res.Status, res.Reason)
	}
}

func TestInsecureDelegation(t *testing.T) {
	w := newWorld(t)
	res := w.query(t, "unsigned.test.", dns.TypeA)
	if res.Status != Insecure || !strings.Contains(res.Reason, "no DS record for unsigned.test, proven by an NSEC record in the .test zone") {
		t.Fatalf("%s %s", res.Status, res.Reason)
	}
	if got := strings.Join(zones(res), " "); got != ".:secure test.:secure unsigned.test.:insecure" {
		t.Fatal(got)
	}
}

// A zone signed only with algorithms this validator lacks must come out
// insecure, as RFC 4035 §5.2 asks, and never secure or bogus.
func TestUnsupportedDSAlgorithmIsInsecure(t *testing.T) {
	w := newWorld(t)
	res := w.query(t, "newalg.test.", dns.TypeA)
	if res.Status != Insecure || !strings.Contains(res.Reason, "unsupported algorithms") {
		t.Fatalf("%s %q\n%v", res.Status, res.Reason, zones(res))
	}
	if got := strings.Join(zones(res), " "); got != ".:secure test.:secure newalg.test.:insecure" {
		t.Fatal(got)
	}
}

func TestNSEC3IterationsOverTheCapProveNothing(t *testing.T) {
	w := newWorld(t)
	costly := *w.n3.nsec3Matching("a.nsec3.test.").(*dns.NSEC3)
	costly.Iterations = maxNSEC3Iterations + 1
	p := nsec3Proof(proof{}, []*dns.NSEC3{&costly}, "a.nsec3.test.", dns.TypeMX)
	if p.kind != proofNone || !strings.Contains(p.reason, "exceed the limit") {
		t.Fatalf("kind %d, reason %q", p.kind, p.reason)
	}
	costly.Iterations = maxNSEC3Iterations
	if p := nsec3Proof(proof{}, []*dns.NSEC3{&costly}, "a.nsec3.test.", dns.TypeMX); strings.Contains(p.reason, "exceed the limit") {
		t.Fatalf("the cap itself is still accepted: %q", p.reason)
	}
}

func TestBogusCases(t *testing.T) {
	w := newWorld(t)
	cases := []struct{ name, want string }{
		{"bogus.test.", "no DNSKEY of bogus.test matches its DS"},
		{"expired.test.", "signature expired"},
		{"future.test.", "signature not yet valid"},
		{"badsig.test.", "does not verify"},
		{"stripped.test.", "has no RRSIG"},
	}
	for _, c := range cases {
		res := w.query(t, c.name, dns.TypeA)
		if res.Status != Bogus || !strings.Contains(res.Reason, c.want) {
			t.Errorf("%s: %s %q (want %q)\n%v", c.name, res.Status, res.Reason, c.want, zones(res))
		}
	}
	// Expired zone: the link for the zone itself is bogus, parents secure.
	res := w.query(t, "expired.test.", dns.TypeA)
	if got := strings.Join(zones(res), " "); got != ".:secure test.:secure expired.test.:bogus" {
		t.Fatal(got)
	}
}

func TestRSAZone(t *testing.T) {
	w := newWorld(t)
	if res := w.query(t, "rsa.test.", dns.TypeA); res.Status != Secure {
		t.Fatalf("%s %s", res.Status, res.Reason)
	}
}

func TestWrongTrustAnchorIsBogus(t *testing.T) {
	w := newWorld(t)
	w.v.Anchors = RootAnchors() // the real root keys do not sign our fixture
	res := w.query(t, "example.test.", dns.TypeA)
	if res.Status != Bogus || len(res.Chain) != 1 || res.Chain[0].Status != Bogus || res.TrustAnchor != nil {
		t.Fatalf("%+v", res)
	}
}

func TestIndeterminateOnFetchFailure(t *testing.T) {
	w := newWorld(t)
	w.fetch.fail["test./DNSKEY"] = true
	res := w.query(t, "example.test.", dns.TypeA)
	if res.Status != Indeterminate || !strings.Contains(res.Reason, "could not fetch DNSKEY for test.") {
		t.Fatalf("%s %s", res.Status, res.Reason)
	}
	// Cancellation surfaces as an error, not a verdict.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, _ := w.fetch.Fetch(context.Background(), "example.test.", dns.TypeA)
	w.fetch.fail = map[string]bool{"./DNSKEY": true}
	if _, err := w.v.Validate(ctx, w.fetch, "example.test.", dns.TypeA, m); !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancelled, got %v", err)
	}
}

func TestEmbeddedAnchors(t *testing.T) {
	anchors := RootAnchors()
	if len(anchors) != 2 || anchors[0].KeyTag != 20326 || anchors[1].KeyTag != 38696 {
		t.Fatalf("%+v", anchors)
	}
	for _, a := range anchors {
		if a.Algorithm != 8 || a.DigestType != 2 || len(a.Digest) != 64 {
			t.Fatalf("%+v", a)
		}
	}
}

func TestCanonicalOrder(t *testing.T) {
	// RFC 4034 §6.1 example ordering.
	names := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.", "\001.z.example.", "*.z.example.", "\200.z.example."}
	for i := 0; i+1 < len(names); i++ {
		if canonicalCompare(names[i], names[i+1]) >= 0 {
			t.Errorf("%q should sort before %q", names[i], names[i+1])
		}
	}
	n := &dns.NSEC{Hdr: dns.RR_Header{Name: "z.example."}, NextDomain: "example."}
	if !nsecCovers(n, "zz.example.") || nsecCovers(n, "a.example.") || nsecCovers(n, "z.example.") {
		t.Fatal("wrap-around cover")
	}
}

func TestKeyTagCollision(t *testing.T) {
	// Two zone keys with the same tag: the signature verifies with the
	// second one, which a first-match lookup would never try.
	z := newZone(t, "collide.test.")
	z.add("collide.test. 300 IN A 192.0.2.90")
	z.sign()
	s := findSet(rrsets(append(append([]dns.RR{}, z.rrsets["collide.test."][dns.TypeA]...), z.sigs["collide.test."][dns.TypeA]...)), "collide.test.", dns.TypeA)
	// The key tag is a 16-bit sum over the key's wire form (RFC 4034
	// appendix B). Raising one high byte and lowering the next high byte
	// keeps the sum, so the decoy is a different key with the same tag.
	raw, err := base64.StdEncoding.DecodeString(z.zsk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for raw[i] == 255 || raw[i+2] == 0 {
		i += 2
	}
	raw[i]++
	raw[i+2]--
	decoy := *z.zsk
	decoy.PublicKey = base64.StdEncoding.EncodeToString(raw)
	if decoy.KeyTag() != z.zsk.KeyTag() || decoy.PublicKey == z.zsk.PublicKey {
		t.Fatalf("decoy tag %d, want %d", decoy.KeyTag(), z.zsk.KeyTag())
	}
	sigs, ok := verifySet(s, []*dns.DNSKEY{&decoy, z.zsk}, "collide.test.", time.Now())
	if !ok {
		t.Fatalf("collision not handled: %+v", sigs)
	}
}

func TestUnsignedDelegationBelowEmptyNonTerminal(t *testing.T) {
	w := newWorld(t)
	res := w.query(t, "sub.ent.example.test.", dns.TypeA)
	if res.Status != Insecure || !strings.Contains(res.Reason, "sub.ent.example.test") {
		t.Fatalf("%s: %s\n%v", res.Status, res.Reason, zones(res))
	}
	// The empty non-terminal itself exists with no data, it is not NXDOMAIN.
	m, _ := w.fetch.Fetch(context.Background(), "ent.example.test.", dns.TypeDS)
	if p := denial(m, "ent.example.test.", dns.TypeDS, dnskeys(mustFetch(t, w, "example.test.", dns.TypeDNSKEY).Answer, "example.test."), "example.test.", time.Now()); p.kind != proofNoData {
		t.Fatalf("ENT proof kind %d: %s", p.kind, p.reason)
	}
}

func mustFetch(t *testing.T, w *world, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m, err := w.fetch.Fetch(context.Background(), name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTrustAnchorIsTheSigningKey(t *testing.T) {
	// Two root KSKs match an anchor, as during the KSK-2017 → KSK-2024
	// rollover; only one signs. The reported anchor must be the signer.
	root := newZone(t, ".")
	standby := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := standby.Generate(256); err != nil {
		t.Fatal(err)
	}
	root.addRR(standby)
	root.sign()
	f := &memFetcher{answer: recursive(root), fail: map[string]bool{}}
	v := &Validator{Anchors: []*dns.DS{standby.ToDS(dns.SHA256), root.ksk.ToDS(dns.SHA256)}}
	m, _ := f.Fetch(context.Background(), ".", dns.TypeSOA)
	res, err := v.Validate(context.Background(), f, ".", dns.TypeSOA, m)
	if err != nil || res.Status != Secure || res.TrustAnchor == nil || res.TrustAnchor.KeyTag != root.ksk.KeyTag() {
		t.Fatalf("%+v %v (signer %d, standby %d)", res.TrustAnchor, err, root.ksk.KeyTag(), standby.KeyTag())
	}
}
