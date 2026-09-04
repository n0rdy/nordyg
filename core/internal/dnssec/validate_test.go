package dnssec

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
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
	w.example.add("alias.example.test. 300 IN CNAME target.other.test.")
	other := newZone(t, "other.test.")
	other.add("target.other.test. 300 IN A 192.0.2.77")
	w.unsigned = newZone(t, "unsigned.test.", unsigned())
	w.unsigned.add("unsigned.test. 300 IN A 192.0.2.20")
	w.bogus = newZone(t, "bogus.test.")
	w.bogus.add("bogus.test. 300 IN A 192.0.2.30")
	w.expiredZ = newZone(t, "expired.test.", expired())
	w.expiredZ.add("expired.test. 300 IN A 192.0.2.40")
	w.badsig = newZone(t, "badsig.test.", corrupt())
	w.badsig.add("badsig.test. 300 IN A 192.0.2.50")
	w.strippedZ = newZone(t, "stripped.test.", stripped())
	w.strippedZ.add("stripped.test. 300 IN A 192.0.2.60")
	w.rsa = newZone(t, "rsa.test.", rsaKeys())
	w.rsa.add("rsa.test. 300 IN A 192.0.2.70")
	w.n3 = newZone(t, "nsec3.test.", withNSEC3(true))
	w.n3.add("nsec3.test. 300 IN A 192.0.2.80")
	w.n3.add("a.nsec3.test. 300 IN A 192.0.2.81")
	w.n3optoutChild = newZone(t, "optout.nsec3.test.", unsigned())
	w.n3optoutChild.add("optout.nsec3.test. 300 IN A 192.0.2.82")
	w.n3signedChild = newZone(t, "signed.nsec3.test.")
	w.n3signedChild.add("signed.nsec3.test. 300 IN A 192.0.2.83")

	w.tld.delegate(w.example, true)
	w.tld.delegate(other, true)
	w.tld.delegate(w.unsigned, false)
	w.tld.delegateBogusDS(w.bogus)
	w.tld.delegate(w.expiredZ, true)
	w.tld.delegate(w.badsig, true)
	w.tld.delegate(w.strippedZ, true)
	w.tld.delegate(w.rsa, true)
	w.tld.delegate(w.n3, true)
	w.n3.delegate(w.n3optoutChild, false)
	w.n3.delegate(w.n3signedChild, true)
	w.root.delegate(w.tld, true)

	for _, z := range []*zone{w.root, w.tld, w.example, other, w.unsigned, w.bogus, w.expiredZ, w.badsig, w.strippedZ, w.rsa, w.n3, w.n3optoutChild, w.n3signedChild} {
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
	if res.Status != Insecure || !strings.Contains(res.Reason, "unsigned.test. is an unsigned delegation") {
		t.Fatalf("%s %s", res.Status, res.Reason)
	}
	if got := strings.Join(zones(res), " "); got != ".:secure test.:secure unsigned.test.:insecure" {
		t.Fatal(got)
	}
}

func TestBogusCases(t *testing.T) {
	w := newWorld(t)
	cases := []struct{ name, want string }{
		{"bogus.test.", "no DNSKEY of bogus.test. matches its DS"},
		{"expired.test.", "expired"},
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
