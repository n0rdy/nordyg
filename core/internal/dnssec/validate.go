package dnssec

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Fetcher obtains a DNS message for (name, type) with DO set. Recursive and
// authoritative implementations live in fetch.go.
type Fetcher interface {
	Fetch(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// Validator holds the trust anchors and the clock.
type Validator struct {
	Anchors []*dns.DS
	Now     func() time.Time
}

// New returns a validator with the embedded root anchors.
func New() *Validator {
	return &Validator{Anchors: RootAnchors()}
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

const maxNested = 3

// Validate builds and checks the chain from the root to qname and then
// validates answer. It returns an error only for context cancellation;
// everything else is expressed in the Result.
func (v *Validator) Validate(ctx context.Context, f Fetcher, qname string, qtype uint16, answer *dns.Msg) (*Result, error) {
	return v.validate(ctx, f, dns.Fqdn(strings.ToLower(qname)), qtype, answer, 0)
}

type walker struct {
	v    *Validator
	f    Fetcher
	now  time.Time
	res  *Result
	zone string
	keys []*dns.DNSKEY
}

func (v *Validator) validate(ctx context.Context, f Fetcher, qname string, qtype uint16, answer *dns.Msg, depth int) (*Result, error) {
	w := &walker{v: v, f: f, now: v.now(), res: &Result{Status: Indeterminate, Chain: []Link{}, AnswerSignatures: []Signature{}}}
	if err := w.root(ctx); err != nil {
		return w.res, ctxErr(ctx, err)
	}
	if w.res.Status != Indeterminate {
		return w.res, nil
	}
	if err := w.walk(ctx, qname, answer); err != nil {
		return w.res, ctxErr(ctx, err)
	}
	if w.res.Status != Indeterminate {
		return w.res, nil
	}
	if err := w.answer(ctx, qname, qtype, answer, depth); err != nil {
		return w.res, ctxErr(ctx, err)
	}
	return w.res, nil
}

// ctxErr turns a fetch failure into a cancellation error when the context is
// done; otherwise the walker already recorded an indeterminate result.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return nil
}

func (w *walker) fail(status, reason string) {
	w.res.Status = status
	w.res.Reason = reason
}

func (w *walker) fetch(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m, err := w.f.Fetch(ctx, name, qtype)
	if err != nil {
		w.fail(Indeterminate, "could not fetch "+dns.TypeToString[qtype]+" for "+name+": "+err.Error())
		return nil, err
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		w.fail(Indeterminate, dns.TypeToString[qtype]+" query for "+name+" returned "+dns.RcodeToString[m.Rcode])
		return nil, errors.New(dns.RcodeToString[m.Rcode])
	}
	return m, nil
}

// root fetches the root DNSKEY set and anchors it.
func (w *walker) root(ctx context.Context) error {
	m, err := w.fetch(ctx, ".", dns.TypeDNSKEY)
	if err != nil {
		return err
	}
	keys := dnskeys(m.Answer, ".")
	link := Link{Zone: ".", Status: Bogus, DS: []DSRef{}, Signatures: []Signature{}}
	anchored, refs, _ := matchDS(keys, w.v.Anchors)
	link.DS = refs
	link.DNSKeys = keyRefs(keys, anchored)
	if len(anchored) == 0 {
		link.Reason = "no root DNSKEY matches a trust anchor"
		w.res.Chain = append(w.res.Chain, link)
		w.fail(Bogus, link.Reason)
		return nil
	}
	set := findSet(rrsets(m.Answer), ".", dns.TypeDNSKEY)
	sigs, ok := verifySet(set, anchored, ".", w.now)
	link.Signatures = sigs
	if !ok {
		link.Reason = "root DNSKEY RRset is not signed by the trust anchor key"
		w.res.Chain = append(w.res.Chain, link)
		w.fail(Bogus, link.Reason)
		return nil
	}
	link.Status = Secure
	w.res.Chain = append(w.res.Chain, link)
	a := anchored[0]
	w.res.TrustAnchor = &KeyRef{KeyTag: a.KeyTag(), Algorithm: a.Algorithm, AlgorithmName: algName(a.Algorithm), Role: role(a.Flags), TrustAnchor: true}
	w.zone, w.keys = ".", keys
	return nil
}

// walk descends from the root through every label of qname, following DS
// records into signed child zones and stopping at an unsigned delegation.
func (w *walker) walk(ctx context.Context, qname string, answer *dns.Msg) error {
	signer := answerSigner(answer)
	labels := dns.SplitDomainName(qname)
	for i := len(labels) - 1; i >= 0; i-- {
		cand := strings.Join(labels[i:], ".") + "."
		// Below the zone that signed the answer there are no more cuts to find.
		if signer != "" && strings.EqualFold(w.zone, signer) && dns.IsSubDomain(signer, cand) && !strings.EqualFold(signer, cand) {
			return nil
		}
		m, err := w.fetch(ctx, cand, dns.TypeDS)
		if err != nil {
			return err
		}
		dss := dsRecords(m.Answer, cand)
		if len(dss) == 0 {
			p := denial(m, cand, dns.TypeDS, w.keys, w.zone, w.now)
			switch p.kind {
			case proofNoData:
				if p.delegation {
					reason := "unsigned delegation: no DS record for " + prose(cand) + ", proven by an NSEC record in " + proseZone(w.zone)
					w.res.Chain = append(w.res.Chain, Link{Zone: cand, Status: Insecure, Reason: reason, DNSKeys: []KeyRef{}, DS: []DSRef{}, Signatures: p.signatures})
					w.fail(Insecure, reason)
					return nil
				}
				// Not a zone cut; keep descending in the same zone.
			case proofOptOut:
				reason := "unsigned delegation: no DS record for " + prose(cand) + ", proven by an NSEC3 opt-out record in " + proseZone(w.zone) + " (RFC 5155)"
				w.res.Chain = append(w.res.Chain, Link{Zone: cand, Status: Insecure, Reason: reason, DNSKeys: []KeyRef{}, DS: []DSRef{}, Signatures: p.signatures})
				w.fail(Insecure, reason)
				return nil
			case proofNXDomain:
				// The name does not exist; nothing below it can be a cut.
				return nil
			case proofBogus:
				w.fail(Bogus, "denial of DS for "+cand+": "+p.reason)
				return nil
			default:
				w.fail(Indeterminate, "cannot prove whether "+cand+" has a DS record: "+p.reason)
				return nil
			}
			continue
		}
		link := Link{Zone: cand, Status: Bogus, DNSKeys: []KeyRef{}, DS: []DSRef{}, Signatures: []Signature{}}
		dsSet := findSet(rrsets(m.Answer), cand, dns.TypeDS)
		sigs, ok := verifySet(dsSet, w.keys, w.zone, w.now)
		link.Signatures = append(link.Signatures, sigs...)
		if !ok {
			link.Reason = "DS RRset for " + cand + " is not validly signed by " + w.zone
			w.res.Chain = append(w.res.Chain, link)
			w.fail(Bogus, link.Reason)
			return nil
		}
		km, err := w.fetch(ctx, cand, dns.TypeDNSKEY)
		if err != nil {
			w.res.Chain = append(w.res.Chain, link)
			return err
		}
		keys := dnskeys(km.Answer, cand)
		matched, refs, supported := matchDS(keys, dss)
		link.DS = refs
		link.DNSKeys = keyRefs(keys, nil)
		if !supported {
			link.Status = Insecure
			link.Reason = "DS records use only unsupported algorithms; treated as unsigned (RFC 4035 §5.2)"
			w.res.Chain = append(w.res.Chain, link)
			w.fail(Insecure, link.Reason)
			return nil
		}
		if len(matched) == 0 {
			link.Reason = "no DNSKEY of " + cand + " matches its DS records"
			w.res.Chain = append(w.res.Chain, link)
			w.fail(Bogus, link.Reason)
			return nil
		}
		keySet := findSet(rrsets(km.Answer), cand, dns.TypeDNSKEY)
		ksigs, ok := verifySet(keySet, matched, cand, w.now)
		link.Signatures = append(link.Signatures, ksigs...)
		if !ok {
			link.Reason = "DNSKEY RRset of " + cand + " is not signed by a key matching its DS"
			w.res.Chain = append(w.res.Chain, link)
			w.fail(Bogus, link.Reason)
			return nil
		}
		link.Status = Secure
		w.res.Chain = append(w.res.Chain, link)
		w.zone, w.keys = cand, keys
	}
	return nil
}

// answerSigner is the signer name of the RRSIGs in the answer section, or in
// the authority section for negative answers. Empty when unsigned.
func answerSigner(m *dns.Msg) string {
	best := ""
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			if sig, ok := rr.(*dns.RRSIG); ok {
				s := strings.ToLower(sig.SignerName)
				if best == "" || dns.CountLabel(s) > dns.CountLabel(best) {
					best = s
				}
			}
		}
		if best != "" {
			return best
		}
	}
	return best
}

// answer validates the final message against the zone the walk ended in.
func (w *walker) answer(ctx context.Context, qname string, qtype uint16, m *dns.Msg, depth int) error {
	sets := rrsets(m.Answer)
	if len(sets) == 0 {
		return w.negative(qname, qtype, m)
	}
	status := Secure
	reason := ""
	for _, s := range sets {
		signer := ""
		if len(s.sigs) > 0 {
			signer = strings.ToLower(s.sigs[0].SignerName)
		}
		switch {
		case len(s.sigs) == 0:
			status, reason = Bogus, "RRset "+s.name+" "+dns.TypeToString[s.typ]+" has no RRSIG although "+w.zone+" is signed"
		case strings.EqualFold(signer, w.zone):
			sigs, ok := verifySet(s, w.keys, w.zone, w.now)
			w.res.AnswerSignatures = append(w.res.AnswerSignatures, sigs...)
			if !ok && status == Secure {
				status, reason = Bogus, "RRset "+s.name+" "+dns.TypeToString[s.typ]+" fails verification: "+firstError(sigs)
			}
		default:
			// Signed by a different zone (CNAME chain into another zone):
			// validate that zone's chain separately.
			if depth >= maxNested {
				status, reason = Indeterminate, "too many nested zones in the answer"
				continue
			}
			sub := new(dns.Msg)
			sub.Answer = append(append([]dns.RR{}, s.rrs...), sigsToRR(s.sigs)...)
			r, err := w.v.validate(ctx, w.f, s.name, s.typ, sub, depth+1)
			if err != nil {
				return err
			}
			w.res.AnswerSignatures = append(w.res.AnswerSignatures, r.AnswerSignatures...)
			if r.Status != Secure && (status == Secure || r.Status == Bogus) {
				status, reason = r.Status, s.name+": "+r.Reason
			}
		}
	}
	w.fail(status, reason)
	return nil
}

// negative validates an NXDOMAIN or NODATA answer via its denial records.
func (w *walker) negative(qname string, qtype uint16, m *dns.Msg) error {
	p := denial(m, qname, qtype, w.keys, w.zone, w.now)
	w.res.AnswerSignatures = append(w.res.AnswerSignatures, p.signatures...)
	switch {
	case m.Rcode == dns.RcodeNameError && p.kind == proofNXDomain:
		w.fail(Secure, "")
	case m.Rcode == dns.RcodeSuccess && p.kind == proofNoData:
		w.fail(Secure, "")
	case m.Rcode == dns.RcodeSuccess && p.kind == proofNXDomain:
		// Some servers answer NOERROR for names under an ENT; the proof still holds.
		w.fail(Secure, "")
	case p.kind == proofBogus:
		w.fail(Bogus, "negative answer for "+qname+": "+p.reason)
	default:
		w.fail(Indeterminate, "negative answer for "+qname+" carries no valid denial proof: "+p.reason)
	}
	return nil
}

func firstError(sigs []Signature) string {
	for _, s := range sigs {
		if s.Error != "" {
			return s.Error
		}
	}
	return "no usable signature"
}

func sigsToRR(sigs []*dns.RRSIG) []dns.RR {
	out := make([]dns.RR, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s)
	}
	return out
}

// prose renders a name for human-readable messages: no trailing dot.
func prose(name string) string {
	if name == "." {
		return "the root"
	}
	return strings.TrimSuffix(name, ".")
}

// proseZone renders a zone for prose so a TLD does not read like a word:
// "." → "the root zone", "me." → "the .me zone", "example.com." → "the zone example.com".
func proseZone(zone string) string {
	switch dns.CountLabel(zone) {
	case 0:
		return "the root zone"
	case 1:
		return "the ." + strings.TrimSuffix(zone, ".") + " zone"
	}
	return "the zone " + strings.TrimSuffix(zone, ".")
}
