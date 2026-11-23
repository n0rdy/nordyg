package dnssec

import (
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/msg"
)

// rrset is a group of records sharing owner, class and type.
type rrset struct {
	name string
	typ  uint16
	rrs  []dns.RR
	sigs []*dns.RRSIG
}

// rrsets groups a section into RRsets with their covering RRSIGs.
func rrsets(rrs []dns.RR) []*rrset {
	var out []*rrset
	index := map[string]*rrset{}
	key := func(name string, typ uint16) string {
		return strings.ToLower(name) + "/" + contract.TypeToString(typ)
	}
	get := func(name string, typ uint16) *rrset {
		k := key(name, typ)
		if s := index[k]; s != nil {
			return s
		}
		s := &rrset{name: dns.Fqdn(strings.ToLower(name)), typ: typ}
		index[k] = s
		out = append(out, s)
		return s
	}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG || h.Rrtype == dns.TypeOPT {
			continue
		}
		s := get(h.Name, h.Rrtype)
		s.rrs = append(s.rrs, rr)
	}
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if s := index[key(sig.Hdr.Name, sig.TypeCovered)]; s != nil {
				s.sigs = append(s.sigs, sig)
			}
		}
	}
	return out
}

func findSet(sets []*rrset, name string, typ uint16) *rrset {
	for _, s := range sets {
		if s.typ == typ && strings.EqualFold(s.name, name) {
			return s
		}
	}
	return nil
}

func supportedAlgorithm(a uint8) bool {
	switch a {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519:
		return true
	}
	return false
}

func supportedDigest(d uint8) bool {
	return d == dns.SHA1 || d == dns.SHA256 || d == dns.SHA384
}

// verifySet checks an RRset against the given keys. It returns every
// signature's outcome and whether at least one verified with a key from keys
// whose signer name is zone.
func verifySet(s *rrset, keys []*dns.DNSKEY, zone string, now time.Time) ([]Signature, bool) {
	out, sig := verifySetSig(s, keys, zone, now)
	return out, sig != nil
}

// verifySetSig is verifySet that also returns the first RRSIG that verified,
// so the caller can read its Labels field for wildcard detection.
func verifySetSig(s *rrset, keys []*dns.DNSKEY, zone string, now time.Time) ([]Signature, *dns.RRSIG) {
	var out []Signature
	var valid *dns.RRSIG
	for _, sig := range s.sigs {
		entry := signatureEntry(sig, now)
		switch {
		case !strings.EqualFold(sig.SignerName, zone):
			entry.Error = "signer " + sig.SignerName + " is not the zone " + zone
		case int(sig.Labels) > ownerLabels(s.name):
			entry.Error = "RRSIG labels field " + itoa(int(sig.Labels)) + " exceeds the " + itoa(ownerLabels(s.name)) + " labels of " + s.name + " (RFC 4035 §5.3.1)"
		case !sig.ValidityPeriod(now):
			if now.After(msg.SerialTime(sig.Expiration)) {
				entry.Error = "signature expired " + msg.SerialTime(sig.Expiration).Format(time.RFC3339)
			} else {
				entry.Error = "signature not yet valid until " + msg.SerialTime(sig.Inception).Format(time.RFC3339)
			}
		default:
			cands := keysFor(keys, sig)
			if len(cands) == 0 {
				entry.Error = "no DNSKEY with tag " + itoa(int(sig.KeyTag)) + " and algorithm " + itoa(int(sig.Algorithm))
			} else if !supportedAlgorithm(sig.Algorithm) {
				entry.Error = "unsupported algorithm " + itoa(int(sig.Algorithm))
			} else {
				// Key tags collide, so every key with the tag is a candidate
				// (RFC 4035 §5.3.1).
				var err error
				for _, key := range cands {
					if err = sig.Verify(key, s.rrs); err == nil {
						break
					}
				}
				if err != nil {
					entry.Error = "signature does not verify: " + err.Error()
				} else {
					entry.Valid = true
					if valid == nil {
						valid = sig
					}
				}
			}
		}
		out = append(out, entry)
	}
	return out, valid
}

// ownerLabels counts the labels of an owner name the way the RRSIG Labels
// field does: a leading "*" label is not counted (RFC 4034 §3.1.3).
func ownerLabels(name string) int {
	n := dns.CountLabel(name)
	if strings.HasPrefix(name, "*.") {
		n--
	}
	return n
}

// wildcardOwner returns the wildcard an RRset was expanded from when its
// RRSIG covers fewer labels than the owner name (RFC 4035 §5.3.2), else "".
func wildcardOwner(name string, sig *dns.RRSIG) string {
	if int(sig.Labels) >= ownerLabels(name) {
		return ""
	}
	if sig.Labels == 0 {
		return "*."
	}
	labels := dns.SplitDomainName(name)
	return "*." + strings.Join(labels[len(labels)-int(sig.Labels):], ".") + "."
}

// keysFor returns every usable zone key matching the signature's tag and
// algorithm.
func keysFor(keys []*dns.DNSKEY, sig *dns.RRSIG) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, k := range keys {
		if k.KeyTag() == sig.KeyTag && k.Algorithm == sig.Algorithm && k.Flags&dns.ZONE != 0 && k.Flags&dns.REVOKE == 0 {
			out = append(out, k)
		}
	}
	return out
}

func signatureEntry(sig *dns.RRSIG, now time.Time) Signature {
	exp := msg.SerialTime(sig.Expiration)
	return Signature{
		TypeCovered: contract.TypeToString(sig.TypeCovered),
		Name:        sig.Hdr.Name,
		KeyTag:      sig.KeyTag,
		Algorithm:   sig.Algorithm,
		Signer:      sig.SignerName,
		Inception:   msg.SerialTime(sig.Inception),
		Expiration:  exp,
		ExpiresInMS: exp.Sub(now).Milliseconds(),
	}
}

func dnskeys(rrs []dns.RR, zone string) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok && strings.EqualFold(k.Hdr.Name, zone) {
			out = append(out, k)
		}
	}
	return out
}

func dsRecords(rrs []dns.RR, name string) []*dns.DS {
	var out []*dns.DS
	for _, rr := range rrs {
		if d, ok := rr.(*dns.DS); ok && strings.EqualFold(d.Hdr.Name, name) {
			out = append(out, d)
		}
	}
	return out
}

// matchDS returns the DNSKEYs that match any DS, and the DS references.
func matchDS(keys []*dns.DNSKEY, dss []*dns.DS) ([]*dns.DNSKEY, []DSRef, bool) {
	var matched []*dns.DNSKEY
	refs := make([]DSRef, 0, len(dss))
	anySupported := false
	for _, d := range dss {
		ref := DSRef{KeyTag: d.KeyTag, Algorithm: d.Algorithm, DigestType: d.DigestType}
		if supportedDigest(d.DigestType) && supportedAlgorithm(d.Algorithm) {
			anySupported = true
			for _, k := range keys {
				if k.KeyTag() != d.KeyTag || k.Algorithm != d.Algorithm || k.Flags&dns.ZONE == 0 || k.Flags&dns.REVOKE != 0 {
					continue
				}
				if computed := k.ToDS(d.DigestType); computed != nil && strings.EqualFold(computed.Digest, d.Digest) {
					ref.MatchesDNSKEY = true
					matched = append(matched, k)
				}
			}
		}
		refs = append(refs, ref)
	}
	return matched, refs, anySupported
}

func keyRefs(keys []*dns.DNSKEY, anchors []*dns.DNSKEY) []KeyRef {
	out := make([]KeyRef, 0, len(keys))
	for _, k := range keys {
		ref := KeyRef{KeyTag: k.KeyTag(), Algorithm: k.Algorithm, AlgorithmName: algName(k.Algorithm), Role: role(k.Flags)}
		for _, a := range anchors {
			if a == k {
				ref.TrustAnchor = true
			}
		}
		out = append(out, ref)
	}
	return out
}

func role(flags uint16) string {
	switch {
	case flags&dns.REVOKE != 0:
		return "revoked"
	case flags&dns.SEP != 0:
		return "ksk"
	case flags&dns.ZONE != 0:
		return "zsk"
	}
	return "other"
}

func algName(a uint8) string {
	if s, ok := dns.AlgorithmToString[a]; ok {
		return s
	}
	return "ALG" + itoa(int(a))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
