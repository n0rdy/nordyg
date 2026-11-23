// Package certs inspects the TLS certificate a server presents: the chain as
// served, whether macOS trusts it for the name, expiry, whether its CA has
// revoked an intermediate, which CAA names the issuer goes by, and whether
// TLSA records (DANE) match it. Used by the health op (HTTPS) and the email
// op (DANE on MX hosts).
package certs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cert is one certificate of a served chain.
type Cert struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Names      []string  `json:"names,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SHA256     string    `json:"sha256"`
	SPKISHA256 string    `json:"spki_sha256"`
}

// Revocation is an intermediate its CA has revoked.
type Revocation struct {
	Subject   string    `json:"subject"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

// Probe is what one server (name, address, port) presented.
type Probe struct {
	Name          string       `json:"name"`
	IP            string       `json:"ip"`
	Port          int          `json:"port"`
	Connected     bool         `json:"connected"`
	Skipped       bool         `json:"skipped"`
	Error         string       `json:"error,omitempty"`
	TLSVersion    string       `json:"tls_version,omitempty"`
	Chain         []Cert       `json:"chain"`
	Trusted       bool         `json:"trusted"`
	TrustError    string       `json:"trust_error,omitempty"`
	NameMatch     bool         `json:"name_match"`
	ExpiresInDays int          `json:"expires_in_days"`
	Revoked       []Revocation `json:"revoked"`
	// RevocationChecked is false when a CRL could not be fetched or verified;
	// RevocationNote says why.
	RevocationChecked bool   `json:"revocation_checked"`
	RevocationNote    string `json:"revocation_note,omitempty"`

	certs []*x509.Certificate // as served, leaf first
}

// Certificates returns the parsed chain as served, leaf first.
func (p *Probe) Certificates() []*x509.Certificate { return p.certs }

// Inspector holds what inspection needs from outside: trust roots, the
// clock, and how to fetch a CRL.
type Inspector struct {
	// Roots are the trust anchors; nil means the system's (macOS's trust
	// store and Go's distrust list).
	Roots *x509.CertPool
	Now   func() time.Time
	// FetchCRL downloads a CRL. The bytes are verified here before use.
	FetchCRL func(ctx context.Context, url string) ([]byte, error)
	Timeout  time.Duration

	mu   sync.Mutex
	crls map[string]crlResult
}

type crlResult struct {
	der []byte
	err error
}

func (in *Inspector) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// Handshake connects to addr and completes a TLS handshake for sni without
// verifying anything, so an invalid chain can still be inspected.
func (in *Inspector) Handshake(ctx context.Context, addr, sni string) (*tls.ConnectionState, error) {
	timeout := in.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, // verified in Inspect, against the right roots
			MinVersion:         tls.VersionTLS10,
		},
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	st := c.(*tls.Conn).ConnectionState()
	return &st, nil
}

// Inspect judges a completed handshake for name.
func (in *Inspector) Inspect(ctx context.Context, st *tls.ConnectionState, name string) Probe {
	p := Probe{Connected: true, Chain: []Cert{}, Revoked: []Revocation{}}
	p.TLSVersion = tls.VersionName(st.Version)
	p.certs = st.PeerCertificates
	if len(p.certs) == 0 {
		p.TrustError = "the server sent no certificate"
		return p
	}
	for _, c := range p.certs {
		p.Chain = append(p.Chain, summarize(c))
	}
	leaf := p.certs[0]
	now := in.now()
	p.ExpiresInDays = int(leaf.NotAfter.Sub(now).Hours() / 24)
	p.NameMatch = leaf.VerifyHostname(strings.TrimSuffix(name, ".")) == nil

	inter := x509.NewCertPool()
	for _, c := range p.certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       strings.TrimSuffix(name, "."),
		Roots:         in.Roots,
		Intermediates: inter,
		CurrentTime:   now,
	})
	if err != nil {
		p.TrustError = err.Error()
	} else {
		p.Trusted = true
	}

	// The chain to check for revocation: the verified one when there is one
	// (it includes the root as issuer of the top intermediate), else as served.
	chain := p.certs
	if len(chains) > 0 {
		chain = chains[0]
	}
	p.RevocationChecked, p.RevocationNote, p.Revoked = in.checkIntermediates(ctx, chain)
	if len(p.Revoked) > 0 {
		p.Trusted = false
		if p.TrustError == "" {
			p.TrustError = "an intermediate certificate in the chain has been revoked"
		}
	}
	return p
}

// checkIntermediates looks every intermediate up in the CRL its issuer
// publishes. Only intermediates: CA lists are small, while leaf CRLs of
// large CAs run to megabytes.
func (in *Inspector) checkIntermediates(ctx context.Context, chain []*x509.Certificate) (bool, string, []Revocation) {
	revoked := []Revocation{}
	if in.FetchCRL == nil {
		return false, "revocation was not checked", revoked
	}
	checked, notes := 0, []string{}
	for i := 1; i < len(chain); i++ {
		cert := chain[i]
		if isSelfSigned(cert) {
			continue // a root: trust stores, not CRLs, decide about roots
		}
		if i+1 >= len(chain) {
			notes = append(notes, "the issuer of "+cert.Subject.CommonName+" was not sent, so its revocation could not be checked")
			continue
		}
		parent := chain[i+1]
		if len(cert.CRLDistributionPoints) == 0 {
			notes = append(notes, cert.Subject.CommonName+" names no revocation list")
			continue
		}
		var lastErr error
		found := false
		for _, url := range cert.CRLDistributionPoints {
			list, err := in.crl(ctx, url, parent)
			if err != nil {
				lastErr = err
				continue
			}
			found = true
			for _, e := range list.RevokedCertificateEntries {
				if e.SerialNumber != nil && e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					revoked = append(revoked, Revocation{Subject: name(cert.Subject.CommonName, cert.Subject.Organization), RevokedAt: e.RevocationTime, Reason: reasonName(e.ReasonCode)})
				}
			}
			break
		}
		if found {
			checked++
		} else if lastErr != nil {
			notes = append(notes, "the revocation list for "+cert.Subject.CommonName+" could not be read: "+lastErr.Error())
		}
	}
	return checked > 0 && len(notes) == 0, strings.Join(notes, ". "), revoked
}

// crl fetches (once per URL) and verifies a CRL against its issuer.
func (in *Inspector) crl(ctx context.Context, url string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	in.mu.Lock()
	if in.crls == nil {
		in.crls = map[string]crlResult{}
	}
	r, ok := in.crls[url]
	in.mu.Unlock()
	if !ok {
		der, err := in.FetchCRL(ctx, url)
		r = crlResult{der, err}
		in.mu.Lock()
		in.crls[url] = r
		in.mu.Unlock()
	}
	if r.err != nil {
		return nil, r.err
	}
	list, err := x509.ParseRevocationList(r.der)
	if err != nil {
		return nil, errors.New("not a valid revocation list")
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return nil, errors.New("the revocation list is not signed by the issuing CA")
	}
	return list, nil
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

// reasonName is the RFC 5280 §5.3.1 reason in words.
func reasonName(code int) string {
	switch code {
	case 1:
		return "key compromise"
	case 2:
		return "CA compromise"
	case 3:
		return "affiliation changed"
	case 4:
		return "superseded"
	case 5:
		return "cessation of operation"
	case 6:
		return "certificate hold"
	case 9:
		return "privilege withdrawn"
	case 10:
		return "AA compromise"
	}
	return "no reason given"
}

func summarize(c *x509.Certificate) Cert {
	sum := sha256.Sum256(c.Raw)
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return Cert{
		Subject:    name(c.Subject.CommonName, c.Subject.Organization),
		Issuer:     name(c.Issuer.CommonName, c.Issuer.Organization),
		Names:      c.DNSNames,
		NotBefore:  c.NotBefore,
		NotAfter:   c.NotAfter,
		SHA256:     hex.EncodeToString(sum[:]),
		SPKISHA256: hex.EncodeToString(spki[:]),
	}
}

// name renders a certificate name: "YE2 (Let's Encrypt)", since a CA's
// common name alone ("YE2", "R11") rarely says who the CA is.
func name(cn string, org []string) string {
	o := strings.Join(org, ", ")
	switch {
	case cn == "":
		return o
	case o == "" || strings.Contains(strings.ToLower(cn), strings.ToLower(o)):
		return cn
	}
	return cn + " (" + o + ")"
}

// MatchTLSA reports whether any TLSA record matches the served chain
// (RFC 6698, RFC 7671). DANE-EE (3) and PKIX-EE (1) match the leaf, DANE-TA
// (2) and PKIX-TA (0) any certificate above it. PKIX usages also need a
// trusted chain.
func MatchTLSA(records []*dns.TLSA, chain []*x509.Certificate, trusted bool) bool {
	if len(chain) == 0 {
		return false
	}
	for _, r := range records {
		var candidates []*x509.Certificate
		switch r.Usage {
		case 3, 1:
			candidates = chain[:1]
		case 2, 0:
			candidates = chain[1:]
		}
		if (r.Usage == 0 || r.Usage == 1) && !trusted {
			continue
		}
		for _, c := range candidates {
			if r.Verify(c) == nil {
				return true
			}
		}
	}
	return false
}

// caaNames maps words in an issuer's name to the identifiers CAs use in CAA
// records. The issuer certificate does not carry its CAA name, so this is a
// table of the CAs that issue most web certificates.
var caaNames = []struct {
	match []string
	ids   []string
}{
	{[]string{"let's encrypt", "isrg"}, []string{"letsencrypt.org"}},
	{[]string{"digicert", "geotrust", "rapidssl", "thawte"}, []string{"digicert.com"}},
	{[]string{"sectigo", "comodo", "usertrust", "zerossl"}, []string{"sectigo.com", "comodoca.com", "usertrust.com"}},
	{[]string{"google trust services", "gts "}, []string{"pki.goog"}},
	{[]string{"globalsign"}, []string{"globalsign.com"}},
	{[]string{"amazon"}, []string{"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"}},
	{[]string{"ssl.com"}, []string{"ssl.com"}},
	{[]string{"entrust"}, []string{"entrust.net"}},
	{[]string{"buypass"}, []string{"buypass.com", "buypass.no"}},
	{[]string{"microsoft"}, []string{"microsoft.com"}},
	{[]string{"harica"}, []string{"harica.gr"}},
	{[]string{"certum", "asseco"}, []string{"certum.pl"}},
	{[]string{"actalis"}, []string{"actalis.it"}},
	{[]string{"emudhra", "emsign"}, []string{"emudhra.com"}},
}

// CAAIdentifiers returns the CAA names the leaf's issuer is known by, or nil
// when the issuer is not in the table.
func CAAIdentifiers(leaf *x509.Certificate) []string {
	issuer := strings.ToLower(leaf.Issuer.CommonName + " " + strings.Join(leaf.Issuer.Organization, " "))
	for _, e := range caaNames {
		for _, m := range e.match {
			if strings.Contains(issuer, m) {
				return e.ids
			}
		}
	}
	return nil
}
