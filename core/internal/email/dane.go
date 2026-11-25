package email

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/certs"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/resolve"
	"github.com/n0rdy/nordyg/core/internal/verdict"
)

// DANE for mail (RFC 7672): TLSA records at _25._tcp.<mx>, which senders use
// only when both the MX records and the TLSA records are DNSSEC-secure.

// DANEServer is one address of an MX host and whether its certificate matches the TLSA records.
type DANEServer struct {
	IP      string `json:"ip"`
	Checked bool   `json:"checked"`
	Match   bool   `json:"match"`
	Skipped bool   `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`

	noSTARTTLS bool
}

// DANEHost is one MX host: its TLSA records and the servers probed for them.
type DANEHost struct {
	Exchange string `json:"exchange"`
	// TLSA records as Nordyg found them and their DNSSEC status as it
	// validated them itself.
	TLSA   []string `json:"tlsa"`
	Status string   `json:"status,omitempty"`
	// Error is set when the TLSA lookup failed, so nothing is known.
	Error   string       `json:"error,omitempty"`
	Servers []DANEServer `json:"servers"`

	// usable are the records mail senders act on: DANE-TA (2) and DANE-EE (3).
	usable []*dns.TLSA
}

// DANESection is DANE across the MX hosts.
type DANESection struct {
	// MXStatus is the DNSSEC status of the MX records; checked only when
	// some host publishes TLSA records.
	MXStatus string     `json:"mx_status,omitempty"`
	Hosts    []DANEHost `json:"hosts"`
	Findings []Verdict  `json:"findings"`
	Verdict  Verdict    `json:"verdict"`

	off bool // DANE does not apply or no TLSA records are published
}

// Validator is the DNSSEC validator; *dnssec.Validator satisfies it.
type Validator interface {
	Validate(ctx context.Context, f dnssec.Fetcher, qname string, qtype uint16, answer *dns.Msg) (*dnssec.Result, error)
}

const maxDANEAddrs = 4

func (op *Op) smtpAddr(ip string) string {
	if op.SMTPAddrFor != nil {
		return op.SMTPAddrFor(ip)
	}
	return net.JoinHostPort(ip, "25")
}

func (op *Op) validator() Validator {
	if op.Validator != nil {
		return op.Validator
	}
	return dnssec.New()
}

func (op *Op) checkDANE(ctx context.Context, r *resolve.Resolver, domain string, mx MXSection) DANESection {
	sec := DANESection{Hosts: []DANEHost{}, Findings: []Verdict{}}
	if mx.NullMX {
		sec.off = true
		sec.Verdict = Verdict{Status: Info, Message: "not applicable: the domain accepts no mail"}
		return sec
	}
	f := dnssec.Shared(&dnssec.Recursive{Client: r.Client, Endpoint: r.Endpoint, Options: r.Options, Bootstrap: r.Bootstrap})
	v := op.validator()

	// TLSA for every MX host, in MX order.
	hosts := make([]DANEHost, len(mx.Hosts))
	var wg sync.WaitGroup
	for i, h := range mx.Hosts {
		hosts[i] = DANEHost{Exchange: h.Exchange, TLSA: []string{}, Servers: []DANEServer{}}
		wg.Add(1)
		go func(dh *DANEHost) {
			defer wg.Done()
			qname := "_25._tcp." + dns.Fqdn(dh.Exchange)
			m, err := dnssec.FetchRRset(ctx, f, qname, dns.TypeTLSA)
			if err != nil {
				dh.Error = err.Error()
				return
			}
			for _, rr := range m.Answer {
				if t, ok := rr.(*dns.TLSA); ok {
					dh.TLSA = append(dh.TLSA, strings.TrimPrefix(t.String(), t.Hdr.String()))
					if t.Usage == 2 || t.Usage == 3 {
						dh.usable = append(dh.usable, t)
					}
				}
			}
			if len(dh.TLSA) > 0 {
				if res, err := v.Validate(ctx, f, qname, dns.TypeTLSA, m); err == nil && res != nil {
					dh.Status = res.Status
				}
			}
		}(&hosts[i])
	}
	wg.Wait()
	sec.Hosts = hosts

	withTLSA, failed := 0, 0
	for _, h := range hosts {
		switch {
		case h.Error != "":
			failed++
		case len(h.TLSA) > 0:
			withTLSA++
		}
	}
	switch {
	case withTLSA == 0 && failed == 0:
		sec.off = true
		sec.Verdict = Verdict{Status: Info, Message: "not configured. DANE is optional and, with DNSSEC, lets senders check the certificate of each MX host"}
		return sec
	case withTLSA == 0:
		sec.Verdict = Verdict{Status: Warn, Message: "the TLSA records could not be looked up through this resolver. Run the check again"}
		return sec
	}

	// Senders ignore TLSA records unless the MX records are secure too.
	if !mx.Implicit {
		sec.MXStatus = dnssec.Indeterminate
		if m, err := dnssec.FetchRRset(ctx, f, domain, dns.TypeMX); err == nil {
			if res, err := v.Validate(ctx, f, domain, dns.TypeMX, m); err == nil && res != nil {
				sec.MXStatus = res.Status
			}
		}
		switch sec.MXStatus {
		case dnssec.Secure:
		case dnssec.Insecure:
			sec.add(Warn, "the MX hosts publish TLSA records, but the MX records are not DNSSEC-signed, so senders ignore them")
		case dnssec.Bogus:
			sec.add(Fail, "the MX records fail DNSSEC validation, so senders that validate cannot deliver mail")
		default:
			sec.add(Warn, "the MX records could not be DNSSEC-validated through this resolver, so DANE was not checked. Run the check again")
		}
		if sec.MXStatus != dnssec.Secure {
			sec.settle("")
			return sec
		}
	}

	// Every host at once: on a network that drops port 25 the whole step
	// then costs one connect timeout, not one per host.
	in := &certs.Inspector{Timeout: op.SMTPTimeout}
	var probes sync.WaitGroup
	for i := range sec.Hosts {
		probes.Add(1)
		go func() {
			defer probes.Done()
			op.probeDANE(ctx, in, &sec.Hosts[i], mx.Hosts[i].Addresses)
		}()
	}
	probes.Wait()
	judgeDANE(&sec, withTLSA, failed)
	return sec
}

// probeDANE connects to port 25 of each address (up to four) and compares
// the certificate with the TLSA records. Only DANE-TA (2) and DANE-EE (3)
// apply to mail.
func (op *Op) probeDANE(ctx context.Context, in *certs.Inspector, h *DANEHost, addrs []string) {
	if h.Status != dnssec.Secure {
		return
	}
	if len(h.usable) == 0 {
		return
	}
	ips := append([]string(nil), addrs...)
	sort.SliceStable(ips, func(a, b int) bool { return !strings.Contains(ips[a], ":") && strings.Contains(ips[b], ":") })
	if len(ips) > maxDANEAddrs {
		ips = ips[:maxDANEAddrs]
	}
	h.Servers = make([]DANEServer, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := DANEServer{IP: ip}
			st, err := in.HandshakeSMTP(ctx, op.smtpAddr(ip), strings.TrimSuffix(h.Exchange, "."))
			var de *certs.DialError
			switch {
			case errors.As(err, &de) && strings.Contains(ip, ":") && noIPv6Route(err):
				s.Skipped = true
				s.Error = "this Mac has no IPv6 route"
			case errors.As(err, &de):
				s.Error = "port 25 could not be reached"
			case err != nil:
				s.Checked = true
				s.Error = err.Error()
				s.noSTARTTLS = errors.Is(err, certs.ErrNoSTARTTLS)
			default:
				s.Checked = true
				s.Match = certs.MatchTLSA(h.usable, st.PeerCertificates, false)
			}
			h.Servers[i] = s
		}()
	}
	wg.Wait()
}

func noIPv6Route(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no route to host") || strings.Contains(msg, "network is unreachable")
}

func judgeDANE(sec *DANESection, withTLSA, failed int) {
	reached, unreached := 0, 0
	for _, h := range sec.Hosts {
		name := strings.TrimSuffix(h.Exchange, ".")
		if h.Error != "" {
			sec.add(Warn, fmt.Sprintf("%s: the TLSA lookup failed through this resolver, so DANE was not checked for it. Run the check again", name))
			continue
		}
		if len(h.TLSA) == 0 {
			continue
		}
		switch h.Status {
		case dnssec.Secure:
		case dnssec.Bogus:
			sec.add(Fail, fmt.Sprintf("%s: the TLSA records fail DNSSEC validation, so DANE senders hold mail for it", name))
			continue
		case dnssec.Insecure:
			sec.add(Warn, fmt.Sprintf("%s publishes TLSA records without DNSSEC, so senders ignore them", name))
			continue
		default:
			sec.add(Warn, fmt.Sprintf("%s: the TLSA records could not be DNSSEC-validated through this resolver, so DANE was not checked for it. Run the check again", name))
			continue
		}
		if len(h.usable) == 0 {
			sec.add(Warn, fmt.Sprintf("%s publishes only TLSA usages 0 or 1, which mail senders do not use (RFC 7672)", name))
			continue
		}
		for _, s := range h.Servers {
			switch {
			case s.Skipped:
			case !s.Checked:
				unreached++
			case s.noSTARTTLS:
				reached++
				sec.add(Fail, fmt.Sprintf("%s (%s) does not offer STARTTLS, so DANE senders refuse to deliver", name, s.IP))
			case s.Error != "":
				reached++
				sec.add(Fail, fmt.Sprintf("%s (%s) failed the TLS handshake: %s", name, s.IP, s.Error))
			case !s.Match:
				reached++
				sec.add(Fail, fmt.Sprintf("%s (%s) presents a certificate that matches none of its TLSA records, so DANE senders refuse to deliver", name, s.IP))
			default:
				reached++
			}
		}
	}
	if n := len(sec.Hosts) - failed; withTLSA < n {
		sec.add(Warn, fmt.Sprintf("only %d of %d MX hosts publish TLSA records, so mail to the others is not protected by DANE", withTLSA, n))
	}
	okMsg := "every MX host publishes signed TLSA records that match its certificate"
	switch {
	case reached == 0 && unreached > 0:
		okMsg = "every MX host publishes signed TLSA records. Port 25 could not be reached from this network (many providers block it), so the certificates were not compared"
	case unreached > 0:
		okMsg = "every MX host publishes signed TLSA records, and every server that could be reached on port 25 matches them"
	}
	sec.settle(okMsg)
}

func (s *DANESection) add(status, msg string) {
	s.Findings = append(s.Findings, Verdict{Status: status, Message: msg})
}

// settle sets the verdict to the worst finding, or to ok with okMsg.
func (s *DANESection) settle(okMsg string) {
	s.Verdict = verdict.Worst(s.Findings, okMsg)
}
