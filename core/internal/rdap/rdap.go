// Package rdap implements the "rdap" op: registration data for a domain via
// RDAP (RFC 9083), following the registry's referral to the registrar, with
// a WHOIS (RFC 3912) fallback for TLDs that have no RDAP server.
package rdap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/fetch"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Params is the op input.
type Params struct {
	Domain    string              `json:"domain"`
	Endpoint  contract.Endpoint   `json:"endpoint"`
	Options   contract.Options    `json:"options"`
	Bootstrap []contract.Endpoint `json:"bootstrap"`
}

type Event struct {
	Action string `json:"action"`
	Date   string `json:"date"`
}

type Contact struct {
	Roles  []string `json:"roles"`
	Handle string   `json:"handle,omitempty"`
	Name   string   `json:"name,omitempty"`
	Org    string   `json:"org,omitempty"`
	Email  string   `json:"email,omitempty"`
	Phone  string   `json:"phone,omitempty"`
}

type Registrar struct {
	Name       string `json:"name,omitempty"`
	IANAID     string `json:"iana_id,omitempty"`
	URL        string `json:"url,omitempty"`
	AbuseEmail string `json:"abuse_email,omitempty"`
	AbusePhone string `json:"abuse_phone,omitempty"`
}

type StatusInfo struct {
	Code    string `json:"code"`
	Meaning string `json:"meaning"`
}

type DS struct {
	KeyTag     int    `json:"key_tag"`
	Algorithm  int    `json:"algorithm"`
	DigestType int    `json:"digest_type"`
	Digest     string `json:"digest"`
}

type DNSSECInfo struct {
	Known  bool `json:"known"`  // the source said something about DNSSEC
	Signed bool `json:"signed"` // registry holds DS records for the delegation
	DS     []DS `json:"ds"`
}

// Result is the op output.
type Result struct {
	Domain          string       `json:"domain"`
	Source          string       `json:"source"` // rdap | whois
	Server          string       `json:"server"`
	RegistrarServer string       `json:"registrar_server,omitempty"`
	Found           bool         `json:"found"`
	Handle          string       `json:"handle,omitempty"`
	Status          []StatusInfo `json:"status"`
	Registered      string       `json:"registered,omitempty"`
	Expires         string       `json:"expires,omitempty"`
	Updated         string       `json:"updated,omitempty"`
	ExpiresInDays   *int         `json:"expires_in_days,omitempty"`
	Registrar       Registrar    `json:"registrar"`
	Contacts        []Contact    `json:"contacts"`
	Nameservers     []string     `json:"nameservers"`
	DNSNameservers  []string     `json:"dns_nameservers"`
	NSMismatch      bool         `json:"ns_mismatch"`
	DNSSEC          DNSSECInfo   `json:"dnssec"`
	Events          []Event      `json:"events"`
	Notices         []string     `json:"notices"`
	Warnings        []string     `json:"warnings"`
	Raw             string       `json:"raw"`
	BootstrapSource string       `json:"bootstrap_source"`
}

// Op is the configured handler.
type Op struct {
	Client    *transport.Client
	Bootstrap *Bootstrap
	// TLS carries test roots; nil means the system store.
	TLS *tls.Config
	// IANAWhois and WhoisPort are overridable for tests.
	IANAWhois string
	WhoisPort int
	// RefreshBootstrap fetches the live registry once per process.
	RefreshBootstrap bool

	refreshOnce sync.Once
}

// New returns an op with the embedded bootstrap.
func New(c *transport.Client) *Op {
	return &Op{Client: c, Bootstrap: Embedded(), IANAWhois: "whois.iana.org", WhoisPort: 43, RefreshBootstrap: true}
}

// Register attaches the op to d.
func (op *Op) Register(d *bridge.Dispatcher) {
	d.Register("rdap", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p Params
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
		}
		return op.Run(ctx, p)
	})
}

// Run looks the domain up.
func (op *Op) Run(ctx context.Context, p Params) (*Result, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Domain), "."))
	if domain == "" {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "domain is required"}
	}
	if _, ok := dns.IsDomainName(domain); !ok || !strings.Contains(domain, ".") {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "a registrable domain name is required, got " + p.Domain}
	}
	if err := p.Endpoint.Validate(); err != nil {
		return nil, err
	}
	o := p.Options.Resolve()
	resolver := fetch.NewResolver(op.Client, p.Endpoint, o, p.Bootstrap)

	if op.RefreshBootstrap {
		op.refreshOnce.Do(func() {
			rctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			if resp, err := fetch.Get(rctx, BootstrapURL, "application/json", resolver, op.TLS); err == nil && resp.Status == 200 {
				if b, err := ParseBootstrap(resp.Body, "iana live"); err == nil {
					op.Bootstrap.Replace(b)
				}
			}
		})
	}

	res := &Result{Domain: domain, Status: []StatusInfo{}, Contacts: []Contact{}, Nameservers: []string{}, DNSNameservers: []string{}, Events: []Event{}, Notices: []string{}, Warnings: []string{}, DNSSEC: DNSSECInfo{DS: []DS{}}, BootstrapSource: op.Bootstrap.Source}
	tld := domain[strings.LastIndex(domain, ".")+1:]

	var lookupErr error
	if servers := op.Bootstrap.Servers(tld); len(servers) > 0 {
		lookupErr = op.viaRDAP(ctx, res, domain, servers, resolver)
	} else {
		lookupErr = op.viaWHOIS(ctx, res, domain, tld, resolver)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if lookupErr != nil {
		return nil, &bridge.Error{Code: contract.CodeNetwork, Message: lookupErr.Error()}
	}

	// Cross-check against the live DNS.
	op.crossCheck(ctx, res, domain, p, o)
	return res, nil
}

// --- RDAP ----------------------------------------------------------------------

func (op *Op) viaRDAP(ctx context.Context, res *Result, domain string, servers []string, r fetch.Resolver) error {
	res.Source = "rdap"
	var lastErr error
	for _, base := range servers {
		u := base + "domain/" + domain
		resp, err := fetch.Get(ctx, u, "application/rdap+json", r, op.TLS)
		if err != nil {
			lastErr = err
			continue
		}
		res.Server = base
		switch {
		case resp.Status == 404:
			res.Found = false
			res.Raw = string(resp.Body)
			return nil
		case resp.Status != 200:
			lastErr = fmt.Errorf("%s returned HTTP %d", base, resp.Status)
			continue
		}
		var doc rdapDomain
		if err := json.Unmarshal(resp.Body, &doc); err != nil {
			lastErr = fmt.Errorf("%s returned invalid RDAP JSON: %v", base, err)
			continue
		}
		res.Found = true
		res.Raw = pretty(resp.Body)
		applyDomain(res, &doc, false)

		// Registrars often hold contacts the registry does not; follow the referral once.
		for _, l := range doc.Links {
			if l.Rel == "related" && strings.Contains(l.Href, "/domain/") && !strings.HasPrefix(l.Href, res.Server) {
				rr, err := fetch.Get(ctx, l.Href, "application/rdap+json", r, op.TLS)
				if err != nil || rr.Status != 200 {
					res.Warnings = append(res.Warnings, "registrar RDAP at "+l.Href+" not reachable")
					break
				}
				var reg rdapDomain
				if json.Unmarshal(rr.Body, &reg) == nil {
					res.RegistrarServer = l.Href
					applyDomain(res, &reg, true)
					res.Raw += "\n\n// registrar response\n" + pretty(rr.Body)
				}
				break
			}
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no RDAP server answered")
	}
	return lastErr
}

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
	Type string `json:"type"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Handle    string                              `json:"handle"`
	Roles     []string                            `json:"roles"`
	VCard     []any                               `json:"vcardArray"`
	PublicIDs []struct{ Type, Identifier string } `json:"publicIds"`
	Entities  []rdapEntity                        `json:"entities"`
	Links     []rdapLink                          `json:"links"`
}

type rdapDomain struct {
	Handle      string   `json:"handle"`
	LDHName     string   `json:"ldhName"`
	Status      []string `json:"status"`
	Events      []rdapEvent
	Entities    []rdapEntity
	Links       []rdapLink
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	}
	SecureDNS *struct {
		DelegationSigned *bool `json:"delegationSigned"`
		DSData           []struct {
			KeyTag     int    `json:"keyTag"`
			Algorithm  int    `json:"algorithm"`
			DigestType int    `json:"digestType"`
			Digest     string `json:"digest"`
		} `json:"dsData"`
	} `json:"secureDNS"`
	Notices []struct {
		Title       string   `json:"title"`
		Description []string `json:"description"`
	}
}

// applyDomain fills res from one RDAP document; supplement=true only adds
// what is missing (the registrar's view must not override the registry's).
func applyDomain(res *Result, d *rdapDomain, supplement bool) {
	if !supplement {
		res.Handle = d.Handle
		for _, s := range d.Status {
			res.Status = append(res.Status, StatusInfo{Code: s, Meaning: statusMeaning(s)})
		}
		for _, e := range d.Events {
			res.Events = append(res.Events, Event(e))
			switch e.Action {
			case "registration":
				res.Registered = e.Date
			case "expiration":
				res.Expires = e.Date
				res.ExpiresInDays = daysUntil(e.Date)
			case "last changed":
				res.Updated = e.Date
			}
		}
		for _, ns := range d.Nameservers {
			res.Nameservers = append(res.Nameservers, strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")))
		}
		sort.Strings(res.Nameservers)
		if d.SecureDNS != nil {
			res.DNSSEC.Known = true
			if d.SecureDNS.DelegationSigned != nil {
				res.DNSSEC.Signed = *d.SecureDNS.DelegationSigned
			}
			for _, ds := range d.SecureDNS.DSData {
				res.DNSSEC.Signed = true
				res.DNSSEC.DS = append(res.DNSSEC.DS, DS{KeyTag: ds.KeyTag, Algorithm: ds.Algorithm, DigestType: ds.DigestType, Digest: strings.ToUpper(ds.Digest)})
			}
		}
		for _, n := range d.Notices {
			if n.Title != "" {
				res.Notices = append(res.Notices, n.Title)
			}
		}
	} else {
		if res.Expires == "" || res.Updated == "" {
			for _, e := range d.Events {
				if e.Action == "expiration" && res.Expires == "" {
					res.Expires, res.ExpiresInDays = e.Date, daysUntil(e.Date)
				}
				if e.Action == "last changed" && res.Updated == "" {
					res.Updated = e.Date
				}
			}
		}
	}
	for _, ent := range d.Entities {
		applyEntity(res, ent, supplement)
	}
}

func applyEntity(res *Result, ent rdapEntity, supplement bool) {
	c := Contact{Roles: ent.Roles, Handle: ent.Handle}
	c.Name, c.Org, c.Email, c.Phone = vcard(ent.VCard)
	if hasRole(ent.Roles, "registrar") {
		if res.Registrar.Name == "" {
			res.Registrar.Name = firstNonEmpty(c.Name, c.Org)
		}
		for _, id := range ent.PublicIDs {
			if strings.Contains(strings.ToLower(id.Type), "iana") && res.Registrar.IANAID == "" {
				res.Registrar.IANAID = id.Identifier
			}
		}
		for _, l := range ent.Links {
			if (l.Rel == "about" || l.Rel == "self") && res.Registrar.URL == "" && !strings.Contains(l.Href, "/rdap") {
				res.Registrar.URL = l.Href
			}
		}
		for _, sub := range ent.Entities {
			if hasRole(sub.Roles, "abuse") {
				_, _, email, phone := vcard(sub.VCard)
				if res.Registrar.AbuseEmail == "" {
					res.Registrar.AbuseEmail = email
				}
				if res.Registrar.AbusePhone == "" {
					res.Registrar.AbusePhone = phone
				}
			}
		}
		return
	}
	if c.Name == "" && c.Org == "" && c.Email == "" && c.Phone == "" && c.Handle == "" {
		return
	}
	// In supplement mode, skip roles the registry already described.
	if supplement {
		for _, existing := range res.Contacts {
			for _, r := range ent.Roles {
				if hasRole(existing.Roles, r) && (existing.Name != "" || existing.Org != "" || existing.Email != "") {
					return
				}
			}
		}
	}
	res.Contacts = append(res.Contacts, c)
	for _, sub := range ent.Entities {
		applyEntity(res, sub, supplement)
	}
}

// vcard pulls the useful fields out of a jCard (RFC 7095) array.
func vcard(v []any) (name, org, email, phone string) {
	if len(v) < 2 {
		return
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		fields, _ := p.([]any)
		if len(fields) < 4 {
			continue
		}
		key, _ := fields[0].(string)
		val := ""
		switch x := fields[3].(type) {
		case string:
			val = x
		case []any:
			var parts []string
			for _, y := range x {
				if s, ok := y.(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
			val = strings.Join(parts, ", ")
		}
		switch key {
		case "fn":
			if name == "" {
				name = val
			}
		case "org":
			if org == "" {
				org = val
			}
		case "email":
			if email == "" {
				email = val
			}
		case "tel":
			if phone == "" {
				phone = strings.TrimPrefix(val, "tel:")
			}
		}
	}
	return
}

func hasRole(roles []string, r string) bool {
	for _, x := range roles {
		if strings.EqualFold(x, r) {
			return true
		}
	}
	return false
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func daysUntil(rfc3339 string) *int {
	t, err := time.Parse(time.RFC3339Nano, rfc3339)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, rfc3339); err != nil {
			return nil
		}
	}
	d := int(math.Floor(time.Until(t).Hours() / 24))
	return &d
}

func pretty(b []byte) string {
	var out bytes.Buffer
	if json.Indent(&out, b, "", "  ") != nil {
		return string(b)
	}
	return out.String()
}

// statusMeaning explains EPP/RDAP status values (RFC 8056, RFC 9083 §10.2.2).
func statusMeaning(s string) string {
	key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if m, ok := statusMeanings[key]; ok {
		return m
	}
	return ""
}

var statusMeanings = map[string]string{
	"active":                   "Normal state; the domain is delegated and resolvable.",
	"ok":                       "Normal state; the domain is delegated and resolvable.",
	"inactive":                 "No nameservers are associated; the domain does not resolve.",
	"clienttransferprohibited": "The registrar has locked the domain against transfers. Normal protection; unlock at the registrar before moving it.",
	"servertransferprohibited": "The registry has locked the domain against transfers, usually a dispute or registry lock service.",
	"clientdeleteprohibited":   "The registrar has locked the domain against deletion. Normal protection.",
	"serverdeleteprohibited":   "The registry has locked the domain against deletion.",
	"clientupdateprohibited":   "The registrar has locked the domain against changes to its data.",
	"serverupdateprohibited":   "The registry has locked the domain against changes, usually a registry lock service.",
	"clienthold":               "The registrar has removed the domain from the zone: it does not resolve. Often unpaid renewal or unverified contact details.",
	"serverhold":               "The registry has removed the domain from the zone: it does not resolve. Often a compliance or legal action.",
	"clientrenewprohibited":    "The registrar blocks renewal.",
	"serverrenewprohibited":    "The registry blocks renewal.",
	"pendingcreate":            "Registration requested, not yet complete.",
	"pendingdelete":            "Scheduled for deletion and about to drop; cannot be restored by the registrant.",
	"pendingrenew":             "Renewal requested, not yet complete.",
	"pendingrestore":           "Restore from redemption requested; the registrar must confirm.",
	"pendingtransfer":          "A transfer to another registrar is in progress.",
	"pendingupdate":            "An update is in progress.",
	"redemptionperiod":         "Deleted by the registrar and in the grace period where it can still be restored, for a fee.",
	"addperiod":                "Recently registered, within the registry's add grace period.",
	"autorenewperiod":          "Auto-renewed by the registry, within the grace period where the renewal can still be reversed.",
	"renewperiod":              "Recently renewed, within the renew grace period.",
	"transferperiod":           "Recently transferred, within the transfer grace period.",
	"associated":               "Object is associated with other objects (RDAP).",
	"validated":                "The registry has validated the registrant's details.",
	"locked":                   "Locked against changes.",
	"obscured":                 "Some data is withheld in this response.",
	"private":                  "Data is private and not shown.",
	"removed":                  "Withdrawn from public view.",
	"proxy":                    "Registered through a proxy service on someone's behalf.",
}

// --- WHOIS fallback --------------------------------------------------------------

func (op *Op) viaWHOIS(ctx context.Context, res *Result, domain, tld string, r fetch.Resolver) error {
	res.Source = "whois"
	iana, err := fetch.TCPQuery(ctx, op.IANAWhois, op.WhoisPort, tld, r)
	if err != nil {
		return fmt.Errorf("no RDAP server for .%s and IANA WHOIS unreachable: %v", tld, err)
	}
	server := whoisField(iana, "whois")
	if server == "" {
		server = whoisField(iana, "refer")
	}
	if server == "" {
		res.Raw = iana
		res.Warnings = append(res.Warnings, "no RDAP server for ."+tld+" and IANA lists no WHOIS server either")
		return nil
	}
	res.Server = server
	text, err := fetch.TCPQuery(ctx, server, op.WhoisPort, domain, r)
	if err != nil {
		return fmt.Errorf("WHOIS %s: %v", server, err)
	}
	res.Raw = text
	parseWHOIS(res, text)
	// Registrar-level WHOIS referral (thin registries such as .com).
	if ref := whoisField(text, "registrar whois server"); ref != "" && !strings.EqualFold(ref, server) {
		if more, err := fetch.TCPQuery(ctx, ref, op.WhoisPort, domain, r); err == nil {
			res.RegistrarServer = ref
			res.Raw += "\n\n% registrar response from " + ref + "\n" + more
			parseWHOIS(res, more)
		}
	}
	return nil
}

var whoisNotFound = regexp.MustCompile(`(?im)^\s*(no match|not found|no data found|no entries found|status:\s*free|the queried object does not exist|domain not found|% no match)`)

func whoisField(text, key string) string {
	re := regexp.MustCompile(`(?im)^\s*` + regexp.QuoteMeta(key) + `\s*:\s*(\S.*)$`)
	if m := re.FindStringSubmatch(text); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func whoisAll(text string, keys ...string) []string {
	var out []string
	for _, k := range keys {
		re := regexp.MustCompile(`(?im)^\s*` + regexp.QuoteMeta(k) + `\.*\s*:\s*(\S.*)$`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return out
}

func parseWHOIS(res *Result, text string) {
	if whoisNotFound.MatchString(text) && !res.Found {
		res.Found = false
		return
	}
	res.Found = true
	if res.Registrar.Name == "" {
		res.Registrar.Name = firstNonEmpty(whoisField(text, "registrar"), whoisField(text, "sponsoring registrar"), whoisField(text, "registrar name"))
	}
	if res.Registrar.IANAID == "" {
		res.Registrar.IANAID = whoisField(text, "registrar iana id")
	}
	if res.Registrar.URL == "" {
		res.Registrar.URL = whoisField(text, "registrar url")
	}
	if res.Registrar.AbuseEmail == "" {
		res.Registrar.AbuseEmail = whoisField(text, "registrar abuse contact email")
	}
	if res.Registered == "" {
		res.Registered = firstNonEmpty(whoisAll(text, "creation date", "created", "registered", "registration date", "created on", "domain registration date")...)
	}
	if res.Expires == "" {
		res.Expires = firstNonEmpty(whoisAll(text, "registry expiry date", "registrar registration expiration date", "expiry date", "expiration date", "expires", "expire", "paid-till", "renewal date")...)
		if res.Expires != "" {
			res.ExpiresInDays = daysUntil(normalizeDate(res.Expires))
		}
	}
	if res.Updated == "" {
		res.Updated = firstNonEmpty(whoisAll(text, "updated date", "last updated", "changed", "last modified", "modified")...)
	}
	if len(res.Nameservers) == 0 {
		seen := map[string]bool{}
		for _, ns := range whoisAll(text, "name server", "nserver", "nameserver", "name servers") {
			ns = strings.ToLower(strings.Fields(ns)[0])
			ns = strings.TrimSuffix(ns, ".")
			if ns != "" && !seen[ns] {
				seen[ns] = true
				res.Nameservers = append(res.Nameservers, ns)
			}
		}
		sort.Strings(res.Nameservers)
	}
	if len(res.Status) == 0 {
		for _, s := range whoisAll(text, "domain status", "status") {
			code := strings.Fields(s)[0]
			res.Status = append(res.Status, StatusInfo{Code: code, Meaning: statusMeaning(code)})
		}
	}
	if ds := whoisField(text, "dnssec"); ds != "" {
		res.DNSSEC.Known = true
		res.DNSSEC.Signed = strings.Contains(strings.ToLower(ds), "signed") && !strings.Contains(strings.ToLower(ds), "unsigned")
	}
	if len(res.Contacts) == 0 {
		for _, role := range []string{"registrant", "admin", "tech"} {
			c := Contact{Roles: []string{role}}
			c.Name = whoisField(text, role+" name")
			c.Org = whoisField(text, role+" organization")
			c.Email = whoisField(text, role+" email")
			c.Phone = whoisField(text, role+" phone")
			if c.Name != "" || c.Org != "" || c.Email != "" {
				res.Contacts = append(res.Contacts, c)
			}
		}
	}
}

// normalizeDate accepts the common WHOIS date shapes and returns RFC 3339.
func normalizeDate(s string) string {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02 15:04:05", "2006-01-02", "02-Jan-2006", "02.01.2006", "2006.01.02", "2006/01/02", "January 2 2006", "Jan 2 2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

// --- cross-check with the DNS ---------------------------------------------------

func (op *Op) crossCheck(ctx context.Context, res *Result, domain string, p Params, o contract.Effective) {
	o.RecursionDesired = true
	q := o.Build(contract.Resolved{Name: dns.Fqdn(domain), Type: dns.TypeNS, Class: dns.ClassINET})
	if r, err := op.Client.Exchange(ctx, p.Endpoint, q, o, p.Bootstrap); err == nil {
		for _, rr := range r.Msg.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				res.DNSNameservers = append(res.DNSNameservers, strings.ToLower(strings.TrimSuffix(ns.Ns, ".")))
			}
		}
		sort.Strings(res.DNSNameservers)
		if len(res.Nameservers) > 0 && len(res.DNSNameservers) > 0 && strings.Join(res.Nameservers, ",") != strings.Join(res.DNSNameservers, ",") {
			res.NSMismatch = true
			res.Warnings = append(res.Warnings, "the nameservers at the registry differ from the NS records the zone itself publishes")
		}
	}
	if res.Found && res.Expires != "" && res.ExpiresInDays != nil && *res.ExpiresInDays < 30 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("the registration expires in %d days", *res.ExpiresInDays))
	}
	for _, s := range res.Status {
		k := strings.ToLower(strings.ReplaceAll(s.Code, " ", ""))
		if k == "clienthold" || k == "serverhold" || k == "pendingdelete" || k == "redemptionperiod" || k == "inactive" {
			res.Warnings = append(res.Warnings, "status "+s.Code+": "+s.Meaning)
		}
	}
}
