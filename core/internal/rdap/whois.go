package rdap

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/n0rdy/nordyg/core/internal/fetch"
)

func (op *Op) viaWHOIS(ctx context.Context, res *Result, domain, tld string, r fetch.Resolver) error {
	res.Source = "whois"
	iana, err := fetch.TCPQuery(ctx, op.IANAWhois, op.WhoisPort, tld, r)
	if err != nil {
		return fmt.Errorf("no RDAP server for .%s and IANA WHOIS unreachable: %w", tld, err)
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
		return fmt.Errorf("WHOIS %s: %w", server, err)
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
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02 15:04:05", "2006-01-02", "02-Jan-2006", "02.01.2006", "2006.01.02", "2006/01/02", "January 2 2006", "Jan 2 2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}
