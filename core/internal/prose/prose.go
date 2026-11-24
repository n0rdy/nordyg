// Package prose holds the wording helpers the ops share when they put DNS
// names and counts into sentences.
package prose

import (
	"strings"

	"github.com/miekg/dns"
)

// Name renders a domain name without its trailing dot.
func Name(name string) string {
	if name == "." {
		return "the root"
	}
	return strings.TrimSuffix(name, ".")
}

// Zone renders a zone so a TLD does not read like a word:
// "." → "the root zone", "me." → "the .me zone", "example.com." → "the zone example.com".
func Zone(zone string) string {
	switch dns.CountLabel(zone) {
	case 0:
		return "the root zone"
	case 1:
		return "the ." + strings.TrimSuffix(zone, ".") + " zone"
	}
	return "the zone " + strings.TrimSuffix(zone, ".")
}

// Plural is the "s" for a count: "1 record", "2 records".
func Plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// PluralEs is the "es" for a count: "1 address", "2 addresses".
func PluralEs(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}
