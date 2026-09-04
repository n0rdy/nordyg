package dnssec

import (
	_ "embed"
	"strings"

	"github.com/miekg/dns"
)

//go:embed trustanchors.txt
var trustAnchorsText string

// RootAnchors parses the embedded trust anchor file. A point release can
// replace the file without touching code.
func RootAnchors() []*dns.DS {
	var out []*dns.DS
	for _, line := range strings.Split(trustAnchorsText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			panic("dnssec: bad trust anchor line: " + line + ": " + err.Error())
		}
		if ds, ok := rr.(*dns.DS); ok {
			out = append(out, ds)
		}
	}
	if len(out) == 0 {
		panic("dnssec: no trust anchors embedded")
	}
	return out
}
