package rdap

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

// IANA's RDAP bootstrap registry for DNS (RFC 9224), snapshot embedded so the
// op works offline; refreshed live on first use when possible.
//
//go:embed bootstrap.json
var bootstrapJSON []byte

// BootstrapURL is where the live registry lives.
const BootstrapURL = "https://data.iana.org/rdap/dns.json"

type bootstrapFile struct {
	Version     string          `json:"version"`
	Publication string          `json:"publication"`
	Services    [][]interface{} `json:"services"`
}

// Bootstrap maps TLDs to RDAP base URLs.
type Bootstrap struct {
	mu          sync.RWMutex
	byTLD       map[string][]string
	Publication string
	Source      string
}

// ParseBootstrap parses an RFC 9224 bootstrap document.
func ParseBootstrap(data []byte, source string) (*Bootstrap, error) {
	var f bootstrapFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	b := &Bootstrap{byTLD: map[string][]string{}, Publication: f.Publication, Source: source}
	for _, svc := range f.Services {
		if len(svc) != 2 {
			continue
		}
		tlds, _ := svc[0].([]interface{})
		urls, _ := svc[1].([]interface{})
		var list []string
		for _, u := range urls {
			if s, ok := u.(string); ok {
				if !strings.HasSuffix(s, "/") {
					s += "/"
				}
				list = append(list, s)
			}
		}
		for _, t := range tlds {
			if s, ok := t.(string); ok {
				b.byTLD[strings.ToLower(s)] = list
			}
		}
	}
	return b, nil
}

// Embedded returns the compiled-in snapshot.
func Embedded() *Bootstrap {
	b, err := ParseBootstrap(bootstrapJSON, "embedded")
	if err != nil {
		panic("rdap: embedded bootstrap is invalid: " + err.Error())
	}
	return b
}

// Servers returns the RDAP base URLs for a TLD, or nil.
func (b *Bootstrap) Servers(tld string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.byTLD[strings.ToLower(strings.TrimSuffix(tld, "."))]
}

// Replace swaps in a newer registry.
func (b *Bootstrap) Replace(n *Bootstrap) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.byTLD, b.Publication, b.Source = n.byTLD, n.Publication, n.Source
}

// Set overrides one TLD (tests).
func (b *Bootstrap) Set(tld string, urls []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.byTLD[strings.ToLower(tld)] = urls
}
