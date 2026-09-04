// Package presets implements the "presets" op (contract §7): the built-in
// public resolvers so the shell never hardcodes addresses.
package presets

import (
	"context"
	"encoding/json"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
)

// Preset is one resolver operator with every endpoint it offers.
type Preset struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Requires  []string            `json:"requires,omitempty"`
	Endpoints []contract.Endpoint `json:"endpoints"`
}

// Result is the op output.
type Result struct {
	Presets []Preset `json:"presets"`
}

// Register attaches the op to d.
func Register(d *bridge.Dispatcher) {
	d.Register("presets", func(context.Context, json.RawMessage) (any, error) {
		return Result{Presets: All()}, nil
	})
}

// All returns a fresh copy of the preset list.
func All() []Preset {
	out := make([]Preset, len(all))
	for i, p := range all {
		out[i] = p
		out[i].Endpoints = append([]contract.Endpoint(nil), p.Endpoints...)
	}
	return out
}

func plain(label, ip string) []contract.Endpoint {
	return []contract.Endpoint{
		{Transport: contract.UDP, Address: contract.JoinHostPort(ip, 53), Label: label + " UDP"},
		{Transport: contract.TCP, Address: contract.JoinHostPort(ip, 53), Label: label + " TCP"},
	}
}

func dot(label, ip, name string) contract.Endpoint {
	return contract.Endpoint{Transport: contract.DoT, Address: contract.JoinHostPort(ip, 853), TLSName: name, Label: label + " DoT"}
}

func doh(label, ip, url string) contract.Endpoint {
	return contract.Endpoint{Transport: contract.DoH, URL: url, Address: contract.JoinHostPort(ip, 443), Label: label + " DoH"}
}

func doq(label, ip, name string) contract.Endpoint {
	return contract.Endpoint{Transport: contract.DoQ, Address: contract.JoinHostPort(ip, 853), TLSName: name, Label: label + " DoQ"}
}

func concat(groups ...[]contract.Endpoint) []contract.Endpoint {
	var out []contract.Endpoint
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

var all = []Preset{
	{
		ID: "cloudflare", Name: "Cloudflare",
		Endpoints: concat(
			plain("Cloudflare", "1.1.1.1"),
			plain("Cloudflare (secondary)", "1.0.0.1"),
			plain("Cloudflare IPv6", "2606:4700:4700::1111"),
			plain("Cloudflare IPv6 (secondary)", "2606:4700:4700::1001"),
			[]contract.Endpoint{
				dot("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
				dot("Cloudflare IPv6", "2606:4700:4700::1111", "cloudflare-dns.com"),
				doh("Cloudflare", "1.1.1.1", "https://cloudflare-dns.com/dns-query"),
				doh("Cloudflare IPv6", "2606:4700:4700::1111", "https://cloudflare-dns.com/dns-query"),
			},
		),
	},
	{
		ID: "google", Name: "Google",
		Endpoints: concat(
			plain("Google", "8.8.8.8"),
			plain("Google (secondary)", "8.8.4.4"),
			plain("Google IPv6", "2001:4860:4860::8888"),
			plain("Google IPv6 (secondary)", "2001:4860:4860::8844"),
			[]contract.Endpoint{
				dot("Google", "8.8.8.8", "dns.google"),
				dot("Google IPv6", "2001:4860:4860::8888", "dns.google"),
				doh("Google", "8.8.8.8", "https://dns.google/dns-query"),
				doh("Google IPv6", "2001:4860:4860::8888", "https://dns.google/dns-query"),
			},
		),
	},
	{
		ID: "quad9", Name: "Quad9",
		Endpoints: concat(
			plain("Quad9", "9.9.9.9"),
			plain("Quad9 (secondary)", "149.112.112.112"),
			plain("Quad9 IPv6", "2620:fe::fe"),
			plain("Quad9 IPv6 (secondary)", "2620:fe::9"),
			[]contract.Endpoint{
				dot("Quad9", "9.9.9.9", "dns.quad9.net"),
				dot("Quad9 IPv6", "2620:fe::fe", "dns.quad9.net"),
				doh("Quad9", "9.9.9.9", "https://dns.quad9.net/dns-query"),
				doh("Quad9 IPv6", "2620:fe::fe", "https://dns.quad9.net/dns-query"),
			},
		),
	},
	{
		ID: "nextdns", Name: "NextDNS", Requires: []string{"profile_id"},
		Endpoints: []contract.Endpoint{
			dot("NextDNS", "45.90.28.0", "{profile_id}.dns.nextdns.io"),
			dot("NextDNS (secondary)", "45.90.30.0", "{profile_id}.dns.nextdns.io"),
			dot("NextDNS IPv6", "2a07:a8c0::", "{profile_id}.dns.nextdns.io"),
			doh("NextDNS", "45.90.28.0", "https://dns.nextdns.io/{profile_id}"),
			doh("NextDNS IPv6", "2a07:a8c0::", "https://dns.nextdns.io/{profile_id}"),
			doq("NextDNS", "45.90.28.0", "{profile_id}.dns.nextdns.io"),
		},
	},
	{
		ID: "adguard", Name: "AdGuard",
		Endpoints: concat(
			plain("AdGuard", "94.140.14.14"),
			plain("AdGuard (secondary)", "94.140.15.15"),
			plain("AdGuard IPv6", "2a10:50c0::ad1:ff"),
			plain("AdGuard IPv6 (secondary)", "2a10:50c0::ad2:ff"),
			[]contract.Endpoint{
				dot("AdGuard", "94.140.14.14", "dns.adguard-dns.com"),
				dot("AdGuard IPv6", "2a10:50c0::ad1:ff", "dns.adguard-dns.com"),
				doh("AdGuard", "94.140.14.14", "https://dns.adguard-dns.com/dns-query"),
				doh("AdGuard IPv6", "2a10:50c0::ad1:ff", "https://dns.adguard-dns.com/dns-query"),
				doq("AdGuard", "94.140.14.14", "dns.adguard-dns.com"),
				doq("AdGuard IPv6", "2a10:50c0::ad1:ff", "dns.adguard-dns.com"),
			},
		),
	},
	{
		// Mullvad only serves encrypted DNS publicly; plain 53 works on their VPN only.
		ID: "mullvad", Name: "Mullvad",
		Endpoints: []contract.Endpoint{
			dot("Mullvad", "194.242.2.2", "dns.mullvad.net"),
			dot("Mullvad IPv6", "2a07:e340::2", "dns.mullvad.net"),
			doh("Mullvad", "194.242.2.2", "https://dns.mullvad.net/dns-query"),
			doh("Mullvad IPv6", "2a07:e340::2", "https://dns.mullvad.net/dns-query"),
		},
	},
}
