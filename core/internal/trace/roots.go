package trace

// Root hints as published by IANA (https://www.internic.net/domain/named.root).
// Only used to bootstrap the first hop; nothing here is trusted for DNSSEC.
var rootHints = []candidate{
	{Name: "a.root-servers.net.", IPs: []string{"198.41.0.4", "2001:503:ba3e::2:30"}},
	{Name: "b.root-servers.net.", IPs: []string{"170.247.170.2", "2801:1b8:10::b"}},
	{Name: "c.root-servers.net.", IPs: []string{"192.33.4.12", "2001:500:2::c"}},
	{Name: "d.root-servers.net.", IPs: []string{"199.7.91.13", "2001:500:2d::d"}},
	{Name: "e.root-servers.net.", IPs: []string{"192.203.230.10", "2001:500:a8::e"}},
	{Name: "f.root-servers.net.", IPs: []string{"192.5.5.241", "2001:500:2f::f"}},
	{Name: "g.root-servers.net.", IPs: []string{"192.112.36.4", "2001:500:12::d0d"}},
	{Name: "h.root-servers.net.", IPs: []string{"198.97.190.53", "2001:500:1::53"}},
	{Name: "i.root-servers.net.", IPs: []string{"192.36.148.17", "2001:7fe::53"}},
	{Name: "j.root-servers.net.", IPs: []string{"192.58.128.30", "2001:503:c27::2:30"}},
	{Name: "k.root-servers.net.", IPs: []string{"193.0.14.129", "2001:7fd::1"}},
	{Name: "l.root-servers.net.", IPs: []string{"199.7.83.42", "2001:500:9f::42"}},
	{Name: "m.root-servers.net.", IPs: []string{"202.12.27.33", "2001:dc3::35"}},
}
