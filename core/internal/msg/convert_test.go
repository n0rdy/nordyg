package msg

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("bad RR %q: %v", s, err)
	}
	return r
}

func TestRecordFields(t *testing.T) {
	cases := []struct {
		rr    string
		typ   string
		rdata string
		check map[string]any
	}{
		{"x. 300 IN A 192.0.2.1", "A", "192.0.2.1", map[string]any{"address": "192.0.2.1"}},
		{"x. 300 IN AAAA 2001:db8::1", "AAAA", "2001:db8::1", map[string]any{"address": "2001:db8::1"}},
		{"x. 300 IN MX 10 mail.x.", "MX", "10 mail.x.", map[string]any{"preference": uint16(10), "exchange": "mail.x."}},
		{"x. 300 IN TXT \"v=spf1\" \"-all\"", "TXT", `"v=spf1" "-all"`, map[string]any{"strings": []string{"v=spf1", "-all"}}},
		{"x. 300 IN CAA 0 issue \"letsencrypt.org\"", "CAA", `0 issue "letsencrypt.org"`, map[string]any{"tag": "issue", "value": "letsencrypt.org"}},
		{"x. 300 IN SRV 10 20 5060 sip.x.", "SRV", "10 20 5060 sip.x.", map[string]any{"port": uint16(5060), "target": "sip.x."}},
		{"x. 300 IN DS 2371 13 2 1F987CC6583E92DF0890718C42", "DS", "2371 13 2 1F987CC6583E92DF0890718C42", map[string]any{"key_tag": uint16(2371), "algorithm_name": "ECDSAP256SHA256", "digest_type_name": "SHA256", "digest": "1f987cc6583e92df0890718c42"}},
		{"x. 300 IN TLSA 3 1 1 0123ABCD", "TLSA", "3 1 1 0123ABCD", map[string]any{"usage": uint8(3), "certificate_data": "0123abcd"}},
		{"x. 300 IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:info@x!\" .", "NAPTR", `100 10 "u" "E2U+sip" "!^.*$!sip:info@x!" .`, map[string]any{"order": uint16(100), "service": "E2U+sip"}},
		{"x. 300 IN SOA ns.x. hostmaster.x. 2026090401 7200 3600 1209600 300", "SOA", "ns.x. hostmaster.x. 2026090401 7200 3600 1209600 300", map[string]any{"serial": uint32(2026090401), "minimum": uint32(300)}},
	}
	for _, c := range cases {
		rec := Record(rr(t, c.rr))
		if rec.Type != c.typ || rec.Rdata != c.rdata || rec.Name != "x." || rec.TTL != 300 || rec.Class != "IN" {
			t.Errorf("%s: %+v", c.rr, rec)
		}
		for k, want := range c.check {
			got := rec.Fields[k]
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			if string(gj) != string(wj) {
				t.Errorf("%s: field %s = %s, want %s", c.rr, k, gj, wj)
			}
		}
	}
}

func TestUnknownTypeIsHexNotError(t *testing.T) {
	rec := Record(rr(t, "x. 60 IN TYPE65534 \\# 4 0A000001"))
	if rec.Type != "TYPE65534" || rec.TypeCode != 65534 || rec.Rdata != `\# 4 0A000001` || rec.Raw != "0a000001" || rec.Fields != nil {
		t.Fatalf("%+v", rec)
	}
}

func TestDNSKEYAndRRSIGFields(t *testing.T) {
	// A real 2048-bit RSA KSK-shaped key is long; use ECDSA and check role/bits/tag.
	k := rr(t, "x. 300 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==").(*dns.DNSKEY)
	rec := Record(k)
	if rec.Fields["role"] != "ksk" || rec.Fields["bits"] != 256 || rec.Fields["key_tag"] != k.KeyTag() || rec.Fields["algorithm_name"] != "ECDSAP256SHA256" {
		t.Fatalf("%+v", rec.Fields)
	}
	z := rr(t, "x. 300 IN DNSKEY 256 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==")
	if Record(z).Fields["role"] != "zsk" {
		t.Fatal("zsk role")
	}

	sig := rr(t, "x. 300 IN RRSIG A 13 1 300 20260918000000 20260904000000 2371 x. AAAA").(*dns.RRSIG)
	rec = Record(sig)
	exp, ok := rec.Fields["expiration"].(time.Time)
	if !ok || exp.Format(time.RFC3339) != "2026-09-18T00:00:00Z" || rec.Fields["type_covered"] != "A" || rec.Fields["signer"] != "x." {
		t.Fatalf("%+v", rec.Fields)
	}
}

func TestSerialTimeWrap(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	// 10 days after now, expressed mod 2^32.
	want := now.Add(10 * 24 * time.Hour)
	if got := serialTimeAt(uint32(want.Unix()), now); !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// 10 days before.
	want = now.Add(-10 * 24 * time.Hour)
	if got := serialTimeAt(uint32(want.Unix()), now); !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestConvertMessageWithEDNS(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("x.", dns.TypeA)
	m.Response, m.RecursionAvailable, m.AuthenticatedData = true, true, true
	m.Answer = []dns.RR{rr(t, "x. 300 IN A 192.0.2.1")}
	m.Ns = []dns.RR{rr(t, "x. 300 IN NS ns.x.")}
	m.Extra = []dns.RR{rr(t, "ns.x. 300 IN A 192.0.2.2")}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.SetDo()
	opt.Option = []dns.EDNS0{
		&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeDNSKEYMissing, ExtraText: "no key"},
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "6e73312e6578616d706c65"},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677aabbccddeeff0011"},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)},
		&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2}},
	}
	m.Extra = append(m.Extra, opt)

	packed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var back dns.Msg
	if err := back.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	out := Convert(&back, len(packed))

	if out.Rcode != "NOERROR" || out.Opcode != "QUERY" || !out.Flags.QR || !out.Flags.AD || out.Flags.AA {
		t.Fatalf("header: %+v", out)
	}
	if len(out.Question) != 1 || out.Question[0].Type != "A" || len(out.Answer) != 1 || len(out.Authority) != 1 || len(out.Additional) != 1 {
		t.Fatalf("sections: q=%d a=%d ns=%d ad=%d", len(out.Question), len(out.Answer), len(out.Authority), len(out.Additional))
	}
	if out.SizeBytes != len(packed) || out.Text == "" {
		t.Fatalf("size/text: %d %q", out.SizeBytes, out.Text)
	}
	e := out.EDNS
	if e == nil || e.UDPSize != 1232 || !e.DNSSECOK || len(e.Options) != 5 {
		t.Fatalf("edns: %+v", e)
	}
	if o := e.Options[0]; o.Name != "EDE" || o.EDE == nil || o.EDE.InfoCode != 9 || o.EDE.Purpose != "DNSKEY Missing" || o.EDE.ExtraText != "no key" || o.Data != "00096e6f206b6579" {
		t.Fatalf("ede: %+v %+v", o, o.EDE)
	}
	if o := e.Options[1]; o.Name != "NSID" || o.NSID == nil || o.NSID.Text != "ns1.example" {
		t.Fatalf("nsid: %+v %+v", o, o.NSID)
	}
	if o := e.Options[2]; o.Name != "COOKIE" || o.Cookie == nil || o.Cookie.Client != "0011223344556677" || o.Cookie.Server != "aabbccddeeff0011" {
		t.Fatalf("cookie: %+v %+v", o, o.Cookie)
	}
	if o := e.Options[3]; o.Name != "ECS" || o.ECS == nil || o.ECS.SourcePrefix != 24 || o.ECS.Address != "192.0.2.0" || o.Data != "00011800c00002" {
		t.Fatalf("ecs: %+v %+v", o, o.ECS)
	}
	if o := e.Options[4]; o.Name != "OPT65001" || o.Data != "0102" {
		t.Fatalf("local: %+v", o)
	}

	// No OPT: edns is null and additional keeps its records.
	m.Extra = m.Extra[:1]
	if Convert(m, 0).EDNS != nil {
		t.Fatal("edns should be nil without OPT")
	}
}

func TestExtendedRcode(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("x.", dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeBadCookie
	m.SetEdns0(1232, false)
	packed, _ := m.Pack()
	var back dns.Msg
	_ = back.Unpack(packed)
	if out := Convert(&back, 0); out.Rcode != "BADCOOKIE" {
		t.Fatalf("rcode = %s", out.Rcode)
	}
}

func TestHTTPSFields(t *testing.T) {
	rec := Record(rr(t, `x. 300 IN HTTPS 1 . alpn="h2,h3" port=8443 ipv4hint=192.0.2.1`))
	p := rec.Fields["params"].(map[string]any)
	if rec.Fields["priority"] != uint16(1) || rec.Fields["target"] != "." || p["port"] != uint16(8443) {
		t.Fatalf("%+v", rec.Fields)
	}
	if alpn, _ := p["alpn"].([]string); len(alpn) != 2 || alpn[1] != "h3" {
		t.Fatalf("alpn %+v", p["alpn"])
	}
	if hints, _ := p["ipv4hint"].([]string); len(hints) != 1 || hints[0] != "192.0.2.1" {
		t.Fatalf("ipv4hint %+v", p["ipv4hint"])
	}
}
