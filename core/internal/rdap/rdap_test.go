package rdap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

const registryJSON = `{
  "objectClassName": "domain", "handle": "D123", "ldhName": "example.test",
  "status": ["client transfer prohibited", "client delete prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "2023-10-03T19:52:31Z"},
    {"eventAction": "expiration", "eventDate": "%EXP%"},
    {"eventAction": "last changed", "eventDate": "2025-10-08T22:57:16Z"}
  ],
  "nameservers": [{"ldhName": "NS2.example.test"}, {"ldhName": "ns1.example.test"}],
  "secureDNS": {"delegationSigned": true, "dsData": [{"keyTag": 2371, "algorithm": 13, "digestType": 2, "digest": "abcdef"}]},
  "entities": [{
    "handle": "1861", "roles": ["registrar"],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Porkbun LLC"]]],
    "publicIds": [{"type": "IANA Registrar ID", "identifier": "1861"}],
    "links": [{"rel": "about", "href": "https://porkbun.com"}],
    "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Porkbun LLC"], ["tel", {"type": "voice"}, "uri", "tel:+1.8557675286"], ["email", {}, "text", "abuse@porkbun.com"]]]}]
  }],
  "notices": [{"title": "Terms of Use", "description": ["..."]}],
  "links": [{"rel": "self", "href": "https://rdap.test:%PORT%/domain/example.test"}, {"rel": "related", "href": "https://registrar.test:%PORT%/rdap/domain/example.test", "type": "application/rdap+json"}]
}`

const registrarJSON = `{
  "objectClassName": "domain", "ldhName": "example.test",
  "events": [{"eventAction": "expiration", "eventDate": "%EXP%"}],
  "entities": [{
    "roles": ["registrant"],
    "vcardArray": ["vcard", [["fn", {}, "text", "Myko Nordy"], ["org", {}, "text", "Nordy Studio"], ["email", {}, "text", "hello@example.test"], ["adr", {}, "text", ["", "", "Some street", "Oslo", "", "0150", "NO"]]]]
  }]
}`

type world struct {
	op  *Op
	ep  contract.Endpoint
	exp string
}

func setup(t *testing.T) *world {
	t.Helper()
	cert := testdns.NewCert(t, "rdap.test", "registrar.test", "data.iana.test")
	exp := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339)

	var port string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		switch {
		case r.Host == "rdap.test:"+port && r.URL.Path == "/domain/example.test":
			_, _ = w.Write([]byte(strings.NewReplacer("%EXP%", exp, "%PORT%", port).Replace(registryJSON)))
		case r.Host == "rdap.test:"+port && r.URL.Path == "/domain/redirect.test":
			http.Redirect(w, r, "/domain/example.test", http.StatusFound)
		case r.Host == "registrar.test:"+port && r.URL.Path == "/rdap/domain/example.test":
			_, _ = w.Write([]byte(strings.ReplaceAll(registrarJSON, "%EXP%", exp)))
		case r.URL.Path == "/domain/missing.test":
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
		default:
			w.WriteHeader(500)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert.TLS}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ = net.SplitHostPort(srv.Listener.Addr().String())

	// WHOIS: one TCP server plays IANA and the ccTLD registry, by query.
	wl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wl.Close() })
	go func() {
		for {
			c, err := wl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				q := strings.TrimSpace(string(buf[:n]))
				switch q {
				case "cc":
					_, _ = c.Write([]byte("domain:       CC\nwhois:        whois.nic.cc.test\nstatus:       ACTIVE\n"))
				case "example.cc":
					_, _ = c.Write([]byte("% Terms apply\nDomain Name: example.cc\nRegistrar: Example Registrar AS\nRegistrar IANA ID: 9999\nCreation Date: 2020-01-15T10:00:00Z\nRegistry Expiry Date: 2027-01-15\nUpdated Date: 2026-01-10T00:00:00Z\nName Server: ns1.example.test\nName Server: NS2.EXAMPLE.TEST\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDNSSEC: unsigned\nRegistrant Organization: Example Org\nRegistrant Email: owner@example.cc\n"))
				case "missing.cc":
					_, _ = c.Write([]byte("% Terms apply\nNo match for \"MISSING.CC\".\n"))
				default:
					_, _ = c.Write([]byte("% unknown query\n"))
				}
			}(c)
		}
	}()
	_, wport, _ := net.SplitHostPort(wl.Addr().String())
	var whoisPort int
	_, _ = fmtSscan(wport, &whoisPort)

	dnsAddr := testdns.UDP(t, testdns.Zone(t,
		"rdap.test. 300 IN A 127.0.0.1",
		"registrar.test. 300 IN A 127.0.0.1",
		"whois.iana.test. 300 IN A 127.0.0.1",
		"whois.nic.cc.test. 300 IN A 127.0.0.1",
		"example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN NS ns2.example.test.",
		"example.cc. 300 IN NS ns1.example.test.",
		"example.cc. 300 IN NS ns9.other.test.",
	))

	b := Embedded()
	b.Set("test", []string{"https://rdap.test:" + port + "/"})
	b.Set("cc", nil)
	op := &Op{
		Client:           &transport.Client{RootCAs: cert.Pool},
		Bootstrap:        b,
		TLS:              &tls.Config{RootCAs: cert.Pool},
		IANAWhois:        "whois.iana.test",
		WhoisPort:        whoisPort,
		RefreshBootstrap: false,
	}
	return &world{op: op, ep: contract.Endpoint{Transport: "udp", Address: dnsAddr}, exp: exp}
}

func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}

func TestRDAPWithRegistrarReferral(t *testing.T) {
	w := setup(t)
	res, err := w.op.Run(context.Background(), Params{Domain: "Example.TEST.", Endpoint: w.ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "rdap" || !res.Found || res.Handle != "D123" || res.RegistrarServer == "" {
		t.Fatalf("%+v", res)
	}
	if res.Registrar.Name != "Porkbun LLC" || res.Registrar.IANAID != "1861" || res.Registrar.URL != "https://porkbun.com" || res.Registrar.AbuseEmail != "abuse@porkbun.com" || res.Registrar.AbusePhone != "+1.8557675286" {
		t.Fatalf("registrar: %+v", res.Registrar)
	}
	if len(res.Status) != 2 || res.Status[0].Code != "client transfer prohibited" || !strings.Contains(res.Status[0].Meaning, "transfers") {
		t.Fatalf("status: %+v", res.Status)
	}
	if res.Registered != "2023-10-03T19:52:31Z" || res.Expires != w.exp || res.ExpiresInDays == nil || *res.ExpiresInDays < 18 || *res.ExpiresInDays > 20 {
		t.Fatalf("dates: %s %s %v", res.Registered, res.Expires, res.ExpiresInDays)
	}
	if strings.Join(res.Nameservers, ",") != "ns1.example.test,ns2.example.test" || res.NSMismatch || strings.Join(res.DNSNameservers, ",") != "ns1.example.test,ns2.example.test" {
		t.Fatalf("ns: %v dns %v mismatch %v", res.Nameservers, res.DNSNameservers, res.NSMismatch)
	}
	if !res.DNSSEC.Known || !res.DNSSEC.Signed || len(res.DNSSEC.DS) != 1 || res.DNSSEC.DS[0].KeyTag != 2371 {
		t.Fatalf("dnssec: %+v", res.DNSSEC)
	}
	// Registrant came from the registrar's response.
	if len(res.Contacts) != 1 || res.Contacts[0].Name != "Myko Nordy" || res.Contacts[0].Org != "Nordy Studio" || res.Contacts[0].Email != "hello@example.test" {
		t.Fatalf("contacts: %+v", res.Contacts)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "expires in") {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	if !strings.Contains(res.Raw, "registrar response") || res.Notices[0] != "Terms of Use" {
		t.Fatalf("raw/notices")
	}
}

func TestRDAPNotFoundAndRedirect(t *testing.T) {
	w := setup(t)
	res, err := w.op.Run(context.Background(), Params{Domain: "missing.test", Endpoint: w.ep})
	if err != nil || res.Found || res.Source != "rdap" {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = w.op.Run(context.Background(), Params{Domain: "redirect.test", Endpoint: w.ep})
	if err != nil || !res.Found || res.Handle != "D123" {
		t.Fatalf("redirect: %+v %v", res, err)
	}
}

func TestWHOISFallback(t *testing.T) {
	w := setup(t)
	res, err := w.op.Run(context.Background(), Params{Domain: "example.cc", Endpoint: w.ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "whois" || res.Server != "whois.nic.cc.test" || !res.Found {
		t.Fatalf("%+v", res)
	}
	if res.Registrar.Name != "Example Registrar AS" || res.Registrar.IANAID != "9999" || res.Registered != "2020-01-15T10:00:00Z" || res.Expires != "2027-01-15" || res.ExpiresInDays == nil || *res.ExpiresInDays < 100 {
		t.Fatalf("fields: %+v", res)
	}
	if strings.Join(res.Nameservers, ",") != "ns1.example.test,ns2.example.test" || !res.NSMismatch {
		t.Fatalf("ns: %v mismatch %v", res.Nameservers, res.NSMismatch)
	}
	if len(res.Status) != 1 || res.Status[0].Code != "clientTransferProhibited" || res.Status[0].Meaning == "" {
		t.Fatalf("status: %+v", res.Status)
	}
	if !res.DNSSEC.Known || res.DNSSEC.Signed {
		t.Fatalf("dnssec: %+v", res.DNSSEC)
	}
	if len(res.Contacts) != 1 || res.Contacts[0].Org != "Example Org" || res.Contacts[0].Email != "owner@example.cc" {
		t.Fatalf("contacts: %+v", res.Contacts)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "differ") {
		t.Fatalf("warnings: %v", res.Warnings)
	}

	res, err = w.op.Run(context.Background(), Params{Domain: "missing.cc", Endpoint: w.ep})
	if err != nil || res.Found {
		t.Fatalf("missing: %+v %v", res, err)
	}
}

func TestValidationAndEnvelope(t *testing.T) {
	w := setup(t)
	for _, bad := range []string{"", "localhost", "no-dots"} {
		_, err := w.op.Run(context.Background(), Params{Domain: bad, Endpoint: w.ep})
		var be *bridge.Error
		if !errors.As(err, &be) || be.Code != bridge.CodeBadRequest {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	d := bridge.New()
	w.op.Register(d)
	var resp bridge.Response
	_ = json.Unmarshal(d.Dispatch([]byte(`{"id":"r","op":"rdap","params":{"domain":"example.test","endpoint":{"transport":"udp","address":"`+w.ep.Address+`"}}}`)), &resp)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var res Result
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Registrar.Name != "Porkbun LLC" || res.ExpiresInDays == nil {
		t.Fatalf("%s", resp.Result)
	}
}

func TestBootstrapParsing(t *testing.T) {
	b := Embedded()
	if b.Publication == "" || len(b.Servers("com")) == 0 || len(b.Servers("foo")) == 0 || b.Servers("com")[0][len(b.Servers("com")[0])-1] != '/' {
		t.Fatalf("embedded bootstrap: %s com=%v foo=%v", b.Publication, b.Servers("com"), b.Servers("foo"))
	}
	if b.Servers("nonexistent-tld") != nil {
		t.Fatal("unknown TLD must return nil")
	}
	if statusMeaning("clientTransferProhibited") == "" || statusMeaning("client transfer prohibited") == "" || statusMeaning("weird") != "" {
		t.Fatal("status meanings")
	}
	if normalizeDate("2027-01-15") != "2027-01-15T00:00:00Z" || normalizeDate("15-Jan-2027") != "2027-01-15T00:00:00Z" {
		t.Fatal("date normalisation")
	}
}
