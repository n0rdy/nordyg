package resolve

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

func TestAddrsKeepsFailureApartFromAbsence(t *testing.T) {
	zone := testdns.Zone(t,
		"both.test. 300 IN A 192.0.2.1",
		"both.test. 300 IN AAAA 2001:db8::1",
		"half.test. 300 IN A 192.0.2.2",
	)
	addr := testdns.UDP(t, func(q *dns.Msg) *dns.Msg {
		name, qtype := q.Question[0].Name, q.Question[0].Qtype
		if name == "broken.test." || (name == "half.test." && qtype == dns.TypeAAAA) {
			return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure)
		}
		return zone(q)
	})
	r := &Resolver{Client: &transport.Client{}, Endpoint: contract.Endpoint{Transport: "udp", Address: addr}, Options: contract.Options{TimeoutMS: 1000}.Resolve()}
	ctx := context.Background()

	if got, err := r.Addrs(ctx, "both.test"); err != nil || !slices.Equal(got, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Errorf("both families: %v, %v", got, err)
	}
	// One family failing does not hide the addresses of the other.
	if got, err := r.Addrs(ctx, "half.test"); err != nil || !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("one family failed: %v, %v", got, err)
	}
	// A name that does not exist has no addresses, which is an answer.
	if got, err := r.Addrs(ctx, "missing.test"); err != nil || len(got) != 0 {
		t.Errorf("NXDOMAIN: %v, %v", got, err)
	}
	// A resolver that cannot answer is an error, and says which.
	var rcode Rcode
	if _, err := r.Addrs(ctx, "broken.test"); !errors.As(err, &rcode) || rcode != dns.RcodeServerFailure || err.Error() != "SERVFAIL" {
		t.Errorf("SERVFAIL: %v", err)
	}
	if _, err := r.Answer(ctx, "broken.test", dns.TypeMX); !errors.As(err, &rcode) {
		t.Errorf("Answer on SERVFAIL: %v", err)
	}
	if m, err := r.Lookup(ctx, "broken.test", dns.TypeMX); err != nil || m.Rcode != dns.RcodeServerFailure {
		t.Errorf("Lookup returns the reply as it came: %v, %v", m, err)
	}
}
