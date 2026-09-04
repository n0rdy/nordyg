package query

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/testdns"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

var zone = []string{
	"example.test. 300 IN A 192.0.2.1",
	"example.test. 300 IN MX 10 mail.example.test.",
	"1.2.0.192.in-addr.arpa. 300 IN PTR example.test.",
}

func newOp() *Op { return &Op{Client: &transport.Client{}} }

func TestRunReturnsContractShape(t *testing.T) {
	addr := testdns.UDP(t, testdns.Zone(t, zone...))
	res, err := newOp().Run(context.Background(), Params{
		Question: contract.Question{Name: "example.test", Type: "mx"},
		Endpoint: contract.Endpoint{Transport: "udp", Address: addr},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.QuestionSent.Name != "example.test." || res.QuestionSent.Type != "MX" || res.QuestionSent.Class != "IN" {
		t.Fatalf("question_sent: %+v", res.QuestionSent)
	}
	m := res.Message
	if m.Rcode != "NOERROR" || !m.Flags.QR || !m.Flags.AA || len(m.Answer) != 1 || m.Answer[0].Fields["exchange"] != "mail.example.test." {
		t.Fatalf("message: %+v", m)
	}
	if m.EDNS == nil || !m.EDNS.DNSSECOK {
		t.Fatalf("edns echoed: %+v", m.EDNS)
	}
	if !strings.Contains(m.Text, ";; ANSWER SECTION") || !strings.Contains(m.Text, ";; SERVER: 127.0.0.1#") || !strings.Contains(m.Text, ";; MSG SIZE  rcvd: ") {
		t.Fatalf("text:\n%s", m.Text)
	}
	if res.Exchange.Protocol != "udp" || res.Exchange.Endpoint.Address != addr {
		t.Fatalf("exchange: %+v", res.Exchange)
	}
	if res.DNSSEC != nil {
		t.Fatal("dnssec must be absent without validate")
	}
}

func TestPTRFromIP(t *testing.T) {
	addr := testdns.UDP(t, testdns.Zone(t, zone...))
	res, err := newOp().Run(context.Background(), Params{
		Question: contract.Question{Name: "192.0.2.1", Type: "PTR"},
		Endpoint: contract.Endpoint{Transport: "udp", Address: addr},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.QuestionSent.Name != "1.2.0.192.in-addr.arpa." || len(res.Message.Answer) != 1 || res.Message.Answer[0].Fields["target"] != "example.test." {
		t.Fatalf("%+v %+v", res.QuestionSent, res.Message.Answer)
	}
}

func TestNXDOMAINIsData(t *testing.T) {
	addr := testdns.UDP(t, testdns.Zone(t, zone...))
	res, err := newOp().Run(context.Background(), Params{
		Question: contract.Question{Name: "nope.test", Type: "A"},
		Endpoint: contract.Endpoint{Transport: "udp", Address: addr},
	})
	if err != nil || res.Message.Rcode != "NXDOMAIN" || len(res.Message.Answer) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestHandleValidation(t *testing.T) {
	op := newOp()
	cases := map[string]struct {
		raw  string
		code string
	}{
		"no params":     {"", bridge.CodeBadRequest},
		"bad json":      {"{", bridge.CodeBadRequest},
		"no question":   {`{"endpoint":{"transport":"udp","address":"127.0.0.1:1"}}`, bridge.CodeBadRequest},
		"bad type":      {`{"question":{"name":"x","type":"ZZ"},"endpoint":{"transport":"udp","address":"127.0.0.1:1"}}`, contract.CodeUnknownType},
		"bad endpoint":  {`{"question":{"name":"x","type":"A"},"endpoint":{"transport":"dot","address":"127.0.0.1:1"}}`, contract.CodeBadEndpoint},
		"unknown field": {`{"question":{"name":"x","type":"A"},"endpoint":{"transport":"udp","address":"127.0.0.1:1"},"future":1}`, ""},
	}
	for name, c := range cases {
		_, err := op.Handle(context.Background(), json.RawMessage(c.raw))
		var e *bridge.Error
		got := ""
		if errors.As(err, &e) {
			got = e.Code
		} else if err != nil {
			got = err.Error()
		}
		if c.code == "" {
			// Unknown fields are tolerated; the request then fails on the network, not on parsing.
			if got == bridge.CodeBadRequest {
				t.Errorf("%s: unknown field must not be a bad_request", name)
			}
			continue
		}
		if got != c.code {
			t.Errorf("%s: want %s, got %v", name, c.code, err)
		}
	}
}

func TestDecoratorAndValidatorHooks(t *testing.T) {
	addr := testdns.UDP(t, testdns.Zone(t, zone...))
	op := newOp()
	op.Decorate = func(m *contract.Message) { m.Answer[0].Decoded = "decorated" }
	op.Validator = fakeValidator{}
	res, err := op.Run(context.Background(), Params{
		Question: contract.Question{Name: "example.test", Type: "A"},
		Endpoint: contract.Endpoint{Transport: "udp", Address: addr},
		Validate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Message.Answer[0].Decoded != "decorated" || res.DNSSEC != "validated" {
		t.Fatalf("hooks: %+v", res)
	}
}

type fakeValidator struct{}

func (fakeValidator) Validate(context.Context, contract.Resolved, *transport.Result, contract.Endpoint, contract.Effective, []contract.Endpoint) (any, error) {
	return "validated", nil
}
