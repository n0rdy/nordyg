package transport

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/testdns"
)

func TestCheckResolver(t *testing.T) {
	c := &Client{}
	o := contract.Options{TimeoutMS: 200}.Resolve()
	refused := testdns.UDP(t, func(q *dns.Msg) *dns.Msg { m := new(dns.Msg); m.SetRcode(q, dns.RcodeRefused); return m })
	if err := c.CheckResolver(context.Background(), contract.Endpoint{Transport: "udp", Address: refused}, o, nil); err != nil {
		t.Fatalf("a REFUSED answer is still an answer: %v", err)
	}
	silent := testdns.UDP(t, testdns.Silent)
	err := c.CheckResolver(context.Background(), contract.Endpoint{Transport: "udp", Address: silent, Label: "Test"}, o, nil)
	var be *bridge.Error
	if !errors.As(err, &be) || be.Code != contract.CodeResolverUnreachable || be.Details["cause"] != contract.CodeTimeout ||
		!strings.HasPrefix(be.Message, "Test ("+silent+") did not answer in time") {
		t.Fatalf("%#v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.CheckResolver(ctx, contract.Endpoint{Transport: "udp", Address: silent}, o, nil); errors.As(err, &be) && be.Code == contract.CodeResolverUnreachable {
		t.Fatalf("cancellation must pass through, got %v", err)
	}
}
