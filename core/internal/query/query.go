// Package query implements the "query" op (contract §4): one question to one
// endpoint, returning the parsed message and the wire exchange.
package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/msg"
	"github.com/n0rdy/nordyg/core/internal/transport"
)

// Params is the op input.
type Params struct {
	Question  contract.Question   `json:"question"`
	Endpoint  contract.Endpoint   `json:"endpoint"`
	Options   contract.Options    `json:"options"`
	Validate  bool                `json:"validate"`
	Bootstrap []contract.Endpoint `json:"bootstrap"`
}

// Result is the op output.
type Result struct {
	QuestionSent contract.Question `json:"question_sent"`
	Message      contract.Message  `json:"message"`
	Exchange     contract.Exchange `json:"exchange"`
	DNSSEC       any               `json:"dnssec,omitempty"`
}

// Validator produces the DNSSEC verdict for a completed query. It is nil
// until the dnssec package is wired in.
type Validator interface {
	Validate(ctx context.Context, r contract.Resolved, res *transport.Result, ep contract.Endpoint, o contract.Effective, bootstrap []contract.Endpoint) (any, error)
}

// Decorator post-processes records, for example attaching decoded TXT data.
type Decorator func(*contract.Message)

// Op is the configured handler.
type Op struct {
	Client    *transport.Client
	Validator Validator
	Decorate  Decorator
}

// Register attaches the op to d.
func (op *Op) Register(d *bridge.Dispatcher) {
	d.Register("query", op.Handle)
}

// Handle is the bridge handler.
func (op *Op) Handle(ctx context.Context, raw json.RawMessage) (any, error) {
	var p Params
	if len(raw) == 0 {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params required"}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
	}
	return op.Run(ctx, p)
}

// Run performs the query. Exported so compare and trace can reuse it.
func (op *Op) Run(ctx context.Context, p Params) (*Result, error) {
	r, err := p.Question.Resolve()
	if err != nil {
		return nil, err
	}
	if err := p.Endpoint.Validate(); err != nil {
		return nil, err
	}
	o := p.Options.Resolve()
	q := o.Build(r)

	res, err := op.Client.Exchange(ctx, p.Endpoint, q, o, p.Bootstrap)
	if err != nil {
		return nil, err
	}
	out := &Result{
		QuestionSent: r.Question(),
		Message:      msg.Convert(res.Msg, res.Size),
		Exchange:     res.Exchange,
	}
	out.Message.Text += Footer(res.Exchange, res.Size)
	if op.Decorate != nil {
		op.Decorate(&out.Message)
	}
	if p.Validate && op.Validator != nil {
		v, err := op.Validator.Validate(ctx, r, res, p.Endpoint, o, p.Bootstrap)
		if err != nil {
			return nil, err
		}
		out.DNSSEC = v
	}
	return out, nil
}

// Footer renders the dig-style trailer so message.text stands on its own.
func Footer(ex contract.Exchange, size int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n;; Query time: %.1f msec\n", ex.RTTms)
	fmt.Fprintf(&b, ";; SERVER: %s\n", serverLine(ex))
	fmt.Fprintf(&b, ";; WHEN: %s\n", ex.StartedAt.Format(time.RFC1123))
	fmt.Fprintf(&b, ";; MSG SIZE  rcvd: %d\n", size)
	return b.String()
}

func serverLine(ex contract.Exchange) string {
	ep := ex.Endpoint
	switch ep.Transport {
	case contract.DoH:
		return ep.URL + " (" + ex.Protocol + ")"
	default:
		host, port, err := net.SplitHostPort(ep.Address)
		if err != nil {
			host, port = ep.Address, "?"
		}
		s := host + "#" + port + "(" + ex.Protocol + ")"
		if ep.TLSName != "" {
			s += " " + ep.TLSName
		}
		return s
	}
}
