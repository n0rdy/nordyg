// Package dnsq implements the "query" op: one question to one explicit
// endpoint. Transport selection (UDP/TCP/DoH/DoT/DoQ), full section detail and
// DNSSEC come with tier 1; this is the minimal wire-verified slice from the
// spike, reshaped to the bridge contract.
package dnsq

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
)

// Params is the "query" op input. Server is always an explicit host:port; the
// core never consults the system resolver (see CONTEXT.md, bridge rules).
type Params struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Server string `json:"server"`
	// TimeoutMS bounds the whole exchange. Zero means the default.
	TimeoutMS int `json:"timeout_ms,omitempty"`
}

// Record is one resource record in presentation format, split so the shell
// can lay it out without re-parsing.
type Record struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// Result is the "query" op output.
type Result struct {
	Rcode   string   `json:"rcode"`
	Answers []Record `json:"answers"`
	RTTms   int64    `json:"rtt_ms"`
}

const defaultTimeout = 5 * time.Second

// Stable error codes for this op.
const (
	CodeUnknownType = "unknown_type"
	CodeBadServer   = "bad_server"
	CodeTimeout     = "timeout"
	CodeNetwork     = "network"
)

// Register attaches the op to d.
func Register(d *bridge.Dispatcher) {
	d.Register("query", handle)
}

func handle(ctx context.Context, raw json.RawMessage) (any, error) {
	var p Params
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
	}
	return Query(ctx, p)
}

// Query performs one exchange. It is exported for tests and future ops
// (compare, trace) that reuse it.
func Query(ctx context.Context, p Params) (*Result, error) {
	if p.Name == "" {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "name is required"}
	}
	qtype, ok := dns.StringToType[strings.ToUpper(p.Type)]
	if !ok {
		return nil, &bridge.Error{Code: CodeUnknownType, Message: "unknown record type " + p.Type}
	}
	if _, _, err := net.SplitHostPort(p.Server); err != nil {
		return nil, &bridge.Error{Code: CodeBadServer, Message: "server must be host:port: " + err.Error()}
	}

	timeout := defaultTimeout
	if p.TimeoutMS > 0 {
		timeout = time.Duration(p.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(p.Name), qtype)
	m.SetEdns0(4096, true)

	c := &dns.Client{}
	in, rtt, err := c.ExchangeContext(ctx, m, p.Server)
	if err != nil {
		return nil, classify(ctx, err)
	}
	// UDP truncation: retry over TCP, as dig does.
	if in.Truncated {
		c.Net = "tcp"
		if in, rtt, err = c.ExchangeContext(ctx, m, p.Server); err != nil {
			return nil, classify(ctx, err)
		}
	}

	out := &Result{Rcode: dns.RcodeToString[in.Rcode], RTTms: rtt.Milliseconds(), Answers: []Record{}}
	for _, rr := range in.Answer {
		h := rr.Header()
		out.Answers = append(out.Answers, Record{
			Name: h.Name,
			Type: dns.TypeToString[h.Rrtype],
			TTL:  h.Ttl,
			Data: strings.TrimSpace(rr.String()[len(h.String()):]),
		})
	}
	return out, nil
}

func classify(ctx context.Context, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return context.Canceled
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return &bridge.Error{Code: CodeTimeout, Message: err.Error()}
	default:
		return &bridge.Error{Code: CodeNetwork, Message: err.Error()}
	}
}
