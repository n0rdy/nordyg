// Package ops assembles the dispatcher with every op the core supports. It is
// the single place the C shim and the tests get a fully wired core from.
package ops

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/compare"
	"github.com/n0rdy/nordyg/core/internal/dnssec"
	"github.com/n0rdy/nordyg/core/internal/email"
	"github.com/n0rdy/nordyg/core/internal/export"
	"github.com/n0rdy/nordyg/core/internal/presets"
	"github.com/n0rdy/nordyg/core/internal/query"
	"github.com/n0rdy/nordyg/core/internal/trace"
	"github.com/n0rdy/nordyg/core/internal/transport"
	"github.com/n0rdy/nordyg/core/internal/txtdecode"
)

// Version is stamped by the Makefile via -ldflags. "dev" when built by hand.
var Version = "dev"

// ContractVersion is bumped only on a breaking change to docs/contract.md.
// Adding fields or ops is not breaking.
const ContractVersion = 1

// PingResult is the "ping" op output: a no-network health check the shell
// uses at startup to confirm the bridge works and to discover supported ops.
type PingResult struct {
	ContractVersion int      `json:"contract_version"`
	Version         string   `json:"version"`
	Ops             []string `json:"ops"`
}

// New returns a dispatcher with all ops registered.
func New() *bridge.Dispatcher {
	return NewWith(&transport.Client{})
}

// NewWith wires the ops around a specific transport client (tests inject
// custom trust roots this way).
func NewWith(tc *transport.Client) *bridge.Dispatcher {
	d := bridge.New()
	d.Register("ping", func(context.Context, json.RawMessage) (any, error) {
		ops := d.Ops()
		sort.Strings(ops)
		return PingResult{ContractVersion: ContractVersion, Version: Version, Ops: ops}, nil
	})
	v := dnssec.New()
	q := &query.Op{Client: tc, Decorate: txtdecode.Decorate, Validator: dnssec.QueryHook{V: v, Client: tc}}
	q.Register(d)
	(&compare.Op{Query: q}).Register(d)
	(&trace.Op{Client: tc, Decorate: txtdecode.Decorate, Validator: dnssec.TraceHook{V: v, Client: tc}}).Register(d)
	(&email.Op{Client: tc}).Register(d)
	presets.Register(d)
	export.Register(d)
	return d
}
