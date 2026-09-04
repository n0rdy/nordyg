// Package ops assembles the dispatcher with every op the core supports. It is
// the single place the C shim and the tests get a fully wired core from.
package ops

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/dnsq"
)

// Version is stamped by the Makefile via -ldflags. "dev" when built by hand.
var Version = "dev"

// PingResult is the "ping" op output: a no-network health check the shell
// uses at startup to confirm the bridge works and to discover supported ops.
type PingResult struct {
	Version string   `json:"version"`
	Ops     []string `json:"ops"`
}

// New returns a dispatcher with all ops registered.
func New() *bridge.Dispatcher {
	d := bridge.New()
	d.Register("ping", func(context.Context, json.RawMessage) (any, error) {
		ops := d.Ops()
		sort.Strings(ops)
		return PingResult{Version: Version, Ops: ops}, nil
	})
	dnsq.Register(d)
	return d
}
