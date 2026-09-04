// Package compare implements the "compare" op (contract §5): the same question
// to several endpoints at once, grouped by answer so disagreement stands out.
package compare

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
	"github.com/n0rdy/nordyg/core/internal/query"
)

// Params is the op input.
type Params struct {
	Question  contract.Question   `json:"question"`
	Endpoints []contract.Endpoint `json:"endpoints"`
	Options   contract.Options    `json:"options"`
	Bootstrap []contract.Endpoint `json:"bootstrap"`
}

// Entry is one endpoint's outcome.
type Entry struct {
	Endpoint contract.Endpoint  `json:"endpoint"`
	OK       bool               `json:"ok"`
	Message  *contract.Message  `json:"message,omitempty"`
	Exchange *contract.Exchange `json:"exchange,omitempty"`
	Error    *bridge.Error      `json:"error,omitempty"`
}

// Group is a set of endpoints that returned the same data.
type Group struct {
	Key     string   `json:"key"`
	Rcode   string   `json:"rcode,omitempty"`
	Answers []string `json:"answers,omitempty"`
	Members []int    `json:"members"`
}

// Result is the op output.
type Result struct {
	QuestionSent contract.Question `json:"question_sent"`
	Results      []Entry           `json:"results"`
	Groups       []Group           `json:"groups"`
	Consistent   bool              `json:"consistent"`
}

// ErrorKey is the group key for endpoints that failed.
const ErrorKey = "error"

// Op is the configured handler.
type Op struct {
	Query *query.Op
}

// Register attaches the op to d.
func (op *Op) Register(d *bridge.Dispatcher) {
	d.Register("compare", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p Params
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
		}
		return op.Run(ctx, p)
	})
}

// Run queries every endpoint concurrently and groups the outcomes.
func (op *Op) Run(ctx context.Context, p Params) (*Result, error) {
	r, err := p.Question.Resolve()
	if err != nil {
		return nil, err
	}
	if len(p.Endpoints) == 0 {
		return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "endpoints must not be empty"}
	}
	for i, ep := range p.Endpoints {
		if err := ep.Validate(); err != nil {
			var be *bridge.Error
			if errors.As(err, &be) {
				be.Message = "endpoints[" + strconv.Itoa(i) + "]: " + be.Message
			}
			return nil, err
		}
	}

	entries := make([]Entry, len(p.Endpoints))
	var wg sync.WaitGroup
	for i, ep := range p.Endpoints {
		wg.Add(1)
		go func(i int, ep contract.Endpoint) {
			defer wg.Done()
			entries[i] = op.one(ctx, p, ep)
		}(i, ep)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	out := &Result{QuestionSent: r.Question(), Results: entries}
	out.Groups = group(entries)
	out.Consistent = len(out.Groups) == 1 && out.Groups[0].Key != ErrorKey
	return out, nil
}

func (op *Op) one(ctx context.Context, p Params, ep contract.Endpoint) Entry {
	res, err := op.Query.Run(ctx, query.Params{Question: p.Question, Endpoint: ep, Options: p.Options, Bootstrap: p.Bootstrap})
	if err != nil {
		var be *bridge.Error
		if !errors.As(err, &be) {
			be = &bridge.Error{Code: bridge.CodeInternal, Message: err.Error()}
			if errors.Is(err, context.Canceled) {
				be = &bridge.Error{Code: bridge.CodeCancelled, Message: "request cancelled"}
			}
		}
		return Entry{Endpoint: ep, Error: be}
	}
	return Entry{Endpoint: ep, OK: true, Message: &res.Message, Exchange: &res.Exchange}
}

// Key computes the grouping key for a message: rcode plus the sorted set of
// "TYPE rdata" strings from the answer section. TTLs and order are ignored.
func Key(m *contract.Message) (key string, answers []string) {
	answers = make([]string, 0, len(m.Answer))
	for _, rr := range m.Answer {
		answers = append(answers, rr.Type+" "+rr.Rdata)
	}
	sort.Strings(answers)
	answers = dedupe(answers)
	return m.Rcode + "|" + strings.Join(answers, "|"), answers
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func group(entries []Entry) []Group {
	byKey := map[string]*Group{}
	var order []string
	for i, e := range entries {
		key := ErrorKey
		var g *Group
		if e.OK {
			key, _ = Key(e.Message)
			if byKey[key] == nil {
				g = &Group{Key: key, Rcode: e.Message.Rcode, Answers: rdataOnly(e.Message)}
			}
		} else if byKey[key] == nil {
			g = &Group{Key: key}
		}
		if g != nil {
			byKey[key] = g
			order = append(order, key)
		}
		byKey[key].Members = append(byKey[key].Members, i)
	}
	groups := make([]Group, 0, len(order))
	for _, k := range order {
		groups = append(groups, *byKey[k])
	}
	// Largest first; ties keep first-seen order; error group last.
	sort.SliceStable(groups, func(a, b int) bool {
		if (groups[a].Key == ErrorKey) != (groups[b].Key == ErrorKey) {
			return groups[b].Key == ErrorKey
		}
		return len(groups[a].Members) > len(groups[b].Members)
	})
	return groups
}

// rdataOnly lists the answer rdata sorted, for display.
func rdataOnly(m *contract.Message) []string {
	out := make([]string, 0, len(m.Answer))
	for _, rr := range m.Answer {
		out = append(out, rr.Rdata)
	}
	sort.Strings(out)
	return dedupe(out)
}
