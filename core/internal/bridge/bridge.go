// Package bridge is the JSON envelope and dispatcher behind the C surface.
//
// It is deliberately free of cgo so it can be tested like any Go package. The
// exported C functions in cmd/libnordyg are thin wrappers around Dispatch and
// Cancel.
//
// Rules enforced here:
//   - every request carries a client-generated id and an op;
//   - every response echoes the id;
//   - a panic inside a handler never escapes: it becomes an error response;
//   - an in-flight request can be cancelled by id.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"sync"
)

// Request is the envelope every call through the C surface uses.
type Request struct {
	ID     string          `json:"id"`
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the envelope every call returns. Exactly one of Result or Error
// is set.
type Response struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error is the error half of the envelope. Code is stable and machine-readable;
// Message is for humans. Details carries code-specific extra data.
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Message is err worded for a sentence shown to the user: an Error's message
// without its code, and the text of any other error.
func Message(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Message
	}
	return err.Error()
}

// Stable error codes.
const (
	CodeBadRequest  = "bad_request"
	CodeUnknownOp   = "unknown_op"
	CodeDuplicateID = "duplicate_id"
	CodeCancelled   = "cancelled"
	CodePanic       = "panic"
	CodeInternal    = "internal"
)

// Handler implements one op. It receives the raw params and returns a value
// that is JSON-marshalled into Response.Result. Returning an *Error keeps the
// code; any other error is reported as CodeInternal.
type Handler func(ctx context.Context, params json.RawMessage) (any, error)

// Typed adapts an op that takes its params as a struct: it decodes the raw
// JSON into P and reports missing or malformed params as bad_request.
func Typed[P, R any](run func(ctx context.Context, p P) (R, error)) Handler {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		if len(raw) == 0 {
			return nil, &Error{Code: CodeBadRequest, Message: "params required"}
		}
		var p P
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &Error{Code: CodeBadRequest, Message: "params: " + err.Error()}
		}
		res, err := run(ctx, p)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
}

// Dispatcher routes requests to handlers and tracks in-flight requests so they
// can be cancelled.
type Dispatcher struct {
	mu       sync.Mutex
	handlers map[string]Handler
	inflight map[string]context.CancelFunc
	// early holds the ids cancelled before their request was registered: the
	// shell can cancel as soon as it has picked an id, while the request is
	// still on its way in. Cancels for requests that already finished end up
	// here too, which is why the list is bounded.
	early []string
}

const maxEarlyCancels = 64

// New returns an empty Dispatcher.
func New() *Dispatcher {
	return &Dispatcher{
		handlers: map[string]Handler{},
		inflight: map[string]context.CancelFunc{},
	}
}

// Register adds a handler for op. Registering the same op twice panics: it is
// a programming error at startup, not a runtime condition.
func (d *Dispatcher) Register(op string, h Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, dup := d.handlers[op]; dup {
		panic("bridge: op registered twice: " + op)
	}
	d.handlers[op] = h
}

// Dispatch parses one request, runs its handler and returns the JSON response.
// It never panics and never returns malformed JSON.
func (d *Dispatcher) Dispatch(raw []byte) (out []byte) {
	var req Request
	defer func() {
		if r := recover(); r != nil {
			out = encode(fail(req.ID, CodePanic,
				fmt.Sprintf("%v\n%s", r, debug.Stack())))
		}
	}()

	if err := json.Unmarshal(raw, &req); err != nil {
		return encode(fail("", CodeBadRequest, "invalid JSON: "+err.Error()))
	}
	if req.ID == "" {
		return encode(fail("", CodeBadRequest, "missing id"))
	}
	if req.Op == "" {
		return encode(fail(req.ID, CodeBadRequest, "missing op"))
	}

	d.mu.Lock()
	h, ok := d.handlers[req.Op]
	if !ok {
		d.mu.Unlock()
		return encode(fail(req.ID, CodeUnknownOp, "unknown op "+req.Op))
	}
	if _, busy := d.inflight[req.ID]; busy {
		d.mu.Unlock()
		return encode(fail(req.ID, CodeDuplicateID, "request id already in flight"))
	}
	if i := slices.Index(d.early, req.ID); i >= 0 {
		d.early = slices.Delete(d.early, i, i+1)
		d.mu.Unlock()
		return encode(fail(req.ID, CodeCancelled, "request cancelled"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.inflight[req.ID] = cancel
	d.mu.Unlock()

	defer func() {
		cancel()
		d.mu.Lock()
		delete(d.inflight, req.ID)
		d.mu.Unlock()
	}()

	result, err := h(ctx, req.Params)
	if err != nil {
		return encode(toResponse(req.ID, err, ctx))
	}
	body, err := json.Marshal(result)
	if err != nil {
		return encode(fail(req.ID, CodeInternal, "marshal result: "+err.Error()))
	}
	return encode(Response{ID: req.ID, OK: true, Result: body})
}

// Cancel aborts the in-flight request with the given id. It reports whether
// such a request existed; cancelling an unknown id is not an error, and the
// request is refused if it arrives afterwards.
func (d *Dispatcher) Cancel(id string) bool {
	d.mu.Lock()
	cancel, ok := d.inflight[id]
	if !ok {
		d.early = append(d.early, id)
		if len(d.early) > maxEarlyCancels {
			d.early = d.early[1:]
		}
	}
	d.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// Ops lists registered ops, sorted by the caller if needed. Used by the "ping"
// op so the shell can discover what a given core build supports.
func (d *Dispatcher) Ops() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	ops := make([]string, 0, len(d.handlers))
	for op := range d.handlers {
		ops = append(ops, op)
	}
	return ops
}

func toResponse(id string, err error, ctx context.Context) Response {
	var e *Error
	switch {
	case errors.As(err, &e):
		return Response{ID: id, OK: false, Error: &Error{Code: e.Code, Message: e.Message, Details: e.Details}}
	case errors.Is(err, context.Canceled) || ctx.Err() != nil:
		return fail(id, CodeCancelled, "request cancelled")
	default:
		return fail(id, CodeInternal, err.Error())
	}
}

func fail(id, code, msg string) Response {
	return Response{ID: id, OK: false, Error: &Error{Code: code, Message: msg}}
}

func encode(r Response) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		// Response only contains strings and raw JSON we produced ourselves;
		// this cannot realistically fail, but never return nothing.
		return []byte(`{"id":"","ok":false,"error":{"code":"internal","message":"encode failed"}}`)
	}
	return b
}
