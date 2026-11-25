package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func decode(t *testing.T, b []byte) Response {
	t.Helper()
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("response is not valid JSON: %v\n%s", err, b)
	}
	return r
}

func TestDispatchEchoesIDAndResult(t *testing.T) {
	d := New()
	d.Register("echo", func(_ context.Context, p json.RawMessage) (any, error) {
		return json.RawMessage(p), nil
	})
	r := decode(t, d.Dispatch([]byte(`{"id":"r1","op":"echo","params":{"x":1}}`)))
	if !r.OK || r.ID != "r1" || string(r.Result) != `{"x":1}` {
		t.Fatalf("unexpected response: %+v", r)
	}
}

func TestDispatchRejectsBadEnvelope(t *testing.T) {
	d := New()
	cases := map[string]string{
		"not json":   `{`,
		"missing id": `{"op":"x"}`,
		"missing op": `{"id":"r1"}`,
	}
	for name, raw := range cases {
		r := decode(t, d.Dispatch([]byte(raw)))
		if r.OK || r.Error == nil || r.Error.Code != CodeBadRequest {
			t.Errorf("%s: want bad_request, got %+v", name, r)
		}
	}
}

func TestDispatchUnknownOp(t *testing.T) {
	r := decode(t, New().Dispatch([]byte(`{"id":"r1","op":"nope"}`)))
	if r.OK || r.Error.Code != CodeUnknownOp || r.ID != "r1" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestDispatchRecoversPanic(t *testing.T) {
	d := New()
	d.Register("boom", func(context.Context, json.RawMessage) (any, error) {
		panic("kaboom")
	})
	r := decode(t, d.Dispatch([]byte(`{"id":"r1","op":"boom"}`)))
	if r.OK || r.Error.Code != CodePanic || !strings.Contains(r.Error.Message, "kaboom") {
		t.Fatalf("unexpected: %+v", r)
	}
	if r.ID != "r1" {
		t.Fatalf("panic response lost the id: %+v", r)
	}
	// A panic must not leave the id stuck in the inflight table.
	if d.Cancel("r1") {
		t.Fatal("request still in flight after panic")
	}
}

func TestDispatchTypedErrorKeepsCode(t *testing.T) {
	d := New()
	d.Register("typed", func(context.Context, json.RawMessage) (any, error) {
		return nil, &Error{Code: "dns_timeout", Message: "no reply"}
	})
	r := decode(t, d.Dispatch([]byte(`{"id":"r1","op":"typed"}`)))
	if r.Error == nil || r.Error.Code != "dns_timeout" {
		t.Fatalf("unexpected: %+v", r)
	}

	d.Register("detailed", func(context.Context, json.RawMessage) (any, error) {
		return nil, &Error{Code: "http", Message: "404", Details: map[string]any{"status": 404}}
	})
	r = decode(t, d.Dispatch([]byte(`{"id":"r3","op":"detailed"}`)))
	if r.Error == nil || r.Error.Details["status"] != float64(404) {
		t.Fatalf("details lost: %+v", r.Error)
	}

	d.Register("plain", func(context.Context, json.RawMessage) (any, error) {
		return nil, errors.New("something")
	})
	r = decode(t, d.Dispatch([]byte(`{"id":"r2","op":"plain"}`)))
	if r.Error == nil || r.Error.Code != CodeInternal {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestCancelAbortsInflightRequest(t *testing.T) {
	d := New()
	started := make(chan struct{})
	d.Register("wait", func(ctx context.Context, _ json.RawMessage) (any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	out := make(chan []byte, 1)
	go func() { out <- d.Dispatch([]byte(`{"id":"slow","op":"wait"}`)) }()
	<-started

	if !d.Cancel("slow") {
		t.Fatal("Cancel reported no such request")
	}
	select {
	case b := <-out:
		r := decode(t, b)
		if r.OK || r.Error.Code != CodeCancelled {
			t.Fatalf("unexpected: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not finish after cancel")
	}
	if d.Cancel("slow") {
		t.Fatal("id still in flight after completion")
	}
}

func TestCancelUnknownIDIsNoop(t *testing.T) {
	if New().Cancel("ghost") {
		t.Fatal("expected false for unknown id")
	}
}

func TestCancelBeforeTheRequestArrives(t *testing.T) {
	d := New()
	ran := false
	d.Register("op", func(context.Context, json.RawMessage) (any, error) {
		ran = true
		return "done", nil
	})
	d.Cancel("early")
	r := decode(t, d.Dispatch([]byte(`{"id":"early","op":"op"}`)))
	if r.OK || r.Error.Code != CodeCancelled || ran {
		t.Fatalf("a request cancelled in advance must not run: %+v (ran %v)", r, ran)
	}
	// The cancel is spent: the same id is free to run again.
	if r := decode(t, d.Dispatch([]byte(`{"id":"early","op":"op"}`))); !r.OK {
		t.Fatalf("second request: %+v", r)
	}
	// Old cancels do not pile up or shadow new requests.
	for i := range maxEarlyCancels + 1 {
		d.Cancel("late-" + strconv.Itoa(i))
	}
	if r := decode(t, d.Dispatch([]byte(`{"id":"late-0","op":"op"}`))); !r.OK {
		t.Fatalf("the oldest remembered cancel should have been dropped: %+v", r)
	}
}

func TestDuplicateInflightID(t *testing.T) {
	d := New()
	started := make(chan struct{})
	release := make(chan struct{})
	d.Register("wait", func(ctx context.Context, _ json.RawMessage) (any, error) {
		close(started)
		<-release
		return "done", nil
	})
	go d.Dispatch([]byte(`{"id":"same","op":"wait"}`))
	<-started
	r := decode(t, d.Dispatch([]byte(`{"id":"same","op":"wait"}`)))
	close(release)
	if r.OK || r.Error.Code != CodeDuplicateID {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestRegisterTwicePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	d := New()
	h := func(context.Context, json.RawMessage) (any, error) { return nil, nil }
	d.Register("x", h)
	d.Register("x", h)
}
