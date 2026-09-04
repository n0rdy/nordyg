package ops

import (
	"encoding/json"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/bridge"
)

func TestPingListsOps(t *testing.T) {
	var resp bridge.Response
	if err := json.Unmarshal(New().Dispatch([]byte(`{"id":"p","op":"ping"}`)), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("unexpected: %+v", resp)
	}
	var res PingResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	want := []string{"ping", "query"}
	if len(res.Ops) != len(want) {
		t.Fatalf("ops = %v, want %v", res.Ops, want)
	}
	for i := range want {
		if res.Ops[i] != want[i] {
			t.Fatalf("ops = %v, want %v", res.Ops, want)
		}
	}
	if res.Version != "dev" {
		t.Fatalf("version = %q", res.Version)
	}
}
