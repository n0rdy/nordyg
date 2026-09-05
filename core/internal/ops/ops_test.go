package ops

import (
	"encoding/json"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/testdns"
)

func dispatch(t *testing.T, d *bridge.Dispatcher, req string) bridge.Response {
	t.Helper()
	var resp bridge.Response
	if err := json.Unmarshal(d.Dispatch([]byte(req)), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPingListsOps(t *testing.T) {
	resp := dispatch(t, New(), `{"id":"p","op":"ping"}`)
	if !resp.OK {
		t.Fatalf("unexpected: %+v", resp)
	}
	var res PingResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	want := []string{"compare", "email", "export", "ping", "presets", "query", "rdap", "trace"}
	if len(res.Ops) != len(want) {
		t.Fatalf("ops = %v, want %v", res.Ops, want)
	}
	for i := range want {
		if res.Ops[i] != want[i] {
			t.Fatalf("ops = %v, want %v", res.Ops, want)
		}
	}
	if res.Version != "dev" || res.ContractVersion != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestQueryEndToEndThroughEnvelope(t *testing.T) {
	addr := testdns.UDP(t, testdns.Zone(t, "example.test. 300 IN A 192.0.2.1"))
	resp := dispatch(t, New(), `{"id":"q1","op":"query","params":{"question":{"name":"example.test","type":"A"},"endpoint":{"transport":"udp","address":"`+addr+`"}}}`)
	if !resp.OK || resp.ID != "q1" {
		t.Fatalf("%+v", resp)
	}
	var res struct {
		QuestionSent struct{ Name string } `json:"question_sent"`
		Message      struct {
			Rcode  string
			Answer []struct {
				Rdata  string
				Fields map[string]any
			}
			EDNS *struct{} `json:"edns"`
		}
		Exchange struct{ Protocol string }
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.QuestionSent.Name != "example.test." || res.Message.Rcode != "NOERROR" || len(res.Message.Answer) != 1 || res.Message.Answer[0].Fields["address"] != "192.0.2.1" || res.Exchange.Protocol != "udp" || res.Message.EDNS == nil {
		t.Fatalf("%s", resp.Result)
	}
}

func TestValidateIsWired(t *testing.T) {
	// The fixture is not signed by the real root keys, so the verdict is bogus;
	// what matters here is that a dnssec object comes back at all.
	addr := testdns.UDP(t, testdns.Zone(t, "example.test. 300 IN A 192.0.2.1"))
	resp := dispatch(t, New(), `{"id":"v","op":"query","params":{"question":{"name":"example.test","type":"A"},"endpoint":{"transport":"udp","address":"`+addr+`"},"validate":true}}`)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var res struct {
		DNSSEC struct {
			Status string
			Reason string
			Chain  []struct{ Zone string }
		} `json:"dnssec"`
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.DNSSEC.Status != "bogus" || len(res.DNSSEC.Chain) != 1 || res.DNSSEC.Chain[0].Zone != "." {
		t.Fatalf("%s", resp.Result)
	}
}
