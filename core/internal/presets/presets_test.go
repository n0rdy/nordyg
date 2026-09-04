package presets

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
)

func TestEveryEndpointValidates(t *testing.T) {
	ids := map[string]bool{}
	for _, p := range All() {
		if ids[p.ID] {
			t.Errorf("duplicate preset id %s", p.ID)
		}
		ids[p.ID] = true
		if p.Name == "" || len(p.Endpoints) == 0 {
			t.Errorf("%s: empty", p.ID)
		}
		labels := map[string]bool{}
		for _, ep := range p.Endpoints {
			// Placeholders are filled by the shell; substitute for validation.
			e := ep
			for _, ph := range p.Requires {
				e.URL = strings.ReplaceAll(e.URL, "{"+ph+"}", "abc123")
				e.TLSName = strings.ReplaceAll(e.TLSName, "{"+ph+"}", "abc123")
			}
			if err := e.Validate(); err != nil {
				t.Errorf("%s %s: %v", p.ID, ep.Label, err)
			}
			if ep.Label == "" || labels[ep.Label+ep.Transport] {
				t.Errorf("%s: missing or duplicate label %q", p.ID, ep.Label)
			}
			labels[ep.Label+ep.Transport] = true
			if strings.Contains(ep.URL+ep.TLSName, "{") && len(p.Requires) == 0 {
				t.Errorf("%s %s: placeholder without requires", p.ID, ep.Label)
			}
		}
	}
	for _, want := range []string{"cloudflare", "google", "quad9", "nextdns", "adguard", "mullvad"} {
		if !ids[want] {
			t.Errorf("missing preset %s", want)
		}
	}
}

func TestOpOutput(t *testing.T) {
	d := bridge.New()
	Register(d)
	var resp bridge.Response
	_ = json.Unmarshal(d.Dispatch([]byte(`{"id":"p","op":"presets"}`)), &resp)
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var res Result
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Presets) != 6 || res.Presets[0].ID != "cloudflare" {
		t.Fatalf("%+v", res.Presets)
	}
	// NextDNS carries its placeholder requirement through JSON.
	for _, p := range res.Presets {
		if p.ID == "nextdns" && (len(p.Requires) != 1 || p.Requires[0] != "profile_id") {
			t.Fatalf("nextdns requires: %v", p.Requires)
		}
	}
	// Mutating a copy must not touch the shared table.
	All()[0].Endpoints[0] = contract.Endpoint{}
	if All()[0].Endpoints[0].Address == "" {
		t.Fatal("All() leaked internal slice")
	}
}
