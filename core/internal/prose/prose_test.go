package prose

import "testing"

func TestNamesAndZones(t *testing.T) {
	for in, want := range map[string][2]string{
		".":            {"the root", "the root zone"},
		"me.":          {"me", "the .me zone"},
		"example.com.": {"example.com", "the zone example.com"},
		"example.com":  {"example.com", "the zone example.com"},
	} {
		if got := [2]string{Name(in), Zone(in)}; got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	if Plural(1)+Plural(0)+Plural(2) != "ss" || PluralEs(1)+PluralEs(2) != "es" {
		t.Error("plurals")
	}
}
