package verdict

import "testing"

func TestWorst(t *testing.T) {
	for name, tc := range map[string]struct {
		findings []Finding
		want     Finding
	}{
		"nothing found":            {nil, Finding{OK, "all good"}},
		"only ok findings":         {[]Finding{{OK, "a"}, {OK, "b"}}, Finding{OK, "all good"}},
		"info outranks ok":         {[]Finding{{OK, "a"}, {Info, "note"}}, Finding{Info, "note"}},
		"fail outranks warn":       {[]Finding{{Warn, "w"}, {Fail, "f"}, {Info, "i"}}, Finding{Fail, "f"}},
		"first of several is kept": {[]Finding{{Warn, "first"}, {Info, "i"}, {Warn, "second"}, {Warn, "third"}}, Finding{Warn, "first (and 2 more)"}},
	} {
		if got := Worst(tc.findings, "all good"); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", name, got, tc.want)
		}
	}
}

func TestTally(t *testing.T) {
	for name, tc := range map[string]struct {
		verdicts []Finding
		want     Finding
		bad      bool
	}{
		"nothing wrong":     {[]Finding{{OK, ""}, {Info, ""}}, Finding{}, false},
		"one failure":       {[]Finding{{Fail, ""}, {OK, ""}}, Finding{Fail, "1 check failing"}, true},
		"failures and more": {[]Finding{{Fail, ""}, {Fail, ""}, {Warn, ""}}, Finding{Fail, "2 checks failing, 1 warning"}, true},
		"warnings only":     {[]Finding{{Warn, ""}, {Warn, ""}, {OK, ""}}, Finding{Warn, "no failures, 2 warnings"}, true},
	} {
		if got, bad := Tally(tc.verdicts...); got != tc.want || bad != tc.bad {
			t.Errorf("%s: got %+v %v, want %+v %v", name, got, bad, tc.want, tc.bad)
		}
	}
}
