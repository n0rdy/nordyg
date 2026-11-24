// Package verdict is the status scale the report ops (email, health) put on
// what they find, and how a list of findings folds into one verdict.
package verdict

import (
	"fmt"

	"github.com/n0rdy/nordyg/core/internal/prose"
)

// Statuses, worst last.
const (
	OK   = "ok"
	Info = "info"
	Warn = "warn"
	Fail = "fail"
)

// Finding is one observation with its severity.
type Finding struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Rank orders the statuses, so a higher rank is worse.
func Rank(status string) int {
	switch status {
	case Info:
		return 1
	case Warn:
		return 2
	case Fail:
		return 3
	}
	return 0
}

// Worst returns the first of the worst findings, noting how many more share
// its status, or ok with okMsg when nothing is worse than ok.
func Worst(findings []Finding, okMsg string) Finding {
	worst, more := Finding{OK, okMsg}, 0
	for _, f := range findings {
		switch {
		case Rank(f.Status) > Rank(worst.Status):
			worst, more = f, 0
		case Rank(f.Status) == Rank(worst.Status) && worst.Status != OK:
			more++
		}
	}
	if more > 0 {
		worst.Message += fmt.Sprintf(" (and %d more)", more)
	}
	return worst
}

// Tally sums up a report's section verdicts: "2 checks failing, 1 warning"
// or "no failures, 3 warnings". The bool is false when nothing fails or warns.
func Tally(verdicts ...Finding) (Finding, bool) {
	fails, warns := 0, 0
	for _, v := range verdicts {
		switch v.Status {
		case Fail:
			fails++
		case Warn:
			warns++
		}
	}
	switch {
	case fails > 0 && warns > 0:
		return Finding{Fail, fmt.Sprintf("%d check%s failing, %d warning%s", fails, prose.Plural(fails), warns, prose.Plural(warns))}, true
	case fails > 0:
		return Finding{Fail, fmt.Sprintf("%d check%s failing", fails, prose.Plural(fails))}, true
	case warns > 0:
		return Finding{Warn, fmt.Sprintf("no failures, %d warning%s", warns, prose.Plural(warns))}, true
	}
	return Finding{}, false
}
