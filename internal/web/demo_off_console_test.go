//go:build !demo

package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// consoleAs renders the console for one configuration and puts the package
// back as it found it.
//
// Configure replaces a rendered page, which every other test in this package
// reads. Leaving it changed would make this file decide what those tests see.
func consoleAs(t *testing.T, verified bool) string {
	t.Helper()

	before := rendered["/"]
	t.Cleanup(func() { rendered["/"] = before })

	Configure(verified)
	return flatten(get(t, "/").Body.String())
}

// The console says what this installation actually is.
//
// The dangerous direction is one sentence: a page telling an operator that
// proof of control is required when it is not tells them their service is safe
// to expose when it is not. A sabotage hardcoding Verified escaped every test
// in this package on 2026-09-12, which is why this exists.
func TestTheConsoleSaysWhetherABoundaryIsConfigured(t *testing.T) {
	const open = "No proof of control is required"

	unbounded := consoleAs(t, false)
	if !strings.Contains(unbounded, open) {
		t.Errorf("an installation with no boundary does not say so. That is the sentence an "+
			"operator needs before putting this anywhere a stranger can reach:\n%s", unbounded)
	}

	bounded := consoleAs(t, true)
	if strings.Contains(bounded, open) {
		t.Errorf("an installation with a boundary is described as having none, which sends "+
			"somebody to look for a flag they already set:\n%s", bounded)
	}
	if !strings.Contains(bounded, "shown control of") {
		t.Errorf("an installation with a boundary does not say what it scans:\n%s", bounded)
	}
}

// What it says about pages follows from the same fact.
//
// internal/httpapi sets ReadMarkup from the verification scope, so a page that
// described the two independently could say the body is read on an
// installation that reads none — and a report silent about mixed content would
// then read as a site that has none (R4).
func TestTheConsoleSaysWhetherPagesAreRead(t *testing.T) {
	unbounded := consoleAs(t, false)
	if !strings.Contains(unbounded, "Not read") {
		t.Errorf("an installation that reads no page does not say so:\n%s", unbounded)
	}

	bounded := consoleAs(t, true)
	if strings.Contains(bounded, "Not read.") {
		t.Errorf("an installation that reads pages where control was proven says it reads "+
			"none:\n%s", bounded)
	}
}

// Every rule set this binary carries is offered as a check.
//
// Tested by existing rather than by a list somebody remembers to extend: a
// fourth check arrives with a fourth rule set, and the console has to grow a
// row for it or this fails. A check nobody can run from the page that exists to
// run them is a check nobody runs.
func TestTheConsoleOffersEveryCheckThisBinaryHas(t *testing.T) {
	page := consoleAs(t, false)

	inForce := []string{policy.TLSVersion, policy.WebVersion, policy.MailVersion}
	offered := consoleChecks()

	if len(offered) != len(inForce) {
		t.Fatalf("the console offers %d checks and this binary carries %d rule sets",
			len(offered), len(inForce))
	}

	for _, version := range inForce {
		found := false
		for _, c := range offered {
			if c.Policy == version {
				found = true
			}
		}
		if !found {
			t.Errorf("%s grades something and the console offers no check for it", version)
		}
		if !strings.Contains(page, version) {
			t.Errorf("the console does not name %s, so a reader cannot tell whether two reports "+
				"are comparable:\n%s", version, page)
		}
	}

	// Each row carries what the box means, because "Mail" alone does not say
	// what will be read.
	for _, c := range offered {
		if c.ID == "" || c.Label == "" || c.Says == "" || c.Policy == "" {
			t.Errorf("the %q row is incomplete: %+v", c.Label, c)
		}
		if !strings.Contains(page, c.Label) {
			t.Errorf("the console does not show the %s check", c.Label)
		}
	}
}

// The console never calls a run "full", "deep" or "active".
//
// docs/scope.md refuses those three words with an argument: each quietly
// authorises something this project has already declined to do, and the axis is
// named for whose network it is rather than for how hard the tool pushes. A
// control labelled "Full scan" would undo that argument in the one place a user
// actually looks.
func TestTheConsoleDoesNotPromiseMoreThanItDoes(t *testing.T) {
	page := strings.ToLower(consoleAs(t, false))

	for _, word := range []string{"full scan", "deep scan", "active scan", "penetration"} {
		if strings.Contains(page, word) {
			t.Errorf("the console offers a %q. docs/scope.md refuses that word, and the reason "+
				"is that it authorises something this tool does not do.", word)
		}
	}
}
