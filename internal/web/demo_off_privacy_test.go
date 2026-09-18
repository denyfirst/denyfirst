//go:build !demo

package web

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/httpapi"
)

// privacyAs renders the served privacy page for one configuration and puts the
// package back as it found it.
func privacyAs(t *testing.T, verified, keeps bool) string {
	t.Helper()
	before, beforeConsole := rendered["/privacy"], rendered["/"]
	t.Cleanup(func() { rendered["/privacy"], rendered["/"] = before, beforeConsole })

	Configure(verified, keeps, false)
	return flatten(get(t, "/privacy").Body.String())
}

// An installation somebody runs says what that installation does.
//
// Until the 2026-09-16 audit (A21) it served the demonstration's page, which
// described a rented server in Frankfurt, an abuse address at this project,
// and a scan that asks no authority anything — none of it true of a copy
// somebody else runs, and the last untrue of every one of them.
func TestASelfHostedCopySaysWhatItDoes(t *testing.T) {
	for _, page := range []string{privacyAs(t, false, false), privacyAs(t, true, true)} {
		for _, never := range []string{"denyfirst.dev", "rented server", "Frankfurt", "no certificate authority is asked"} {
			if strings.Contains(page, never) {
				t.Errorf("the self-hosted page says %q", never)
			}
		}
		for _, want := range []string{
			"What this installation keeps", "three minutes", "revocation list",
			"The DNS resolver", "No record of requests", "without warranty",
			"at least " + strconv.Itoa(httpapi.TargetThreshold()) + " scans",
		} {
			if !strings.Contains(page, want) {
				t.Errorf("the self-hosted page does not say %q", want)
			}
		}
		for _, anchor := range []string{"kept", "scans", "stopping", "promises"} {
			if !strings.Contains(page, `id="`+anchor+`"`) || !strings.Contains(page, `href="#`+anchor+`"`) {
				t.Errorf("the self-hosted page has no section #%s", anchor)
			}
		}
	}
}

// What it says follows how it was started, in both directions.
func TestTheSelfHostedPrivacyPageFollowsTheConfiguration(t *testing.T) {
	open := privacyAs(t, false, false)
	bounded := privacyAs(t, true, true)

	for name, c := range map[string]struct {
		open, bounded string
	}{
		"results":   {"not kept. Close the page", "kept on this machine"},
		"proof":     {"checks any public name it is given", "Only names whose domain publishes"},
		"pages":     {"No page body is read", "The final page is read"},
		"exchanger": {"No mail server is contacted", "asks each mail exchanger on port 25"},
		"secret":    {"", "A verification secret"},
		"file":      {"", "/.well-known/porch-challenge"},
	} {
		if c.open != "" && (!strings.Contains(open, c.open) || strings.Contains(bounded, c.open)) {
			t.Errorf("%s: an open installation does not say %q, or a bounded one does", name, c.open)
		}
		if !strings.Contains(bounded, c.bounded) || strings.Contains(open, c.bounded) {
			t.Errorf("%s: a bounded installation does not say %q, or an open one does", name, c.bounded)
		}
	}
}

// The retention the page states is the one the code holds.
func TestTheSelfHostedPageStatesTheRealRetentionPeriod(t *testing.T) {
	if got := httpapi.DefaultRetentionPeriod().Round(time.Minute); got != 3*time.Minute {
		t.Errorf("the page says three minutes and the defaults hold an address for %v", got)
	}
}
