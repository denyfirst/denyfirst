package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/results"
)

// keep records one scan, where the operator asked for records to be kept.
//
// A failure is reported and never fatal. The scan already happened and the
// report is already in front of them; losing the copy is worth a line on stderr
// and is not worth failing a check that succeeded.
func keep(store *results.Store, check, target string, verdict policy.Verdict, ruleSet string, findings []policy.Finding) {
	if !store.Enabled() {
		return
	}

	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}

	if err := store.Put(check, target, string(verdict), ruleSet, ids); err != nil {
		fmt.Fprintf(os.Stderr, "the result was not kept: %v\n", err)
	}
}

// printHistory answers -history: what this machine has kept for one target.
//
// Read from disk and nothing else. Nothing is scanned, nothing is resolved, and
// no connection is made — this is the operator looking at their own notes, and
// a command that quietly reached the network to answer it would be doing
// something they did not ask for.
func printHistory(w io.Writer, store *results.Store, check string, targets []string) int {
	if !store.Enabled() {
		fmt.Fprintf(os.Stderr, "nothing is kept: -history reads what -results-dir wrote, and no "+
			"directory was given\n")
		return exitError
	}

	for i, target := range targets {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "\n%s\n%s\n", target, strings.Repeat("=", len(target)))

		records, err := store.History(check, target)
		if err != nil {
			fmt.Fprintf(w, "\n  the history could not be read: %v\n", err)
			return exitError
		}

		// Nothing kept and never scanned are the same file on disk, so the
		// sentence says both rather than picking one (R4).
		if len(records) == 0 {
			fmt.Fprintf(w, "\n  No %s scan of this target has been kept here.\n", check)
			continue
		}

		fmt.Fprintf(w, "\n  %-12s %-10s %s\n", "DATE", "VERDICT", "FINDINGS")
		for _, r := range records {
			verdict := r.Verdict
			if verdict == "" {
				verdict = "ungraded"
			}

			findings := "none"
			if len(r.Findings) > 0 {
				findings = strings.Join(r.Findings, ", ")
			}
			fmt.Fprintf(w, "  %-12s %-10s %s\n", r.Date, verdict, findings)
		}

		printRuleSetBreaks(w, records)
	}

	return exitOK
}

// printRuleSetBreaks says where in a history the rules changed.
//
// The one thing that makes two rows incomparable, and the one a reader would
// otherwise not think to check. A server that went from strong to weak because
// a rule got stricter has not changed at all, and a history that presented the
// two rows side by side without saying so would be handing somebody a reason to
// go looking for a change that never happened.
func printRuleSetBreaks(w io.Writer, records []results.Record) {
	var breaks []string
	for i := 1; i < len(records); i++ {
		if records[i].Policy != records[i-1].Policy {
			breaks = append(breaks, fmt.Sprintf("%s: %s became %s",
				records[i].Date, records[i-1].Policy, records[i].Policy))
		}
	}
	if len(breaks) == 0 {
		fmt.Fprintf(w, "\n  All graded by %s.\n", records[len(records)-1].Policy)
		return
	}

	fmt.Fprintf(w, "\n  The rules changed during this history, so rows on either side of a\n")
	fmt.Fprintf(w, "  change are not comparable:\n")
	for _, b := range breaks {
		fmt.Fprintf(w, "    · %s\n", b)
	}
	fmt.Fprintf(w, "  What changed is in docs/policy-changes.md.\n")
}

// historyName is the name a target's history is filed under.
//
// The TLS check takes host:port, and a colon is not a filename character on
// every platform this ships to. Host and port are kept apart rather than the
// port dropped: scanning one host on two ports is two different measurements —
// the service's own per-target budget says so — and folding them into one
// history would interleave two servers' verdicts under one name.
func historyName(target string) string {
	return strings.ReplaceAll(target, ":", "_")
}
