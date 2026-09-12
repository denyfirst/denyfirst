package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/results"
	"github.com/denyfirst/denyfirst/internal/scan"
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

		records, err := store.History(check, historyName(check, target))
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

// historyName is the name a target's history is filed under, for one check.
//
// One function for writing and for reading, because the two disagreed the first
// time they were written separately. A scan of the TLS check files under
// host_port — the port comes from the scan, which fills in the default — while
// -history passed its argument through untouched and looked for the bare host.
// Everything worked for the web and mail checks, which have no port, so the
// defect was invisible until somebody read a TLS history back. Found by running
// it rather than by any test, which is why the test below asserts that the two
// agree rather than asserting two literals.
//
// Host and port are kept apart rather than the port dropped: scanning one host
// on two ports is two different measurements — the service's own per-target
// budget says so in the same words — and folding them into one history would
// interleave two servers' verdicts under one name. A colon is not a filename
// character on every platform this ships to, so the separator is not one.
//
// Only the TLS check has a port. The other two take a bare name, and giving
// them a default one would file a history under a port nothing measured.
func historyName(check, target string) string {
	if check != checkTLS {
		return strings.TrimSpace(target)
	}

	host, port, _, err := scan.SplitTargetPort(target)
	if err != nil {
		// Not this function's error to report. Whatever is wrong with the
		// target will be said by the scan or by the store, in words about the
		// rule that was broken rather than about a filename.
		return strings.ReplaceAll(strings.TrimSpace(target), ":", "_")
	}
	return host + "_" + port
}
