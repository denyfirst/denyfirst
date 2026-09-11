package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/mailscan"
	"github.com/denyfirst/denyfirst/internal/policy"
)

// mailResult is one domain, with room for the reason it could not be measured.
type mailResult struct {
	*mailscan.Result
	Domain string `json:"domain"`
	Error  string `json:"error,omitempty"`
}

// runMail reads what each domain's DNS says about its mail.
//
// No -allow-private here and none to add: this check opens no connection at
// all, so there is no dialler to relax and nothing an operator could be asking
// for by relaxing one.
func runMail(ctx context.Context, domains []string, timeout time.Duration, resolver string, asJSON bool) int {
	scanner := &mailscan.Scanner{}
	if resolver != "" {
		scanner.Resolver = &dnsclient.Client{Server: resolver, Timeout: timeout}
	}

	results := make([]mailResult, 0, len(domains))
	for _, domain := range domains {
		r := mailResult{Domain: domain}

		out, err := scanner.Scan(ctx, domain)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Result = out
		}
		results = append(results, r)
	}

	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "writing JSON: %v\n", err)
			return exitError
		}
	} else {
		for i, r := range results {
			if i > 0 {
				fmt.Println()
			}
			printMail(os.Stdout, r)
		}
	}

	return exitCode(mailOutcomes(results))
}

// printMail writes one domain's report.
func printMail(w io.Writer, r mailResult) {
	fmt.Fprintf(w, "\n%s\n%s\n", r.Domain, strings.Repeat("=", len(r.Domain)))

	if r.Error != "" {
		fmt.Fprintf(w, "\n  scan failed: %s\n", r.Error)
		return
	}

	verdict := string(r.Verdict)
	if verdict == "" {
		verdict = "ungraded (nothing was found wrong, and nothing was established)"
	}
	fmt.Fprintf(w, "\n  Verdict   %s\n", verdict)
	if r.Verdict == policy.Weak || r.Verdict == policy.Insecure {
		fmt.Fprintf(w, "            %s\n", wrap(policy.WorstCase, 66, "            "))
	}
	fmt.Fprintf(w, "  Policy    %s\n", r.Policy)

	if f := r.Observed; f != nil {
		fmt.Fprintf(w, "\n  Sender policy\n")
		switch {
		case f.SPFReason != "":
			fmt.Fprintf(w, "    SPF        not read: %s\n", f.SPFReason)
		case f.SPFRecords == 0:
			fmt.Fprintf(w, "    SPF        none published\n")
		case f.SPFRecords > 1:
			fmt.Fprintf(w, "    SPF        %d records, which is a permanent error\n", f.SPFRecords)
		default:
			fmt.Fprintf(w, "    SPF        ends in %sall, %d of the ten lookups allowed\n",
				allOrNone(f.SPFAll), f.SPFLookups)
		}

		fmt.Fprintf(w, "\n  Authentication policy\n")
		switch {
		case f.DMARCReason != "":
			fmt.Fprintf(w, "    DMARC      not read: %s\n", f.DMARCReason)
		case f.DMARCRecords == 0:
			fmt.Fprintf(w, "    DMARC      none published\n")
		case f.DMARCRecords > 1:
			fmt.Fprintf(w, "    DMARC      %d records, so a receiver applies none\n", f.DMARCRecords)
		case f.DMARCPolicy == "":
			fmt.Fprintf(w, "    DMARC      published, and names no policy\n")
		default:
			fmt.Fprintf(w, "    DMARC      p=%s at %d%%\n", f.DMARCPolicy, f.DMARCPercent)
		}

		reporting := "no"
		if f.TLSReporting {
			reporting = "yes"
		}
		fmt.Fprintf(w, "    TLS-RPT    %s\n", reporting)
	}

	printFindings(w, r.Findings)
	printNotes(w, r.Notes, mailMethodPage)
}

// allOrNone writes the qualifier a record ends with, or says it has none.
func allOrNone(qualifier string) string {
	if qualifier == "" {
		return "no "
	}
	return qualifier
}

// mailOutcomes collects what each domain was graded, for the exit status.
//
// The same shape the other two checks use, through the same exitCode: a
// pipeline gated on this command should not have to learn a third set of
// numbers because a third check exists.
func mailOutcomes(results []mailResult) []outcome {
	out := make([]outcome, 0, len(results))
	for _, r := range results {
		o := outcome{Failed: r.Error != ""}
		if r.Result != nil {
			o.Verdict = r.Verdict
		}
		out = append(out, o)
	}
	return out
}
