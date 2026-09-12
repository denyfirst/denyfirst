package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/dkim"
	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/mailscan"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/results"
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
func runMail(ctx context.Context, domains []string, timeout time.Duration, resolver string, asJSON bool, store *results.Store, selectors []dkim.Selector) int {
	scanner := &mailscan.Scanner{DKIMSelectors: selectors}
	if resolver != "" {
		scanner.Resolver = &dnsclient.Client{Server: resolver, Timeout: timeout}
	}

	// reports rather than results: internal/results is the store, and a local
	// name shadowing a package is a name somebody later reads as the package.
	reports := make([]mailResult, 0, len(domains))
	for _, domain := range domains {
		r := mailResult{Domain: domain}

		measured, err := scanner.Scan(ctx, domain)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Result = measured
		}
		reports = append(reports, r)

		// Kept under the domain the scan reported rather than the string that
		// was typed. An address may be given and its local part is discarded
		// on arrival; keeping a history under what somebody pasted would put
		// the part that was dropped into a filename.
		if r.Result != nil {
			keep(store, checkMail, r.Domain, r.Verdict, r.Policy, r.Findings)
		}
	}

	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(reports); err != nil {
			fmt.Fprintf(os.Stderr, "writing JSON: %v\n", err)
			return exitError
		}
	} else {
		for i, r := range reports {
			if i > 0 {
				fmt.Println()
			}
			printMail(os.Stdout, r)
		}
	}

	return exitCode(mailOutcomes(reports))
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

		printMailPath(w, f)
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

// printMailPath shows where the domain's mail goes and what protects it there.
//
// Three states kept apart in every line, because the difference between them is
// the whole value: a domain with no DANE, a domain whose DANE could not be read,
// and a domain that accepts no mail at all are three answers a reader would act
// on differently.
func printMailPath(w io.Writer, f *policy.MailFacts) {
	fmt.Fprintf(w, "\n  Mail path\n")

	switch {
	case f.MXReason != "":
		fmt.Fprintf(w, "    MX         not read: %s\n", f.MXReason)
		return
	case f.NullMX:
		fmt.Fprintf(w, "    MX         null MX: the domain accepts no mail\n")
		return
	case !f.MXRead:
		fmt.Fprintf(w, "    MX         not read\n")
		return
	case len(f.MXHosts) == 0:
		fmt.Fprintf(w, "    MX         none published\n")
	default:
		fmt.Fprintf(w, "    MX         %s\n", strings.Join(f.MXHosts, ", "))
	}

	sts := "no"
	if f.MTASTSRecords > 0 {
		sts = "announced; the policy itself was not fetched"
	}
	fmt.Fprintf(w, "    MTA-STS    %s\n", sts)

	switch {
	case len(f.MXHosts) == 0:
	case len(f.DANEHosts) == 0:
		fmt.Fprintf(w, "    DANE       none of the %d\n", len(f.MXHosts))
	case len(f.DANEHosts) == len(f.MXHosts):
		fmt.Fprintf(w, "    DANE       all %d\n", len(f.MXHosts))
	default:
		fmt.Fprintf(w, "    DANE       %d of the %d: %s\n",
			len(f.DANEHosts), len(f.MXHosts), strings.Join(f.DANEHosts, ", "))
	}

	if f.DANEUnread > 0 {
		fmt.Fprintf(w, "               %d could not be read\n", f.DANEUnread)
	}
}

// selectorsFrom builds the list of names to look for DKIM keys under.
//
// The operator's own come first, because they are the authoritative answer and
// the bound on how many names one scan asks about is small. A provider's
// documented defaults are added only when asked for: they are a convenience,
// and a scan that quietly tried ten names nobody mentioned would be reporting
// on a list this program chose.
func selectorsFrom(named string, common bool) []dkim.Selector {
	out := dkim.Named(named)
	if common {
		out = append(out, dkim.DocumentedSelectors()...)
	}
	return out
}
