package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
	"github.com/denyfirst/denyfirst/internal/webscan"
)

// The checks this command can run, spelled once.
const (
	checkTLS = "tls"
	checkWeb = "web"
)

// checkKnown refuses a check nobody wrote.
//
// A typo has to be an error rather than a silent fall back to the default.
// `-check wbe` running the TLS check and exiting zero is a pipeline that
// believes it is testing something it has never tested.
func checkKnown(name string) error {
	switch name {
	case checkTLS, checkWeb:
		return nil
	}
	return fmt.Errorf("unknown check %q: it is %s or %s", name, checkTLS, checkWeb)
}

// limitsFor selects the limits of the check being run, and the page that
// explains them.
//
// A function rather than a branch inside run(), because a branch inside run()
// is a branch nothing can reach: -limits under -check web printed the TLS
// limits and pointed at the TLS method page, and a sabotage saying so escaped
// every test in this package.
func limitsFor(check string) ([]policy.StandingLimit, string) {
	if check == checkWeb {
		return policy.WebStandingLimits(), webMethodPage
	}
	return policy.StandingLimits(), tlsMethodPage
}

// webResult is one host, with room for the reason it could not be measured.
type webResult struct {
	*webscan.Result
	Host  string `json:"host"`
	Error string `json:"error,omitempty"`
}

// runWeb measures how each target is reached over HTTP.
func runWeb(ctx context.Context, targets []string, timeout time.Duration, allowPrivate, asJSON bool) int {
	scanner := &webscan.Scanner{
		Prober: &webprobe.Prober{TotalTimeout: timeout},
	}
	if allowPrivate {
		// The same deliberate opt-out the TLS check offers, and for the same
		// reason: an operator checking their own network is not the abuse the
		// guard exists for. It runs on their machine, from their address. The
		// service has no equivalent switch and will not be given one.
		d := &net.Dialer{Timeout: timeout}
		scanner.Prober.Dial = d.DialContext
	}

	results := make([]webResult, 0, len(targets))
	for _, target := range targets {
		r := webResult{Host: target}
		out, err := scanner.Scan(ctx, target)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Result = out
		}
		results = append(results, r)

		if !asJSON {
			printWebReport(os.Stdout, r)
		}
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "encoding output: %v\n", err)
			return exitError
		}
	}

	return exitCode(webOutcomes(results))
}

func webOutcomes(results []webResult) []outcome {
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

// printWebReport renders one host.
//
// The findings and the notes go through the same two functions the TLS report
// uses. A second pair composing the same claims from the same facts is how
// two faces of one report drift apart, and this project has caught that
// happening twice already.
func printWebReport(w io.Writer, r webResult) {
	fmt.Fprintf(w, "\n%s\n%s\n", r.Host, strings.Repeat("=", len(r.Host)))

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

	printChains(w, r)
	printFindings(w, r.Findings)
	printNotes(w, r.Notes, webMethodPage)

	fmt.Fprintf(w, "\n  Completed in %s\n", r.Duration.Round(time.Millisecond))
}

// printChains shows what was actually requested and what answered.
//
// The evidence, not a summary of it. A reader who disagrees with a verdict
// about redirects needs the redirects, and this is the one part of the report
// that cannot be reconstructed from the findings.
func printChains(w io.Writer, r webResult) {
	if r.Observed == nil {
		return
	}
	for _, c := range []struct {
		heading string
		chain   *webprobe.Chain
	}{
		{"Over TLS", r.Observed.Secure},
		{"Over plaintext", r.Observed.Plain},
	} {
		if c.chain == nil || len(c.chain.Hops) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  %s\n", c.heading)
		for _, h := range c.chain.Hops {
			switch {
			case h.Err != "":
				fmt.Fprintf(w, "    %s\n      no answer: %s\n", h.URL, h.Err)
			default:
				fmt.Fprintf(w, "    %d  %s\n", h.Status, h.URL)
				if loc := h.Headers["Location"]; len(loc) > 0 {
					fmt.Fprintf(w, "         -> %s\n", loc[0])
				}
			}
		}
		if c.chain.Truncated {
			fmt.Fprintf(w, "    (the chain was still redirecting when the limit was reached)\n")
		}
		if c.chain.Stopped != "" {
			fmt.Fprintf(w, "    (%s)\n", c.chain.Stopped)
		}
	}
}
