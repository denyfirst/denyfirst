// Command denyfirst-scan inspects a server's TLS configuration and
// certificate chain from the command line.
//
// It exists to exercise the whole pipeline against real servers. The library
// packages are tested against certificates generated in memory, which proves
// the logic but not the plumbing; this proves the plumbing.
//
// Usage:
//
//	denyfirst-scan example.com
//	denyfirst-scan example.com:8443 another.example
//	denyfirst-scan -json example.com
//	denyfirst-scan -allow-private 10.0.0.5
//
// Exit status is the worst verdict found, so the command can gate a pipeline:
// 0 when everything is strong, 1 on a weak finding, 2 on an insecure one, and
// 3 when the scan itself could not be completed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/denyfirst/denyfirst/internal/certinfo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

const (
	exitOK       = 0
	exitWeak     = 1
	exitInsecure = 2
	exitError    = 3
)

func main() {
	os.Exit(run())
}

// result pairs a scan with the error that prevented it, so one failed target
// does not stop the rest.
type result struct {
	*scan.Result
	Error string `json:"error,omitempty"`
}

func run() int {
	var (
		asJSON       = flag.Bool("json", false, "emit the report as JSON")
		timeout      = flag.Duration("timeout", 30*time.Second, "budget for one target")
		allowPrivate = flag.Bool("allow-private", false,
			"permit private, loopback and link-local addresses; off by default so a\n"+
				"\tmistyped or attacker-supplied name cannot be aimed at internal hosts")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "denyfirst-scan inspects TLS configuration and certificates.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags] host[:port] ...\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		return exitError
	}

	// Ctrl-C cancels in flight rather than leaving half-open connections.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner := &scan.Scanner{
		Prober: &tlsprobe.Prober{TotalTimeout: *timeout},
	}
	if *allowPrivate {
		// Deliberate opt-out of the SSRF guard. Reasonable for a local
		// operator scanning their own network; never reachable from the HTTP
		// service, which has no equivalent switch.
		d := &net.Dialer{Timeout: *timeout}
		scanner.Prober.Dial = d.DialContext
	}

	worst := policy.Ungraded
	results := make([]result, 0, len(targets))

	for _, target := range targets {
		r := runScan(ctx, scanner, target, *timeout)
		results = append(results, r)
		worst = policy.Worst(worst, r.Verdict)

		if !*asJSON {
			printReport(r)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "encoding output: %v\n", err)
			return exitError
		}
	}

	for _, r := range results {
		if r.Error != "" {
			return exitError
		}
	}

	switch worst {
	case policy.Insecure:
		return exitInsecure
	case policy.Weak:
		return exitWeak
	default:
		return exitOK
	}
}

func runScan(ctx context.Context, s *scan.Scanner, target string, timeout time.Duration) result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r, err := s.Scan(ctx, target)
	if err != nil {
		return result{Result: &scan.Result{Target: target}, Error: err.Error()}
	}
	return result{Result: r}
}

func printReport(r result) {
	fmt.Printf("\n%s\n%s\n", r.Target, strings.Repeat("=", len(r.Target)))

	if r.Error != "" {
		fmt.Printf("\n  scan failed: %s\n", r.Error)
		return
	}

	verdict := string(r.Verdict)
	if verdict == "" {
		verdict = "ungraded (nothing could be measured)"
	}
	fmt.Printf("\n  Verdict   %s\n", verdict)
	fmt.Printf("  Policy    %s\n", r.Policy)
	if r.TLS != nil && r.TLS.Address != "" {
		fmt.Printf("  Address   %s\n", r.TLS.Address)
	}

	printVersions(r.TLS)
	printCiphers(r.TLS)
	printCertificate(r.Certificate)
	printFindings(r)
	printNotes(r)

	if r.TLS != nil {
		fmt.Printf("\n  Completed in %s\n", r.TLS.Duration.Round(time.Millisecond))
	}
}

func printVersions(t *tlsprobe.Report) {
	if t == nil {
		return
	}

	fmt.Printf("\n  Protocol versions\n")
	for _, v := range t.Versions {
		switch {
		case v.Supported && v.Grade.Preferred:
			fmt.Printf("    %-9s accepted   %s, preferred\n", v.Name, v.Grade.Verdict)
		case v.Supported:
			fmt.Printf("    %-9s accepted   %s\n", v.Name, v.Grade.Verdict)
		default:
			fmt.Printf("    %-9s refused    %s\n", v.Name, v.Error)
		}
	}
}

func printCiphers(t *tlsprobe.Report) {
	if t == nil {
		return
	}

	for _, v := range t.Versions {
		if !v.Supported || len(v.Ciphers) == 0 {
			continue
		}
		fmt.Printf("\n  Cipher suites accepted at %s\n", v.Name)
		for _, c := range v.Ciphers {
			fmt.Printf("    %-9s %-48s %s / %s\n", c.Verdict, c.Name, c.KeyExchange, c.Cipher)
		}
	}

	if t.PreferenceKnown {
		if t.ServerPreference {
			fmt.Printf("\n  The server imposes its own cipher order.\n")
		} else {
			fmt.Printf("\n  The server follows the client's cipher order, which lets an outdated\n" +
				"  client steer the connection towards a weaker suite.\n")
		}
	}
}

func printCertificate(c *certinfo.Report) {
	if c == nil || len(c.Chain) == 0 {
		return
	}
	leaf := c.Chain[0]

	fmt.Printf("\n  Certificate\n")
	fmt.Printf("    Subject      %s\n", leaf.Subject)
	fmt.Printf("    Issuer       %s\n", leaf.Issuer)
	fmt.Printf("    Valid        %s to %s",
		leaf.NotBefore.UTC().Format(time.DateOnly),
		leaf.NotAfter.UTC().Format(time.DateOnly))

	if c.Grade.DaysRemaining >= 0 {
		fmt.Printf("  (%d days remaining)\n", c.Grade.DaysRemaining)
	} else {
		fmt.Printf("  (expired %d days ago)\n", -c.Grade.DaysRemaining)
	}

	fmt.Printf("    Lifetime     %d days, limit at issuance %d\n",
		c.Grade.ValidityDays, c.Grade.MaxValidityDays)

	if leaf.KeyBits > 0 {
		fmt.Printf("    Key          %s %d\n", leaf.KeyAlgorithm, leaf.KeyBits)
	} else {
		fmt.Printf("    Key          %s\n", leaf.KeyAlgorithm)
	}
	fmt.Printf("    Signature    %s\n", leaf.SignatureAlgorithm)

	if len(leaf.DNSNames) > 0 {
		fmt.Printf("    Names        %s\n", strings.Join(leaf.DNSNames, ", "))
	}
	if len(leaf.IPAddresses) > 0 {
		fmt.Printf("    Addresses    %s\n", strings.Join(leaf.IPAddresses, ", "))
	}

	fmt.Printf("    Fingerprint  %s\n", leaf.FingerprintSHA256)

	if c.Trusted {
		fmt.Printf("    Chain        %d certificate(s), trusted\n", len(c.Chain))
	} else {
		fmt.Printf("    Chain        %d certificate(s), not trusted: %s\n", len(c.Chain), c.VerifyError)
	}
}

func printFindings(r result) {
	findings := r.Findings()
	if len(findings) == 0 {
		fmt.Printf("\n  No findings.\n")
		return
	}

	fmt.Printf("\n  Findings\n")
	for _, f := range findings {
		fmt.Printf("\n    [%s] %s  (%s)\n", f.Verdict, f.Title, f.RuleID)
		fmt.Printf("      %s\n", wrap(f.Rationale, 72, "      "))
		for _, ref := range f.References {
			fmt.Printf("      · %s\n        %s\n", ref.Label, ref.URL)
		}
	}
}

func printNotes(r result) {
	notes := r.Notes()
	if len(notes) == 0 {
		return
	}

	fmt.Printf("\n  Notes\n")
	for _, n := range notes {
		fmt.Printf("    · %s\n", wrap(n, 70, "      "))
	}
}

// wrap breaks text at word boundaries so long rationales stay readable in a
// terminal without depending on a formatting library.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	var (
		b    strings.Builder
		line = words[0]
	)
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			b.WriteString(line)
			b.WriteString("\n")
			b.WriteString(indent)
			line = w
			continue
		}
		line += " " + w
	}
	b.WriteString(line)
	return b.String()
}
