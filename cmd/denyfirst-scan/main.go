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
//	denyfirst-scan 93.184.216.34
//
// Exit status is the worst verdict found, so the command can gate a pipeline:
// 0 when everything measured was strong, 1 on a weak finding, 2 on an insecure
// one, 3 when the scan itself could not be completed, and 4 when a scan
// finished but graded nothing.
//
// The fourth code is the one worth explaining. A verdict of ungraded is not a
// pass: it means no measurement survived to be graded, and the commonest way
// to reach it is a host that answers a handshake or two and then goes quiet,
// which is something the scanned host chooses. Folding that into 0 would let
// the party being gated turn the gate off, so it has a code of its own.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	exitUngraded = 4
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

		// A local operator scanning their own network is not the abuse the
		// port list guards against, so the command line lifts it. The HTTP
		// service has no equivalent switch.
		AllowAnyPort: true,

		// An operator checking their own server before its name resolves is
		// exactly the case the service refuses and this one should not. This
		// runs on their machine, from their address, so whatever they do is
		// theirs rather than laundered through somebody else's service.
		AllowIPTargets: true,
	}
	if *allowPrivate {
		// Deliberate opt-out of the SSRF guard. Reasonable for a local
		// operator scanning their own network; never reachable from the HTTP
		// service, which has no equivalent switch.
		d := &net.Dialer{Timeout: *timeout}
		scanner.Prober.Dial = d.DialContext
	}

	results := make([]result, 0, len(targets))

	for _, target := range targets {
		r := runScan(ctx, scanner, target, *timeout)
		results = append(results, r)

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

	return exitCode(results)
}

// exitCode turns a run into a status a shell can act on.
//
// Separate from run so it can be tested without a network, a flag set or a
// process. The decision it makes is the whole value of this command in a
// pipeline, and until this function existed nothing checked it.
//
// Most severe first, and ungraded above clean. policy.Worst deliberately
// ignores ungraded entries — aggregating grades has to skip the ones that are
// not grades — so a run of two targets, one strong and one ungraded, comes out
// of it as strong. Reading the status off that alone published a pass for a
// target nobody measured, and hid it behind one that was fine.
func exitCode(results []result) int {
	worst := policy.Ungraded
	ungraded := false

	for _, r := range results {
		if r.Error != "" {
			return exitError
		}
		worst = policy.Worst(worst, r.Verdict)
		if r.Verdict == policy.Ungraded {
			ungraded = true
		}
	}

	switch {
	case worst == policy.Insecure:
		return exitInsecure
	case worst == policy.Weak:
		return exitWeak
	case ungraded:
		// Nothing was found wrong and nothing was established either. A gate
		// that treats the two alike can be opened by whatever is behind it.
		return exitUngraded
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

	printVersions(os.Stdout, r.TLS)
	printCiphers(os.Stdout, r.TLS)
	printCertificate(r.Certificate)
	printFindings(r)
	printNotes(r)

	if r.TLS != nil {
		fmt.Printf("\n  Completed in %s\n", r.TLS.Duration.Round(time.Millisecond))
	}
}

// The writer is a parameter so a test can read what this prints. Until it
// was, nothing checked a single line of this command's output, which is the
// only thing most of its users ever see.
func printVersions(w io.Writer, t *tlsprobe.Report) {
	if t == nil {
		return
	}

	fmt.Fprintf(w, "\n  Protocol versions\n")
	for _, v := range t.Versions {
		switch {
		case v.Supported && v.Grade.Preferred:
			fmt.Fprintf(w, "    %-9s accepted       %s, preferred\n", v.Name, v.Grade.Verdict)
		case v.Supported:
			fmt.Fprintf(w, "    %-9s accepted       %s\n", v.Name, v.Grade.Verdict)
		case v.Refused:
			fmt.Fprintf(w, "    %-9s refused        %s\n", v.Name, v.Error)
		default:
			// Not "refused". The word is a claim about the server, and the
			// sentence printed beside it frequently said the opposite —
			// "refused    not tested: this build of Go declined to offer TLS
			// 1.0" was one line of output contradicting itself, and the
			// column is the half a reader takes in.
			fmt.Fprintf(w, "    %-9s not measured   %s\n", v.Name, v.Error)
		}
	}
}

func printCiphers(w io.Writer, t *tlsprobe.Report) {
	if t == nil {
		return
	}

	for _, v := range t.Versions {
		if !v.Supported || len(v.Ciphers) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  Cipher suites accepted at %s\n", v.Name)
		if !v.CipherListComplete {
			// Beside the list rather than only in the notes at the foot of
			// the report. A heading that says "accepted" over a list that
			// stopped early is read as the whole set, and the suites missing
			// from it are the weak ones: enumeration finds them strongest
			// first.
			fmt.Fprintf(w, "    (incomplete: the host stopped answering before the list ran out,\n"+
				"     so the weaker end of it was never reached)\n")
		}
		for _, c := range v.Ciphers {
			fmt.Fprintf(w, "    %-9s %-48s %s / %s\n", c.Verdict, c.Name, c.KeyExchange, c.Cipher)
		}
	}

	if t.PreferenceKnown {
		if t.ServerPreference {
			fmt.Fprintf(w, "\n  The server imposes its own cipher order.\n")
		} else {
			fmt.Fprintf(w, "\n  The server follows the client's cipher order, which lets an outdated\n"+
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
