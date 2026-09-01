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

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// version is the release this binary was built from, set by scripts/build.sh
// with -ldflags -X. An unset value means it was not built by that script.
//
// A binary cannot otherwise say what it is. -buildvcs=false is deliberate —
// the embedded VCS stamp varies with how the tree was fetched and would make
// two honest builds of one tag differ — and the tag in the filename is lost
// the moment somebody renames or packages the file. So an operator holding
// this program had no way to check whether it was the version that fixed
// anything, which for a tool people run to answer security questions is not a
// cosmetic gap.
//
// It is set from the tag rather than read from the filesystem, so it is
// covered by the hash in SHA256SUMS and cannot be edited without changing it.
var version = "(unknown: not built by scripts/build.sh)"

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

	showVersion := flag.Bool("version", false, "print the release and policy versions, then exit")

	// Needs no network and no page. A report names these and does not repeat
	// them; this is where somebody offline reads them in full.
	showLimits := flag.Bool("limits", false,
		"print the limits of this method — true of every scan — then exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "denyfirst-scan inspects TLS configuration and certificates.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags] host[:port] ...\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Both, because they answer different questions and neither implies the
	// other. The release says which build this is; the policy version says
	// which rules produced a verdict, and a verdict from one policy is not
	// comparable with a verdict from another.
	if *showVersion {
		fmt.Printf("denyfirst-scan %s\npolicy %s\n", version, policy.Version)
		return exitOK
	}

	if *showLimits {
		printLimits(os.Stdout)
		return exitOK
	}

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
			printReport(os.Stdout, r)
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

// The writer is a parameter for the reason printVersions gives below, and
// this is the function that made it worth doing: everything a person reading
// a terminal ever sees passes through here, and until a test could read it,
// three sentences were wrong at once and all three were found by a person
// looking at a live report rather than by anything in this repository.
func printReport(w io.Writer, r result) {
	fmt.Fprintf(w, "\n%s\n%s\n", r.Target, strings.Repeat("=", len(r.Target)))

	if r.Error != "" {
		fmt.Fprintf(w, "\n  scan failed: %s\n", r.Error)
		return
	}

	verdict := string(r.Verdict)
	if verdict == "" {
		verdict = "ungraded (nothing could be measured)"
	}
	fmt.Fprintf(w, "\n  Verdict   %s\n", verdict)
	fmt.Fprintf(w, "  Policy    %s\n", r.Policy)
	if r.TLS != nil && r.TLS.Address != "" {
		fmt.Fprintf(w, "  Address   %s\n", r.TLS.Address)
	}

	printVersions(w, r.TLS)
	printCiphers(w, r.TLS)

	// A property of the transport rather than of the certificate, so it sits
	// with the suites rather than with the chain. It is the one measurement
	// in this report that costs the scanned server an extra handshake.
	if r.KeyExchangeLine != "" {
		fmt.Fprintf(w, "\n  Key exchange  %s\n", wrap(r.KeyExchangeLine, 60, "                "))
	}

	printCertificate(w, r)
	printFindings(w, r)
	printAssurances(w, r)
	printNotes(w, r)

	if r.TLS != nil {
		fmt.Fprintf(w, "\n  Completed in %s\n", r.TLS.Duration.Round(time.Millisecond))
	}
}

// The writer is a parameter so a test can read what this prints. Until it
// was, nothing checked a single line of this command's output, which is the
// only thing most of its users ever see.
func printVersions(w io.Writer, t *tlsprobe.Report) {
	if t == nil {
		return
	}

	fmt.Fprint(w, "\n  Protocol versions\n")
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
			fmt.Fprint(w, "    (incomplete: the host stopped answering before the list ran out,\n"+
				"     so the weaker end of it was never reached)\n")
		}
		for _, c := range v.Ciphers {
			fmt.Fprintf(w, "    %-9s %-48s %s / %s\n", c.Verdict, c.Name, c.KeyExchange, c.Cipher)
		}
	}

	if t.PreferenceKnown {
		if t.ServerPreference {
			fmt.Fprint(w, "\n  The server imposes its own cipher order.\n")
		} else {
			fmt.Fprint(w, "\n  The server follows the client's cipher order, which lets an outdated\n"+
				"  client steer the connection towards a weaker suite.\n")
		}
	}
}

func printCertificate(w io.Writer, r result) {
	c := r.Certificate
	if c == nil || len(c.Chain) == 0 {
		return
	}
	leaf := c.Chain[0]

	fmt.Fprintf(w, "\n  Certificate\n")
	fmt.Fprintf(w, "    Subject      %s\n", leaf.Subject)
	fmt.Fprintf(w, "    Issuer       %s\n", leaf.Issuer)
	fmt.Fprintf(w, "    Valid        %s to %s",
		leaf.NotBefore.UTC().Format(time.DateOnly),
		leaf.NotAfter.UTC().Format(time.DateOnly))

	if c.Grade.DaysRemaining >= 0 {
		fmt.Fprintf(w, "  (%d days remaining)\n", c.Grade.DaysRemaining)
	} else {
		fmt.Fprintf(w, "  (expired %d days ago)\n", -c.Grade.DaysRemaining)
	}

	fmt.Fprintf(w, "    Lifetime     %d days, limit at issuance %d\n",
		c.Grade.ValidityDays, c.Grade.MaxValidityDays)

	if leaf.KeyBits > 0 {
		fmt.Fprintf(w, "    Key          %s %d\n", leaf.KeyAlgorithm, leaf.KeyBits)
	} else {
		fmt.Fprintf(w, "    Key          %s\n", leaf.KeyAlgorithm)
	}
	fmt.Fprintf(w, "    Signature    %s\n", leaf.SignatureAlgorithm)

	if len(leaf.DNSNames) > 0 {
		fmt.Fprintf(w, "    Names        %s\n", strings.Join(leaf.DNSNames, ", "))
	}
	if len(leaf.IPAddresses) > 0 {
		fmt.Fprintf(w, "    Addresses    %s\n", strings.Join(leaf.IPAddresses, ", "))
	}

	fmt.Fprintf(w, "    Fingerprint  %s\n", leaf.FingerprintSHA256)

	if c.Trusted {
		fmt.Fprintf(w, "    Chain        %d certificate(s), trusted\n", len(c.Chain))
	} else {
		fmt.Fprintf(w, "    Chain        %d certificate(s), not trusted: %s\n", len(c.Chain), c.VerifyError)
	}

	// The page has shown this since the row was added and this report never
	// has, so the answer to "who may issue for this name" reached a reader
	// with a browser and nobody at a terminal. It was not hidden in the notes
	// either: it was absent.
	//
	// The sentence is the one the policy package wrote, not one built here.
	// Two renderers composing the same claim from the same facts is how the
	// two come to say different things, which this whole file is now tested
	// against.
	// The same three lines the page shows, in the same order, from the same
	// strings. Two renderers composing one claim from the same facts is how
	// the two come to say different things, so neither builds a sentence here.
	if r.RevocationLine != "" {
		fmt.Fprintf(w, "    Revocation   %s\n", wrap(r.RevocationLine, 60, "                 "))
	}
	if r.Issuance != nil && r.Issuance.Line != "" {
		fmt.Fprintf(w, "    Issuance     %s\n", wrap(r.Issuance.Line, 60, "                 "))
	}
	if r.TransparencyLine != "" {
		fmt.Fprintf(w, "    Transparency %s\n", wrap(r.TransparencyLine, 60, "                 "))
	}
}

func printFindings(w io.Writer, r result) {
	findings := r.Findings()
	if len(findings) == 0 {
		fmt.Fprintf(w, "\n  No findings.\n")
		return
	}

	fmt.Fprintf(w, "\n  Findings\n")
	for _, f := range findings {
		fmt.Fprintf(w, "\n    [%s] %s  (%s)\n", f.Verdict, f.Title, f.RuleID)
		fmt.Fprintf(w, "      %s\n", wrap(f.Rationale, 72, "      "))
		for _, ref := range f.References {
			fmt.Fprintf(w, "      · %s\n        %s\n", ref.Label, ref.URL)
		}
	}
}

// noteSections is the order the three kinds are read in, and the words used
// for them. Both faces of the report take the order from here, because a
// reader comparing the two should not have to work out that they match.
//
// The order is deliberate: what was found, then what this host prevented, then
// what this program never claims. It used to be one heading — "What this did
// not measure" — over all three, which told a reader that a scan establishing
// a great deal had established nothing.
var noteSections = []struct {
	kind    policy.NoteKind
	heading string
}{
	{policy.KindObserved, "Observed"},
	{policy.KindUnsettled, "Not established for this host"},
}

// The third kind is not a section. A standing limit is the same on every
// report, so printing all four on every report is how they stop being read —
// and under a heading beside a host's own shortcomings they read as though
// they were some. They are named here and printed in full by -limits, which
// needs no network and no page.
const methodPage = "https://denyfirst.dev/method"

// printAssurances says what holds, after what fell short.
//
// Before this, a report on a well configured server described only rules
// unbroken and absences observed — the strongest thing it could say was
// "Nothing here fell short of the rules", which is two negatives. Every line
// below was measured and was already used to reach the verdict.
//
// It sits after the findings and not before them, which is the second half of
// the same argument. Measured on 2026-09-01: kapitalbank.az is insecure, and
// with this block first a reader met seven reassuring sentences before the
// reason for the verdict. The ordering is self-adjusting — where there are no
// findings this is the first prose on the report, which is exactly where it
// should be, and where there are findings the reason comes first.
func printAssurances(w io.Writer, r result) {
	if len(r.Assurances) == 0 {
		return
	}

	fmt.Fprintf(w, "\n  What holds\n")
	for _, a := range r.Assurances {
		fmt.Fprintf(w, "    · %s\n", wrap(a.Text, 70, "      "))
	}
}

func printNotes(w io.Writer, r result) {
	notes := r.Notes()
	for _, section := range noteSections {
		chosen := policy.NotesOfKind(notes, section.kind)
		if len(chosen) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  %s\n", section.heading)
		for _, n := range chosen {
			fmt.Fprintf(w, "    · %s\n", wrap(n.Text, 70, "      "))
		}
	}

	// Said rather than dropped. The count is the point: a reader has to know
	// there are limits and where they are, or leaving them off the report
	// would be hiding them rather than moving them.
	if standing := policy.NotesOfKind(notes, policy.KindStanding); len(standing) > 0 {
		fmt.Fprintf(w, "\n  Limits of this method\n")
		fmt.Fprintf(w, "    · %d apply to every scan and are the same here as anywhere.\n", len(standing))
		fmt.Fprintf(w, "      denyfirst-scan -limits, or %s\n", methodPage)
	}
}

// printLimits answers -limits: the standing limits in full, from the same
// declaration the reports and the page read.
func printLimits(w io.Writer) {
	fmt.Fprintf(w, "\nLimits of this method\n")
	fmt.Fprintf(w, "=====================\n\n")
	fmt.Fprintf(w, "  True of every scan this program runs, whatever server it looks at.\n")
	fmt.Fprintf(w, "  Read alongside %s\n", methodPage)

	for _, limit := range policy.StandingLimits() {
		fmt.Fprintf(w, "\n  %s\n", limit.Title)
		fmt.Fprintf(w, "    %s\n", wrap(limit.Text, 70, "    "))
	}
	fmt.Fprintln(w)
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
