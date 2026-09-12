package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
	"github.com/denyfirst/denyfirst/internal/webscan"
)

func TestAnUnknownCheckIsRefused(t *testing.T) {
	// A typo has to be an error rather than a silent fall back to the
	// default. `-check wbe` running the TLS check and exiting zero is a
	// pipeline that believes it is testing something it has never tested.
	if err := checkKnown("wbe"); err == nil {
		t.Fatal("an unknown check was accepted")
	}
	if err := checkKnown(""); err == nil {
		t.Fatal("an empty check was accepted")
	}
	for _, ok := range []string{checkTLS, checkWeb, checkMail} {
		if err := checkKnown(ok); err != nil {
			t.Errorf("checkKnown(%q) = %v", ok, err)
		}
	}
}

func TestTheDefaultCheckIsTheOneThatHasAlwaysRun(t *testing.T) {
	// Changing this default would change the exit status of a pipeline
	// nobody touched: the status is the worst verdict found, and a second
	// check can find something the first never looked for. That is the same
	// argument as versioning the rules, one level up, and it is worth a test
	// because the change is one word.
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `flag.String("check", checkTLS,`) {
		t.Error("the default check is no longer checkTLS")
	}
}

func TestLimitsFollowTheCheckBeingRun(t *testing.T) {
	// Written because a sabotage escaped on 2026-09-04: -limits under
	// -check web printed the TLS limits and sent the reader to the TLS
	// method page, which would tell them cipher suites had been considered.
	web, webPage := limitsFor(checkWeb)
	tls, tlsPage := limitsFor(checkTLS)

	if webPage != webMethodPage || tlsPage != tlsMethodPage {
		t.Fatalf("pages are crossed: web=%q tls=%q", webPage, tlsPage)
	}
	if len(web) == 0 || len(tls) == 0 {
		t.Fatal("one of the checks declares no limits")
	}
	for _, a := range web {
		for _, b := range tls {
			if a.ID == b.ID {
				t.Errorf("%s appears in both sets", a.ID)
			}
		}
	}

	// And the rendering follows the selection, not just the selection itself.
	var buf bytes.Buffer
	printLimits(&buf, web, webPage)
	for _, l := range web {
		if !strings.Contains(buf.String(), l.Title) {
			t.Errorf("-check web -limits omits %q", l.ID)
		}
	}
	for _, l := range tls {
		if strings.Contains(buf.String(), l.Title) {
			t.Errorf("-check web -limits printed the TLS limit %q", l.ID)
		}
	}
}

func TestTheVersionNamesEveryRuleSet(t *testing.T) {
	// This binary carries three, and a reader holding one report cannot tell
	// which produced it from the release number.
	line := versionLine()
	for _, want := range []string{version, policy.TLSVersion, policy.WebVersion, policy.MailVersion} {
		if !strings.Contains(line, want) {
			t.Errorf("-version does not name %q:\n%s", want, line)
		}
	}
}

// webReport renders one result for the assertions below.
func webReport(t *testing.T, r webResult) string {
	t.Helper()
	var b bytes.Buffer
	printWebReport(&b, r)
	return b.String()
}

func sample() webResult {
	observed := &webprobe.Report{
		Host: "example.test",
		Secure: &webprobe.Chain{Hops: []webprobe.Hop{
			{URL: "https://example.test:443/", TLS: true, Status: 200},
		}},
		Plain: &webprobe.Chain{Hops: []webprobe.Hop{
			{URL: "http://example.test:80/", Status: 200},
		}},
	}
	return webResult{Result: webscan.Grade(observed), Host: "example.test"}
}

func TestTheWebReportShowsWhatWasRequestedAndWhatAnswered(t *testing.T) {
	// The evidence, not a summary of it. A reader who disagrees with a
	// verdict about redirects needs the redirects, and this is the one part
	// of the report that cannot be reconstructed from the findings.
	text := webReport(t, sample())
	for _, want := range []string{
		"Over TLS", "https://example.test:443/",
		"Over plaintext", "http://example.test:80/",
		"insecure", "reach.plaintext-served", "hsts.absent",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not carry %q:\n%s", want, text)
		}
	}
}

func TestTheWebReportPointsAtItsOwnMethodPage(t *testing.T) {
	// The limits of a header check are not the limits of a TLS scan, and a
	// report that sent its reader to the wrong page would tell them cipher
	// suites had been considered.
	text := webReport(t, sample())
	if !strings.Contains(text, webMethodPage) {
		t.Errorf("the report does not point at %s:\n%s", webMethodPage, text)
	}
	if strings.Contains(text, tlsMethodPage) {
		t.Errorf("the report points at the TLS method page:\n%s", text)
	}
}

func TestTheWebReportNamesTheWebRuleSet(t *testing.T) {
	text := webReport(t, sample())
	if !strings.Contains(text, policy.WebVersion) {
		t.Errorf("the report does not name %q:\n%s", policy.WebVersion, text)
	}
	if strings.Contains(text, policy.TLSVersion) {
		t.Errorf("the report names the TLS rule set:\n%s", text)
	}
}

func TestTheWebReportPrintsNoStandingLimitInFull(t *testing.T) {
	// Named and counted, not repeated. A limit printed on every report is a
	// limit nobody reads, and under a heading beside a host's own
	// shortcomings it reads as though it were one.
	text := webReport(t, sample())
	for _, l := range policy.WebStandingLimits() {
		if strings.Contains(text, l.Text) {
			t.Errorf("the standing limit %q is printed in full", l.ID)
		}
	}
	if !strings.Contains(text, "Limits of this method") {
		t.Errorf("the report does not say the limits exist:\n%s", text)
	}
}

func TestAFailedWebScanPrintsTheReasonAndNothingElse(t *testing.T) {
	text := webReport(t, webResult{Host: "example.test", Error: "webprobe: target must be a bare hostname"})
	if !strings.Contains(text, "scan failed") || !strings.Contains(text, "bare hostname") {
		t.Errorf("the failure is not explained:\n%s", text)
	}
	if strings.Contains(text, "Verdict") {
		t.Errorf("a failed scan printed a verdict:\n%s", text)
	}
}

func TestWebOutcomesCarryTheVerdictAndTheFailure(t *testing.T) {
	// One decision function serves both checks, so what it is handed has to
	// mean the same thing from both.
	got := webOutcomes([]webResult{
		sample(),
		{Host: "nope.test", Error: "refused"},
	})
	if len(got) != 2 {
		t.Fatalf("got %d outcomes", len(got))
	}
	if got[0].Verdict != policy.Insecure || got[0].Failed {
		t.Errorf("a graded result became %+v", got[0])
	}
	if !got[1].Failed {
		t.Errorf("a failed scan became %+v", got[1])
	}
	if exitCode(got) != exitError {
		t.Error("a failed scan did not decide the status")
	}
}

// The command line reads the page.
//
// Asserted because the alternative is a field that is set, documented and
// handed to nothing — which has happened twice in this repository, and which a
// sabotage found again here on 2026-09-11 by turning this off and watching
// every test pass.
func TestTheCommandLineReadsThePage(t *testing.T) {
	s := webScanner(5*time.Second, false)
	if !s.ReadMarkup {
		t.Error("the command line does not read the page. It runs on the operator's own machine, " +
			"from their own address, and the report goes to whoever ran it — there is nobody " +
			"else for the restriction to protect.")
	}

	// And -allow-private does not quietly change it. The two switches answer
	// different questions and neither is the other's default.
	if !webScanner(5*time.Second, true).ReadMarkup {
		t.Error("-allow-private turned off reading the page")
	}
}

// -allow-private reaches the dialler, and nothing else does.
func TestPrivateAddressesReachTheWebProberOnlyWhenAsked(t *testing.T) {
	if webScanner(5*time.Second, false).Prober.Dial != nil {
		t.Error("a dialler was installed without -allow-private, which is how the refusal of " +
			"private addresses stops being the default")
	}
	if webScanner(5*time.Second, true).Prober.Dial == nil {
		t.Error("-allow-private was asked for and no dialler was installed, so the flag does nothing")
	}
}

// This binary says which hosts it will connect to, like the other one.
//
// porchd said and this did not, which made the deploy check's whole argument —
// read what a binary claims rather than trusting a filename — true of one of
// the two programs this project ships. A demonstration build of this command
// exists and is what scripts/build.sh produces under the tag; somebody holding
// one had no way to find out that it refuses every host but ours, and would
// read the refusal as a fault in their own configuration.
func TestTheVersionSaysWhichHostsThisBinaryWillReach(t *testing.T) {
	line := reach()
	if strings.TrimSpace(line) == "" {
		t.Fatal("this binary says nothing about which hosts it will reach")
	}
	if !strings.Contains(versionLine(), line) {
		t.Errorf("-version does not carry the reach line:\n%s", versionLine())
	}

	if demo.Enabled {
		if !strings.HasPrefix(line, "demonstration: ") {
			t.Errorf("a demonstration build says %q", line)
		}
		for _, host := range demo.Targets() {
			if !strings.Contains(line, host) {
				t.Errorf("the binary reaches %s and does not say so: %q", host, line)
			}
		}
		return
	}

	if strings.HasPrefix(line, "demonstration") {
		t.Errorf("the ordinary build calls itself a demonstration: %q", line)
	}
	if !strings.Contains(line, "whatever it is pointed at") {
		t.Errorf("the ordinary build does not say it is unrestricted: %q", line)
	}

	// And it says where the scan leaves from, which is the difference between
	// this program and the service. docs/scope.md rests on it: whoever runs
	// this already has the machine, and the scan is theirs rather than
	// laundered through somebody else's.
	if !strings.Contains(line, "from this machine") {
		t.Errorf("the line does not say the scan leaves from the operator's own machine: %q", line)
	}
}
