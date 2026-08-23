package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/httpapi"
)

// The privacy page states how long a client address is held. That number was
// written once and checked by nobody, while the flags that decide it sit on
// the same command line as everything else.
//
// This is the argument the PGP fingerprint already makes in this package: two
// sources that agree only because nobody compares them are one source written
// twice. Change the defaults and this fails; change the sentence and this
// fails. Either failure is a reminder to make the other change, which is the
// only reliable way a page and a program stay in step.
func TestPrivacyPageStatesTheRealRetentionPeriod(t *testing.T) {
	const stated = "dropped about three minutes"
	const statedMinutes = 3

	body, err := assets.ReadFile("assets/privacy.html")
	if err != nil {
		t.Fatalf("reading the privacy page: %v", err)
	}
	if !strings.Contains(string(body), stated) {
		t.Fatalf("the privacy page no longer contains %q. If the wording changed, change the "+
			"figure in this test with it; if the period changed, the page has to say so.", stated)
	}

	got := httpapi.DefaultRetentionPeriod()
	want := time.Duration(statedMinutes) * time.Minute
	if got.Round(time.Minute) != want {
		t.Errorf("the page says %q but the defaults hold an address for %v. One of them is now "+
			"wrong, and it is the page a reader believes.", stated, got)
	}
}

// The same argument, applied to the other number on that page.
//
// The privacy page states the threshold at which the per-target limit begins
// refusing, and it is the only figure there from which a reader could work out
// anything about what somebody else has been doing: being refused means that
// many scans of that host have already happened. The page says eight. The
// constant said two until 2026-08-20, and moving it was a deliberate privacy
// decision — precisely the kind of change whose whole value is that the page
// explaining it is right.
//
// A page that overstates the threshold tells a reader they are safer than they
// are. One that understates it discredits the page. Neither is discoverable by
// reading either file alone.
func TestPrivacyPageStatesTheRealTargetThreshold(t *testing.T) {
	const stated = "at least eight times"
	const statedScans = 8

	body, err := assets.ReadFile("assets/privacy.html")
	if err != nil {
		t.Fatalf("reading the privacy page: %v", err)
	}
	if !strings.Contains(string(body), stated) {
		t.Fatalf("the privacy page no longer contains %q. If the wording changed, change the "+
			"figure in this test with it; if the threshold changed, the page has to say so.", stated)
	}

	if got := httpapi.TargetThreshold(); got != statedScans {
		t.Errorf("the page says %q but the limit refuses after %d. One of them is now wrong, "+
			"and it is the page a reader believes.", stated, got)
	}
}

// The claim on that page is not "we throw addresses away eventually". It is a
// number, so the number has to be one a person would recognise as short.
func TestRetentionPeriodStaysShort(t *testing.T) {
	if got := httpapi.DefaultRetentionPeriod(); got > 5*time.Minute {
		t.Errorf("the defaults hold a client address for %v; anything longer than a few minutes "+
			"needs a reason written next to it and a page that says so", got)
	}
}

// The script builds every node with createElement and textContent, and a test
// in this package already fails if innerHTML appears. That is a check on the
// file this repository ships. This is the same rule expressed where a browser
// can enforce it on the script it actually ran.
func TestPolicyForbidsScriptReachingAMarkupParser(t *testing.T) {
	for _, directive := range []string{"require-trusted-types-for 'script'", "trusted-types 'none'"} {
		if !strings.Contains(contentSecurityPolicy, directive) {
			t.Errorf("the policy has no %q: %s", directive, contentSecurityPolicy)
		}
	}
}

// The privacy page promises no fonts from elsewhere, no content delivery
// network and no tag of any kind. That holds today because nobody has added
// one. This makes a browser refuse the resource if somebody does.
func TestNothingFromAnyoneElseIsEnforcedByAHeader(t *testing.T) {
	h := get(t, "/").Header()
	if got := h.Get("Cross-Origin-Embedder-Policy"); got != "require-corp" {
		t.Errorf("Cross-Origin-Embedder-Policy = %q, want require-corp", got)
	}
}

// A class name is not a script, but it decides what the page looks like, and a
// page that will paste any string into a class attribute has handed its
// appearance to whoever answers. Every class here is built from one list, and
// this fails if a second way of building one appears.
func TestScriptBuildsClassNamesFromOneList(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	for _, required := range []string{"const VERDICTS = ", "function markClass(", "function verdictClass("} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js no longer contains %q", required)
		}
	}

	// A class assembled from a value rather than chosen from the list. The
	// helpers above are the only places a prefix and a value may be joined,
	// and they are matched by name so that this does not flag them.
	concatenation := regexp.MustCompile(`"(mark|stamp|finding)-" \+`)
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if !concatenation.MatchString(line) {
			continue
		}
		if strings.Contains(line, "VERDICTS.includes") {
			continue // markClass and verdictClass, which check first
		}
		t.Errorf("a class name is built by concatenation outside the helpers: %s", trimmed)
	}
}

// A page that denies doing something this project now does is worse than a
// page that says nothing.
//
// The privacy page and the README both said revocation is not checked. That
// was true and load-bearing for as long as it was true, and it stopped being
// true the day internal/ocsp landed — while both sentences stayed. A reader
// deciding whether to rely on a report reads those pages, not the changelog.
//
// The rule is pinned to the code rather than to a date: as long as a rule with
// this identifier exists, neither page may say the check does not happen.
func TestThePagesDoNotDenyACheckThatNowHappens(t *testing.T) {
	if !strings.Contains(gradesRevocation(), "cert.revoked") {
		t.Skip("no revocation rule; the pages are free to say it is not checked")
	}

	pages := map[string]string{
		"assets/privacy.html": "",
		"../../README.md":     "",
	}
	for path := range pages {
		var body []byte
		var err error
		if strings.HasPrefix(path, "assets/") {
			body, err = assets.ReadFile(path)
		} else {
			body, err = os.ReadFile(path)
		}
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := strings.ToLower(string(body))

		for _, denial := range []string{
			"revocation is not checked",
			"no revocation check",
			"revocation is not\n      checked",
		} {
			if strings.Contains(text, denial) {
				t.Errorf("%s still says %q, and it is checked", path, denial)
			}
		}
	}
}

// The privacy page states the per-target threshold in more than one place, and
// only one of them had a test. The other said "twice" long after the limit
// moved to eight — the page contradicting itself two sections apart, which is
// the reading a visitor is most likely to take at face value.
//
// A number is not restated. The second mention now points at the first.
func TestTheThresholdIsStatedInOnePlace(t *testing.T) {
	body, err := assets.ReadFile("assets/privacy.html")
	if err != nil {
		t.Fatalf("reading the privacy page: %v", err)
	}
	text := strings.ToLower(string(body))

	for _, restated := range []string{"been checked twice", "checked twice,"} {
		if strings.Contains(text, restated) {
			t.Errorf("the page restates the threshold as %q while the limit is %d",
				restated, httpapi.TargetThreshold())
		}
	}
}

// gradesRevocation returns the rule identifiers this policy can raise about a
// stapled response, read from the source so the test above cannot be silenced
// by renaming a rule.
func gradesRevocation() string {
	body, err := os.ReadFile("../../internal/policy/staple.go")
	if err != nil {
		return ""
	}
	return string(body)
}
