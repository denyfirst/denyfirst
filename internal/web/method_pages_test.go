package web

import (
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// Why the obsolete suites are asked by hand is said on the method page, and
// the report says only how to read a row and where the rest is.
//
// The report used to open the section with "Go cannot offer these", which
// explained this program's internals to a reader who had asked about their
// server. The explanation moved; the link to it is what stays behind.
func TestTheObsoleteSuitesAreExplainedOnTheMethodPage(t *testing.T) {
	src := script(t)
	if strings.Contains(src, "Go cannot offer") {
		t.Error("the report still explains the library it is built with")
	}
	for _, want := range []string{
		`"Refused means the server accepted none of them. "`,
		`why.href = CHECKS.tls.methodPage + "#obsolete-suites";`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the obsolete-suite section no longer contains %s", want)
		}
	}

	page := get(t, "/tls/method").Body.String()
	if !strings.Contains(page, `<h2 id="obsolete-suites">`) || !strings.Contains(page, `href="#obsolete-suites"`) {
		t.Fatal("the method page has no obsolete-suite section to link to")
	}

	// Every row the report draws is a term the page defines, in the same
	// words, so a reader who follows the link finds the row they came from.
	rows := regexp.MustCompile(`answer\("([^"]+)", l\.`).FindAllStringSubmatch(src, -1)
	if len(rows) != 4 {
		t.Fatalf("the report draws %d family rows, want 4", len(rows))
	}
	labels := []string{"Downgrade signal"}
	for _, r := range rows {
		labels = append(labels, r[1])
	}
	if !strings.Contains(src, `el("td", null, "Downgrade signal")`) {
		t.Error("the fallback row is not labelled as the page defines it")
	}
	for _, l := range labels {
		if !strings.Contains(page, "<dt>"+l+"</dt>") {
			t.Errorf("the method page does not define %q, which the report draws", l)
		}
	}
}

// The mail check has a method page, and it is the one its reports point at.
func TestTheMailCheckHasAMethodPage(t *testing.T) {
	page := get(t, "/mail/method").Body.String()

	for _, l := range policy.MailStandingLimits() {
		if !strings.Contains(page, `<h2 id="`+l.ID+`">`) {
			t.Errorf("the mail method page does not carry the limit %s", l.ID)
		}
	}
	// The question its reports raise most, answered where the report points.
	for _, want := range []string{`<h2 id="exchangers">`, "reverse DNS name", "<code>-helo</code>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the mail method page does not say %q", want)
		}
	}

	// Which connections this deployment makes differs by build, and the page
	// says the one that is true of the build serving it.
	demoSentence := "This deployment makes neither connection"
	if strings.Contains(page, demoSentence) != demo.Enabled {
		t.Errorf("the mail method page misdescribes this build's connections (demo %v)", demo.Enabled)
	}

	// Listed with the other two where a reader looks for them.
	if docs := get(t, "/docs").Body.String(); !strings.Contains(docs, `href="/mail/method"`) {
		t.Error("/docs does not list the mail method page")
	}
}

// What the web check calls itself is said on its method page, not under
// every report.
func TestTheUserAgentIsOnTheMethodPageAndNotTheReport(t *testing.T) {
	// Unescaped, because html/template writes the plus sign as an entity.
	page := html.UnescapeString(get(t, "/web/method").Body.String())
	if !strings.Contains(page, "<code>"+webprobe.DefaultUserAgent+"</code>") {
		t.Error("the web method page does not say what the probe calls itself")
	}
	src := script(t)
	if strings.Contains(src, "Requested as") || strings.Contains(src, "observed.userAgent") {
		t.Error("the Reach report still draws the user agent")
	}
}
