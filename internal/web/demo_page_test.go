//go:build demo

package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
)

// What a visitor to denyfirst.dev is given.
//
// The deployment connects only to hosts this project owns, so the page offers
// what there is rather than a field that mostly answers no. A control that
// invites a request the server will refuse is a page arguing with its own
// server, and the visitor is the one who loses.
func TestTheDemonstrationPageOffersWhatItCanScan(t *testing.T) {
	page := get(t, "/tls").Body.String()

	if !strings.Contains(page, `<select`) {
		t.Error("the demonstration page still offers a free-text field")
	}
	if strings.Contains(page, `type="text"`) {
		t.Error("the demonstration page carries a text field it cannot answer")
	}

	hosts := demo.Hosts()
	if len(hosts) == 0 {
		t.Fatal("the demonstration page has nothing to offer")
	}
	for _, h := range hosts {
		if !strings.Contains(page, `value="`+h.Host+`"`) {
			t.Errorf("the page does not offer %s, which the deployment can scan", h.Host)
		}
		if !strings.Contains(page, h.Shows) {
			t.Errorf("the page offers %s and does not say what it shows", h.Host)
		}
	}

	// The script reads one id, so the two deployments share one script and
	// there is no branch in it to go stale.
	if !strings.Contains(page, `id="target"`) {
		t.Error("the control the script reads is not on the page")
	}
}

// The page says what this deployment is, and where the tool is.
//
// A visitor who is offered two hosts and no explanation reads a crippled
// service. What they are looking at is a demonstration of a tool they are
// meant to run themselves, and the page has to say so at the moment they
// notice the limit — which is at the control, not in the footer.
func TestTheDemonstrationPageSaysWhatItIsAndWhereTheToolIs(t *testing.T) {
	page := get(t, "/tls").Body.String()

	for _, want := range []string{
		"scans only hosts this project owns",
		"Run it yourself",
		"docs/self-host.md",
		"leaves your machine",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the demonstration page does not say %q", want)
		}
	}
}

// The demonstration serves its own privacy page, written about the machine
// this project runs, and never the self-hosted one (audit A21).
func TestTheDemonstrationKeepsItsOwnPrivacyPage(t *testing.T) {
	page := get(t, "/privacy").Body.String()
	if !strings.Contains(page, "abuse@denyfirst.dev") || strings.Contains(page, "What this installation keeps") {
		t.Error("the demonstration does not serve its own privacy page")
	}
	Configure(true, true, false)
	if strings.Contains(get(t, "/privacy").Body.String(), "What this installation keeps") {
		t.Error("configuring the demonstration replaced its privacy page")
	}
	if root := get(t, "/").Body.String(); strings.Contains(root, `id="console-form"`) || !strings.Contains(root, `id="products"`) {
		t.Error("configuring the demonstration replaced its front page with the console")
	}
}

// The Porch page offers what the demonstration can check, every check this
// binary has, and runs them from the page.
func TestThePorchPageRunsEveryCheckOnTheHostsItOffers(t *testing.T) {
	page := get(t, "/porch").Body.String()
	hosts := demo.Hosts()
	for _, h := range hosts {
		offered := strings.Contains(page, `<option value="`+h.Host+`">`)
		if len(hosts) == 1 {
			offered = strings.Contains(page, `<input type="hidden" id="porch-target" name="target" value="`+h.Host+`">`)
		}
		if !offered {
			t.Errorf("the Porch page does not offer %s", h.Host)
		}
	}
	// A menu with one entry is an arrow that opens onto nothing.
	if menu := strings.Contains(page, `<select`); menu != (len(hosts) > 1) {
		t.Errorf("the Porch page draws a menu: %v, for %d hosts", menu, len(hosts))
	}
	if strings.Contains(page, `type="text"`) {
		t.Error("the Porch page offers a free-text field the deployment cannot answer")
	}
	for _, c := range consoleChecks() {
		if !strings.Contains(page, `value="`+c.ID+`" checked`) {
			t.Errorf("the Porch page does not offer the %s check", c.Label)
		}
	}
	if !strings.Contains(page, `<script src="/app.js"></script>`) || !strings.Contains(page, `id="porch-results"`) {
		t.Error("the Porch page cannot run or show a check")
	}
}

// The front page claims nothing about a product that is not available.
func TestTheFrontPageSaysWhatIsNotAvailable(t *testing.T) {
	page := get(t, "/").Body.String()
	if strings.Contains(page, `<script src="/app.js">`) {
		t.Error("the front page loads the check script, and runs no check")
	}
	if strings.Count(page, `class="badge badge-live"`) != 1 {
		t.Error("more or fewer than one offering is marked available")
	}
	if !strings.Contains(page, "They are not available, and no date is promised.") {
		t.Error("the front page does not say its planned offerings are not available")
	}
}
