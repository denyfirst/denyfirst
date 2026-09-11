package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
)

// flatten collapses the whitespace a template wraps its prose with, so an
// assertion is about what a reader sees rather than about where a line broke.
// Two of the assertions below failed on correct markup before it existed.
func flatten(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// A page must not tell a log reader about a deployment that did not reach them.
//
// The user agent names one address from every installation of this tool, so
// somebody who found a scan in their access log arrives at /web/method whichever
// installation made it. A sentence there that describes the demonstration is
// read by people the demonstration never touched.
//
// That is not hypothetical and it is not only about the body. Two paragraphs on
// that page said "this deployment" and meant the compiled-in one:
//
//   - "This deployment never reads a body", which a self-hosted installation
//     that reads pages would have been serving as a description of itself.
//   - "On this deployment that means the hosts this project owns", about which
//     redirects are followed, which was already wrong on every self-hosted
//     installation before any of this.
//
// The first was written on 2026-09-11 and caught the same day by opening the
// page in a browser rather than by any test. This is that test.
//
// It asserts the shape rather than the prose: whichever build is running, the
// page says what *this* installation does, and it never claims the other one's
// behaviour as its own.
func TestTheMethodPageDescribesTheDeploymentServingIt(t *testing.T) {
	page := flatten(get(t, "/web/method").Body.String())

	// The demonstration's promise, in the words that make it a promise.
	const neverReadsABody = "never reads a body"

	// What a deployment that reads pages has to say instead.
	const readsWhatItWasShown = "reads the page of a domain it has been shown control of"

	if demo.Enabled {
		if !strings.Contains(page, neverReadsABody) {
			t.Errorf("the demonstration's page does not say it never reads a body. That promise " +
				"is why somebody who found this scanner in their access log is entitled not to " +
				"investigate further.")
		}
		if strings.Contains(page, readsWhatItWasShown) {
			t.Error("the demonstration's page claims it reads pages, and this build cannot: " +
				"the call is compiled out")
		}
		if !strings.Contains(page, "the hosts this project owns") {
			t.Error("the demonstration's page no longer says which hosts it will follow a " +
				"redirect to")
		}
		return
	}

	if !strings.Contains(page, readsWhatItWasShown) {
		t.Error("a self-hosted installation's page does not say what it reads")
	}
	if strings.Contains(page, "This deployment "+neverReadsABody) {
		t.Error("a self-hosted installation's page says of itself that it never reads a body. " +
			"It may; that is what proof of control buys. A scanning notice that misdescribes " +
			"the scan is worse than no notice, because a log reader acts on it.")
	}
	if strings.Contains(page, "On this deployment that means the hosts this project owns") {
		t.Error("a self-hosted installation's page says it follows redirects only to hosts this " +
			"project owns. It follows them into the estate it was shown control of, which is " +
			"somebody else's estate entirely.")
	}

	// And it still says what the public deployment does, because a log reader
	// may have been reached by that one and lands on the same page.
	if !strings.Contains(page, "denyfirst.dev never reads a body") {
		t.Error("the page no longer tells a reader what the public deployment does, so somebody " +
			"reached by that one and reading this page is told about an installation that is " +
			"not the one in their log")
	}
}

// Both method pages carry the switch that makes the above possible.
//
// Cheap, and it guards the wiring rather than the prose: a page whose template
// branches on .Demo while its data never sets it renders the false branch
// silently, and every assertion above would then be testing one build twice.
func TestTheMethodPagesKnowWhichBuildTheyAre(t *testing.T) {
	for _, path := range []string{"/web/method", "/tls/method"} {
		p, ok := pages[path]
		if !ok {
			t.Fatalf("%s is not a page", path)
		}
		data, ok := p.Data.(methodPage)
		if !ok {
			t.Fatalf("%s does not carry methodPage data", path)
		}
		if data.Demo != demo.Enabled {
			t.Errorf("%s was built with Demo=%v in a build where demo.Enabled is %v",
				path, data.Demo, demo.Enabled)
		}
		if len(data.Limits) == 0 {
			t.Errorf("%s ranges over no limits", path)
		}
	}
}
