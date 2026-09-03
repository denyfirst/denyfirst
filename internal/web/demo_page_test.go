//go:build demo

package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/scan"
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

	hosts := scan.DemoHosts()
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
		"github.com/denyfirst/denyfirst",
		"leaves your machine",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the demonstration page does not say %q", want)
		}
	}
}
