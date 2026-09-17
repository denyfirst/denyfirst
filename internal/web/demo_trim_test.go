package web

import (
	"html"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
)

// The demonstration keeps no copy of a report and counts nothing for its
// visitor.
//
// A report of our own domain is ours, so the download is offered only by an
// installation somebody runs, where the report is theirs. The scan counter is
// a figure about this deployment, not about the visitor's check, and
// /api/v1/stats still publishes it. Read from the source, as the other script
// tests are.
func TestTheDemonstrationOffersNoDownloadAndNoCounter(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		`const DEMO_SITE = document.body.dataset.site === "demo";`,
		`if (!DEMO_SITE) left.appendChild(downloadLink(data));`,
		`if (!tally || DEMO_SITE) return;`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js no longer contains %q", want)
		}
	}
	if n := strings.Count(src, "appendChild(downloadLink("); n != 1 {
		t.Errorf("app.js offers the download in %d places; the one above is the only one gated", n)
	}
}

// The three steps on the Porch page are the guide's own commands.
//
// The guide is the reference and says why each step is there; a command on
// the page that the guide no longer gives is one nobody is maintaining.
func TestThePorchStepsAreTheGuidesCommands(t *testing.T) {
	page, err := assets.ReadFile("assets/porch.html")
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile("../../docs/self-host.md")
	if err != nil {
		t.Fatal(err)
	}
	// Whole lines: "docker compose up -d" is inside the guide's
	// "docker compose up -d --build" and is not the same command.
	given := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(string(guide), "\r\n", "\n"), "\n") {
		given[strings.TrimSpace(line)] = true
	}
	blocks := regexp.MustCompile(`(?s)<pre><code>(.*?)</code></pre>`).FindAllStringSubmatch(string(page), -1)
	if len(blocks) != 3 {
		t.Fatalf("the Porch page has %d command blocks, want 3", len(blocks))
	}
	for _, b := range blocks {
		for _, line := range strings.Split(html.UnescapeString(b[1]), "\n") {
			if !given[line] {
				t.Errorf("the Porch page gives %q, which docs/self-host.md does not", line)
			}
		}
	}
}

// One host is shown, and more than one is a menu.
//
// Rendered with made-up hosts rather than read from the page, because the
// build carries one host today and the branch for two would otherwise go
// untested until the day it is needed.
func TestThePorchPageShowsOneHostAndOffersSeveral(t *testing.T) {
	for _, hosts := range [][]demo.Host{
		{{Host: "one.test", Shows: "a"}},
		{{Host: "one.test", Shows: "a"}, {Host: "two.test", Shows: "b"}},
	} {
		body, err := render(&page{Title: "t", Fragment: "assets/porch.html", Data: porchPage{Hosts: hosts, Checks: consoleChecks()}})
		if err != nil {
			t.Fatal(err)
		}
		out := string(body)
		menu := strings.Contains(out, `<select class="field" id="porch-target"`)
		fixed := strings.Contains(out, `<input type="hidden" id="porch-target" name="target" value="one.test">`)
		if menu != (len(hosts) > 1) || fixed != (len(hosts) == 1) {
			t.Errorf("%d hosts: menu %v, fixed field %v", len(hosts), menu, fixed)
		}
		for _, h := range hosts {
			if !strings.Contains(out, h.Host) {
				t.Errorf("%d hosts: %s is not on the page", len(hosts), h.Host)
			}
		}
	}
}
