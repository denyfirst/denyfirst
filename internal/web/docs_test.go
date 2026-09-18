package web

import (
	"regexp"
	"strings"
	"testing"
)

// Every document is on one page, and the footer offers four ways on.
//
// The footer carried six links and the privacy page three more. They are on
// /docs now, grouped by the question they answer, and the footer is short
// enough to read.
func TestEveryDocumentIsOnTheDocsPage(t *testing.T) {
	page := get(t, "/docs").Body.String()
	for _, want := range []string{
		`href="/tls/method"`, `href="/web/method"`, `href="/privacy"`, `href="/terms"`,
		"docs/self-host.md", "docs/verify.md", "docs/scope.md", "docs/policy-changes.md",
		"docs/invariants.md", "SECURITY.md", `href="https://github.com/denyfirst/porch"`,
		`href="/pgp-key.txt"`, `href="/.well-known/security.txt"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("/docs does not lead to %s", want)
		}
	}

	// A link inside a link is not a link a browser can be relied on to follow.
	cards := regexp.MustCompile(`(?s)<a class="card[^"]*"[^>]*>(.*?)</a>`).FindAllStringSubmatch(page, -1)
	if len(cards) < 10 {
		t.Fatalf("only %d cards on /docs", len(cards))
	}
	for _, c := range cards {
		if strings.Contains(c[1], "<a ") {
			t.Errorf("a card on /docs holds a link of its own: %s", c[1])
		}
	}

	for path := range pages {
		body := get(t, path).Body.String()
		_, foot, _ := strings.Cut(body, `<footer class="colophon">`)
		if n := strings.Count(foot, "<a "); n != 3 {
			t.Errorf("%s: the footer carries %d links, want three", path, n)
		}
		if !strings.Contains(foot, `href="/docs">Docs</a>`) {
			t.Errorf("%s: the footer does not lead to /docs", path)
		}
		// The masthead on the demonstration, the rail on an installation: either
		// way before the page begins.
		head, _, _ := strings.Cut(body, "<main>")
		if !strings.Contains(head, `href="/docs"`) {
			t.Errorf("%s: the header does not lead to /docs", path)
		}
	}

	// The privacy page ends by pointing there, not with a list of its own.
	for name, privacy := range map[string]string{"served": string(rendered["/privacy"]), "demonstration": demoPrivacy(t)} {
		if strings.Count(privacy, `class="colophon-links"`) != 1 {
			t.Errorf("the %s privacy page carries a link list of its own again", name)
		}
		if !strings.Contains(privacy, `<a class="text-link arrow-e" href="/docs">`) {
			t.Errorf("the %s privacy page does not end by pointing at /docs", name)
		}
	}
}

// Arrows are drawn by the stylesheet with empty alternative text, so a screen
// reader reads the link and not the arrow.
func TestArrowsAreDecoration(t *testing.T) {
	sheet := stylesheet(t)
	for _, arrow := range []string{`"↗" / ""`, `"↘" / ""`, `"→" / ""`, `"↓" / ""`} {
		if !strings.Contains(sheet, arrow) {
			t.Errorf("the stylesheet does not draw %s as decoration", arrow)
		}
	}
	for _, name := range []string{"assets/home.html", "assets/porch.html", "assets/docs.html", "assets/app.js"} {
		body, err := assets.ReadFile(name)
		if err != nil {
			continue
		}
		if strings.ContainsAny(string(body), "↗↘→") && name != "assets/app.js" {
			t.Errorf("%s writes an arrow into its text", name)
		}
	}
}

// Nothing moves for a reader who asked the system for less motion.
func TestHoverMotionRespectsReducedMotion(t *testing.T) {
	sheet := stylesheet(t)
	blocks := regexp.MustCompile(`(?s)@media \(prefers-reduced-motion: reduce\) \{(.*?)\n\}`).FindAllStringSubmatch(sheet, -1)
	all := ""
	for _, b := range blocks {
		all += b[1]
	}
	for _, want := range []string{".card-link:hover { transform: none; }", ".arrow-ne::after", "transition: none;"} {
		if !strings.Contains(all, want) {
			t.Errorf("the reduced-motion rules do not include %q", want)
		}
	}
}

// The demonstration's header lists products under one entry, so the bar does
// not grow with the catalog, and the list works without a script.
func TestProductsAreAMenuNotABar(t *testing.T) {
	src, err := assets.ReadFile("assets/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	layout := string(src)
	// The demonstration's header is the masthead; an installation's rail comes
	// first in the file and is not it.
	_, brand, _ := strings.Cut(layout, `<header class="masthead">`)
	brand, _, _ = strings.Cut(brand, "</header>")

	if strings.Count(brand, `href="/porch"`) != 1 || !strings.Contains(brand, `<ul class="nav-menu-list">`) {
		t.Error("Porch is not listed under the Products menu")
	}
	bar := regexp.MustCompile(`(?s)<ul class="nav-menu-list">.*?</ul>`).ReplaceAllString(brand, "")
	if strings.Contains(bar, `href="/porch"`) {
		t.Error("a product sits in the bar itself")
	}
	for _, want := range []string{`href="/">Home</a>`, `<a class="nav-menu-button" href="/#products">Products</a>`, `href="/docs">Docs</a>`} {
		if !strings.Contains(brand, want) {
			t.Errorf("the demonstration's header lacks %s", want)
		}
	}

	sheet := stylesheet(t)
	for _, want := range []string{".nav-menu:hover .nav-menu-list", ".nav-menu:focus-within .nav-menu-list", ".nav-menu-list::before"} {
		if !strings.Contains(sheet, want) {
			t.Errorf("the menu does not open with %s", want)
		}
	}
	if !strings.Contains(cssRule(t, sheet, ".nav-menu-list"), "display: none") {
		t.Error("the menu is open before anybody asks for it")
	}
}
