package web

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The page's own furniture — the mark at the top, the links at the foot, and
// the notices under the field. None of it is the report, and all of it is on
// every page the report appears on.

// asset returns a shipped file.
func asset(t *testing.T, name string) string {
	t.Helper()
	body, err := assets.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(body)
}

// A row of links is not a sentence, so it is not held to a sentence's width.
//
// The colophon's paragraphs carry `max-width: var(--measure)`, the width
// running text can be read at, and the link row is written as a paragraph, so
// it inherited it. Measured in a browser: the five links come to 677 pixels
// against a 578 pixel measure, so they broke onto a second line inside a
// footer 884 pixels wide with 207 to spare.
//
// The exclusion is checked at the selector rather than as an override, because
// `.colophon p` beats a bare `.colophon-links` on specificity whatever the
// order — an override there has to be written stronger than it looks, and the
// next person to read it would not know why.
func TestTheFooterLinksAreNotHeldToAProseMeasure(t *testing.T) {
	sheet := stylesheet(t)

	if !strings.Contains(sheet, ".colophon p:not(.colophon-links)") {
		t.Error("the colophon's measure is not excluded from the link row, so the links wrap with room to spare")
	}
	if regexp.MustCompile(`(?m)^\.colophon p\s*\{[^}]*max-width`).MatchString(sheet) {
		t.Error("a bare .colophon p still sets a measure, which the link row inherits")
	}

	// The row is a flex row that may wrap. It has to be able to: on a phone
	// there is no width at which five links fit, and wrapping there is the
	// right answer rather than a defect.
	if body := cssRule(t, sheet, ".colophon-links"); !strings.Contains(body, "flex-wrap: wrap") {
		t.Error("the link row cannot wrap, so on a narrow screen it will overflow instead")
	}
}

// One notice under the field, not a stack of them.
//
// The link to what a scan sends sat in a paragraph of its own beneath the
// paragraph about the terms: two rules of documentation under one input,
// which reads as a page papered with notices, and a reader who learns to skip
// one notice skips the next.
//
// It is also the better target where it is now. A link alone in a paragraph
// is a control 16 pixels high, under the 24 a pointer needs; the same link
// inside a sentence is an inline link, exempt because the sentence around it
// is what makes it findable.
func TestTheLandingPageDoesNotStackNoticesUnderTheField(t *testing.T) {
	page := asset(t, "assets/index.html")

	if strings.Contains(page, `class="promise"`) {
		t.Error("the standalone notice is back under the field")
	}

	// The disclosure did not go away; it joined the sentence a reader is
	// already reading before pressing the button.
	//
	// Read from the rendered page rather than from the template, because the
	// template now carries two paragraphs — one for this deployment and one
	// for the demonstration — and what matters is the one a visitor is
	// actually given.
	help := regexp.MustCompile(`(?s)<p class="field-help".*?</p>`).FindString(get(t, "/tls").Body.String())
	if help == "" {
		t.Fatal("the field's help paragraph could not be found")
	}
	for _, want := range []string{`href="/terms"`, `href="/privacy#scans"`} {
		if !strings.Contains(help, want) {
			t.Errorf("the help paragraph does not carry %s, so the reader is not told before deciding", want)
		}
	}

	// And the stylesheet does not keep a rule for a class nothing wears.
	if strings.Contains(stylesheet(t), ".promise") {
		t.Error("the stylesheet still styles .promise, which no longer exists in the markup")
	}
}

// The mark at the top is a link home, and a link home is a target.
//
// Measured at 106 by 26 pixels, which clears the 24 a pointer needs — by two
// pixels, and by accident: the height was the line box of a 1rem word and
// nothing said it had to stay that. A font-size trimmed one afternoon would
// take the target under the floor and change nothing anybody would notice.
func TestTheWordmarkDeclaresATargetFloor(t *testing.T) {
	body := cssRule(t, stylesheet(t), ".wordmark")

	// A min-height only applies to a box that has one.
	if !strings.Contains(body, "display: inline-block") {
		t.Error("the wordmark is an inline box, where a declared height does nothing")
	}

	m := regexp.MustCompile(`min-height:\s*([0-9.]+)(px|rem)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the wordmark declares no minimum height, so its target size is whatever the type happens to be")
	}
	size, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("reading the wordmark's minimum height: %v", err)
	}
	if m[2] == "rem" {
		// The root is set in px on this page, and read from it rather than
		// assumed: a rem floor is only a floor if the root does not shrink.
		root := regexp.MustCompile(`html\s*\{[^}]*font-size:\s*([0-9.]+)px`).FindStringSubmatch(stylesheet(t))
		if root == nil {
			t.Fatal("the root font size is not declared in pixels, so a rem floor cannot be checked")
		}
		px, err := strconv.ParseFloat(root[1], 64)
		if err != nil {
			t.Fatalf("reading the root font size: %v", err)
		}
		size *= px
	}
	if size < 24 {
		t.Errorf("the wordmark's floor is %.1fpx, below the 24 a pointer needs", size)
	}
}
