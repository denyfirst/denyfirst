package web

import (
	"regexp"
	"strings"
	"testing"
)

// The cipher tables are the only place on a report where the same four
// columns are printed more than once, one table under another. Until
// 2026-09-02 each table sized its own columns to its own contents: measured
// in a browser on a live report, "Key exchange" began 92 pixels further right
// under TLS 1.2 than under TLS 1.3, and "Cipher" 68 pixels further left.
// Every row was correct and the table could not be read as a table.
//
// These tests hold the four decisions that fixed it. They read the assets
// rather than a rendered page, which is what this package can honestly check;
// the rendering itself was measured in a browser at 380, 794 and 1000 pixels
// wide, in both colour schemes, before any of this was written.

// stylesheet returns the stylesheet as shipped.
func stylesheet(t *testing.T) string {
	t.Helper()
	body, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("reading the stylesheet: %v", err)
	}
	return string(body)
}

// cssRule returns the body of the first rule whose selector list matches.
func cssRule(t *testing.T, sheet, selector string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`)
	m := pattern.FindStringSubmatch(sheet)
	if m == nil {
		t.Fatalf("the stylesheet has no rule for %q", selector)
	}
	return m[1]
}

// Every cipher table is given its columns before it is given its rows.
//
// A <colgroup> is the only place a table can be told its geometry ahead of
// its contents, and a fixed layout is what makes the browser obey it. With
// either one missing the columns go back to being sized by whichever suites
// the host happened to accept, and two tables on one page stop lining up.
func TestEveryCipherTableIsGivenTheSameColumns(t *testing.T) {
	source := script(t)

	for _, want := range []string{
		`el("colgroup")`,
		`el("col", "col-grade")`,
		`el("col", "col-suite")`,
		`el("col", "col-kex")`,
		`el("col", "col-cipher")`,
	} {
		if !strings.Contains(source, want) {
			t.Errorf("the cipher table does not declare %s", want)
		}
	}

	// Declared before the header row, because a colgroup after the first row
	// is ignored.
	group := strings.Index(source, `table.appendChild(group)`)
	head := strings.Index(source, `for (const label of ["Grade", "Suite", "Key exchange", "Cipher"])`)
	switch {
	case group < 0:
		t.Error("the column group is never attached to the table")
	case head < 0:
		t.Error("the cipher table header could not be found")
	case group > head:
		t.Error("the column group is attached after the header row, where a browser ignores it")
	}

	if body := cssRule(t, stylesheet(t), ".suites"); !strings.Contains(body, "table-layout: fixed") {
		t.Error("the cipher table does not use a fixed layout, so the declared column widths are advisory")
	}
}

// A cipher suite name is an identifier and identifiers are not broken.
//
// The column carried word-break: break-all so that a long name would fit a
// narrow screen. It fits by arriving as TLS_ECDHE_RSA_W / ITH_AES_128_GCM /
// _SHA256, and the name is the finding: a reader copying that by hand writes
// down a suite that does not exist. The container scrolls instead.
func TestASuiteNameIsNeverBrokenOnScreen(t *testing.T) {
	sheet := stylesheet(t)

	body := cssRule(t, sheet, ".suites td.identifier")
	if !strings.Contains(body, "white-space: nowrap") {
		t.Error("a suite name may still be broken across lines on screen")
	}
	for _, forbidden := range []string{"break-all", "anywhere"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the suite column still asks to be broken mid-word (%s)", forbidden)
		}
	}

	// The general rule this one overrides is still there for the identifiers
	// outside a cipher table, which have no container to scroll.
	if !strings.Contains(sheet, ".rows td.identifier") {
		t.Error("the general identifier rule is gone, so identifiers elsewhere no longer wrap at all")
	}
}

// Nothing is hidden without a sign that it is there.
//
// A table wider than the screen is put in a container that scrolls, and the
// container is shaded at whichever edge it can still travel towards. Without
// the shading a reader on a phone sees Grade and Suite and never learns that
// the key exchange and the mode of encryption were recorded at all.
func TestTheCipherTableScrollsInsideItsOwnContainer(t *testing.T) {
	source := script(t)
	if !strings.Contains(source, `el("div", "table-scroll")`) {
		t.Fatal("the cipher table is not put in a scrolling container")
	}
	if !strings.Contains(source, `frag.appendChild(el("div", "table-scroll")).appendChild(table)`) {
		t.Error("the container is built but the table is not put inside it")
	}

	body := cssRule(t, stylesheet(t), ".table-scroll")
	if !strings.Contains(body, "overflow-x: auto") {
		t.Error("the container does not scroll, so a wide table overflows the page instead")
	}
	if strings.Count(body, "var(--edge)") != 2 {
		t.Error("the container is not shaded at both edges, so a reader is not told there is more")
	}
	// Both colour schemes define the shade, because a black shadow on a dark
	// page is no shadow at all.
	if strings.Count(stylesheet(t), "--edge:") != 2 {
		t.Error("the edge shade is not defined for both colour schemes")
	}
}

// Paper does not scroll.
//
// The fix for the screen introduces a way to lose data on a printed page: a
// container that scrolls has somewhere to put the overflow and a sheet of
// paper does not. On paper the geometry is released, the columns are given
// shares of the sheet so that they still line up, and the identifier is
// allowed to wrap — which is the one place breaking a name is better than
// dropping it.
func TestNothingIsLostOffTheEdgeOnPaper(t *testing.T) {
	sheet := stylesheet(t)

	start := strings.Index(sheet, "@media print {")
	if start < 0 {
		t.Fatal("the stylesheet says nothing about paper, so the scrolling container prints truncated")
	}
	end := strings.Index(sheet[start:], "\n}")
	if end < 0 {
		t.Fatal("the print block is not closed")
	}
	block := sheet[start : start+end]

	for _, want := range []string{
		"overflow-x: visible",
		"min-width: 0",
		"white-space: normal",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("on paper the cipher table still carries %q's opposite", want)
		}
	}
	// Shares of the sheet, so that the two tables still agree with each other
	// where there is no scrolling to fall back on.
	for _, want := range []string{".col-grade", ".col-kex", ".col-cipher"} {
		if !regexp.MustCompile(regexp.QuoteMeta(want) + `\s*\{[^}]*width:\s*\d+%`).MatchString(block) {
			t.Errorf("on paper %s is not given a share of the sheet", want)
		}
	}
}

// The stylesheet is a stylesheet, not a note about how to edit one.
//
// Two comments reading "Append this to internal/web/assets/style.css" and
// "Replace the .prose block near the end of style.css with this" were served
// to every visitor for weeks. They are harmless to a browser and wrong about
// the file they are in, and a project whose whole claim is that it does not
// say things it cannot support should not ship a file that misdescribes
// itself.
func TestTheAssetsDoNotCarryInstructionsForEditingThemselves(t *testing.T) {
	for _, name := range []string{"assets/style.css", "assets/app.js"} {
		body, err := assets.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, phrase := range []string{
			"Append this to",
			"Replace the \"",
			"Everything above",
			"Nothing above it changes",
			"near the end of style.css",
		} {
			if strings.Contains(string(body), phrase) {
				t.Errorf("%s carries a patch instruction: %q", name, phrase)
			}
		}
	}
}
