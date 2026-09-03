package web

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A report that cannot be read is a report that misleads.
//
// The stylesheet opens by saying that what could not be measured is set in the
// same weight as what could, "because a reader who is not told what was
// skipped will read silence as a clean result". The weight was equalised and
// the colour was not: measured in a browser on 2026-09-02, the faint ink came
// to 3.11:1 against paper in the light scheme, and it carries the coverage
// line, the count of what was observed and not graded, the pointer to the
// standing limits, and the words "not measured" — the whole of what a reader
// has to see in order not to mistake silence for a clean result. The amber of
// a weak verdict came to 3.60:1 against the paper a finding is drawn on, on
// the one word the report exists to deliver.
//
// So the threshold is checked here rather than left to taste.

// The ratio a reader with ordinary vision needs at the sizes this page uses.
// Every text on a report is below 24px, and below 18.66px where it is bold, so
// the large-text allowance of 3:1 never applies and is not offered here.
const readableContrast = 4.5

var (
	// A token defined as a hex colour. Values that are not hex — the edge
	// shading, which is deliberately translucent — are not colours anything is
	// set in and are not checked.
	tokenPattern = regexp.MustCompile(`--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;`)

	// A token used as the colour of text. The leading class excludes
	// background-color, border-color, and every other -color property, because
	// in those the character before "color" is a hyphen.
	textColourPattern = regexp.MustCompile(`(?m)(?:^|[;{\s])color:\s*var\(--([a-z-]+)\)`)
)

// relativeLuminance is the sRGB definition WCAG uses.
func relativeLuminance(hex string) float64 {
	channel := func(offset int) float64 {
		v, err := strconv.ParseInt(hex[offset:offset+2], 16, 32)
		if err != nil {
			return 0
		}
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	hex = strings.TrimPrefix(hex, "#")
	return 0.2126*channel(0) + 0.7152*channel(2) + 0.0722*channel(4)
}

func contrast(a, b string) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	high, low := math.Max(la, lb), math.Min(la, lb)
	return (high + 0.05) / (low + 0.05)
}

// schemes returns the token table for each colour scheme, the dark one being
// the light one with the dark block's overrides applied — which is what a
// browser does with a token the dark block does not mention.
func schemes(t *testing.T, sheet string) map[string]map[string]string {
	t.Helper()

	block := func(from string) string {
		start := strings.Index(sheet, from)
		if start < 0 {
			t.Fatalf("the stylesheet has no %q block", from)
		}
		rest := sheet[start:]
		end := strings.Index(rest, "\n}")
		if end < 0 {
			t.Fatalf("the %q block is not closed", from)
		}
		return rest[:end]
	}

	parse := func(text string) map[string]string {
		found := map[string]string{}
		for _, m := range tokenPattern.FindAllStringSubmatch(text, -1) {
			found[m[1]] = strings.ToLower(m[2])
		}
		return found
	}

	light := parse(block(":root {"))
	if len(light) < 8 {
		t.Fatalf("only %d colour tokens were found, which is too few to be right", len(light))
	}

	dark := map[string]string{}
	for k, v := range light {
		dark[k] = v
	}
	for k, v := range parse(block("@media (prefers-color-scheme: dark)")) {
		dark[k] = v
	}

	return map[string]map[string]string{"light": light, "dark": dark}
}

// Every colour text is set in is legible on the paper it is set on.
//
// The tokens are read out of the stylesheet rather than listed here, so a
// colour added later is checked without anyone remembering to add it — the
// same reason the class-coverage test reads its list out of the script.
func TestEveryColourTextIsSetInIsLegible(t *testing.T) {
	sheet := stylesheet(t)
	tables := schemes(t, sheet)

	used := map[string]bool{}
	for _, m := range textColourPattern.FindAllStringSubmatch(sheet, -1) {
		used[m[1]] = true
	}
	if len(used) < 5 {
		t.Fatalf("only %d text colours were found in the stylesheet, which is too few to be right", len(used))
	}

	// The two surfaces anything can be printed on. A finding sits on the sunk
	// paper and everything else on the paper, and neither is picked per rule
	// here: a colour that is legible on one and not the other is a colour
	// waiting for the day somebody moves the element.
	surfaces := []string{"paper", "paper-sunk"}

	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		for token := range used {
			value, ok := tokens[token]
			if !ok {
				t.Errorf("%s: text is set in --%s, which is not defined", scheme, token)
				continue
			}

			// The one inversion on the page: the submit button prints the
			// paper colour on ink. Checking it against paper would be
			// checking paper against itself.
			if token == "paper" {
				if got := contrast(value, tokens["ink"]); got < readableContrast {
					t.Errorf("%s: --paper on --ink is %.2f:1, below %.1f:1", scheme, got, readableContrast)
				}
				continue
			}

			for _, surface := range surfaces {
				got := contrast(value, tokens[surface])
				if got < readableContrast {
					t.Errorf("%s: --%s (%s) on --%s (%s) is %.2f:1, below %.1f:1 — %s",
						scheme, token, value, surface, tokens[surface], got, readableContrast,
						"text set in it cannot be read by a reader with ordinary vision")
				}
			}
		}
	}
}

// The rule colour draws lines and is never used for text.
//
// It is far below the text threshold on purpose — a hairline between rows
// that met it would be a bar, not a hairline — so the moment somebody sets a
// word in it, the word is unreadable and the test above would not see it,
// because the test above only checks the colours that are used for text.
func TestTheRuleColourIsNeverUsedForText(t *testing.T) {
	sheet := stylesheet(t)

	for _, m := range textColourPattern.FindAllStringSubmatch(sheet, -1) {
		if m[1] == "rule" || m[1] == "edge" {
			t.Errorf("text is set in --%s, which is a line colour and is below the readable threshold", m[1])
		}
	}

	// And it really is below it, so the exclusion is not quietly protecting a
	// colour that would now pass anyway.
	tables := schemes(t, sheet)
	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		if got := contrast(tokens["rule"], tokens["paper"]); got >= readableContrast {
			t.Errorf("%s: --rule is now %.2f:1 against paper; if it is dark enough for text, say so and drop this exception",
				scheme, got)
		}
	}
}

// A guard on the guard: the arithmetic above agrees with the published
// examples, so a mistake in it cannot quietly pass the whole page.
func TestTheContrastArithmeticIsRight(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want float64
	}{
		{"#000000", "#ffffff", 21},
		{"#ffffff", "#ffffff", 1},
		{"#777777", "#ffffff", 4.48},
		{"#767676", "#ffffff", 4.54},
	} {
		got := contrast(c.a, c.b)
		if math.Abs(got-c.want) > 0.01 {
			t.Errorf("contrast(%s, %s) = %.2f, want %.2f", c.a, c.b, got, c.want)
		}
	}
	if fmt.Sprintf("%.2f", contrast("#ffffff", "#000000")) != "21.00" {
		t.Error("contrast is not symmetric")
	}
}

// Nothing on this page is faded out of legibility.
//
// The submit button carried opacity: 0.55 while a scan ran, which fades the
// label and the ink under it together against the page: 2.29:1 in the light
// scheme and 2.54:1 in the dark, measured in a browser. That is the only
// thing the page shows for the several seconds a scan takes, and reading the
// word "Checking" is the entire purpose of the state.
//
// Opacity is allowed inside @keyframes, where it is a transition rather than
// a resting state and where a reader is not asked to read anything mid-fade.
// Everywhere else a state is said in words and in colour.
func TestNoRestingStateIsFadedOut(t *testing.T) {
	sheet := stylesheet(t)

	// Cut out the keyframe blocks, braces and all.
	stripped := sheet
	for {
		start := strings.Index(stripped, "@keyframes")
		if start < 0 {
			break
		}
		depth, end := 0, -1
		for i := start; i < len(stripped); i++ {
			switch stripped[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i + 1
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			t.Fatal("a @keyframes block is not closed")
		}
		stripped = stripped[:start] + stripped[end:]
	}

	faded := regexp.MustCompile(`opacity:\s*(0(?:\.\d+)?)\s*[;}]`)
	for _, m := range faded.FindAllStringSubmatch(stripped, -1) {
		t.Errorf("a resting state is faded to opacity %s; say the state in words and colour instead", m[1])
	}
}

// The working state is legible on the ink it is printed on.
//
// The button prints the paper colour, so whatever the disabled rule puts
// behind it has to hold the same threshold as everything else.
func TestTheWorkingStateIsLegible(t *testing.T) {
	sheet := stylesheet(t)
	tables := schemes(t, sheet)

	body := cssRule(t, sheet, ".submit:disabled")
	m := regexp.MustCompile(`background:\s*var\(--([a-z-]+)\)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the working state does not set a background of its own, so it cannot be told from the resting one")
	}

	for _, scheme := range []string{"light", "dark"} {
		tokens := tables[scheme]
		behind, ok := tokens[m[1]]
		if !ok {
			t.Errorf("%s: the working state is drawn on --%s, which is not defined", scheme, m[1])
			continue
		}
		if got := contrast(tokens["paper"], behind); got < readableContrast {
			t.Errorf("%s: the word on a working button is %.2f:1 against --%s, below %.1f:1",
				scheme, got, m[1], readableContrast)
		}
		// And it has to differ from the resting ink, or the state is invisible.
		if behind == tokens["ink"] {
			t.Errorf("%s: the working state is drawn on the same ink as the resting one", scheme)
		}
	}
}
