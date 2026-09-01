package web

import (
	"regexp"
	"strings"
	"testing"
)

// The verdict comes before the sentence explaining it.
//
// The summary was one flex row: a left column holding the target, the
// address and the download link, and the stamp beside it on the right. On
// 2026-09-01 the coverage line was added to that left column as a dl, and a
// dl is a block — the column took the whole width, the row had nowhere to put
// the stamp, and it wrapped to a line of its own. On a live report of a bank
// the reader met, in order: the hostname, "Worst case: an attacker chooses
// which option to negotiate…", four lines of coverage, and only then the word
// INSECURE.
//
// So the sentence explaining the verdict arrived before the verdict, and the
// one element the whole page exists to deliver was the last thing in its own
// block. Nothing was false and nothing failed; it rendered, and it read
// backwards.
//
// The row holding the stamp is its own element now. This checks the order the
// reader actually gets.
func TestTheVerdictIsGivenBeforeItIsExplained(t *testing.T) {
	source := script(t)

	// Where each of the three is attached, in source order. The summary is
	// built by appending in order, so source order is reading order.
	at := func(needle string) int {
		i := strings.Index(source, needle)
		if i < 0 {
			t.Fatalf("app.js no longer contains %q, so this test has stopped checking anything", needle)
		}
		return i
	}

	stamp := at("head.appendChild(stamp)")
	worst := at(`wrap.appendChild(el("p", "summary-worst"`)
	coverage := at("wrap.appendChild(reached)")
	row := at("wrap.appendChild(head)")

	if !(row < worst && row < coverage) {
		t.Error("the row holding the verdict is added after the sentences about it, " +
			"so a reader meets the explanation first")
	}
	if stamp > row {
		t.Error("the stamp is not in the row that is added first")
	}
	if worst > coverage {
		t.Error("what a verdict means now comes after how much was reached; " +
			"the sentence explains the stamp and belongs next to it")
	}

	// The two sentences must not go back into the row. That is the exact
	// shape that broke it: anything in there that wraps to more than a few
	// words pushes the stamp out of the line.
	for _, wrong := range []string{
		`left.appendChild(el("p", "summary-worst"`,
		"left.appendChild(reached)",
		`head.appendChild(el("p", "summary-worst"`,
		"head.appendChild(reached)",
	} {
		if strings.Contains(source, wrong) {
			t.Errorf("%s puts a growing block in the row with the stamp, which is what "+
				"pushed the verdict below four lines of coverage", wrong)
		}
	}
}

// Whatever holds the verdict is a row of its own.
//
// The defect above was not in the script. The script appended a dl to a
// column, which is ordinary; what turned it into a wrapped stamp was that the
// column and the stamp shared a flex container. Keeping the order right in
// the script and leaving `.summary` a flex row would reproduce it the next
// time anything is added to the summary.
func TestTheVerdictRowIsSeparateFromWhatIsWrittenUnderIt(t *testing.T) {
	css, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("reading the stylesheet: %v", err)
	}

	rule := func(selector string) string {
		re := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(selector) + `\s*\{(.*?)\}`)
		m := re.FindStringSubmatch(string(css))
		if m == nil {
			t.Fatalf("the stylesheet has no rule for %s", selector)
		}
		return m[1]
	}

	if !strings.Contains(rule(".summary-head"), "display: flex") {
		t.Error(".summary-head is the row that puts the stamp beside the target and is no longer a row")
	}
	if strings.Contains(rule(".summary"), "display: flex") {
		t.Error(".summary is a flex container again, so the block written under the verdict " +
			"shares a line with it and the stamp wraps below it")
	}
}

// A count of one reads as one.
//
// The pointer at the standing limits was built as `n + " limits of this
// method apply…"`, so a report carrying a single limit said "1 limits". That
// is reachable rather than theoretical: two of the four are conditional, and
// a host that speaks only TLS 1.2 and returns no transparency receipts leaves
// exactly one. Both faces had it, in their own words.
func TestOneLimitIsNotWrittenAsPlural(t *testing.T) {
	source := script(t)

	if !strings.Contains(source, `"1 limit of this method applies to every scan`) {
		t.Error("the page has no singular form, so a report carrying one limit says \"1 limits\"")
	}
	if !strings.Contains(source, `" limits of this method apply to every scan`) {
		t.Error("the plural form is gone, so every report with four limits now says \"4 limit\"")
	}
}
