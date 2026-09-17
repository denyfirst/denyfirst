package web

import (
	"strings"
	"testing"
)

// The page draws the obsolete-suite section as the terminal does (R16): the
// same title, no SSL 3.0 row in it, and no repeated refusal sentence.
func TestTheLegacySectionMatchesTheTerminal(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	if !strings.Contains(src, `sectionTitle("Obsolete suites, asked for directly")`) {
		t.Error("the section is not titled as the terminal titles it")
	}
	if strings.Contains(src, `answer("SSL 3.0"`) {
		t.Error("the suites section still lists SSL 3.0, which the version table carries")
	}
	if !strings.Contains(src, "if (!v.supported && !v.refused && v.error)") {
		t.Error("a refused row still repeats its refusal as a note")
	}
	if !strings.Contains(src, "ssl3.suite.name") {
		t.Error("the SSL 3.0 row does not name its suite")
	}
}
