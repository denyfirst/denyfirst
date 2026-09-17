package web

import (
	"strings"
	"testing"
)

// The Porch page gives each check a tab of its own and a state of its own.
//
// Read from the source, as the other script tests are: nothing here runs it.
// What matters is that a check's verdict is written to that check's tab only,
// that a failure is written as "not run" rather than left as "running", and
// that the tabs are a tab list a keyboard can move through.
func TestEachCheckHasATabAndAStateOfItsOwn(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		`tabs.setAttribute("role", "tablist");`,
		`tab.setAttribute("role", "tab");`,
		`panel.setAttribute("role", "tabpanel");`,
		`entry.state.className = "tab-state " + verdictClass("stamp", verdict);`,
		`entry.state.textContent = "not run";`,
		`entry.tab.setAttribute("aria-selected", String(on));`,
		`entry.panel.hidden = !on;`,
		`if (event.key === "ArrowRight")`,
		`entry.panel.appendChild(entry.spec.build(data));`,
		`await runPorchEntry(entry, target);`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the Porch runner no longer contains %q", want)
		}
	}
	// One at a time, as the console runs them.
	if strings.Contains(src, "Promise.all(entries") {
		t.Error("the Porch page runs its checks at once, which the per-host budget exists to discourage")
	}
}
