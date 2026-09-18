package web

import (
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/demo"
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

// Every check keeps its tab when fewer are chosen.
//
// One chosen check drew a single tab across the whole row. The others are
// drawn switched off: disabled, saying so, with no panel behind them and no
// place in the arrow-key rotation.
func TestAnUnchosenCheckKeepsATabItCannotOpen(t *testing.T) {
	src := script(t)
	start := strings.Index(src, "function porchTabs(")
	end := strings.Index(src, "async function runPorchEntry(")
	if start < 0 || end < start {
		t.Fatal("the Porch tab builder was not found")
	}
	body := src[start:end]
	for _, want := range []string{
		"for (const name of CHECK_ORDER) {",
		`const on = chosen.includes(name);`,
		`el("button", on ? "tab" : "tab tab-off")`,
		`on ? "running" : "not selected"`,
		"tab.disabled = true;",
		"continue;",
		"entries.push({ spec, tab, state, panel });",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the tab builder no longer contains %q", want)
		}
	}
	// The switch-off comes before the panel is made, so an unchosen check has none.
	if strings.Index(body, "continue;") > strings.Index(body, `el("div", "tab-panel")`) {
		t.Error("an unchosen check is given a panel before it is skipped")
	}
	if strings.Contains(body, "chosen.map(") {
		t.Error("the tabs are built from the chosen checks alone again")
	}
	if css, _ := assets.ReadFile("assets/style.css"); !strings.Contains(string(css), ".tab.tab-off {") {
		t.Error("a switched-off tab is not styled")
	}
}

// The help under the form says one thing and leads to the steps on the page.
func TestThePorchHelpLeadsToTheSteps(t *testing.T) {
	if !demo.Enabled {
		t.Skip("the Porch page is the demonstration's")
	}
	page := get(t, "/porch").Body.String()
	_, help, _ := strings.Cut(page, `id="porch-help"`)
	help, _, _ = strings.Cut(help, "</p>")
	if !strings.Contains(help, `<a href="#start">run Porch yourself</a>`) || !strings.Contains(page, `id="start"`) {
		t.Errorf("the help does not lead to the steps on this page:%s", help)
	}
	if strings.Contains(help, "/privacy") || strings.Contains(help, "/terms") {
		t.Errorf("the help repeats what /docs lists:%s", help)
	}
}
