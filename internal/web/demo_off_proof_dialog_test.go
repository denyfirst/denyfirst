//go:build !demo

package web

import (
	"strings"
	"testing"
)

// The proof dialog exists where proof is required, and only there.
//
// An open installation has nothing to prove, and a page that asked would send
// somebody off to publish a record that changes nothing.
func TestTheProofDialogIsOfferedOnlyWhereProofIsRequired(t *testing.T) {
	bounded := consoleAs(t, true)
	for _, want := range []string{`id="proof-dialog"`, `data-proof="required"`, `id="proof-name"`, `id="proof-value"`} {
		if !strings.Contains(bounded, want) {
			t.Errorf("an installation requiring proof has no %s", want)
		}
	}

	open := consoleAs(t, false)
	for _, never := range []string{`id="proof-dialog"`, `data-proof`} {
		if strings.Contains(open, never) {
			t.Errorf("an open installation carries %s", never)
		}
	}
}

// The checks run only after the proof is asked for, and the script asks the
// endpoint the service registers.
func TestTheConsoleAsksForProofBeforeItRuns(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	if !strings.Contains(src, `const VERIFY = { endpoint: "/api/v1/verify" };`) {
		t.Error("the script does not ask /api/v1/verify")
	}
	proof := strings.Index(src, "if (!(await proven(target))) return;")
	run := strings.Index(src, "await runCheck(name, target);")
	if proof < 0 || run < 0 || proof > run {
		t.Error("the checks can run before proof is asked for")
	}
	if !strings.Contains(src, `consoleForm.dataset.proof !== "required"`) {
		t.Error("the script asks for proof on an installation that requires none")
	}
	if !strings.Contains(src, "if (answer.verified) {") {
		t.Error("the dialog does not end when the record is seen")
	}
}

// A name that is not proven is not let through.
func TestAnUnprovenNameOpensTheDialog(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		"if (!answer.required || answer.verified) return true;",
		"return waitForProof(target, answer);",
		"cancel.onclick = () => finish(false);",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the proof flow no longer contains %q", want)
		}
	}
}
