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

// Both places that show the record default to the name itself, the first in
// the list, and never to the broadest (audit 2026-09-18, D05): the last entry
// for www.shop.co.uk is co.uk, a zone its owner does not run. A parent is
// the operator's choice, and the hint says what choosing one gives away.
func TestTheProofDefaultsToTheNameItself(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, fill := range []string{"function fillProof(records) {", "function showDomainRecord(answer) {"} {
		start := strings.Index(src, fill)
		if start < 0 {
			t.Fatalf("the script no longer has %q", fill)
		}
		end := strings.Index(src[start:], "\n}\n")
		fn := src[start : start+end]
		if !strings.Contains(fn, `level.value = "0";`) {
			t.Errorf("%s does not default to the name itself", fill)
		}
		if strings.Contains(fn, "records.length - 1") {
			t.Errorf("%s still reaches for the broadest domain", fill)
		}
	}
	for _, page := range []string{"assets/console.html", "assets/domains.html"} {
		if !strings.Contains(asset(t, page), "choose one only if you run its DNS") {
			t.Errorf("%s does not say what a domain above the name gives away", page)
		}
	}
}

// Domains says whether the proof was signed, as the resolver's word (A06).
func TestDomainsSaysWhetherTheProofWasSigned(t *testing.T) {
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		`"The resolver reported the record DNSSEC-signed."`,
		`"The record is not DNSSEC-signed, so the proof rests on the resolver's answer alone."`,
		`answer.signed ? "proven, signed" : "proven"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js no longer says %s", want)
		}
	}
}
