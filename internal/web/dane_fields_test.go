package web

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
)

// The page reads the field names the API sends for a DANE binding, and knows the
// outcome words the API uses.
//
// "validated" misspelled on either side reads as undefined, which is falsy, and
// every binding would carry "records not reported validated" beside a record the
// resolver did validate. An outcome word the page does not know falls through to
// "not established", which is how a match would be drawn as a question.
func TestThePageReadsTheDANEFieldsTheAPISends(t *testing.T) {
	raw, err := json.Marshal(policy.MailFacts{
		DANEBindings: []policy.DANEBinding{{
			Host: "mx1.example.net", Validated: true, Usable: 1, Outcome: policy.DANEMismatched, Reason: "a reason",
		}},
	})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	source := script(t)

	if !strings.Contains(source, "facts.daneBindings") {
		t.Error("the page does not read facts.daneBindings")
	}
	list, _ := sent["daneBindings"].([]any)
	if len(list) != 1 {
		t.Fatalf("daneBindings sent as %v", sent["daneBindings"])
	}
	one, _ := list[0].(map[string]any)
	for _, field := range []string{"host", "validated", "outcome", "reason"} {
		if _, ok := one[field]; !ok {
			t.Errorf("the API sends no %s on a binding", field)
		}
		if !regexp.MustCompile(`\bb\.` + field + `\b`).MatchString(source) {
			t.Errorf("the page does not read b.%s on a binding", field)
		}
	}

	for _, outcome := range []string{policy.DANEMatched, policy.DANEMismatched, policy.DANENoSTARTTLS, policy.DANENoUsableRecords} {
		if !strings.Contains(source, `b.outcome === "`+outcome+`"`) {
			t.Errorf("the page does not know the outcome %q, so it would draw it as not established", outcome)
		}
	}
}
