package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
)

// Each exchanger's DANE binding is a row, in the words the page uses (R16).
func TestEachDANEBindingIsARowInThePagesWords(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}

	for _, tc := range []struct {
		b    policy.DANEBinding
		want string
	}{
		{policy.DANEBinding{Validated: true, Outcome: policy.DANEMatched}, "matches the certificate presented"},
		{policy.DANEBinding{Validated: true, Outcome: policy.DANEMismatched, Reason: "a reason"}, "does not match: a reason"},
		{policy.DANEBinding{Validated: true, Outcome: policy.DANENoSTARTTLS}, "records published, STARTTLS not offered"},
		{policy.DANEBinding{Validated: true, Outcome: policy.DANENoUsableRecords}, "no record a sender uses for SMTP"},
		{policy.DANEBinding{Validated: true, Outcome: policy.DANEUndetermined, Reason: "a reason"}, "not established: a reason"},
		{policy.DANEBinding{Outcome: policy.DANEMatched}, "matches the certificate presented (records not reported validated)"},
	} {
		got := daneLine(tc.b)
		if got != tc.want {
			t.Errorf("%+v: the row says %q, want %q", tc.b, got, tc.want)
		}
		// The page says the same words: each fixed phrase is in its source.
		phrase, _, _ := strings.Cut(tc.want, ": a reason")
		for _, part := range strings.Split(phrase, " (") {
			if !strings.Contains(string(page), strings.TrimSuffix(part, ")")) {
				t.Errorf("the page does not say %q", part)
			}
		}
	}

	// And the report prints them under the mail path.
	var buf bytes.Buffer
	printMailPath(&buf, &policy.MailFacts{
		MXRead: true, MXHosts: []string{"mx1.example.net"},
		ExchangersContacted: true,
		DANEBindings:        []policy.DANEBinding{{Host: "mx1.example.net", Validated: true, Outcome: policy.DANEMatched}},
	})
	if !strings.Contains(buf.String(), "DANE       mx1.example.net: matches the certificate presented") {
		t.Errorf("the mail path does not carry the binding:\n%s", buf.String())
	}
}
