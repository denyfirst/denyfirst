package web

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// The page reads the field names the API sends for the exchangers.
//
// "offered" misspelled on either side of the seam reads as undefined, which is
// falsy — so every exchanger would be drawn "not offered" over servers that
// offer STARTTLS, and nothing errors. The reassuring word would at least be
// loud; this is the alarming one, and it would be wrong.
func TestThePageReadsTheExchangerFieldsTheAPISends(t *testing.T) {
	raw, err := json.Marshal(policy.MailFacts{
		ExchangersContacted: true,
		ExchangersReason:    "a reason",
		Exchangers: []policy.ExchangerTLS{{
			Host: "mx1.example.net", Connected: true, Measured: true, Offered: true, Upgraded: true,
			Version: "TLS 1.3", Suite: "TLS_AES_128_GCM_SHA256", Trusted: true, NameMatches: true,
			CertificateReason: "a reason", Reason: "a reason", ConnectTimedOut: true,
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

	for _, field := range []string{"exchangersContacted", "exchangersReason", "exchangers"} {
		if _, ok := sent[field]; !ok {
			t.Errorf("the API sends no %s", field)
		}
		if !strings.Contains(source, "facts."+field) {
			t.Errorf("the page does not read facts.%s", field)
		}
	}

	list, _ := sent["exchangers"].([]any)
	if len(list) != 1 {
		t.Fatalf("exchangers sent as %v", sent["exchangers"])
	}
	one, _ := list[0].(map[string]any)
	for _, field := range []string{"host", "measured", "offered", "upgraded", "version", "suite",
		"trusted", "nameMatches", "certificateReason", "reason", "connectTimedOut"} {
		if _, ok := one[field]; !ok {
			t.Errorf("the API sends no %s on an exchanger", field)
		}
		// A whole word, not a substring. "x.connectTimedOuts" contains
		// "x.connectTimedOut", and a sabotage misspelling it that way escaped
		// on 2026-09-13 — undefined in the page, and a blocked port 25 drawn
		// as the long sentence rather than the short row.
		if !regexp.MustCompile(`\bx\.` + field + `\b`).MatchString(source) {
			t.Errorf("the page does not read x.%s on an exchanger", field)
		}
	}
}
