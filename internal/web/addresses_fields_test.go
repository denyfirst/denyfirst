package web

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// The page reads the field names the API sends for each address, and draws the
// section.
//
// "answered" misspelled on either side reads as undefined, which is falsy, and
// every address would be drawn "no answer" beside machines that answered — the
// alarming sentence, and a wrong one.
func TestThePageReadsTheAddressFieldsTheAPISends(t *testing.T) {
	raw, err := json.Marshal(tlsprobe.Report{
		Addresses: []tlsprobe.AddressAnswer{{
			Address: "192.0.2.1:443", Answered: true, Version: "TLS 1.3", Suite: "TLS_AES_128_GCM_SHA256",
			Certificate: "0123", Reason: "a reason",
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

	if !strings.Contains(source, "tls.addresses") {
		t.Error("the page does not read tls.addresses")
	}
	// The call, not the name. "addresses(tls)" is the function's own signature,
	// and a sabotage removing the only call escaped on 2026-09-14 because this
	// accepted either.
	if !strings.Contains(source, "frag.appendChild(addresses(data.tls))") {
		t.Error("nothing on the page draws addresses(), so the section is never shown")
	}
	// And the sentence's own condition. The row's class reads a.answered too,
	// so a misspelling inside addressSays alone escaped the whole-word check
	// below on the same day, and every row would have said "no answer".
	if !strings.Contains(source, "if (!a.answered) return") {
		t.Error("addressSays does not read a.answered, so every address would be drawn as not answering")
	}
	list, _ := sent["addresses"].([]any)
	if len(list) != 1 {
		t.Fatalf("addresses sent as %v", sent["addresses"])
	}
	one, _ := list[0].(map[string]any)
	for _, field := range []string{"address", "answered", "version", "suite", "certificate", "reason"} {
		if _, ok := one[field]; !ok {
			t.Errorf("the API sends no %s on an address", field)
		}
		if !regexp.MustCompile(`\ba\.` + field + `\b`).MatchString(source) {
			t.Errorf("the page does not read a.%s on an address", field)
		}
	}
}
