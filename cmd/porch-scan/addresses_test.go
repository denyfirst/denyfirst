package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/tlsprobe"
)

// sampleWithAddresses is a scan whose name answered on the given addresses.
func sampleWithAddresses(answers ...tlsprobe.AddressAnswer) *scan.Result {
	return &scan.Result{Target: "multi.example.test:443", TLS: &tlsprobe.Report{Addresses: answers}}
}

// Each address is a row, in the words the page uses (R16), and the report
// prints them rather than only the helper.
func TestEachAddressIsARowInThePagesWords(t *testing.T) {
	page, err := os.ReadFile("../../internal/web/assets/app.js")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}

	answered := tlsprobe.AddressAnswer{Address: "192.0.2.1:443", Answered: true, Version: "TLS 1.3",
		Suite: "TLS_AES_128_GCM_SHA256", Certificate: "0123456789abcdef0123456789abcdef"}
	silent := tlsprobe.AddressAnswer{Address: "192.0.2.2:443", Reason: "no connection opened"}

	if got := addressLine(answered); got != "TLS 1.3 TLS_AES_128_GCM_SHA256, certificate 0123456789abcdef…" {
		t.Errorf("an answering address reads %q", got)
	}
	if got := addressLine(silent); got != "no answer: no connection opened" {
		t.Errorf("a silent address reads %q", got)
	}
	if got := addressLine(tlsprobe.AddressAnswer{Answered: true, Version: "TLS 1.2", Suite: "x"}); !strings.HasSuffix(got, "certificate none presented") {
		t.Errorf("an address presenting no certificate reads %q", got)
	}
	for _, phrase := range []string{`"no answer: "`, `", certificate "`, `"none presented"`, "slice(0, 16)", `"…"`} {
		if !strings.Contains(string(page), phrase) {
			t.Errorf("the page does not say %s, so the two faces word an address differently", phrase)
		}
	}

	var buf bytes.Buffer
	printReport(&buf, result{Result: sampleWithAddresses(answered, silent)})
	for _, want := range []string{"Each address, asked on its own", "192.0.2.1:443", "no answer: no connection opened"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the report does not print %q:\n%s", want, buf.String())
		}
	}
}

// A report of a name on one address prints no section for it.
func TestOneAddressPrintsNoAddressSection(t *testing.T) {
	var buf bytes.Buffer
	printReport(&buf, result{Result: sampleWithAddresses()})
	if strings.Contains(buf.String(), "Each address") {
		t.Errorf("a section was printed for addresses nobody asked about:\n%s", buf.String())
	}
}
