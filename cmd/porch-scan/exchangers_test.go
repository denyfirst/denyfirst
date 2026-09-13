package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// Each exchanger is a row, in the words the page uses.
func TestEachExchangerIsARowInThePagesWords(t *testing.T) {
	good := policy.ExchangerTLS{Host: "mx1.example.net", Measured: true, Offered: true, Upgraded: true,
		Version: "TLS 1.3", Suite: "TLS_AES_128_GCM_SHA256", Trusted: true, NameMatches: true}

	for name, tc := range map[string]struct {
		change func(*policy.ExchangerTLS)
		want   string
	}{
		"verifies":     {func(*policy.ExchangerTLS) {}, "TLS 1.3 TLS_AES_128_GCM_SHA256, certificate verifies"},
		"not measured": {func(x *policy.ExchangerTLS) { x.Measured, x.Reason = false, "a reason" }, "not measured: a reason"},
		"port 25 blocked": {func(x *policy.ExchangerTLS) {
			x.Measured, x.ConnectTimedOut, x.Reason = false, true, "a long sentence that belongs in the notes"
		}, "not measured: port 25 could not be reached from here"},
		"not offered":    {func(x *policy.ExchangerTLS) { x.Offered = false }, "not offered"},
		"not negotiated": {func(x *policy.ExchangerTLS) { x.Upgraded, x.Reason = false, "a reason" }, "offered, not negotiated: a reason"},
		"untrusted":      {func(x *policy.ExchangerTLS) { x.Trusted, x.CertificateReason = false, "it expired" }, "certificate does not verify: it expired"},
		"another's name": {func(x *policy.ExchangerTLS) { x.NameMatches = false }, "certificate does not name this exchanger"},
	} {
		x := good
		tc.change(&x)
		if got := exchangerLine(x); !strings.Contains(got, tc.want) {
			t.Errorf("%s: the row says %q, want %q", name, got, tc.want)
		}
	}

	// And the report prints them under the mail path, not only the helper.
	var buf bytes.Buffer
	printMailPath(&buf, &policy.MailFacts{
		MXRead: true, MXHosts: []string{"mx1.example.net"},
		ExchangersContacted: true, Exchangers: []policy.ExchangerTLS{good},
	})
	if !strings.Contains(buf.String(), "STARTTLS   mx1.example.net: TLS 1.3") {
		t.Errorf("the mail path does not carry the exchanger:\n%s", buf.String())
	}
}

// Exchangers not contacted are a row saying so, with the reason.
func TestExchangersNotContactedAreARowSayingWhy(t *testing.T) {
	var buf bytes.Buffer
	printMailPath(&buf, &policy.MailFacts{
		MXRead: true, MXHosts: []string{"mx1.example.net"},
		ExchangersReason: "this deployment does not contact mail servers",
	})
	if !strings.Contains(buf.String(), "STARTTLS   not measured: this deployment does not contact mail servers") {
		t.Errorf("no row says the exchangers were not contacted:\n%s", buf.String())
	}
}

// The command line asks the exchangers, with the name -helo gave.
func TestTheCommandLineAsksTheExchangersWithItsName(t *testing.T) {
	s := mailScanner(5*time.Second, nil, "mail.example.test")
	if !s.ReadExchangers {
		t.Error("the command line does not ask the exchangers")
	}
	if s.HeloName != "mail.example.test" {
		t.Errorf("HeloName = %q; -helo did not reach the scanner", s.HeloName)
	}
}
