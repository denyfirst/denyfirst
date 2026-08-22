package certinfo

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
	"time"
)

// An expired certificate from an authority nobody trusts must not be reported
// as trusted.
//
// Go checks a certificate's dates before it looks for an issuer, so Expired is
// the error it returns for an expired certificate whether or not anything
// would ever have vouched for it. Reading that error as "trusted apart from
// the dates" was true for a real certificate past its renewal date and false
// for every self-signed or private-CA certificate that had gone stale — and
// those are the ones a scan of an abandoned service actually finds.
//
// Three things went wrong at once, which is why this is asserted rather than
// left to the expiry test: the trusted flag itself, the suppression of
// cert.chain-untrusted, and a transparency note that turns round and tells a
// private certificate that browsers refuse it for not being logged.
func TestAnExpiredUntrustedChainIsNotReportedTrusted(t *testing.T) {
	root := newRoot(t) // deliberately not installed anywhere
	leaf := newLeaf(t, root, leafOpts{
		dnsNames:  []string{"expired.test"},
		notBefore: refNow.AddDate(0, 0, -60),
		notAfter:  refNow.AddDate(0, 0, -7),
	})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "expired.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if report.Trusted {
		t.Error(`an expired certificate from an untrusted root was reported as trusted.

Verification failed with Expired, which says nothing about whether any
authority vouches for this certificate: Go never got as far as looking. Ask
again at a moment inside the certificate's own validity window and report that
answer.`)
	}

	var untrusted, expired bool
	for _, f := range report.Grade.Findings {
		switch f.RuleID {
		case "cert.chain-untrusted":
			untrusted = true
		case "cert.expired":
			expired = true
		}
	}
	if !expired {
		t.Error("the certificate is out of date and no expiry finding was raised")
	}
	if !untrusted {
		t.Error("no authority vouches for this certificate and no untrusted-chain finding was raised")
	}
}

// The mechanism, asserted separately from the report it feeds.
func TestTrustWithinValidityAsksARealQuestion(t *testing.T) {
	root := newRoot(t)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)

	// This root is in no trust store, so the honest answer inside the window
	// is still no. What is asserted is that the answer comes from asking
	// rather than from the error code.
	stale := newLeaf(t, root, leafOpts{
		dnsNames:  []string{"stale.test"},
		notBefore: refNow.AddDate(0, 0, -60),
		notAfter:  refNow.AddDate(0, 0, -7),
	})
	if trustedWithinValidity(stale, pool) {
		t.Error("a chain to an uninstalled root verified inside its window; the intermediates pool is not the trust store")
	}

	// A window with no interior is refused rather than probed at some moment
	// that does not exist.
	backwards := newLeaf(t, root, leafOpts{
		dnsNames:  []string{"backwards.test"},
		notBefore: refNow,
		notAfter:  refNow.Add(-time.Hour),
	})
	if trustedWithinValidity(backwards, pool) {
		t.Error("a certificate whose validity ends before it begins was reported trusted")
	}
}

// A scanned server chooses the text in its own certificate, and this report is
// a claim about which name that server presented. A character that changes how
// the following text is displayed lets the server choose what the claim looks
// like.
//
// U+202E is the published form — Trojan Source, CVE-2021-42574. The zero-width
// characters are the quieter one: a name that reads as another name while
// being a different string. Neither is a control byte, so neither was caught
// by the rule that catches ESC, and both reach a terminal and a browser
// intact; textContent does not switch off the bidirectional algorithm.
func TestNothingCanRewriteHowTheReportReads(t *testing.T) {
	cases := []struct {
		label string
		in    string
	}{
		{"right-to-left override U+202E", "safe.test\u202Emoc.knab-live"},
		{"left-to-right override U+202D", "safe.test\u202Dsomething"},
		{"left-to-right embedding U+202A", "a\u202Ab"},
		{"right-to-left embedding U+202B", "a\u202Bb"},
		{"pop directional formatting U+202C", "a\u202Cb"},
		{"first strong isolate U+2068", "a\u2068b\u2069c"},
		{"right-to-left isolate U+2067", "a\u2067b\u2069c"},
		{"left-to-right mark U+200E", "a\u200Eb"},
		{"right-to-left mark U+200F", "a\u200Fb"},
		{"zero-width space U+200B", "goo\u200Bgle.test"},
		{"zero-width non-joiner U+200C", "a\u200Cb"},
		{"zero-width joiner U+200D", "a\u200Db"},
		{"word joiner U+2060", "a\u2060b"},
		{"byte order mark U+FEFF", "a\uFEFFb"},
		{"soft hyphen U+00AD", "exam\u00ADple.test"},
		{"escape, already caught", "a\x1b[2Kb"},
	}

	for _, c := range cases {
		if got := sanitise(c.in); got == c.in {
			t.Errorf("%s: sanitise left the input unchanged, so a server can use it to decide "+
				"what this report appears to say", c.label)
		}
	}

	// And nothing ordinary is touched: no marker where nothing was wrong.
	for _, ok := range []string{
		"example.com",
		"CN=example.com,O=Example Ltd,C=GB",
		"münchen.example",
		"日本.example",
		"xn--mnchen-3ya.example",
		"*.wildcard.example",
	} {
		if got := sanitise(ok); got != ok {
			t.Errorf("sanitise(%q) = %q; an ordinary name was altered", ok, got)
		}
	}
}

// The verdict must not disagree with the line above it.
func TestSummaryDoesNotCallAnExpiredCertificateCurrent(t *testing.T) {
	root := newRoot(t)
	// Expired eight hours ago: DaysRemaining truncates to zero, which used to
	// read as "0 days remaining" beside a verdict of insecure.
	leaf := newLeaf(t, root, leafOpts{
		dnsNames:  []string{"just.test"},
		notBefore: refNow.AddDate(0, 0, -30),
		notAfter:  refNow.Add(-8 * time.Hour),
	})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "just.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	summary := report.Summary()
	if report.Grade.DaysRemaining != 0 {
		t.Fatalf("this test needs the truncating case; DaysRemaining = %d", report.Grade.DaysRemaining)
	}
	if !strings.Contains(summary, "expired") {
		t.Errorf("Summary() = %q, and the report carries a cert.expired finding; the two disagree", summary)
	}
}

// A capability the standard library has no name for is still a capability.
//
// Go puts an extended key usage it holds no constant for into
// UnknownExtKeyUsage rather than into ExtKeyUsage, and this report used to
// read only the second. A certificate carrying an OID outside the seven Go
// names therefore rendered as though it carried nothing but the ones it did
// name — which is the wrong answer to "what is this certificate allowed to
// do", and wrong in the direction that makes the certificate look narrower
// than it is.
//
// The OID is printed as an OID. This package holds no registry that would
// turn it into a name, and a report that guesses at one has started
// inventing.
func TestAnUnnamedExtendedKeyUsageIsStillReported(t *testing.T) {
	root := newRoot(t)

	// id-kp-documentSigning, 1.3.6.1.5.5.7.3.36: real, registered, and not
	// one of the seven crypto/x509 has a constant for.
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}
	leaf := newLeaf(t, root, leafOpts{unknownEKU: []asn1.ObjectIdentifier{oid}})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	usages := strings.Join(report.Chain[0].ExtKeyUsage, " ")
	if !strings.Contains(usages, oid.String()) {
		t.Errorf("extended key usages = %q; the certificate also carries %s and the report does not say so",
			usages, oid)
	}
	if !strings.Contains(usages, "serverAuth") {
		t.Errorf("extended key usages = %q; the named usage was lost", usages)
	}
}
