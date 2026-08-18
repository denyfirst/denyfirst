package web

import (
	"strings"
	"testing"
)

// Measured and not shown is the quietest way a report lies.
//
// The probe has always recorded whether a status response arrived — the field
// was populated in tlsprobe and read by nobody. A reader looking at a
// certificate section that says nothing about revocation concludes there was
// nothing to say, and the scanner had the answer the whole time.
//
// This checks the script rather than a rendered page, because the page is
// assembled in the browser. It is a shape check: the branch is there and each
// of the four states has its own sentence.
func TestRevocationStateReachesThePage(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	for _, required := range []string{
		"revocationText",
		"mustStaple",
		"ocspStapled",
		"responderCount",
		`pair("Revocation"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("the script does not contain %q, so the revocation state is measured and not shown", required)
		}
	}

	// The four states have to be distinguishable in the output. A page that
	// prints "not stapled" for both a server that could have stapled and a
	// certificate with nothing to staple has collapsed the only distinction
	// that matters, and the first reading — that something is wrong — is the
	// wrong one for most certificates issued now.
	for _, state := range []string{
		"requires a stapled response and none was sent",
		"stapled, and the certificate requires it",
		"a status response was stapled",
		"names a responder a client would have to ask",
		"names no responder",
	} {
		if !strings.Contains(source, state) {
			t.Errorf("the script has no wording for the state %q", state)
		}
	}
}

// The certificate section needs the transport report to answer the question,
// because the request lives in the certificate and the answer arrives in the
// handshake. Called with one argument it silently reports every server as not
// stapling, which is the failure this whole change exists to remove.
func TestCertificateSectionIsGivenTheHandshake(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	if strings.Contains(source, "certificate(data.certificate)") {
		t.Error("certificate() is called without the transport report; every server will read as not stapling")
	}

	// Matched without the closing bracket on purpose. The section has since
	// been given a third argument, and pinning the exact call meant this test
	// failed for a change that was correct — which teaches whoever meets it
	// to edit the test rather than read it. What matters is that the
	// transport report is passed at all.
	if !strings.Contains(source, "certificate(data.certificate, data.tls") {
		t.Error("certificate() is not given the transport report")
	}
}
