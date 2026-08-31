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
// What this checks changed on 2026-08-31. The sentence used to be composed
// here, in JavaScript, from four fields; it is built in internal/policy now
// and arrives as one string, because a sentence composed in this file could
// not be shown by the terminal report and could not be executed by any test.
// So the shape to check is no longer "does the script build the sentence" but
// "does the script show the one it was given, and refrain from building
// another".
func TestRevocationStateReachesThePage(t *testing.T) {
	source := script(t)

	if !strings.Contains(source, `pair("Revocation"`) {
		t.Error("the certificate section has no Revocation row, so the state is measured and not shown")
	}
	if !strings.Contains(source, "revocationLine") {
		t.Error("the row does not read the line the report carries")
	}

	// Composing it again here is the defect this arrangement exists to
	// prevent: two renderers building one claim from the same facts is how
	// the two come to disagree, and this report has already been through it.
	for _, gone := range []string{
		"function revocationText",
		"revocation.mustStaple",
		"tls.ocspStapled",
		"revocation.responderCount",
	} {
		if strings.Contains(source, gone) {
			t.Errorf("the script still composes the revocation sentence from %q; "+
				"the sentence belongs in internal/policy so that both faces read one string", gone)
		}
	}
}

// The certificate section needs the transport report to answer the question,
// because the request lives in the certificate and the answer arrives in the
// handshake. Called with one argument it silently reports every server as not
// stapling, which is the failure this whole change exists to remove.
func TestCertificateSectionIsGivenTheHandshake(t *testing.T) {
	source := script(t)

	if strings.Contains(source, "certificate(data.certificate)") {
		t.Error("certificate() is called without the transport report; every server will read as not stapling")
	}

	// Matched without the closing bracket on purpose. The section has since
	// been given further arguments, and pinning the exact call meant this
	// test failed for a change that was correct — which teaches whoever meets
	// it to edit the test rather than read it.
	if !strings.Contains(source, "certificate(data.certificate, data.tls") {
		t.Error("certificate() is not given the transport report")
	}

	// And the report itself, which is where the two sentences now arrive.
	if !strings.Contains(source, "data.stapling, data)") {
		t.Error("the section is not given the report, so the revocation and transparency lines are empty")
	}
}
