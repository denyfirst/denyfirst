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

	// The states have to be distinguishable in the output. A page that prints
	// "not stapled" for both a server that could have stapled and a
	// certificate with nothing to staple has collapsed the only distinction
	// that matters, and the first reading — that something is wrong — is the
	// wrong one for most certificates issued now.
	//
	// There were four states and there are now six: reading the response
	// splits "stapled" into verified and unverifiable, in both the ordinary
	// and the must-staple case. This list used to require the exact sentence
	// "stapled, and the certificate requires it", which the more precise
	// wording no longer contains — a test pinning a phrase rather than a
	// state, which is the trap the privacy page fell into. Each entry below
	// is now the shortest fragment that identifies its state and nothing
	// about how it is phrased.
	for _, state := range []string{
		"requires a stapled response and none was sent",
		"the one sent could not be verified",
		"the certificate requires it",
		"a status response was stapled",
		"establishes nothing",
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

// The certificate section has to say whether the stapled response was read.
//
// This line said "a status response was stapled" for a whole policy version
// after that stopped being the whole story. internal/ocsp parses the
// response, matches it to the certificate, checks it has not expired and
// verifies the authority's signature — and the one line a reader looks at for
// exactly this went on reporting a byte count. The same defect as R12, in the
// same file, one round later.
func TestTheRevocationLineSaysWhetherTheResponseWasVerified(t *testing.T) {
	source, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	script := string(source)

	if !strings.Contains(script, "function revocationText(revocation, tls, stapling)") {
		t.Error("revocationText is not given the stapling result, so it cannot say whether it verified")
	}
	if !strings.Contains(script, "stapling.validated") {
		t.Error("the script never reads whether the response verified")
	}
	if !strings.Contains(script, "establishes nothing") {
		t.Error("an unverifiable response has no sentence of its own")
	}

	// Negated rather than compared against false: a response missing the
	// field must get the cautious sentence, which is the polarity the Go
	// fields were given for the same reason.
	if strings.Contains(script, "stapling.validated === true") {
		t.Error("an absent validated field would be read as verified")
	}

	// The page has to be handed the field in the first place.
	if !strings.Contains(script, "data.stapling") {
		t.Error("the report's stapling result never reaches the certificate section")
	}
}
