package policy

import (
	"strings"
	"testing"
)

// A well configured server, as measured.
func holding() AssuranceFacts {
	return AssuranceFacts{
		TLS13Accepted:      true,
		TLS13Preferred:     true,
		ObsoleteAccepted:   false,
		SuitesGraded:       4,
		CipherListComplete: true,
		AllSuitesStrong:    true,
		PreferenceKnown:    true,
		ServerPreference:   true,
		ChainTrusted:       true,
		ChainComplete:      true,
		ChainLength:        3,
		NameMatches:        true,
		CertificateInDate:  true,
		RevocationVerified: true,
		TransparencyCount:  3,
		TransparencyLogs:   3,
		PostQuantumOffered: true,
		PostQuantumGroup:   "X25519MLKEM768",
		IssuanceRestricted: true,
		IssuanceFoundAt:    "example.com",
	}
}

func ids(f AssuranceFacts) map[string]string {
	out := map[string]string{}
	for _, a := range Assurances(f) {
		out[a.ID] = a.Text
	}
	return out
}

// The direction that matters least and is checked first: everything measured
// produces everything that can be said.
func TestEverythingThatHeldIsSaid(t *testing.T) {
	got := ids(holding())
	for _, want := range []string{
		"tls13", "no-obsolete", "suites", "server-order",
		"chain", "revocation", "transparency", "post-quantum", "issuance",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s was measured and is not said", want)
		}
	}
}

// The direction that matters: nothing measured, nothing claimed.
//
// This is the failure an affirmative summary invites. Read the findings
// instead of the measurements and "no rule fired" becomes an assurance —
// which is true of a scan that established nothing at all, and would put a
// list of reassurances on the emptiest report this program can produce.
func TestAScanThatMeasuredNothingAssuresNothing(t *testing.T) {
	if got := Assurances(AssuranceFacts{}); len(got) != 1 {
		t.Fatalf("an empty scan produced %d assurances, want only the one about obsolete versions:\n%+v",
			len(got), got)
	}

	// The single exception, and it is honest: no handshake completed at TLS
	// 1.0 or 1.1 is a true statement about a scan where no handshake
	// completed at all. It says what was measured and not that the server
	// refuses anything, which is the standing limit this could most easily
	// have broken.
	only := Assurances(AssuranceFacts{})[0]
	if only.ID != "no-obsolete" {
		t.Errorf("the one assurance an empty scan makes is %q", only.ID)
	}
	if strings.Contains(strings.ToLower(only.Text), "refus") {
		t.Errorf("it claims the server refused something, which was not measured:\n  %s", only.Text)
	}
}

// Strong is the verdict that claims an absence, and so is this sentence.
//
// A truncated suite list supports "something weak is here" and never "nothing
// weak is here". The host decides when to stop answering, so a server could
// otherwise buy itself a line of praise by going quiet after two handshakes —
// the same shape as the 2026-08-22 defect where a truncated list produced a
// strong verdict.
func TestATruncatedSuiteListAssuresNothingAboutSuites(t *testing.T) {
	f := holding()
	f.CipherListComplete = false

	if _, said := ids(f)["suites"]; said {
		t.Error("a suite list that was cut short still produced a claim about every suite")
	}

	// And one weak suite in a complete list is enough to withhold it.
	f = holding()
	f.AllSuitesStrong = false
	if _, said := ids(f)["suites"]; said {
		t.Error("a suite graded below strong still produced a claim that every suite was strong")
	}
}

// Each line withholds itself when its own fact is absent.
func TestEachAssuranceWaitsForItsOwnMeasurement(t *testing.T) {
	cases := []struct {
		id     string
		absent func(*AssuranceFacts)
	}{
		{"tls13", func(f *AssuranceFacts) { f.TLS13Accepted = false }},
		{"no-obsolete", func(f *AssuranceFacts) { f.ObsoleteAccepted = true }},
		{"server-order", func(f *AssuranceFacts) { f.ServerPreference = false }},
		{"server-order", func(f *AssuranceFacts) { f.PreferenceKnown = false }},
		{"chain", func(f *AssuranceFacts) { f.ChainTrusted = false }},
		{"chain", func(f *AssuranceFacts) { f.ChainComplete = false }},

		// The two that "trusted" does not cover. Both were measured against
		// badssl.com on 2026-09-01 and both produced the sentence.
		{"chain", func(f *AssuranceFacts) { f.NameMatches = false }},
		{"chain", func(f *AssuranceFacts) { f.CertificateInDate = false }},
		{"revocation", func(f *AssuranceFacts) { f.RevocationVerified = false }},
		{"transparency", func(f *AssuranceFacts) { f.TransparencyCount = 0 }},
		{"post-quantum", func(f *AssuranceFacts) { f.PostQuantumOffered = false }},
		{"issuance", func(f *AssuranceFacts) { f.IssuanceRestricted = false }},
	}

	for _, c := range cases {
		f := holding()
		c.absent(&f)
		if _, said := ids(f)[c.id]; said {
			t.Errorf("%s is claimed with the measurement behind it removed", c.id)
		}
	}
}

// No verdict is invented, and no threshold is repeated.
//
// An assurance states what was measured. "Every suite was graded strong" is a
// report of this rule set's own output; "this server has forward secrecy" is
// an inference from it, and rule sets move. The key size and the days
// remaining are on the certificate line, where the rules own the numbers that
// decide whether they are enough.
func TestAnAssuranceStatesAMeasurementRatherThanAJudgement(t *testing.T) {
	joined := strings.ToLower(strings.Join(func() []string {
		var out []string
		for _, a := range Assurances(holding()) {
			out = append(out, a.Text)
		}
		return out
	}(), " "))

	for _, forbidden := range []string{
		"forward secrecy",
		"secure",
		"safe",
		"excellent",
		"best practice",
		"bits",
		"days",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("an assurance says %q, which is a judgement or a threshold this file does not own:\n%s",
				forbidden, joined)
		}
	}
}

// The two live counter-examples, kept as cases rather than as a comment.
//
// Both are true statements about a chain and both sat under a heading called
// What holds, above a verdict of insecure, on a report whose whole subject was
// that the certificate did not identify the server.
func TestAChainThatFailsIdentityHoldsNothing(t *testing.T) {
	// expired.badssl.com: valid for three days in 2015, and this chain still
	// reaches a root because trust is re-asked at a moment it was valid.
	expired := holding()
	expired.CertificateInDate = false

	// wrong.host.badssl.com: a certificate for *.badssl.com, served for a
	// name it does not cover.
	wrongName := holding()
	wrongName.NameMatches = false

	for name, f := range map[string]AssuranceFacts{"expired": expired, "wrong name": wrongName} {
		for _, a := range Assurances(f) {
			if a.ID == "chain" {
				t.Errorf("%s: the chain is assured anyway:\n  %s", name, a.Text)
			}
		}
	}
}

// An assurance is a phrase, not a paragraph.
//
// Written as sentences, every line of this block restated something already
// on the report — the version table, the suite grades, the certificate rows,
// and in one case the sentence printed under the cipher table, word for word.
// Nine out of nine. A summary that repeats the page in longer form is not a
// summary; it is a screen of prose between a reader and the evidence.
//
// The ceiling is what stops it growing back. Explanations belong on /method,
// where they are written once instead of on every report.
func TestAnAssuranceIsAPhraseAndNotAParagraph(t *testing.T) {
	const ceiling = 72

	for _, a := range Assurances(holding()) {
		if len(a.Text) > ceiling {
			t.Errorf("%s is %d characters, and the ceiling is %d:\n  %s",
				a.ID, len(a.Text), ceiling, a.Text)
		}

		// A phrase, so no full stop and no second sentence. Both are how one
		// grows into the paragraph this replaced.
		if strings.Contains(a.Text, ". ") || strings.HasSuffix(a.Text, ".") {
			t.Errorf("%s is written as a sentence rather than a phrase:\n  %s", a.ID, a.Text)
		}
	}
}
