package policy

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// now is a fixed reference point so results do not drift with the clock.
var now = time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

// healthy is a certificate with nothing wrong with it, used as the base for
// tests that introduce exactly one problem.
func healthy() LeafFacts {
	return LeafFacts{
		NotBefore:          now.AddDate(0, 0, -30),
		NotAfter:           now.AddDate(0, 0, 90),
		KeyAlgorithm:       "ECDSA",
		KeyBits:            256,
		SignatureAlgorithm: "ECDSA-SHA256",
		HasSAN:             true,
		SelfSigned:         false,
		ChainTrusted:       true,
		ChainComplete:      true,
		HostnameMatches:    true,
	}
}

func ruleIDs(f LeafFinding) []string {
	out := make([]string, 0, len(f.Findings))
	for _, x := range f.Findings {
		out = append(out, x.RuleID)
	}
	return out
}

func TestHealthyCertificateHasNoFindings(t *testing.T) {
	got := GradeLeaf(healthy(), now)

	if got.Verdict != Strong {
		t.Errorf("Verdict = %q, want %q (findings: %v)", got.Verdict, Strong, ruleIDs(got))
	}
	if len(got.Findings) != 0 {
		t.Errorf("expected no findings, got %v", ruleIDs(got))
	}
	if got.DaysRemaining != 90 {
		t.Errorf("DaysRemaining = %d, want 90", got.DaysRemaining)
	}
}

func TestCertificateRules(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*LeafFacts)
		rule    string
		verdict Verdict
	}{
		{
			name:    "expired",
			mutate:  func(f *LeafFacts) { f.NotAfter = now.AddDate(0, 0, -1) },
			rule:    "cert.expired",
			verdict: Insecure,
		},
		{
			name: "not yet valid",
			mutate: func(f *LeafFacts) {
				f.NotBefore = now.AddDate(0, 0, 5)
				f.NotAfter = now.AddDate(0, 0, 95)
			},
			rule:    "cert.not-yet-valid",
			verdict: Insecure,
		},
		{
			name:    "expiring soon",
			mutate:  func(f *LeafFacts) { f.NotAfter = now.AddDate(0, 0, 7) },
			rule:    "cert.expiring-soon",
			verdict: Weak,
		},
		{
			name:    "self-signed",
			mutate:  func(f *LeafFacts) { f.SelfSigned = true },
			rule:    "cert.self-signed",
			verdict: Insecure,
		},
		{
			name:    "untrusted chain",
			mutate:  func(f *LeafFacts) { f.ChainTrusted = false },
			rule:    "cert.chain-untrusted",
			verdict: Insecure,
		},
		{
			name:    "incomplete chain",
			mutate:  func(f *LeafFacts) { f.ChainComplete = false },
			rule:    "cert.chain-incomplete",
			verdict: Weak,
		},
		{
			name:    "hostname mismatch",
			mutate:  func(f *LeafFacts) { f.HostnameMatches = false },
			rule:    "cert.hostname-mismatch",
			verdict: Insecure,
		},
		{
			name:    "no subject alternative name",
			mutate:  func(f *LeafFacts) { f.HasSAN = false },
			rule:    "cert.no-san",
			verdict: Insecure,
		},
		{
			name:    "SHA-1 signature",
			mutate:  func(f *LeafFacts) { f.SignatureAlgorithm = "SHA1-RSA" },
			rule:    "cert.signature-sha1",
			verdict: Insecure,
		},
		{
			name:    "MD5 signature",
			mutate:  func(f *LeafFacts) { f.SignatureAlgorithm = "MD5-RSA" },
			rule:    "cert.signature-md5",
			verdict: Insecure,
		},
		{
			name: "RSA key below 2048 bits",
			mutate: func(f *LeafFacts) {
				f.KeyAlgorithm = "RSA"
				f.KeyBits = 1024
				f.SignatureAlgorithm = "SHA256-RSA"
			},
			rule:    "cert.rsa-key-too-small",
			verdict: Insecure,
		},
		{
			name: "elliptic curve below P-256",
			mutate: func(f *LeafFacts) {
				f.KeyAlgorithm = "ECDSA"
				f.KeyBits = 224
			},
			rule:    "cert.ec-key-too-small",
			verdict: Insecure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := healthy()
			tc.mutate(&f)
			got := GradeLeaf(f, now)

			if !slices.Contains(ruleIDs(got), tc.rule) {
				t.Fatalf("rule %s not raised; got %v", tc.rule, ruleIDs(got))
			}
			if got.Verdict != tc.verdict {
				t.Errorf("Verdict = %q, want %q", got.Verdict, tc.verdict)
			}
		})
	}
}

// A 2048-bit RSA key and a P-256 curve are the accepted minimums, not
// borderline cases. Flagging them would produce noise on correct servers.
func TestAcceptedKeySizesRaiseNothing(t *testing.T) {
	rsa := healthy()
	rsa.KeyAlgorithm = "RSA"
	rsa.KeyBits = 2048
	rsa.SignatureAlgorithm = "SHA256-RSA"

	if got := GradeLeaf(rsa, now); len(got.Findings) != 0 {
		t.Errorf("2048-bit RSA raised %v", ruleIDs(got))
	}

	ed := healthy()
	ed.KeyAlgorithm = "Ed25519"
	ed.KeyBits = 0
	ed.SignatureAlgorithm = "Ed25519"

	if got := GradeLeaf(ed, now); len(got.Findings) != 0 {
		t.Errorf("Ed25519 raised %v; it has no size parameter to compare", ruleIDs(got))
	}
}

// The CA/Browser Forum limit is a schedule. A rule that hardcoded one value
// would become wrong on a date already fixed by ballot SC-081v3.
func TestMaxValidityDaysFollowsTheSchedule(t *testing.T) {
	cases := []struct {
		issued string
		want   int
	}{
		{"2025-06-01", 398},
		{"2026-03-14", 398},
		{"2026-03-15", 200},
		{"2026-08-03", 200},
		{"2027-03-14", 200},
		{"2027-03-15", 100},
		{"2029-03-14", 100},
		{"2029-03-15", 47},
		{"2030-01-01", 47},
	}

	for _, tc := range cases {
		issued, err := time.Parse(time.DateOnly, tc.issued)
		if err != nil {
			t.Fatalf("bad test data %q: %v", tc.issued, err)
		}
		if got := MaxValidityDays(issued); got != tc.want {
			t.Errorf("MaxValidityDays(%s) = %d, want %d", tc.issued, got, tc.want)
		}
	}
}

// Compliance is judged when the certificate is signed, not when it is
// scanned. The same lifetime can be valid or a misissuance depending only on
// the issuance date.
func TestValidityIsJudgedAtIssuance(t *testing.T) {
	beforeCutoff := healthy()
	beforeCutoff.NotBefore = time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	beforeCutoff.NotAfter = beforeCutoff.NotBefore.AddDate(0, 0, 390)

	if got := GradeLeaf(beforeCutoff, now); slices.Contains(ruleIDs(got), "cert.validity-too-long") {
		t.Error("a 390-day certificate issued before 15 March 2026 was flagged; the limit then was 398 days")
	}

	afterCutoff := healthy()
	afterCutoff.NotBefore = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	afterCutoff.NotAfter = afterCutoff.NotBefore.AddDate(0, 0, 390)

	got := GradeLeaf(afterCutoff, now)
	if !slices.Contains(ruleIDs(got), "cert.validity-too-long") {
		t.Errorf("a 390-day certificate issued after the cutoff was not flagged; got %v", ruleIDs(got))
	}
	if got.MaxValidityDays != 200 {
		t.Errorf("MaxValidityDays = %d, want 200", got.MaxValidityDays)
	}
}

// One insecure problem outranks any number of weak ones.
func TestWorstCaseWins(t *testing.T) {
	f := healthy()
	f.ChainComplete = false           // weak
	f.NotAfter = now.AddDate(0, 0, 5) // weak
	f.SignatureAlgorithm = "SHA1-RSA" // insecure

	got := GradeLeaf(f, now)
	if got.Verdict != Insecure {
		t.Errorf("Verdict = %q, want %q (findings: %v)", got.Verdict, Insecure, ruleIDs(got))
	}
}

// A verdict without a citation is an assertion.
func TestEveryCertificateFindingCitesASource(t *testing.T) {
	broken := healthy()
	broken.NotAfter = now.AddDate(0, 0, -1)
	broken.SelfSigned = true
	broken.HasSAN = false
	broken.HostnameMatches = false
	broken.ChainComplete = false
	broken.SignatureAlgorithm = "SHA1-RSA"
	broken.KeyAlgorithm = "RSA"
	broken.KeyBits = 1024

	got := GradeLeaf(broken, now)
	if len(got.Findings) < 6 {
		t.Fatalf("expected several findings on a thoroughly broken certificate, got %v", ruleIDs(got))
	}

	for _, f := range got.Findings {
		if len(f.References) == 0 {
			t.Errorf("rule %s has no reference", f.RuleID)
		}
		for _, ref := range f.References {
			if ref.Label == "" {
				t.Errorf("rule %s has a reference with no label", f.RuleID)
			}
			if !strings.HasPrefix(ref.URL, "https://") {
				t.Errorf("rule %s cites %q, which is not an https URL", f.RuleID, ref.URL)
			}
		}
		if f.Rationale == "" {
			t.Errorf("rule %s has no rationale", f.RuleID)
		}
		if f.Policy != Version {
			t.Errorf("rule %s reports policy %q, want %q", f.RuleID, f.Policy, Version)
		}
	}
}

// A self-signed certificate is already reported as untrusted by the
// self-signed rule; raising the chain rule as well would say the same thing
// twice in different words.
func TestSelfSignedDoesNotAlsoReportUntrustedChain(t *testing.T) {
	f := healthy()
	f.SelfSigned = true
	f.ChainTrusted = false

	ids := ruleIDs(GradeLeaf(f, now))

	if !slices.Contains(ids, "cert.self-signed") {
		t.Errorf("cert.self-signed not raised; got %v", ids)
	}
	if slices.Contains(ids, "cert.chain-untrusted") {
		t.Errorf("both cert.self-signed and cert.chain-untrusted raised; got %v", ids)
	}
	if slices.Contains(ids, "cert.chain-incomplete") {
		t.Errorf("cert.chain-incomplete raised for a self-signed certificate, which has no chain to complete; got %v", ids)
	}
}
