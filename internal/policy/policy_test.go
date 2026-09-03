package policy

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

func TestDescribeCipherKeyExchange(t *testing.T) {
	cases := map[string]struct {
		forwardSecret bool
		keyExchange   string
	}{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   {true, "ECDHE"},
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": {true, "ECDHE"},
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":     {true, "DHE"},
		"TLS_AES_128_GCM_SHA256":                  {true, "ephemeral"},
		"TLS_CHACHA20_POLY1305_SHA256":            {true, "ephemeral"},
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         {false, "static RSA"},
		"TLS_RSA_WITH_AES_128_CBC_SHA":            {false, "static RSA"},
		"TLS_DH_RSA_WITH_AES_128_CBC_SHA":         {false, "static DH"},
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA":       {false, "static ECDH"},
	}

	for name, want := range cases {
		got := DescribeCipher(name)
		if got.ForwardSecret != want.forwardSecret {
			t.Errorf("%s: ForwardSecret = %v, want %v", name, got.ForwardSecret, want.forwardSecret)
		}
		if got.KeyExchange != want.keyExchange {
			t.Errorf("%s: KeyExchange = %q, want %q", name, got.KeyExchange, want.keyExchange)
		}
	}
}

func TestDescribeCipherMode(t *testing.T) {
	aead := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_AES_128_CCM",
	}
	for _, name := range aead {
		if got := DescribeCipher(name); !got.AEAD {
			t.Errorf("%s: AEAD = false, want true", name)
		}
	}

	notAEAD := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA256",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_NULL_SHA",
	}
	for _, name := range notAEAD {
		if got := DescribeCipher(name); got.AEAD {
			t.Errorf("%s: AEAD = true, want false", name)
		}
	}
}

func TestGradeCipherInsecure(t *testing.T) {
	cases := map[string]string{
		"TLS_RSA_WITH_NULL_SHA":                  "cipher.null",
		"TLS_DH_anon_WITH_AES_128_CBC_SHA":       "cipher.anonymous",
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5":         "cipher.export",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA":         "cipher.rc4",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":    "cipher.3des",
		"TLS_RSA_WITH_DES_CBC_SHA":               "cipher.des",
		"TLS_RSA_WITH_AES_128_GCM_SHA256":        "cipher.no-forward-secrecy",
		"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256": "cipher.no-forward-secrecy",
	}

	for name, wantRule := range cases {
		got := GradeCipher(name)

		if got.Verdict != Insecure {
			t.Errorf("%s: Verdict = %q, want %q", name, got.Verdict, Insecure)
		}
		if len(got.Findings) == 0 {
			t.Fatalf("%s: graded insecure with no finding to explain it", name)
		}
		if got.Findings[0].RuleID != wantRule {
			t.Errorf("%s: RuleID = %q, want %q", name, got.Findings[0].RuleID, wantRule)
		}
	}
}

func TestGradeCipherWeak(t *testing.T) {
	// Forward secret and authenticated, but CBC rather than AEAD.
	got := GradeCipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")

	if got.Verdict != Weak {
		t.Errorf("Verdict = %q, want %q", got.Verdict, Weak)
	}
	if len(got.Findings) == 0 || got.Findings[0].RuleID != "cipher.cbc" {
		t.Errorf("expected rule cipher.cbc, got %+v", got.Findings)
	}
}

func TestGradeCipherStrong(t *testing.T) {
	strong := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	for _, name := range strong {
		got := GradeCipher(name)
		if got.Verdict != Strong {
			t.Errorf("%s: Verdict = %q, want %q (findings: %+v)", name, got.Verdict, Strong, got.Findings)
		}
		if len(got.Findings) != 0 {
			t.Errorf("%s: graded strong but carries findings: %+v", name, got.Findings)
		}
	}
}

// A verdict without a citation is an assertion. Every rule must name a
// document the reader can check.
func TestEveryFindingCitesASource(t *testing.T) {
	names := []string{
		"TLS_RSA_WITH_NULL_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_UNKNOWN_FUTURE_SUITE",
	}

	for _, name := range names {
		for _, f := range GradeCipher(name).Findings {
			if len(f.References) == 0 {
				t.Errorf("%s: rule %s has no reference", name, f.RuleID)
			}
			for _, ref := range f.References {
				if ref.Label == "" {
					t.Errorf("%s: rule %s has a reference with no label", name, f.RuleID)
				}
				if !strings.HasPrefix(ref.URL, "https://") {
					t.Errorf("%s: rule %s cites %q, which is not an https URL", name, f.RuleID, ref.URL)
				}
			}
			if f.Policy != Version {
				t.Errorf("%s: rule %s reports policy %q, want %q", name, f.RuleID, f.Policy, Version)
			}
			if f.Rationale == "" {
				t.Errorf("%s: rule %s has no rationale", name, f.RuleID)
			}
		}
	}
}

// An unrecognised suite must not be graded strong by default. Silence about
// something untested reads as approval.
func TestUnknownSuiteIsNotGradedStrong(t *testing.T) {
	got := GradeCipher("TLS_SOMETHING_NOBODY_HAS_SEEN")

	if got.Verdict == Strong {
		t.Error("an unrecognised suite was graded strong")
	}
	if len(got.Findings) == 0 {
		t.Error("an unrecognised suite produced no finding to explain the grade")
	}
}

func TestGradeVersion(t *testing.T) {
	cases := map[uint16]Verdict{
		VersionSSL30: Insecure,
		VersionTLS10: Insecure,
		VersionTLS11: Insecure,
		VersionTLS12: Strong,
		VersionTLS13: Strong,
	}

	for version, want := range cases {
		got := GradeVersion(version)
		if got.Verdict != want {
			t.Errorf("version %#04x: Verdict = %q, want %q", version, got.Verdict, want)
		}
	}

	if !GradeVersion(VersionTLS13).Preferred {
		t.Error("TLS 1.3 is not marked preferred")
	}
	if GradeVersion(VersionTLS12).Preferred {
		t.Error("TLS 1.2 is marked preferred; current guidance points to 1.3")
	}

	// Deprecated versions must explain themselves.
	for _, version := range []uint16{VersionSSL30, VersionTLS10, VersionTLS11} {
		if len(GradeVersion(version).Findings) == 0 {
			t.Errorf("version %#04x graded insecure with no finding", version)
		}
	}
}

// The constants here must match crypto/tls. They are declared separately so
// this package stays independent of it, which only works if they agree.
func TestVersionConstantsMatchCryptoTLS(t *testing.T) {
	cases := map[string][2]uint16{
		"TLS 1.0": {VersionTLS10, tls.VersionTLS10},
		"TLS 1.1": {VersionTLS11, tls.VersionTLS11},
		"TLS 1.2": {VersionTLS12, tls.VersionTLS12},
		"TLS 1.3": {VersionTLS13, tls.VersionTLS13},
	}
	for name, pair := range cases {
		if pair[0] != pair[1] {
			t.Errorf("%s: policy has %#04x, crypto/tls has %#04x", name, pair[0], pair[1])
		}
	}
}

// Go's InsecureCipherSuites is treated as an outside observer, not as the
// source of truth. When Go condemns a suite these rules do not, that is worth
// knowing: it may mean the rules need revisiting, or that Go is applying a
// stricter standard than the documents require.
//
// This reports rather than fails. A disagreement is a prompt to think, not
// evidence that either side is wrong.
func TestCrossCheckAgainstGo(t *testing.T) {
	var disagreements int

	for _, cs := range tls.InsecureCipherSuites() {
		if got := GradeCipher(cs.Name); got.Verdict != Insecure {
			disagreements++
			t.Logf("Go marks %s insecure; policy %s grades it %q", cs.Name, Version, got.Verdict)
		}
	}

	for _, cs := range tls.CipherSuites() {
		if got := GradeCipher(cs.Name); got.Verdict == Insecure {
			disagreements++
			t.Logf("Go considers %s acceptable; policy %s grades it insecure (%s)",
				cs.Name, Version, got.Findings[0].RuleID)
		}
	}

	if disagreements > 0 {
		t.Logf("%d suite(s) graded differently by policy %s and this build of Go. "+
			"Expected: the policy follows RFC 9325 and BSI TR-02102-2, which are "+
			"stricter than Go on suites without forward secrecy.", disagreements, Version)
	}
}

// The rules are only as current as the last time somebody checked them
// against the documents they cite.
func TestRulesAreDueForReview(t *testing.T) {
	due, err := time.Parse(time.DateOnly, ReviewBy)
	if err != nil {
		t.Fatalf("ReviewBy is not a date: %v", err)
	}
	if time.Now().After(due) {
		t.Errorf("the rules were due for review on %s. Read internal/policy against its references, confirm each is still current, then move ReviewBy forward.", ReviewBy)
	}
}
