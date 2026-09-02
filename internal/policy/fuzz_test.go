package policy

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// FuzzGradeCipher feeds arbitrary strings to the cipher rules.
//
// Real suite names come from the IANA registry, but the function is reached
// through tls.CipherSuiteName, which returns a placeholder for identifiers Go
// does not know. A future Go release, or a server answering with something
// unexpected, can therefore hand this anything at all.
func FuzzGradeCipher(f *testing.F) {
	seeds := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_AES_128_GCM_SHA256",
		"TLS_DH_anon_WITH_AES_128_CBC_SHA",
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		"TLS_RSA_WITH_NULL_SHA",
		"",
		"_",
		"NULL",
		"null",
		"_CBC_",
		"_3DES__DES_",
		"TLS_",
		"0x1301",
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
		strings.Repeat("TLS_", 500),
		"tls_ecdhe_rsa_with_aes_128_gcm_sha256",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	valid := []Verdict{Strong, Weak, Insecure}

	f.Fuzz(func(t *testing.T, name string) {
		got := GradeCipher(name)

		// Every suite gets a verdict. Ungraded is reserved for things that
		// could not be measured, and a name is always measurable.
		if !slices.Contains(valid, got.Verdict) {
			t.Fatalf("GradeCipher(%q) returned verdict %q, not one of %v", name, got.Verdict, valid)
		}

		// Anything short of current practice must say why. Silence would be
		// read as approval.
		if got.Verdict != Strong && len(got.Findings) == 0 {
			t.Fatalf("GradeCipher(%q) returned %q with no finding to explain it", name, got.Verdict)
		}

		// A verdict without a citation is an assertion.
		for _, finding := range got.Findings {
			if len(finding.References) == 0 {
				t.Fatalf("GradeCipher(%q): rule %s carries no reference", name, finding.RuleID)
			}
			if finding.RuleID == "" {
				t.Fatalf("GradeCipher(%q): a finding has no rule identifier", name)
			}
			if finding.Policy != Version {
				t.Fatalf("GradeCipher(%q): rule %s reports policy %q, want %q",
					name, finding.RuleID, finding.Policy, Version)
			}
			for _, ref := range finding.References {
				if !strings.HasPrefix(ref.URL, "https://") {
					t.Fatalf("GradeCipher(%q): rule %s cites %q, which is not an https URL",
						name, finding.RuleID, ref.URL)
				}
			}
		}

		// A suite graded strong must genuinely meet the bar, whatever route
		// through the rules produced that answer.
		if got.Verdict == Strong && !(got.ForwardSecret && got.AEAD) {
			t.Fatalf("GradeCipher(%q) graded strong without both forward secrecy and AEAD", name)
		}
	})
}

// composed reports whether a run of spaces in a sentence was put there by the
// template rather than carried in by a value.
//
// The distinction matters and the fuzzer taught it. A missing value leaving a
// hole — "  expires in 10 days" — is this package's defect and was fixed
// three times over. A value that itself contains two spaces is not: an
// organisation really can be called "Foo  Bar", and tidying the certificate's
// own text would be reporting something the server did not send. So the
// assertion applies where the inputs are clean, and says nothing where they
// are not.
func composed(values ...string) bool {
	for _, v := range values {
		if strings.Contains(v, "  ") {
			return false
		}
	}
	return true
}

// FuzzGradeLeaf drives the certificate rules with arbitrary dates and
// algorithm names. Certificates in the wild carry dates centuries apart, and
// the arithmetic here must not fall over on them.
func FuzzGradeLeaf(f *testing.F) {
	f.Add(int64(0), int64(90), "RSA", 2048, "SHA256-RSA", true, false, true, true, true)
	f.Add(int64(-4000), int64(-3900), "RSA", 1024, "SHA1-RSA", true, false, true, true, true)
	f.Add(int64(0), int64(730), "ECDSA", 256, "ECDSA-SHA256", true, true, false, false, false)
	f.Add(int64(-100000), int64(100000), "Ed25519", 0, "Ed25519", true, false, true, true, true)
	f.Add(int64(0), int64(0), "", 0, "", false, false, false, false, false)
	// The same hole, on this face: an algorithm name that is only whitespace,
	// and one with a trailing space.
	f.Add(int64(0), int64(90), " ", 256, "SHA256-RSA", true, false, true, true, true)
	f.Add(int64(0), int64(90), "0 ", 256, "SHA256-RSA", true, false, true, true, true)

	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	valid := []Verdict{Strong, Weak, Insecure}

	f.Fuzz(func(t *testing.T,
		startDays, endDays int64,
		keyAlg string, keyBits int, sigAlg string,
		hasSAN, selfSigned, chainTrusted, chainComplete, hostnameMatches bool,
	) {
		// Keep the offsets inside a range time.Duration can express. Beyond
		// roughly 292 years a subtraction saturates rather than overflowing,
		// which is a separate question from the one this target asks.
		const limit = 36500 // a century
		if startDays > limit || startDays < -limit || endDays > limit || endDays < -limit {
			t.Skip()
		}

		facts := LeafFacts{
			NotBefore:          now.AddDate(0, 0, int(startDays)),
			NotAfter:           now.AddDate(0, 0, int(endDays)),
			KeyAlgorithm:       keyAlg,
			KeyBits:            keyBits,
			SignatureAlgorithm: sigAlg,
			HasSAN:             hasSAN,
			SelfSigned:         selfSigned,
			ChainTrusted:       chainTrusted,
			ChainComplete:      chainComplete,
			HostnameMatches:    hostnameMatches,
		}

		got := GradeLeaf(facts, now)

		if !slices.Contains(valid, got.Verdict) {
			t.Fatalf("GradeLeaf returned verdict %q, not one of %v", got.Verdict, valid)
		}
		if got.Verdict != Strong && len(got.Findings) == 0 {
			t.Fatalf("GradeLeaf returned %q with no finding to explain it", got.Verdict)
		}
		if got.MaxValidityDays <= 0 {
			t.Fatalf("MaxValidityDays = %d; every issuance date has a limit", got.MaxValidityDays)
		}

		// An expired certificate must never be graded strong, whatever else
		// is true of it.
		if facts.NotAfter.Before(now) && got.Verdict == Strong {
			t.Fatalf("a certificate that expired on %s was graded strong", facts.NotAfter)
		}

		// The same for one that does not cover the name it was asked about.
		if !hostnameMatches && got.Verdict == Strong {
			t.Fatal("a certificate that does not cover the hostname was graded strong")
		}

		for _, finding := range got.Findings {
			if len(finding.References) == 0 {
				t.Fatalf("rule %s carries no reference", finding.RuleID)
			}
			if finding.Rationale == "" {
				t.Fatalf("rule %s carries no rationale", finding.RuleID)
			}
			// Held to the same standard as the chain grader: a sentence with
			// a gap in it is a sentence something was supposed to fill.
			if composed(keyAlg, sigAlg) && strings.Contains(finding.Rationale, "  ") {
				t.Fatalf("rule %s produced a sentence with a gap in it: %q", finding.RuleID, finding.Rationale)
			}
		}
	})
}

// FuzzMaxValidityDays checks the schedule holds across the whole range of
// issuance dates, including the ones on either side of each cutoff.
func FuzzMaxValidityDays(f *testing.F) {
	f.Add(int64(1700000000))
	f.Add(int64(0))
	f.Add(int64(-1))

	f.Fuzz(func(t *testing.T, unix int64) {
		// Beyond this the year is meaningless and time.Unix wraps.
		if unix > 1<<40 || unix < -(1<<40) {
			t.Skip()
		}

		issued := time.Unix(unix, 0).UTC()
		got := MaxValidityDays(issued)

		if got <= 0 {
			t.Fatalf("MaxValidityDays(%s) = %d; a limit must be positive", issued, got)
		}

		// The schedule only ever tightens. A later issuance date must never
		// be granted a longer lifetime than an earlier one.
		later := MaxValidityDays(issued.AddDate(10, 0, 0))
		if later > got {
			t.Fatalf("MaxValidityDays loosened over time: %s allows %d, ten years later allows %d",
				issued, got, later)
		}
	})
}

// FuzzGradeIssuer drives the chain rules the same way, and adds the question
// the leaf target does not have to ask: the subject.
//
// GradeIssuer repeats the subject back into every sentence it writes, and a
// subject is bytes the scanned server chose. certinfo sanitises the value
// before handing it over — this target is about what happens here whatever
// arrives: no panic, a verdict from the set, a finding for every verdict that
// is not strong, and a sentence that still reads as one.
func FuzzGradeIssuer(f *testing.F) {
	f.Add(int64(-365), int64(2920), "CN=Example Issuing CA", "RSA", 4096, "SHA256-RSA", false)
	f.Add(int64(-365), int64(-1), "CN=COMODO SSL CA,O=COMODO CA Limited,C=GB", "RSA", 2048, "SHA1-RSA", false)
	f.Add(int64(-3650), int64(3650), "", "RSA", 1024, "MD5-RSA", true)
	f.Add(int64(0), int64(10), "CN=\x1b[2K", "ECDSA", 224, "0", false)
	f.Add(int64(0), int64(0), "CN=…", "", 0, "", true)
	// The three shapes of nothing the fuzzer found on 2026-09-02: a subject
	// that is only a space, an algorithm name with a trailing space, and one
	// that is only a space. Each produced a sentence with a hole in it.
	f.Add(int64(-87), int64(10), " ", "0", 224, "0", false)
	f.Add(int64(-87), int64(10), "CN=x", "0 ", 224, "0", false)
	f.Add(int64(-87), int64(10), "CN=x", " ", 224, "0", false)

	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	valid := []Verdict{Strong, Weak, Insecure}

	f.Fuzz(func(t *testing.T,
		startDays, endDays int64,
		subject, keyAlg string, keyBits int, sigAlg string, broken bool,
	) {
		const limit = 36500 // a century, for the reason the leaf target gives
		if startDays > limit || startDays < -limit || endDays > limit || endDays < -limit {
			t.Skip()
		}

		facts := IssuerFacts{
			Subject:                subject,
			NotBefore:              now.AddDate(0, 0, int(startDays)),
			NotAfter:               now.AddDate(0, 0, int(endDays)),
			KeyAlgorithm:           keyAlg,
			KeyBits:                keyBits,
			SignatureAlgorithm:     sigAlg,
			KeyFromBrokenGenerator: broken,
		}

		got := GradeIssuer(facts, now)

		if !slices.Contains(valid, got.Verdict) {
			t.Fatalf("GradeIssuer returned verdict %q, not one of %v", got.Verdict, valid)
		}
		if got.Verdict != Strong && len(got.Findings) == 0 {
			t.Fatalf("GradeIssuer returned %q with no finding to explain it", got.Verdict)
		}

		// An expired issuer must never be graded strong, whatever else is
		// true of it: a chain is only as valid as every certificate in it.
		if facts.NotAfter.Before(now) && got.Verdict == Strong {
			t.Fatalf("an issuer that expired on %s was graded strong", facts.NotAfter)
		}

		for _, finding := range got.Findings {
			if len(finding.References) == 0 {
				t.Fatalf("rule %s carries no reference", finding.RuleID)
			}
			if finding.Rationale == "" {
				t.Fatalf("rule %s carries no rationale", finding.RuleID)
			}
			if !strings.HasPrefix(finding.RuleID, "chain.") {
				t.Fatalf("rule %s came out of the chain grader without a chain. identifier", finding.RuleID)
			}
			// The subject is interpolated. Whatever it held, the sentence
			// must not end up with a hole where a name belongs.
			if composed(subject, keyAlg, sigAlg) && strings.Contains(finding.Rationale, "  ") {
				t.Fatalf("rule %s produced a sentence with a gap in it: %q", finding.RuleID, finding.Rationale)
			}
		}
	})
}
