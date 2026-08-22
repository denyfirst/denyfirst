package policy

import (
	"strings"
	"testing"
)

// Every rule states a reason. This asserts the reason is true of the suite.
//
// Nothing did, and that is how TLS_SM4_GCM_SM3 came to be graded insecure for
// having no forward secrecy — a property every TLS 1.3 suite has by
// construction. FuzzGradeCipher checked the other direction, that a suite
// graded strong really is forward-secret and AEAD, which is the direction that
// fails safe for this service. This is the direction that fails safe for the
// server being described, and it was missing.
//
// A verdict is an accusation. An accusation with a reason nobody checked is
// worse than no verdict, because it is specific enough to be believed.
func TestEveryStatedReasonIsTrueOfTheSuite(t *testing.T) {
	// Each rule, and what the suite must actually look like for its sentence
	// to be honest. A rule added without an entry here fails the test below.
	holds := map[string]func(CipherProperties) bool{
		"cipher.null":                 func(p CipherProperties) bool { return p.Cipher == "none" && !p.AEAD },
		"cipher.no-encryption":        func(p CipherProperties) bool { return p.Cipher == "none" && !p.AEAD },
		"cipher.anonymous":            func(p CipherProperties) bool { return strings.Contains(p.Name, "_anon_") },
		"cipher.export":               func(p CipherProperties) bool { return strings.Contains(p.Name, "EXPORT") },
		"cipher.rc4":                  func(p CipherProperties) bool { return p.Cipher == "RC4" },
		"cipher.3des":                 func(p CipherProperties) bool { return strings.Contains(p.Name, "_3DES_") },
		"cipher.des":                  func(p CipherProperties) bool { return strings.Contains(p.Name, "_DES_") },
		"cipher.md5":                  func(p CipherProperties) bool { return strings.HasSuffix(p.Name, "_MD5") },
		"cipher.ffdhe":                func(p CipherProperties) bool { return p.KeyExchange == "DHE" },
		"cipher.no-forward-secrecy":   func(p CipherProperties) bool { return !p.ForwardSecret && strings.HasPrefix(p.KeyExchange, "static ") },
		"cipher.cbc":                  func(p CipherProperties) bool { return p.Cipher == "CBC" },
		"cipher.unrecognised":         func(p CipherProperties) bool { return p.KeyExchange == "unknown" },
		"cipher.not-current-practice": func(p CipherProperties) bool { return !(p.AEAD && p.ForwardSecret) },
	}

	names := []string{
		// The suites this service can actually negotiate.
		"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA",
		// The ones that produced a false reason before 2026-08-22.
		"TLS_SM4_GCM_SM3", "TLS_SM4_CCM_SM3", "TLS_SHA256_SHA256", "TLS_SHA384_SHA384",
		"0x00C6", "TLS_FALLBACK_SCSV", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
		// Prohibited by RFC 10015, and forward-secret, which is the pair that
		// makes it need a rule of its own.
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		// Static exchanges, which is what no-forward-secrecy is for.
		"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
		// Nonsense, which must still not produce a specific claim.
		"", "TLS_", "_", "NULL", "TLS_SOMETHING_NOBODY_HAS_SEEN",
	}

	for _, name := range names {
		got := GradeCipher(name)
		for _, f := range got.Findings {
			check, known := holds[f.RuleID]
			if !known {
				t.Errorf("rule %s has no entry here, so nothing checks that its reason is true. "+
					"Add one: state what must be observable about a suite for the sentence to hold.", f.RuleID)
				continue
			}
			if !check(got.CipherProperties) {
				t.Errorf(`%s: rule %s says %q, and that is not true of this suite.

  forward secret : %v
  AEAD           : %v
  key exchange   : %s
  cipher         : %s

A verdict is believed because it names a reason. Naming one that does not hold
is worse than declining to grade.`,
					name, f.RuleID, f.Title,
					got.ForwardSecret, got.AEAD, got.KeyExchange, got.Cipher)
			}
		}
	}
}

// The one sentence that would have caught it, stated on its own so it cannot
// be lost in a table: nothing may be accused of lacking forward secrecy while
// having it.
func TestForwardSecrecyIsNeverDeniedOfASuiteThatHasIt(t *testing.T) {
	for _, name := range []string{
		"TLS_SM4_GCM_SM3", "TLS_SM4_CCM_SM3", "TLS_SHA256_SHA256", "TLS_SHA384_SHA384",
		"TLS_AES_128_CCM_8_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AEGIS_128L_SHA256",
	} {
		got := GradeCipher(name)
		if !got.ForwardSecret {
			continue
		}
		for _, f := range got.Findings {
			if f.RuleID == "cipher.no-forward-secrecy" {
				t.Errorf("%s is forward-secret and was told it is not", name)
			}
		}
	}
}

// _DHE_ must not match _ECDHE_. The whole FFDHE rule rests on that, and it
// rests on the character before DHE being C rather than an underscore, which
// is not the kind of thing to leave as a reader's exercise.
func TestFFDHERuleDoesNotCatchTheEllipticCurveForm(t *testing.T) {
	for _, name := range []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
	} {
		for _, f := range GradeCipher(name).Findings {
			if f.RuleID == "cipher.ffdhe" {
				t.Errorf("%s was graded as finite-field DHE; RFC 10015 leaves the elliptic curve form alone", name)
			}
		}
	}

	for _, name := range []string{
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
	} {
		var found bool
		for _, f := range GradeCipher(name).Findings {
			if f.RuleID == "cipher.ffdhe" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is a finite-field DHE suite and RFC 10015 prohibits it; no rule fired", name)
		}
	}
}
