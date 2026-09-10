package policy

import (
	"strings"
	"testing"
)

// findingFor returns the named finding a suite produces, or nil.
func findingFor(t *testing.T, suite, ruleID string) *Finding {
	t.Helper()
	for _, f := range GradeCipher(suite).Findings {
		if f.RuleID == ruleID {
			return &f
		}
	}
	return nil
}

// A static RSA key exchange says what it is the precondition for, and says
// what was not established about it.
//
// ROBOT has been in this rule's references since it was written and the
// rationale never mentioned it, so a reader who did not already know what a
// Bleichenbacher oracle is learnt nothing from a link. It is the one place
// where refusing to send malformed input costs a reader something, and the
// point of saying it is that the cost turns out to be almost nothing: the
// oracle can only live behind this arrangement, the arrangement is visible,
// and the remedy is the same instruction either way.
func TestStaticRSANamesTheOracleItIsThePreconditionFor(t *testing.T) {
	f := findingFor(t, "TLS_RSA_WITH_AES_128_GCM_SHA256", "cipher.no-forward-secrecy")
	if f == nil {
		t.Fatal("a static RSA suite produced no no-forward-secrecy finding")
	}

	for _, want := range []string{
		// Why the arrangement matters at all, which is the half that was
		// there first. Removing it leaves "the session key is derived from a
		// long-term key" — a fact with no consequence attached — beside a
		// paragraph about oracles, and a reader loses the primary reason.
		"months or years earlier",

		// What the arrangement is the precondition for.
		"Bleichenbacher",
		// What this scan did not establish (R17).
		"not established here",
		// Why that costs the reader nothing they can act on.
		"the remedy is the same",
	} {
		if !strings.Contains(f.Rationale, want) {
			t.Errorf("the rationale does not say %q:\n%s", want, f.Rationale)
		}
	}
}

// And it does not claim the oracle exists.
//
// The distinction is the whole of R17. A rule that said "this server is
// vulnerable to ROBOT" would be grading an implication from a fact it read,
// and it would be wrong on most of the servers it fired on: a static RSA key
// exchange is necessary for the oracle and nowhere near sufficient.
func TestStaticRSADoesNotClaimTheOracleExists(t *testing.T) {
	f := findingFor(t, "TLS_RSA_WITH_AES_128_GCM_SHA256", "cipher.no-forward-secrecy")
	if f == nil {
		t.Fatal("a static RSA suite produced no no-forward-secrecy finding")
	}

	lower := strings.ToLower(f.Rationale)
	for _, overclaim := range []string{
		"is vulnerable", "is an oracle", "is affected by robot", "robot attack succeeds",
	} {
		if strings.Contains(lower, overclaim) {
			t.Errorf("the rationale claims more than the scan established (%q):\n%s",
				overclaim, f.Rationale)
		}
	}
}

// A suite with forward secrecy says none of it.
//
// The sentence belongs to the arrangement that carries the risk. On a suite
// that cannot host an oracle it would be a paragraph about somebody else's
// problem, printed on a correct configuration (R6).
func TestAForwardSecretSuiteSaysNothingAboutOracles(t *testing.T) {
	for _, f := range GradeCipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").Findings {
		if strings.Contains(f.Rationale, "Bleichenbacher") {
			t.Errorf("a forward-secret suite carries the oracle sentence:\n%s", f.Rationale)
		}
	}
}
