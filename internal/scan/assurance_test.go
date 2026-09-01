package scan

import (
	"testing"

	"github.com/denyfirst/denyfirst/internal/certinfo"
	"github.com/denyfirst/denyfirst/internal/policy"
)

// An assurance comes from a measurement, never from a rule failing to fire.
//
// This is the one way an affirmative summary goes wrong, and it goes wrong
// quietly. Read off the findings, "the chain reaches a root" becomes "nothing
// complained about the chain" — which is also what an empty scan looks like,
// and what a scan looks like when the rule that would have complained was the
// one nobody wrote.
//
// The sabotage this test was written for: replacing the measured
// Certificate.Trusted with len(Grade.Findings) == 0. Every other test in this
// repository still passed, because the scan they run has an untrusted chain
// and a finding at the same time, so the two readings agree. They only differ
// on a server that is fine in one respect and not in another, which is most
// real servers.
func TestAnAssuranceIsNotReadOffTheFindings(t *testing.T) {
	// Trusted, and something unrelated went wrong. Reading the findings would
	// withdraw an assurance that was measured and holds.
	trustedWithAProblemElsewhere := &Result{
		Certificate: &certinfo.Report{
			Trusted: true,
			Chain:   []certinfo.Certificate{{}, {}, {}},
			Grade: policy.LeafFinding{
				Findings: []policy.Finding{{RuleID: "cipher.cbc"}},
			},
		},
	}
	if f := assuranceFacts(trustedWithAProblemElsewhere); !f.ChainTrusted {
		t.Error("a chain that was measured as trusted is not assured, because something else was wrong")
	}

	// Not trusted, and no rule fired about it. Reading the findings would
	// invent an assurance from silence.
	untrustedAndUnremarked := &Result{
		Certificate: &certinfo.Report{
			Trusted: false,
			Chain:   []certinfo.Certificate{{}},
		},
	}
	if f := assuranceFacts(untrustedAndUnremarked); f.ChainTrusted {
		t.Error("a chain that was measured as untrusted is assured, because no rule said otherwise")
	}
}

// Completeness is the one place a finding is read, and it has to be read.
//
// A chain can verify and still be incomplete: the platform verifier fetches a
// missing issuer on macOS and Windows, and this program's own trust store may
// already hold it. "Complete and reaches a root" would then be half false —
// the half that tells an operator their server is sending everything a client
// needs, when a client on another platform gets nothing.
//
// cert.chain-incomplete is the measurement of that, so this is the exception
// to reading findings, and it is narrow: one identifier, which
// docs/policy-changes.md guarantees is stable.
func TestAnIncompleteChainIsNotAssuredComplete(t *testing.T) {
	incomplete := &Result{
		Certificate: &certinfo.Report{
			Trusted: true,
			Chain:   []certinfo.Certificate{{}},
			Grade: policy.LeafFinding{
				Findings: []policy.Finding{{RuleID: "cert.chain-incomplete"}},
			},
		},
	}
	if f := assuranceFacts(incomplete); f.ChainComplete {
		t.Error("a chain the server did not send in full is assured to be complete")
	}

	got := policy.Assurances(assuranceFacts(incomplete))
	for _, a := range got {
		if a.ID == "chain" {
			t.Errorf("the chain is assured anyway:\n  %s", a.Text)
		}
	}
}

// The suite claim needs a complete list and every suite strong, and both come
// from the walk rather than from the absence of a cipher finding.
func TestTheSuiteClaimComesFromTheWalk(t *testing.T) {
	if f := assuranceFacts(&Result{}); f.CipherListComplete || f.AllSuitesStrong {
		t.Error("a scan with no TLS report claims something about the suites it never reached")
	}
}
