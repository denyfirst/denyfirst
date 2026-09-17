package mailscan

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/mtasts"
)

// A file that is not a policy is graded as one, and nothing in it is used.
//
// The 2026-09-16 audit (A18): a file no sending server applies was read as the
// enforcing policy its remaining lines described.
func TestAnInvalidPolicyIsGradedAndNotRead(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	sts := &fixedPolicy{policy: mtasts.Policy{Fetched: true, Invalid: "it does not declare version STSv1"}}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if !got.Observed.MTASTSPolicyRead || got.Observed.MTASTSPolicyInvalid == "" {
		t.Errorf("the invalid policy did not reach the facts: %+v", got.Observed)
	}
	if got.Observed.MTASTSMode != "" || len(got.Observed.MTASTSUncovered) != 0 {
		t.Errorf("something in an invalid policy was used: mode %q, uncovered %v",
			got.Observed.MTASTSMode, got.Observed.MTASTSUncovered)
	}
	if ids := findingIDs(got); !slices.Contains(ids, "mail.mta-sts-policy-invalid") {
		t.Errorf("findings are %v; a policy no sender applies is not among them", ids)
	}
	said := false
	for _, f := range got.Findings {
		said = said || (f.RuleID == "mail.mta-sts-policy-invalid" && strings.Contains(f.Rationale, "version STSv1"))
	}
	if !said {
		t.Errorf("the reason the policy is invalid is not said: %+v", got.Findings)
	}
}

// A policy cut at the bound is not compared against the exchangers.
//
// A pattern past the ones kept might be the one that covers a host, so a host
// missing from the kept ones is not uncovered, and none missing is not "all
// covered".
func TestACutPolicyIsNotComparedWithTheExchangers(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net", "mx2.example.net")
	cut := enforcing("mx1.example.net")
	cut.MXTruncated = true
	sts := &fixedPolicy{policy: cut}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(got.Observed.MTASTSUncovered) != 0 {
		t.Errorf("MTASTSUncovered = %v against a list this scan did not keep whole",
			got.Observed.MTASTSUncovered)
	}
	if ids := findingIDs(got); slices.Contains(ids, "mail.mta-sts-uncovered-exchanger") {
		t.Errorf("graded %v against a cut list", ids)
	}
	if sentenceAbout(got, "Every mail exchanger the domain publishes is matched") != "" {
		t.Error("a cut list is said to cover every exchanger")
	}
	if sentenceAbout(got, "more host patterns than this scan keeps") == "" {
		t.Errorf("the cut is not said:\n%s", aboutTheDomain(got))
	}
}
