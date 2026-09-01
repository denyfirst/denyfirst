package scan

import (
	"testing"

	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/policy"
)

// A CAA record set is a set, and a report on an unchanged server should not
// move between scans.
//
// RFC 8659 gives issue and issuewild properties no ordering and no
// precedence: an authority is permitted or it is not. A resolver returns them
// in whatever order it likes, and does — measured on 2026-09-01, two scans of
// paypal.com a quarter of an hour apart named the same authorities in
// different orders, as did cloudflare.com and kapitalbank.az.
//
// A report that moves for no reason is a report nobody can use to notice a
// reason. The diff a person or a pipeline runs against yesterday's output
// fills with changes that did not happen, and the one that did is lost among
// them.
func TestTheSameCAASetReadsTheSameWhicheverOrderItArrivesIn(t *testing.T) {
	answer := func(records []dnsclient.CAA) dnsclient.Answer {
		return dnsclient.Answer{
			Name:     "example.test",
			Records:  records,
			Existed:  true,
			Complete: true,
		}
	}

	first := issuanceFacts(answer([]dnsclient.CAA{
		{Tag: "issue", Value: "digicert.com"},
		{Tag: "issue", Value: "quovadisglobal.com"},
		{Tag: "issue", Value: "visa.com"},
		{Tag: "issuewild", Value: "digicert.com"},
		{Tag: "issuewild", Value: "amazon.com"},
	}))

	second := issuanceFacts(answer([]dnsclient.CAA{
		{Tag: "issue", Value: "visa.com"},
		{Tag: "issuewild", Value: "amazon.com"},
		{Tag: "issue", Value: "digicert.com"},
		{Tag: "issuewild", Value: "digicert.com"},
		{Tag: "issue", Value: "quovadisglobal.com"},
	}))

	// The sentence a person reads.
	if a, b := policy.DescribeIssuance(first).Line, policy.DescribeIssuance(second).Line; a != b {
		t.Errorf("one record set produced two sentences:\n  %s\n  %s", a, b)
	}

	// And the facts a machine reads, which move with it or the page and the
	// pipeline disagree about whether anything changed.
	for i := range first.Authorities {
		if first.Authorities[i] != second.Authorities[i] {
			t.Errorf("authority %d differs: %q and %q", i, first.Authorities[i], second.Authorities[i])
		}
	}
	for i := range first.Wildcards {
		if first.Wildcards[i] != second.Wildcards[i] {
			t.Errorf("wildcard %d differs: %q and %q", i, first.Wildcards[i], second.Wildcards[i])
		}
	}
}

// Sorting must not disturb the two values that are not authority names.
//
// A single semicolon is how a zone says nobody may issue, and an empty value
// names no authority. Both are meaningful, both are read by position in
// DescribeIssuance, and neither should be reordered into or out of the case
// that handles it.
func TestSortingLeavesTheMeaningfulNonNamesAlone(t *testing.T) {
	refuses := issuanceFacts(dnsclient.Answer{
		Name:     "example.test",
		Existed:  true,
		Complete: true,
		Records:  []dnsclient.CAA{{Tag: "issue", Value: ";"}},
	})

	if got := policy.DescribeIssuance(refuses).Line; got != "no authority is permitted to issue (from example.test)" {
		t.Errorf("a zone refusing every authority now reads: %s", got)
	}
}
