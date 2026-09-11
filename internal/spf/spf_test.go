package spf

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// zone answers TXT lookups from a table, so a policy chain can be walked with
// no network and no timing.
type zone struct {
	records map[string][]string
	missing map[string]bool
	asked   []string
	fail    map[string]bool
}

func (z *zone) LookupTXT(_ context.Context, name string) ([]string, bool, error) {
	z.asked = append(z.asked, name)
	if z.fail[name] {
		return nil, false, errors.New("the resolver did not answer")
	}
	if z.missing[name] {
		return nil, false, nil
	}
	return z.records[name], true, nil
}

// A domain with no policy is not a domain with a bad one.
func TestADomainWithNoPolicyIsSaidToHaveNone(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {"some-other-record=value"},
	}}

	got := Check(context.Background(), z, "example.test")
	if got.Found {
		t.Error("a TXT record that is not a policy was read as one")
	}
	if got.Records != 0 {
		t.Errorf("counted %d policies", got.Records)
	}
}

// Two records are not a stricter policy. They are no policy.
//
// The commonest way to break SPF while appearing to strengthen it: a second
// record added to bring in a new provider. RFC 7208 makes more than one a
// permanent error, so the domain that was trying to authorise one more sender
// has switched the whole policy off.
func TestTwoRecordsAreCountedAsTwo(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {
			"v=spf1 include:one.test -all",
			"v=spf1 include:two.test -all",
		},
	}}

	got := Check(context.Background(), z, "example.test")
	if got.Records != 2 {
		t.Errorf("counted %d records, want 2", got.Records)
	}
	if got.Found {
		t.Error("two records were read as a policy to evaluate; there is no policy to evaluate")
	}
}

// The qualifier on all is what a receiver is told to do.
func TestTheQualifierOnAllIsRead(t *testing.T) {
	for _, tc := range []struct {
		record string
		want   Qualifier
	}{
		{"v=spf1 ip4:192.0.2.0/24 -all", Fail},
		{"v=spf1 ip4:192.0.2.0/24 ~all", SoftFail},
		{"v=spf1 ip4:192.0.2.0/24 ?all", Neutral},
		{"v=spf1 ip4:192.0.2.0/24 +all", Pass},

		// A bare all is a pass, which is the one worth getting right: a record
		// ending in "all" tells every receiver that anybody may send as this
		// domain, and it does not look like it does.
		{"v=spf1 ip4:192.0.2.0/24 all", Pass},

		// Case is insignificant.
		{"V=SPF1 IP4:192.0.2.0/24 -ALL", Fail},
	} {
		z := &zone{records: map[string][]string{"example.test": {tc.record}}}

		got := Check(context.Background(), z, "example.test")
		if got.All != tc.want {
			t.Errorf("%q gave qualifier %q, want %q", tc.record, got.All, tc.want)
		}
	}
}

// A record with no all leaves the receiver where publishing nothing would.
func TestARecordWithNoAllSaysSo(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {"v=spf1 ip4:192.0.2.0/24"},
	}}

	if got := Check(context.Background(), z, "example.test"); got.All != "" {
		t.Errorf("a record with no all reported qualifier %q", got.All)
	}
}

// Only terms that cost a lookup are counted.
func TestOnlyResolvingTermsAreCounted(t *testing.T) {
	z := &zone{records: map[string][]string{
		// Four that cost a lookup: a, mx, exists, ptr. Three that do not:
		// ip4, ip6, all.
		"example.test": {"v=spf1 a mx exists:%{i}.test ptr ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"},
	}}

	got := Check(context.Background(), z, "example.test")
	if got.Lookups != 4 {
		t.Errorf("counted %d lookups, want 4: ip4, ip6 and all resolve nothing", got.Lookups)
	}
	if !got.UsesPTR {
		t.Error("ptr was used and is not reported; RFC 7208 says it SHOULD NOT be, it loads " +
			"the receiver, and several large receivers ignore it")
	}
}

// The count follows every include, which is the whole point of it.
//
// The failure this check exists for is invisible in the record: a policy with
// three includes can be over the limit because one of them has eight of its
// own. Nothing in the zone file says so, and a receiver that hits the limit
// treats the domain as having published no policy at all.
func TestTheCountFollowsEveryInclude(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {"v=spf1 include:provider.test -all"},
		"provider.test": {
			"v=spf1 a mx include:deeper.test -all",
		},
		"deeper.test": {"v=spf1 a a a -all"},
	}}

	got := Check(context.Background(), z, "example.test")

	// include:provider (1) + a + mx (2) + include:deeper (1) + a a a (3) = 7
	if got.Lookups != 7 {
		t.Errorf("counted %d lookups, want 7: the cost of a policy is what a receiver would "+
			"resolve, not what its own line contains", got.Lookups)
	}
	if got.LookupLimit {
		t.Error("seven lookups was reported as over the limit of ten")
	}
}

// Over ten is a permanent error, and a receiver reads that as no policy.
func TestMoreThanTenLookupsIsOverTheLimit(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {"v=spf1 include:one.test include:two.test -all"},
		"one.test":     {"v=spf1 a a a a a a -all"},
		"two.test":     {"v=spf1 a a a a -all"},
	}}

	got := Check(context.Background(), z, "example.test")

	// 2 includes + 6 + 4 = 12
	if got.Lookups != 12 {
		t.Fatalf("counted %d lookups, want 12", got.Lookups)
	}
	if !got.LookupLimit {
		t.Error("twelve lookups was not reported as over the limit. A receiver that hits it " +
			"gets a permanent error and treats the domain as having published nothing, which " +
			"is the opposite of what the record appears to say")
	}
}

// Exactly ten is not over.
func TestTenLookupsIsNotOverTheLimit(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {"v=spf1 a a a a a a a a a a -all"},
	}}

	got := Check(context.Background(), z, "example.test")
	if got.Lookups != 10 {
		t.Fatalf("counted %d lookups, want 10", got.Lookups)
	}
	if got.LookupLimit {
		t.Error("ten lookups was reported as over a limit of ten; a domain sitting exactly on " +
			"the line is correct, and telling it otherwise is the false finding this project " +
			"objects to in other tools")
	}
}

// An include that resolves to nothing is a void lookup, and too many are fatal.
func TestIncludesThatResolveToNothingAreCountedAsVoid(t *testing.T) {
	z := &zone{
		records: map[string][]string{
			"example.test": {"v=spf1 include:gone.test include:also-gone.test include:third.test -all"},
		},
		missing: map[string]bool{
			"gone.test":      true,
			"also-gone.test": true,
			"third.test":     true,
		},
	}

	got := Check(context.Background(), z, "example.test")
	if got.VoidLookups != 3 {
		t.Errorf("counted %d void lookups, want 3", got.VoidLookups)
	}
	if !got.VoidLimit {
		t.Error("three void lookups was not reported as over the limit of two. A policy resting " +
			"on names that no longer resolve is a policy nobody is maintaining, and the third " +
			"one is fatal to the evaluation")
	}
}

// A policy that includes itself stops.
//
// The lookup budget would stop it eventually. This stops it before the
// recursion rather than after, so a zone that points at itself costs a bounded
// walk rather than a stack.
func TestAPolicyThatIncludesItselfStops(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {"v=spf1 include:loop.test -all"},
		"loop.test":    {"v=spf1 include:example.test include:loop.test -all"},
	}}

	got := Check(context.Background(), z, "example.test")
	if got.Reason != "" {
		t.Fatalf("the walk failed: %s", got.Reason)
	}
	if len(z.asked) > maxLookups+maxDepth+2 {
		t.Errorf("the walk made %d lookups around a loop", len(z.asked))
	}
}

// The domains a policy pulls in are listed, because that is what an operator
// works from when the count is too high.
func TestTheIncludedDomainsAreListed(t *testing.T) {
	z := &zone{records: map[string][]string{
		"example.test": {"v=spf1 include:one.test include:two.test include:one.test -all"},
		"one.test":     {"v=spf1 -all"},
		"two.test":     {"v=spf1 -all"},
	}}

	got := Check(context.Background(), z, "example.test")
	if len(got.Includes) != 2 {
		t.Fatalf("listed %v, want each domain once", got.Includes)
	}
	if got.Includes[0] != "one.test" || got.Includes[1] != "two.test" {
		t.Errorf("listed %v, want them in the order the record has them", got.Includes)
	}
}

// A redirect is followed only where it would be, and counted only then.
//
// redirect applies when no mechanism matched, so a record carrying all as well
// never reaches it. Counting it regardless would overstate the cost of a policy
// that does not pay it.
func TestARedirectIsCountedOnlyWhereItWouldBeFollowed(t *testing.T) {
	withAll := &zone{records: map[string][]string{
		"example.test": {"v=spf1 a -all redirect=other.test"},
		"other.test":   {"v=spf1 a a a a a -all"},
	}}
	if got := Check(context.Background(), withAll, "example.test"); got.Lookups != 1 {
		t.Errorf("counted %d lookups for a record whose redirect is unreachable, want 1", got.Lookups)
	}

	withoutAll := &zone{records: map[string][]string{
		"example.test": {"v=spf1 a redirect=other.test"},
		"other.test":   {"v=spf1 a a -all"},
	}}
	// a (1) + redirect (1) + a a (2) = 4
	if got := Check(context.Background(), withoutAll, "example.test"); got.Lookups != 4 {
		t.Errorf("counted %d lookups for a record that redirects, want 4", got.Lookups)
	}
}

// A resolver that will not answer is not a domain with no policy.
func TestAResolverThatWillNotAnswerIsNotAMissingPolicy(t *testing.T) {
	z := &zone{fail: map[string]bool{"example.test": true}}

	got := Check(context.Background(), z, "example.test")
	if got.Reason == "" {
		t.Fatal("a failed lookup was reported as a domain with no policy, which is the one " +
			"wrong answer here: it reads as a finding about the domain")
	}
	if got.Found {
		t.Error("a policy was reported from a lookup that failed")
	}
}

// A domain that does not exist says so.
func TestADomainThatDoesNotExistSaysSo(t *testing.T) {
	z := &zone{missing: map[string]bool{"example.test": true}}

	got := Check(context.Background(), z, "example.test")
	if !strings.Contains(got.Reason, "does not exist") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// No reason names a resolver, an address or a Go type.
func TestNoReasonDescribesTheMachine(t *testing.T) {
	reasons := []string{
		Check(context.Background(), &zone{fail: map[string]bool{"example.test": true}}, "example.test").Reason,
		Check(context.Background(), nil, "example.test").Reason,
		Check(context.Background(), &zone{}, "").Reason,
	}

	for _, reason := range reasons {
		if reason == "" {
			t.Error("a failure came back with no reason")
			continue
		}
		for _, leak := range []string{"dial ", "tcp ", "0x", "*dnsclient.", "resolver did not answer"} {
			if strings.Contains(reason, leak) {
				t.Errorf("the reason contains %q: %s", leak, reason)
			}
		}
	}
}

// A record longer than anything real is bounded before it is kept.
func TestAnOverlongRecordIsBounded(t *testing.T) {
	long := "v=spf1 " + strings.Repeat("ip4:192.0.2.1 ", maxRecordLength)
	z := &zone{records: map[string][]string{"example.test": {long}}}

	got := Check(context.Background(), z, "example.test")
	if len(got.Raw) > maxRecordLength {
		t.Errorf("kept %d characters of a record, and the bound is %d", len(got.Raw), maxRecordLength)
	}
}
