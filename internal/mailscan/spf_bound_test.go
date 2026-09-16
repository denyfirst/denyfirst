package mailscan

import (
	"context"
	"errors"
	"testing"
)

// What the SPF walk could not read reaches the report, and keeps it from being
// strong.
func TestAnUnreadIncludeReachesTheReport(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{
		records: map[string][]string{
			"example.com":        {"v=spf1 include:down.example.net -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
		fail: map[string]error{"down.example.net": errors.New("the resolver did not answer")},
	}
	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	f := got.Observed
	if f.SPFUnreadIncludes != 1 || !f.SPFLookupsAtLeast {
		t.Errorf("unread %d, at least %v; the include the resolver could not answer is not carried",
			f.SPFUnreadIncludes, f.SPFLookupsAtLeast)
	}
	if f.SPFVoidLookups != 0 {
		t.Errorf("%d void lookups; a resolver failure is not a name with no records", f.SPFVoidLookups)
	}
	if got.Verdict == "strong" {
		t.Error("a domain whose sender policy could not be read in full is strong")
	}
}
