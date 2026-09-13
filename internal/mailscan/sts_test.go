package mailscan

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/mtasts"
)

// fixedPolicy stands in for the policy host, and records whether it was asked.
//
// The list rather than a boolean, because two of the tests below are about a
// request never being made at all and one is about it being made exactly once.
type fixedPolicy struct {
	policy mtasts.Policy
	asked  []string
}

func (f *fixedPolicy) Fetch(_ context.Context, domain string) mtasts.Policy {
	f.asked = append(f.asked, domain)
	return f.policy
}

// enforcing is a fetched policy in enforce mode naming the hosts given.
func enforcing(hosts ...string) mtasts.Policy {
	return mtasts.Policy{
		Fetched: true, Mode: mtasts.Enforce, MaxAge: 604800, MX: hosts,
	}
}

// stsZone publishes an MTA-STS record and the exchangers named.
func stsZone(exchangers ...string) *zone {
	var mx []dnsclient.MX
	for _, host := range exchangers {
		mx = append(mx, dnsclient.MX{Preference: 10, Host: host})
	}
	return &zone{
		records: map[string][]string{
			"example.com":          {"v=spf1 -all"},
			"_dmarc.example.com":   {"v=DMARC1; p=reject; rua=mailto:r@example.com"},
			"_mta-sts.example.com": {"v=STSv1; id=20260913T000000"},
		},
		exchangers: map[string][]dnsclient.MX{"example.com": mx},
	}
}

// The mode reaches the report, which is the whole reason the file is fetched.
//
// Everything a domain can be said to have done about MTA-STS from DNS alone is
// "announced a policy", and that one sentence covers a domain fully protected
// and a domain that has been rehearsing for two years.
func TestThePolicyModeReachesTheReport(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	sts := &fixedPolicy{policy: enforcing("mx1.example.net")}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(sts.asked) != 1 || sts.asked[0] != "example.com" {
		t.Fatalf("the policy host was asked %v, want exactly one request for the domain", sts.asked)
	}
	if !got.Observed.MTASTSPolicyRead {
		t.Fatal("the policy was fetched and the report does not say it was read")
	}
	if got.Observed.MTASTSMode != "enforce" {
		t.Errorf("MTASTSMode = %q, want enforce", got.Observed.MTASTSMode)
	}
	if got.Observed.MTASTSMaxAge != 604800 {
		t.Errorf("MTASTSMaxAge = %d, want the value the policy carried", got.Observed.MTASTSMaxAge)
	}
	if sentenceAbout(got, "enforce mode") == "" {
		t.Errorf("no sentence says what mode the policy is in:\n%s", aboutTheDomain(got))
	}
}

// A policy in testing mode is described and never graded.
//
// The distinction the whole fetch was built to draw, and the one place a reader
// is most likely to have been given the wrong impression for years. Not graded,
// for the reason p=none and ~all are not: it is the staging position on the way
// to enforce, and marking it down would penalise an operator doing the right
// thing in the right order (R6).
func TestATestingPolicyIsDescribedRatherThanGraded(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	sts := &fixedPolicy{policy: mtasts.Policy{
		Fetched: true, Mode: mtasts.Testing, MaxAge: 86400,
		MX: []string{"mx1.example.net"},
	}}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if ids := findingIDs(got); len(ids) != 0 {
		t.Errorf("graded %v for a policy in the mode MTA-STS is rolled out through", ids)
	}

	sentence := sentenceAbout(got, "testing mode")
	if sentence == "" {
		t.Fatalf("the report does not say the policy is in testing mode, which is the one fact "+
			"DNS could not have told anybody:\n%s", aboutTheDomain(got))
	}
	if !containsAny(sentence, "measuring the problem", "deliver as it would have anyway") {
		t.Errorf("the report names the mode without saying what it means, so a reader takes "+
			"testing for protection: %q", sentence)
	}
}

// No record, no request.
//
// Not an optimisation. A request to mta-sts.<domain> for a domain that announced
// nothing is this program choosing an address and trying it, which is the thing
// N7 refuses. A record is the zone naming the address itself, which is what makes
// reading it the following of an instruction the domain published.
func TestThePolicyIsFetchedOnlyWhereTheZoneAnnouncesOne(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	delete(z.records, "_mta-sts.example.com")

	sts := &fixedPolicy{policy: enforcing("mx1.example.net")}
	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(sts.asked) != 0 {
		t.Errorf("the policy host was asked about %v for a domain that announced no policy; that "+
			"is an address this program chose rather than one the zone named", sts.asked)
	}
	if got.Observed.MTASTSPolicyRead {
		t.Error("the report claims a policy was read for a domain that announces none")
	}
}

// A deployment that does not read the policy says so, and is not graded for it.
//
// The default, and the behaviour of every deployment that requires no proof of
// control. A report showing an empty mode without saying why reads as a policy
// that names none, which is graded (R4).
func TestADeploymentThatDoesNotReadThePolicySaysSo(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	sts := &fixedPolicy{policy: enforcing("mx1.example.net")}

	// ReadSTSPolicy unset, and a fetcher supplied anyway: the gate is the flag
	// rather than whether a caller remembered to leave the field nil.
	got, err := (&Scanner{Resolver: z, STS: sts}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(sts.asked) != 0 {
		t.Errorf("the policy was fetched by a deployment that does not read it: %v", sts.asked)
	}
	if got.Observed.MTASTSPolicyRead {
		t.Fatal("the report says the policy was read and nothing fetched it")
	}
	if got.Observed.MTASTSPolicyReason == "" {
		t.Error("nothing says why the policy was not read, so an empty mode is left for a reader " +
			"to take as a policy that names none")
	}
	if ids := findingIDs(got); len(ids) != 0 {
		t.Errorf("graded %v for a policy nobody read", ids)
	}
}

// An exchanger the enforcing policy does not cover is found and named.
//
// The finding this fetch exists to make possible. RFC 8461 says a sending server
// applying an enforcing policy must not deliver to a host the policy does not
// match, so an exchanger added to DNS and not to the policy is mail that stops —
// and nothing an operator can run tells them, because from DNS the policy looks
// the same either way.
func TestAnExchangerTheEnforcingPolicyExcludesIsFound(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net", "mx2.example.net")

	// The second exchanger was added to DNS and not to the policy, which is how
	// this happens in practice.
	sts := &fixedPolicy{policy: enforcing("mx1.example.net")}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(got.Observed.MTASTSUncovered) != 1 || got.Observed.MTASTSUncovered[0] != "mx2.example.net" {
		t.Fatalf("MTASTSUncovered = %v, want the one exchanger the policy leaves out",
			got.Observed.MTASTSUncovered)
	}
	if ids := findingIDs(got); !slices.Contains(ids, "mail.mta-sts-uncovered-exchanger") {
		t.Errorf("findings are %v; an enforcing policy excluding the domain's own exchanger is "+
			"not among them", ids)
	}
}

// A policy covering everything is not reported as excluding anything.
//
// The other direction of the test above, and the one that matters more often: a
// coverage test that always answered no would pass that one and invent this
// finding on every correctly configured domain, which is what R6 exists for.
func TestAPolicyCoveringEveryExchangerIsNotAFinding(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net", "mx2.example.net")
	sts := &fixedPolicy{policy: enforcing("mx1.example.net", "mx2.example.net")}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(got.Observed.MTASTSUncovered) != 0 {
		t.Errorf("MTASTSUncovered = %v for a policy naming both exchangers",
			got.Observed.MTASTSUncovered)
	}
	if ids := findingIDs(got); len(ids) != 0 {
		t.Errorf("graded %v for a domain whose policy covers its own mail", ids)
	}
}

// A fetch that failed is not a policy that names no mode.
//
// Both are an empty MTASTSMode, one is graded and the other must not be. A fetch
// failing here is also what this machine's own egress being blocked looks like,
// and no measurement available from here separates them — so grading it would
// send an operator to edit a file that may be perfectly correct.
func TestAFailedFetchIsNotAPolicyThatNamesNoMode(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net")
	sts := &fixedPolicy{policy: mtasts.Policy{
		Reason: "the policy file could not be fetched over TLS",
	}}

	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got.Observed.MTASTSPolicyRead {
		t.Fatal("a fetch that failed was recorded as a policy that was read")
	}
	if got.Observed.MTASTSPolicyReason == "" {
		t.Error("nothing says why the policy was not read")
	}
	if ids := findingIDs(got); len(ids) != 0 {
		t.Errorf("graded %v against a policy nobody could fetch", ids)
	}
}

// Where the exchangers were not read, nothing is claimed about coverage.
//
// An empty MTASTSUncovered has to mean "the policy covers everything" and never
// "nobody looked", or the graded rule above is switched off by an unrelated DNS
// failure while the report goes on saying the policy is fine (R4).
func TestCoverageIsNotClaimedWhereTheExchangersWereNotRead(t *testing.T) {
	skipUnderDemo(t)
	z := stsZone("mx1.example.net", "mx2.example.net")
	z.fail = map[string]error{"example.com": errors.New("the resolver would not answer")}

	sts := &fixedPolicy{policy: enforcing("mx1.example.net")}
	got, err := (&Scanner{Resolver: z, ReadSTSPolicy: true, STS: sts}).
		Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(got.Observed.MTASTSUncovered) != 0 {
		t.Errorf("MTASTSUncovered = %v where the MX records were never read",
			got.Observed.MTASTSUncovered)
	}
	if ids := findingIDs(got); slices.Contains(ids, "mail.mta-sts-uncovered-exchanger") {
		t.Errorf("graded %v against a list of exchangers this scan does not have", ids)
	}
}

// containsAny reports whether the text holds any of the phrases.
func containsAny(text string, phrases ...string) bool {
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

// The default fetcher judges certificates against this scanner's store.
//
// Every other test here supplies its own fetcher, so without this one a scanner
// that quietly stopped handing its Roots to the real fetch would pass all of
// them and trust whatever the platform picks (R7).
func TestTheDefaultFetcherUsesTheScannersTrustStore(t *testing.T) {
	roots := x509.NewCertPool()

	f, ok := (&Scanner{Roots: roots}).stsFetcher().(*mtasts.Fetcher)
	if !ok {
		t.Fatal("the default fetcher is not internal/mtasts")
	}
	if f.Roots != roots {
		t.Error("the trust store this scanner was given did not reach the policy fetch")
	}
}
