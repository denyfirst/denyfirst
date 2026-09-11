package mailscan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/verify"
)

// zone answers from a table, so a report can be checked against records this
// test wrote rather than against whatever the machine running it can reach.
//
// It records what was asked, because half of what this package promises is
// about the questions rather than the answers: a check that connects to nothing
// is a check whose every outbound act is a lookup, and the way to assert that
// is to look at the list.
type zone struct {
	records map[string][]string
	fail    map[string]error
	asked   []string
}

func (z *zone) LookupTXT(_ context.Context, name string) (dnsclient.TXTAnswer, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	z.asked = append(z.asked, name)

	if err := z.fail[name]; err != nil {
		return dnsclient.TXTAnswer{}, err
	}
	values, ok := z.records[name]
	return dnsclient.TXTAnswer{Values: values, Existed: ok}, nil
}

func (z *zone) askedFor(name string) bool {
	for _, got := range z.asked {
		if got == name {
			return true
		}
	}
	return false
}

func findingIDs(r *Result) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

// A domain with everything published is read as it stands.
func TestScanReadsWhatTheZonePublishes(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{records: map[string][]string{
		"example.com":             {"v=spf1 include:mail.example.net -all"},
		"mail.example.net":        {"v=spf1 ip4:198.51.100.0/24 -all"},
		"_dmarc.example.com":      {"v=DMARC1; p=reject; rua=mailto:reports@example.com"},
		"_smtp._tls.example.com":  {"v=TLSRPTv1; rua=mailto:tls@example.com"},
		"_dmarc.mail.example.net": {"v=DMARC1; p=none"},
	}}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got.Policy != policy.MailVersion {
		t.Errorf("report carries policy %q, want %q", got.Policy, policy.MailVersion)
	}
	if got.Verdict != policy.Strong {
		t.Errorf("verdict = %q, want strong (findings %v)", got.Verdict, findingIDs(got))
	}

	f := got.Observed
	if f == nil {
		t.Fatal("the report carries no observations, so nothing in it can be checked")
	}
	if f.SPFRecords != 1 || f.SPFAll != "-" {
		t.Errorf("SPF = %d records ending in %q, want 1 ending in -", f.SPFRecords, f.SPFAll)
	}
	if f.SPFLookups != 1 {
		t.Errorf("lookups = %d, want 1: one include and nothing inside it that resolves", f.SPFLookups)
	}
	if f.DMARCPolicy != "reject" || f.DMARCPercent != 100 || !f.DMARCReporting {
		t.Errorf("DMARC = p=%q at %d%%, reporting %v", f.DMARCPolicy, f.DMARCPercent, f.DMARCReporting)
	}
	if !f.TLSReporting {
		t.Error("the TLS-RPT record was published and was not read")
	}

	// The DMARC record of a domain the policy merely includes is none of this
	// scan's business, and asking would make the report about somebody else.
	if z.askedFor("_dmarc.mail.example.net") {
		t.Errorf("the scan asked about an included provider's own DMARC record. Questions asked: %v", z.asked)
	}
}

// pct= is the domain's, and 100 is RFC 7489's — never this program's zero.
//
// A report printing "p=reject at 0%" for a record carrying no pct= would be
// showing a reader a default of ours as though it were their configuration, and
// the number it shows is the one an operator would act on.
func TestTheDefaultPercentIsTheOneRFC7489Specifies(t *testing.T) {
	skipUnderDemo(t)
	for _, tc := range []struct {
		record string
		want   int
	}{
		{"v=DMARC1; p=reject", 100},
		{"v=DMARC1; p=reject; pct=20", 20},
		{"v=DMARC1; p=reject; pct=0", 0},
		{"v=DMARC1; p=reject; pct=notanumber", 100},
		{"v=DMARC1; p=reject; pct=400", 100},
		{"v=DMARC1; p=reject; pct=-5", 100},
	} {
		z := &zone{records: map[string][]string{"_dmarc.example.com": {tc.record}}}
		got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if got.Observed.DMARCPercent != tc.want {
			t.Errorf("%q read as %d%%, want %d%%", tc.record, got.Observed.DMARCPercent, tc.want)
		}
	}
}

// A record that mentions DMARC is not a DMARC record.
//
// Both directions matter. Counting a stray TXT record as a policy invents a
// duplicate the domain does not have and grades it; refusing a record whose
// tags are spaced or cased unusually reports a domain with DMARC as having
// none. Neither is a thing a reader can tell from the report.
func TestOnlyARecordThatAnnouncesItselfIsDMARC(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"v=DMARC1; p=reject", true},
		{"v=dmarc1;p=none", true},
		{"  V = DMARC1 ; p=none", true},
		{"v=spf1 -all", false},
		{"this record is about DMARC1 and is not one", false},
		{"p=reject; v=DMARC1", false},
		{"", false},
	} {
		if got := isDMARC(tc.value); got != tc.want {
			t.Errorf("isDMARC(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// A lookup that failed is not a domain that publishes nothing (R4).
func TestAFailedLookupIsNotADomainWithNoPolicy(t *testing.T) {
	skipUnderDemo(t)
	broken := errors.New("the resolver at 198.51.100.1:53 did not answer")
	z := &zone{
		records: map[string][]string{},
		fail: map[string]error{
			"example.com":        broken,
			"_dmarc.example.com": broken,
		},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got.Observed.SPFReason == "" || got.Observed.DMARCReason == "" {
		t.Fatalf("a failure to look was recorded as an absence: SPF reason %q, DMARC reason %q",
			got.Observed.SPFReason, got.Observed.DMARCReason)
	}
	if got.Observed.SPFRecords != 0 || got.Observed.DMARCRecords != 0 {
		t.Errorf("records were counted from a failed lookup")
	}
	if len(got.Findings) != 0 {
		t.Errorf("a domain nothing could be read from was graded %v", findingIDs(got))
	}

	// And the reason names no resolver and no address (I6).
	for _, reason := range []string{got.Observed.SPFReason, got.Observed.DMARCReason} {
		if strings.Contains(reason, "198.51.100.1") {
			t.Errorf("the reason repeats the resolver's address: %q", reason)
		}
	}
}

// A TLS-RPT lookup that fails says the record was not found, not that it is
// absent — and either way nothing is graded, so the two lead to the same
// sentence and the sentence claims only what was seen.
func TestTLSReportingIsOnlyTrueWhenTheRecordSaysSo(t *testing.T) {
	skipUnderDemo(t)
	for _, tc := range []struct {
		name   string
		zone   *zone
		expect bool
	}{
		{"published", &zone{records: map[string][]string{"_smtp._tls.example.com": {"v=TLSRPTv1; rua=mailto:t@example.com"}}}, true},
		{"a different record at the same name", &zone{records: map[string][]string{"_smtp._tls.example.com": {"some other thing"}}}, false},
		{"nothing published", &zone{records: map[string][]string{}}, false},
		{"the lookup failed", &zone{fail: map[string]error{"_smtp._tls.example.com": errors.New("no answer")}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (&Scanner{Resolver: tc.zone}).Scan(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got.Observed.TLSReporting != tc.expect {
				t.Errorf("TLSReporting = %v, want %v", got.Observed.TLSReporting, tc.expect)
			}
		})
	}
}

// The three names this check asks about, and no fourth.
//
// The package's first sentence is that it connects to nothing and that every
// outbound act is a lookup at a name derived from the target. A test that only
// read the report would pass over a version that had quietly started asking
// somewhere else, which is the failure the standing limit would then be lying
// about.
func TestTheScanAsksOnlyAboutTheDomainItWasGiven(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{records: map[string][]string{
		"example.com":        {"v=spf1 include:spf.provider.example -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}}

	if _, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com"); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	allowed := map[string]bool{
		"example.com":            true,
		"_dmarc.example.com":     true,
		"_smtp._tls.example.com": true,

		// Reached because the domain's own policy names it. A sender policy
		// that includes a provider is a domain asking receivers to resolve
		// that name, so resolving it is reading the policy rather than
		// wandering off it.
		"spf.provider.example": true,
	}
	for _, name := range z.asked {
		if !allowed[name] {
			t.Errorf("the scan asked about %q, which is neither the domain, one of its three "+
				"records, nor a name its own policy points at", name)
		}
	}
}

// Refused before anything is looked up, and refused by this package rather than
// by whatever calls it (N8, N6, N9).
func TestScanRefusesBeforeItAsksAnything(t *testing.T) {
	skipUnderDemo(t)
	for _, tc := range []struct {
		name    string
		scanner func(*zone) *Scanner
		target  string
	}{
		{
			name:    "a name no deployment scans",
			scanner: func(z *zone) *Scanner { return &Scanner{Resolver: z} },
			target:  "www.gchq.gov.uk",
		},
		{
			name: "a domain this deployment has not been shown control of",
			scanner: func(z *zone) *Scanner {
				return &Scanner{Resolver: z, Verify: &verify.Scope{Secret: []byte("s")}}
			},
			target: "example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := &zone{records: map[string][]string{}}
			if _, err := tc.scanner(z).Scan(context.Background(), tc.target); err == nil {
				t.Fatal("the scan was allowed")
			}
			if len(z.asked) != 0 {
				t.Errorf("a refused target was looked up anyway: %v. A guard that runs after the "+
					"question has been asked has not stopped anything.", z.asked)
			}
		})
	}
}

// An excluded name is refused however it is spelled (I7).
func TestExclusionSurvivesTheSpelling(t *testing.T) {
	for _, spelling := range []string{"www.gchq.gov.uk", "WWW.GCHQ.GOV.UK", " www.gchq.gov.uk ", "www.gchq.gov.uk."} {
		z := &zone{records: map[string][]string{}}
		if _, err := (&Scanner{Resolver: z}).Scan(context.Background(), spelling); err == nil {
			t.Errorf("%q was accepted", spelling)
		}
	}
}

// The proof this check requires is the zone proof, not the file proof.
//
// The whole of the difference: a file at /.well-known proves control of one
// host's web surface, and every record read here lives in the zone. A
// deployment that accepted the file proof for a mail scan would let somebody
// who can publish a page under a name read the mail policy of a zone they do
// not run.
func TestOnlyTheZoneProofAuthorisesAMailScan(t *testing.T) {
	skipUnderDemo(t)
	secret := []byte("a deployment secret")
	domain := "example.com"

	scope := &verify.Scope{
		Secret:   secret,
		Resolver: fixedChallenge{},
		Fetcher:  fixedFile{body: verify.Token(secret, domain)},
	}

	// The file proof is genuine and is accepted for the surface it covers, so
	// this test fails for the right reason if the surface is ever widened.
	if err := scope.Covers(context.Background(), domain, verify.HTTPOnly); err != nil {
		t.Fatalf("the file proof was not accepted even for HTTP: %v", err)
	}

	z := &zone{records: map[string][]string{}}
	if _, err := (&Scanner{Resolver: z, Verify: scope}).Scan(context.Background(), domain); err == nil {
		t.Fatal("a mail scan was authorised by a file served over HTTP. The records this check " +
			"reads are in the zone, and a page under a name proves nothing about the zone.")
	}
}

// fixedChallenge publishes no TXT record, so only the file proof can succeed.
type fixedChallenge struct{}

func (fixedChallenge) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, true, nil
}

// fixedFile serves one body at every host.
type fixedFile struct{ body string }

func (f fixedFile) FetchChallenge(context.Context, string) (string, error) { return f.body, nil }

// A target that is not a bare domain is refused, and the refusal repeats
// nothing that was sent (I3).
func TestScanTakesADomainAndNothingElse(t *testing.T) {
	for _, target := range []string{
		"",
		"localhost",
		"https://example.com",
		"example.com/path",
		"example.com:25",
		"user@example.com",
		"exam\nple.com",
		strings.Repeat("a.", 200) + "example.com",
	} {
		z := &zone{records: map[string][]string{}}
		_, err := (&Scanner{Resolver: z}).Scan(context.Background(), target)
		if err == nil {
			t.Errorf("%q was accepted as a domain", target)
			continue
		}
		if target != "" && strings.Contains(err.Error(), target) {
			t.Errorf("the error repeats what was sent: %q", err)
		}
		if len(z.asked) != 0 {
			t.Errorf("%q was looked up before it was checked", target)
		}
	}
}

// Every mail report carries the standing limit, whatever the domain looks like.
func TestEveryReportSaysItOnlyReadDNS(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{records: map[string][]string{
		"example.com":        {"v=spf1 -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:r@example.com"},
	}}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	standing := policy.NotesOfKind(got.Notes, policy.KindStanding)
	if len(standing) == 0 {
		t.Fatal("a report that read only DNS does not say so, so it reads as a complete picture " +
			"of the domain's mail rather than of its DNS")
	}
}

// A value from somebody else's zone is bounded before it is carried anywhere.
func TestAnEnormousTagDoesNotTravel(t *testing.T) {
	skipUnderDemo(t)
	huge := strings.Repeat("x", 40000)
	z := &zone{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=" + huge},
	}}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got.Observed.DMARCPolicy) > maxTagLength {
		t.Errorf("a %d-byte tag was carried into the report whole", len(got.Observed.DMARCPolicy))
	}

	// And what survives is the start of what was published.
	//
	// Bounding it to nothing would be the other way to pass the line above,
	// and it turns a domain with an overlong policy into a domain the report
	// says names no policy at all — an absent value invented by a size cap,
	// which is what R4 is about. A sabotage doing exactly that escaped on
	// 2026-09-11 and this is what closed it.
	if !strings.HasPrefix(huge, got.Observed.DMARCPolicy) || got.Observed.DMARCPolicy == "" {
		t.Errorf("the bounded tag is %q, which is not the beginning of what was published",
			got.Observed.DMARCPolicy)
	}

	// A value that fits is not touched.
	fits := strings.Repeat("y", maxTagLength)
	z = &zone{records: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=" + fits},
	}}
	got, err = (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Observed.DMARCPolicy != fits {
		t.Errorf("a tag of exactly the permitted length was shortened to %d bytes",
			len(got.Observed.DMARCPolicy))
	}
}

// The duration comes from the clock the caller supplies.
func TestTheDurationIsMeasuredRatherThanAssumed(t *testing.T) {
	skipUnderDemo(t)
	at := time.Unix(1757000000, 0)
	ticks := 0
	z := &zone{records: map[string][]string{}}

	got, err := (&Scanner{Resolver: z, Now: func() time.Time {
		ticks++
		return at.Add(time.Duration(ticks) * 250 * time.Millisecond)
	}}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Duration != 250*time.Millisecond {
		t.Errorf("duration = %s, want 250ms", got.Duration)
	}
}

// skipUnderDemo steps aside in a demonstration build.
//
// Every test above points at example.com, which that build refuses before it
// looks anything up — so under the tag they would be asserting the refusal
// rather than what they were written for. The refusal has tests of its own,
// beside this file. A skip that says which, rather than a build tag, because a
// tagged file is one nobody notices has stopped running.
func skipUnderDemo(t *testing.T) {
	t.Helper()
	if demo.Enabled {
		t.Skip("a demonstration build refuses example.com before any lookup; see demo_guard_test.go")
	}
}
