package mailscan

import (
	"context"
	"errors"
	"strconv"
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

	// exchangers and dane answer the two lookups that are not TXT. Empty maps
	// mean a domain that publishes neither, which is the ordinary case and the
	// one every test written before them assumed.
	exchangers map[string][]dnsclient.MX
	dane       map[string][]dnsclient.TLSA

	asked []string
}

func (z *zone) LookupMX(_ context.Context, name string) (dnsclient.MXAnswer, error) {
	name = fold(name)
	z.asked = append(z.asked, name)

	if err := z.fail[name]; err != nil {
		return dnsclient.MXAnswer{}, err
	}
	records, ok := z.exchangers[name]
	return dnsclient.MXAnswer{Records: records, Existed: ok}, nil
}

func (z *zone) LookupTLSA(_ context.Context, name string) (dnsclient.TLSAAnswer, error) {
	name = fold(name)
	z.asked = append(z.asked, name)

	if err := z.fail[name]; err != nil {
		return dnsclient.TLSAAnswer{}, err
	}
	records, ok := z.dane[name]
	return dnsclient.TLSAAnswer{Records: records, Existed: ok}, nil
}

func (z *zone) LookupTXT(_ context.Context, name string) (dnsclient.TXTAnswer, error) {
	name = fold(name)
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

	// Every name below is the target, or a label beneath it, or a name the
	// target's own records point at. Nothing else may appear here, and the
	// list grows only by somebody deciding it should — which is the point of
	// writing it out rather than deriving it.
	allowed := map[string]bool{
		"example.com":            true,
		"_dmarc.example.com":     true,
		"_smtp._tls.example.com": true,
		"_mta-sts.example.com":   true,

		// Reached because the domain's own policy names it. A sender policy
		// that includes a provider is a domain asking receivers to resolve
		// that name, so resolving it is reading the policy rather than
		// wandering off it.
		"spf.provider.example": true,
	}
	for _, name := range z.asked {
		if !allowed[name] {
			t.Errorf("the scan asked about %q, which is neither the domain, a label beneath it, "+
				"nor a name its own records point at", name)
		}
	}
}

// DANE is asked about beneath the exchangers the domain itself named.
//
// The one place this check follows a name out of the target's own zone, and it
// is the same reasoning that lets a sender policy's include be resolved: the
// domain published an MX saying "this host takes my mail", so asking what that
// host publishes is reading the domain's own answer rather than wandering off
// it. Asserted separately because it is the case a reader would most reasonably
// object to.
func TestDANEIsAskedOnlyBeneathTheExchangersTheDomainNamed(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{
		records: map[string][]string{},
		exchangers: map[string][]dnsclient.MX{
			"example.com": {{Preference: 10, Host: "mx1.provider.example"}},
		},
		dane: map[string][]dnsclient.TLSA{
			"_25._tcp.mx1.provider.example": {{Usage: 3, Selector: 1, Matching: 1}},
		},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if !z.askedFor("_25._tcp.mx1.provider.example") {
		t.Errorf("DANE was not asked about beneath the exchanger the domain named: %v", z.asked)
	}
	for _, name := range z.asked {
		if strings.HasPrefix(name, "_25._tcp.") && name != "_25._tcp.mx1.provider.example" {
			t.Errorf("DANE was asked about beneath %q, which the domain never named", name)
		}
	}

	if len(got.Observed.DANEHosts) != 1 || got.Observed.DANEHosts[0] != "mx1.provider.example" {
		t.Errorf("DANE hosts are %v", got.Observed.DANEHosts)
	}
}

// A domain that says it takes no mail is not told what it is missing.
//
// RFC 7505's null MX is a statement, and it is the clearest case of a correct
// configuration a scanner could mark down: every sentence about delivery is
// inapplicable rather than unsatisfied (R6).
func TestANullMXEndsTheQuestionsAboutDelivery(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{
		records: map[string][]string{},
		exchangers: map[string][]dnsclient.MX{
			"example.com": {{Preference: 0, Host: "."}},
		},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if !got.Observed.NullMX {
		t.Fatal("a null MX was not read as one")
	}
	if len(got.Observed.MXHosts) != 0 {
		t.Errorf("a null MX was kept as a host: %v", got.Observed.MXHosts)
	}

	text := noteText(got)
	if !strings.Contains(text, "accepts no mail at all") {
		t.Errorf("the report does not say what a null MX means:\n%s", text)
	}

	// What the report says about *this domain*, which is the property. The
	// standing limit names MTA-STS and DANE on every report by design — it
	// describes the method rather than the domain, and it is the same sentence
	// whoever is being looked at.
	about := aboutTheDomain(got)
	for _, unwanted := range []string{"MTA-STS", "DANE"} {
		if strings.Contains(about, unwanted) {
			t.Errorf("a domain that accepts no mail was told about %s, which cannot apply to "+
				"it:\n%s", unwanted, about)
		}
	}
}

// aboutTheDomain is every sentence that is a claim about the target, which is
// every note except the standing limits.
//
// The limits are true of every scan this check runs and say so; folding them in
// would make a test about what a report claims of one domain fail on a sentence
// that is deliberately identical on all of them.
func aboutTheDomain(r *Result) string {
	var b strings.Builder
	for _, n := range r.Notes {
		if n.Kind == policy.KindStanding {
			continue
		}
		b.WriteString(n.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// noteText is every sentence a report would print, joined.
func noteText(r *Result) string {
	var b strings.Builder
	for _, n := range r.Notes {
		b.WriteString(n.Text)
		b.WriteString("\n")
	}
	return b.String()
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

// A typed nil resolver is treated as no resolver.
//
// `resolver == nil` does not catch an interface carrying a nil *dnsclient.Client,
// so a caller writing `Resolver: someScanner.Resolver` hands this package
// something that passes every nil test and dereferences nothing on first use.
// It panicked on the first real request to the mail endpoint on 2026-09-11.
//
// The caller was fixed too. This is here because the trap is in the language
// rather than in that caller, and the cost of being wrong is a service that
// crashes on a request a stranger sends.
func TestATypedNilResolverIsTreatedAsNone(t *testing.T) {
	skipUnderDemo(t)

	var missing *dnsclient.Client
	s := &Scanner{Resolver: missing}

	if s.Resolver == nil {
		t.Fatal("the fixture is not the state being tested: a typed nil should not compare equal to nil")
	}

	// It must not panic. Whether the lookups succeed depends on the machine's
	// own resolver and is not what this asserts.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a typed nil resolver panicked: %v", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := s.Scan(ctx, "example.com"); err != nil {
		t.Fatalf("Scan: %v", err)
	}
}

// An address is accepted, and the part before the @ never travels.
//
// Somebody checking a domain's mail policy has an address in front of them and
// pasting it is the natural thing to do. Refusing it teaches nothing. Keeping
// the left half would be this project recording the one kind of value it
// undertakes never to hold: a local part is a person's identity, and every
// question this check asks is about the zone.
func TestAnAddressIsAcceptedAndTheLocalPartIsDropped(t *testing.T) {
	skipUnderDemo(t)

	for _, tc := range []struct {
		given string
		want  string
	}{
		{"user@example.com", "example.com"},
		{"first.last+tag@example.com", "example.com"},
		{`"odd@name"@example.com`, "example.com"},
		{"USER@EXAMPLE.COM", "example.com"},
		{"example.com", "example.com"},
	} {
		z := &zone{records: map[string][]string{}}

		got, err := (&Scanner{Resolver: z}).Scan(context.Background(), tc.given)
		if err != nil {
			t.Errorf("Scan(%q): %v", tc.given, err)
			continue
		}
		if got.Domain != tc.want {
			t.Errorf("Scan(%q) reported the domain as %q, want %q", tc.given, got.Domain, tc.want)
		}

		// Nothing anywhere in the report, and nothing in any question asked,
		// carries what was to the left of the @.
		local, _, _ := strings.Cut(tc.given, "@")
		if local == tc.given {
			continue
		}
		local = strings.Trim(local, `"`)

		if strings.Contains(got.Domain, local) {
			t.Errorf("the local part of %q reached the report's domain field", tc.given)
		}
		for _, asked := range z.asked {
			if strings.Contains(asked, strings.ToLower(local)) {
				t.Errorf("the local part of %q reached a DNS question: %q", tc.given, asked)
			}
		}
	}
}

// The split is at the last @, because a quoted local part may contain one and a
// domain may not.
func TestTheAddressIsSplitWhereTheDomainBegins(t *testing.T) {
	for _, tc := range []struct {
		given   string
		domain  string
		address bool
	}{
		{"example.com", "example.com", false},
		{"user@example.com", "example.com", true},
		{`"a@b"@example.com`, "example.com", true},
		{"@example.com", "example.com", true},
		{"user@", "", true},
	} {
		domain, wasAddress := DropLocalPart(tc.given)
		if domain != tc.domain || wasAddress != tc.address {
			t.Errorf("DropLocalPart(%q) = %q, %v; want %q, %v",
				tc.given, domain, wasAddress, tc.domain, tc.address)
		}
	}
}

// An exchanger that could not be asked about is not an exchanger without DANE.
//
// The reassuring direction, which is the one that matters: a resolver that
// failed on one host would otherwise make a domain look like it had simply not
// deployed DANE there, and the report would present an incomplete picture as a
// complete one (R4).
func TestAFailedDANELookupIsNotAnAbsenceOfDANE(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{
		records: map[string][]string{},
		exchangers: map[string][]dnsclient.MX{
			"example.com": {
				{Preference: 10, Host: "mx1.example.net"},
				{Preference: 20, Host: "mx2.example.net"},
			},
		},
		dane: map[string][]dnsclient.TLSA{
			"_25._tcp.mx1.example.net": {{Usage: 3, Selector: 1, Matching: 1}},
		},
		fail: map[string]error{
			"_25._tcp.mx2.example.net": errors.New("the resolver did not answer"),
		},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	f := got.Observed
	if f.DANEUnread != 1 {
		t.Errorf("DANEUnread = %d, want 1. An exchanger nobody could ask about has to be counted, "+
			"or the report claims a completeness it does not have.", f.DANEUnread)
	}
	if f.DANEAsked != 1 {
		t.Errorf("DANEAsked = %d, want 1", f.DANEAsked)
	}
	if len(f.DANEHosts) != 1 || f.DANEHosts[0] != "mx1.example.net" {
		t.Errorf("DANE hosts are %v", f.DANEHosts)
	}

	if text := aboutTheDomain(got); !strings.Contains(text, "could not be read") {
		t.Errorf("the report does not say an exchanger could not be asked about:\n%s", text)
	}
}

// A domain cannot decide how many questions this scan asks.
//
// The exchanger list is written by whoever is being measured. Without a bound,
// a zone publishing four hundred of them would turn one scan into four hundred
// lookups — and the report would say so, which is the other half: a sample
// presented as the set is a reader fixing what they can see and believing there
// was nothing else.
func TestADomainWithManyExchangersIsBoundedAndSaysSo(t *testing.T) {
	skipUnderDemo(t)

	var many []dnsclient.MX
	for i := range 40 {
		many = append(many, dnsclient.MX{
			Preference: uint16(10 + i),
			Host:       "mx" + strconv.Itoa(i) + ".example.net",
		})
	}

	z := &zone{
		records:    map[string][]string{},
		exchangers: map[string][]dnsclient.MX{"example.com": many},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got.Observed.DANEAsked > maxExchangers {
		t.Errorf("%d DANE lookups were made and the bound is %d", got.Observed.DANEAsked, maxExchangers)
	}
	if !got.Observed.DANEPartial {
		t.Error("more exchangers were published than were asked about, and the report does not " +
			"say so, so an empty DANE list reads as the whole picture")
	}

	// The bound is on the questions, not on what the report names: an operator
	// with forty exchangers is entitled to see that they have forty.
	if len(got.Observed.MXHosts) != 40 {
		t.Errorf("the report names %d exchangers, and the domain published 40",
			len(got.Observed.MXHosts))
	}

	if text := aboutTheDomain(got); !strings.Contains(text, "more mail exchangers than this scan") {
		t.Errorf("the report does not say the DANE picture is partial:\n%s", text)
	}
}

// A record that mentions MTA-STS is not an MTA-STS record.
//
// The same rule DMARC gets, and for the same reason in both directions:
// counting a stray TXT record credits a domain with a policy it does not
// announce, and refusing one spaced or cased unusually reports a domain that
// announces one as silent. A reader can tell neither from the report.
func TestOnlyARecordThatAnnouncesItselfIsMTASTS(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"v=STSv1; id=20260912T000000", true},
		{"v=stsv1;id=x", true},
		{"  V = STSv1 ; id=x", true},
		{"v=spf1 -all", false},
		{"this record is about STSv1 and is not one", false},
		{"id=x; v=STSv1", false},
		{"", false},
	} {
		if got := isMTASTS(tc.value); got != tc.want {
			t.Errorf("isMTASTS(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// An announced policy is read from the record and reported as announced only.
//
// The sentence a reader would otherwise complete in the stronger direction: the
// record says a policy exists, and what mode it is in lives in a file this check
// does not fetch.
func TestAnAnnouncedMTASTSPolicyIsSeenAndNotFetched(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{
		records: map[string][]string{
			"_mta-sts.example.com": {"v=STSv1; id=20260912T000000"},
		},
		exchangers: map[string][]dnsclient.MX{
			"example.com": {{Preference: 10, Host: "mx1.example.net"}},
		},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got.Observed.MTASTSRecords != 1 {
		t.Fatalf("MTASTSRecords = %d, want 1", got.Observed.MTASTSRecords)
	}

	// The MTA-STS sentence itself, not merely the report.
	//
	// "was not read" appears in the SPF sentence too whenever a lookup fails,
	// so an assertion over the whole report passes while this one says the
	// opposite. That is how the first version of this test missed a sabotage
	// turning "not read" into "read in full".
	sts := sentenceAbout(got, "MTA-STS")
	if sts == "" {
		t.Fatalf("the report says nothing about MTA-STS:\n%s", aboutTheDomain(got))
	}
	if !strings.Contains(sts, "policy is announced") {
		t.Errorf("the report does not say a policy is announced: %q", sts)
	}
	if !strings.Contains(sts, "was not read") {
		t.Errorf("the MTA-STS sentence does not say the policy itself was not read, so a reader "+
			"completes it in the stronger direction: %q", sts)
	}

	// And nothing was fetched: the policy lives at mta-sts.<domain> over HTTPS,
	// and this check asks DNS and nothing else.
	for _, asked := range z.asked {
		if strings.HasPrefix(asked, "mta-sts.") {
			t.Errorf("the scan went looking at %q, which is the policy file's host", asked)
		}
	}
}

// A domain announcing nothing is told what that costs, and not graded for it.
func TestNoMTASTSIsDescribedRatherThanGraded(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{
		records: map[string][]string{},
		exchangers: map[string][]dnsclient.MX{
			"example.com": {{Preference: 10, Host: "mx1.example.net"}},
		},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got.Observed.MTASTSRecords != 0 {
		t.Errorf("MTASTSRecords = %d, want 0", got.Observed.MTASTSRecords)
	}
	for _, f := range got.Findings {
		if strings.Contains(f.RuleID, "sts") {
			t.Errorf("%s grades a domain for not announcing MTA-STS, which no document requires",
				f.RuleID)
		}
	}
	if text := aboutTheDomain(got); !strings.Contains(text, "announces no MTA-STS policy") {
		t.Errorf("the report does not name what is absent:\n%s", text)
	}
}

// sentenceAbout returns the one note mentioning a word, so an assertion is
// about the sentence it means rather than about the whole report.
//
// A report is several claims, and a phrase that appears in two of them makes an
// assertion over the joined text pass while the sentence it was written for says
// the opposite.
func sentenceAbout(r *Result, word string) string {
	for _, n := range r.Notes {
		if n.Kind == policy.KindStanding {
			continue
		}
		if strings.Contains(n.Text, word) {
			return n.Text
		}
	}
	return ""
}

// A stray record at the MTA-STS name is not an MTA-STS policy.
//
// The name is beneath a domain anybody may publish anything under. Counting
// whatever is there credits a domain with a policy it never announced, and a
// report crediting protection that does not exist is the reassuring direction —
// the one that matters.
func TestAStrayRecordAtTheMTASTSNameIsNotAPolicy(t *testing.T) {
	skipUnderDemo(t)
	z := &zone{
		records: map[string][]string{
			"_mta-sts.example.com": {
				"google-site-verification=abc",
				"some note the operator left here",
			},
		},
		exchangers: map[string][]dnsclient.MX{
			"example.com": {{Preference: 10, Host: "mx1.example.net"}},
		},
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got.Observed.MTASTSRecords != 0 {
		t.Errorf("MTASTSRecords = %d for a name carrying no MTA-STS record at all. Anything may "+
			"be published under that label, and counting it credits a domain with a policy it "+
			"never announced.", got.Observed.MTASTSRecords)
	}
	if sts := sentenceAbout(got, "MTA-STS"); !strings.Contains(sts, "announces no MTA-STS policy") {
		t.Errorf("the report describes a domain with no policy as having one: %q", sts)
	}
}
