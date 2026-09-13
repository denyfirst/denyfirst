// Package mailscan reads what a domain publishes about its mail and grades it.
//
// Almost everything here comes out of a DNS lookup: the sender policy and what
// it costs a receiver to evaluate, the DMARC instruction, whether the domain
// asks for reports when transport security fails, which hosts accept its mail,
// and what those hosts publish about protecting it in transit. No mail server is
// contacted, no message is composed, nothing is sent, and nothing that would
// change state at the other end is attempted. That is a property of what these
// records are rather than a restraint applied to them: the queries go to the
// resolver this machine already asks about every target, and the domain being
// examined learns nothing at all.
//
// # The one exception, and what it is fenced with
//
// An MTA-STS policy is announced in DNS and served as a file over HTTPS. The
// record says a policy exists; only the file says what it is, and the difference
// between a policy in testing mode and one in enforce mode is the difference
// between measuring the problem and preventing it. For the whole life of this
// check a report could say a policy was announced and nothing more, and an
// operator who left a rollout in testing mode two years ago had the appearance
// of protection and none of it.
//
// So the policy is fetched, under four conditions, and ReadSTSPolicy is off
// until a caller says otherwise:
//
//   - **Only where the domain announces one.** No record, no request. The
//     record is the zone saying *there is a policy at that address*, which is
//     what makes reading it an instruction being followed rather than an
//     address being tried (N7).
//   - **Only where control of the domain has been proven.** The same condition
//     the web check reads a page under, and the same reason: the request goes to
//     a host in an estate the person asking has shown is theirs.
//   - **One address, fixed by RFC 8461.** No path is constructed, no redirect
//     is followed, and the certificate must verify.
//   - **Not a mail server.** mta-sts.<domain> on port 443 is a web host. The
//     claim that nothing on the mail path is contacted survives intact.
//
// See internal/mtasts, and N13 for the argument.
//
// # What is deliberately not here
//
// **The mail servers themselves.** Whether an MX accepts STARTTLS, and what
// certificate it presents, needs a connection to port 25. That is one ordinary
// SMTP conversation and would not break anything — but it is a connection on
// the mail path, which is the claim above, and outbound port 25 is blocked by
// most hosting providers, so the check would fail for a large share of the
// deployments that would run it. A separate decision, deliberately.
//
// **Discovering a DKIM selector.** A key lives at <selector>._domainkey.<domain>
// and DNS offers no query for what is beneath a name, so there is no set to
// find. Keys are read under selectors this scan is told to look under — the
// operator's own, and the ones mail providers document for their own service —
// and a report names every selector it tried. "These names hold nothing" is
// never rendered as "this domain publishes no key" (R4). See internal/dkim.
//
// **The MTA-STS policy, where a deployment does not fetch it.** Reading the
// policy is one HTTPS request and runs only behind proof of control, so a
// deployment configured without proof reads the record and stops there. What
// such a report says is that a policy is announced and that what it says was not
// read — never the stronger reading, which is the one a reader supplies for
// themselves if nobody stops them.
//
// **Whether a DANE binding is correct.** The TLSA records are read, so a report
// can say which exchangers publish one and what kind of binding they declare.
// Checking that the binding matches means holding a certificate from the mail
// host, which needs a connection to it.
package mailscan

import (
	"context"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/dkim"
	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/exclusion"
	"github.com/denyfirst/denyfirst/internal/mtasts"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/spf"
	"github.com/denyfirst/denyfirst/internal/verify"
)

const (
	// dmarcPrefix is where a DMARC policy lives, beneath the domain.
	dmarcPrefix = "_dmarc."

	// tlsReportPrefix is where a TLS-RPT record lives.
	tlsReportPrefix = "_smtp._tls."

	// stsPrefix is where the record announcing an MTA-STS policy lives.
	//
	// The record, not the policy. RFC 8461 puts the policy itself in a file at
	// mta-sts.<domain>, which is fetched where the deployment is allowed to and
	// reported as unread where it is not (N13). Reading the record first is not
	// only ordering: no record means no request, and the record is what makes
	// the request an instruction from the zone rather than an address tried.
	stsPrefix = "_mta-sts."

	// danePrefix is where DANE for SMTP lives, beneath each exchanger.
	danePrefix = "_25._tcp."

	// maxExchangers bounds how many hosts are looked up for DANE.
	//
	// One lookup each, and the list is written by whoever is being measured. A
	// domain publishing four hundred exchangers would otherwise decide how many
	// questions this scan asks.
	maxExchangers = 8

	// maxTagLength bounds one value read out of a record. These come from a
	// zone the scanned party controls, so they are chosen by whoever is being
	// measured.
	maxTagLength = 256
)

// Resolver is the lookup this check needs, and the only one.
//
// An interface for the reason internal/verify's is: a test has to be able to
// answer without a network, or the only thing exercised is whichever zone the
// machine running the tests happens to reach. *dnsclient.Client satisfies it as
// it stands.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) (dnsclient.TXTAnswer, error)
	LookupMX(ctx context.Context, name string) (dnsclient.MXAnswer, error)
	LookupTLSA(ctx context.Context, name string) (dnsclient.TLSAAnswer, error)
}

// PolicyFetcher reads the MTA-STS policy file for a domain.
//
// No error in the signature, deliberately. A policy that could not be fetched
// and a domain with no policy are different answers, and an implementation that
// returned the first as an error would eventually be called by somebody who
// treated the zero value as the second (R4). The reason travels inside.
type PolicyFetcher interface {
	Fetch(ctx context.Context, domain string) mtasts.Policy
}

// Scanner measures one domain's mail policy. The zero value is usable.
type Scanner struct {
	// Resolver asks the questions. Nil means one reading this machine's own
	// configuration, which is what every other check here uses.
	Resolver Resolver

	// Verify is the proof of control this deployment requires before it will
	// scan a name. Nil means none is required, which is what the command line
	// wants and what a service must not have.
	Verify *verify.Scope

	// ReadSTSPolicy asks for the MTA-STS policy file to be fetched, where the
	// domain announces one.
	//
	// False by default, which is the behaviour this check had for its whole life
	// and the safe thing for an unset field to mean. What a true here buys is
	// the one fact DNS cannot carry: whether the policy enforces or is only
	// rehearsing. What it costs is one HTTPS request to mta-sts.<domain> — not a
	// mail server, and not a path this program invented.
	//
	// A caller sets this where control of the domain has been proven and
	// nowhere else. It is a separate field from Verify rather than derived from
	// it, because the two answer different questions: Verify says whose estate
	// this is, and this says whether this deployment fetches files at all. A
	// service ties them together (see internal/httpapi); the command line sets
	// this and leaves Verify nil, because it runs on the operator's own machine
	// from their own address — the same argument webscan.ReadMarkup rests on.
	ReadSTSPolicy bool

	// STS fetches the policy. Nil means internal/mtasts, dialling through the
	// guard that refuses private and reserved destinations.
	//
	// An interface for the reason Resolver is one: a test that could not answer
	// without a network would exercise whichever domain the machine running the
	// tests happens to reach.
	STS PolicyFetcher

	// Roots is the trust store the policy fetch is judged against. Nil means
	// the system store.
	//
	// Here because this check now verifies a certificate, which it did not
	// before, and R7 says a verdict must not depend on which platform ran it.
	// A service that resolved its own store, checked it was not empty and
	// refused to start without one has to be able to hand over the store it
	// resolved — the field the web check was missing for a while, for the same
	// reason and with the same consequence.
	Roots *x509.CertPool

	// DKIMSelectors are the names to look for signing keys under.
	//
	// Empty looks for none, and that is the default. DNS cannot list what is
	// beneath a name, so there is no set to discover: a selector is either one
	// the operator named or one a provider documents, and either way somebody
	// has to say. See internal/dkim.
	DKIMSelectors []dkim.Selector

	// Now supplies the current time, so a duration is reproducible in tests.
	Now func() time.Time
}

// Result is one domain, measured and graded.
type Result struct {
	Domain string `json:"domain"`

	// Policy names the rule set behind every verdict here. Never the TLS or
	// web rule set: these are different questions over different evidence.
	Policy string `json:"policy"`

	// Verdict is the worst of everything below. Empty means nothing was
	// graded, which is not the same as nothing being wrong.
	Verdict policy.Verdict `json:"verdict,omitempty"`

	Findings []policy.Finding `json:"findings,omitempty"`
	Notes    []policy.Note    `json:"notes,omitempty"`

	// Observed is what the lookups established, kept so a reader can check a
	// verdict against the evidence rather than taking it on trust.
	Observed *policy.MailFacts `json:"observed,omitempty"`

	Duration time.Duration `json:"duration"`
}

// Scan reads one domain's mail policy.
//
// An error means the domain was refused before anything was looked up. A domain
// with no records is not an error: it is a result with notes saying what is not
// published, which is a different thing and is reported as one.
func (s *Scanner) Scan(ctx context.Context, domain string) (*Result, error) {
	started := s.now()

	// An address becomes a domain here, at the edge, and the local part is
	// gone before anything else in this function can see it. See DropLocalPart.
	domain, _ = DropLocalPart(domain)

	domain = fold(domain)
	if err := CheckDomain(domain); err != nil {
		return nil, err
	}

	// The same three sources of authority the other checks ask, in the same
	// order and for the same reasons (N8, N6, N9). Asked here rather than in
	// whatever calls this, so they hold for the command line and for entry
	// points not written yet.
	if exclusion.Covers(domain) {
		return nil, exclusion.ErrRefused
	}
	if demo.Refusal(domain) {
		return nil, demo.ErrNotATarget
	}
	if s.Verify != nil {
		// AnyPort, not HTTPOnly, and the difference is the whole of it. A
		// file served at /.well-known proves control of one host's web
		// surface; it says nothing about the zone's MX, its DMARC record or
		// its sender policy, and this check reads none of those over HTTP.
		// Only the zone proof authorises a question about the zone.
		if err := s.Verify.Covers(ctx, domain, verify.AnyPort); err != nil {
			return nil, err
		}
	}

	resolver := s.Resolver
	if resolver == nil || isNilClient(resolver) {
		resolver = &dnsclient.Client{}
	}

	facts := policy.MailFacts{}
	s.readSPF(ctx, resolver, domain, &facts)
	s.readDMARC(ctx, resolver, domain, &facts)
	s.readTLSReporting(ctx, resolver, domain, &facts)
	s.readExchangers(ctx, resolver, domain, &facts)
	s.readTransportSecurity(ctx, resolver, domain, &facts)
	s.readDKIM(ctx, resolver, domain, &facts)

	graded := policy.GradeMail(facts)

	return &Result{
		Domain:   domain,
		Policy:   policy.MailVersion,
		Verdict:  graded.Verdict,
		Findings: graded.Findings,
		Notes:    graded.Notes,
		Observed: &facts,
		Duration: s.now().Sub(started),
	}, nil
}

// readSPF walks the sender policy and records what it costs.
func (s *Scanner) readSPF(ctx context.Context, r Resolver, domain string, facts *policy.MailFacts) {
	got := spf.Check(ctx, txtAdapter{r}, domain)

	facts.SPFRecords = got.Records
	facts.SPFAll = string(got.All)
	facts.SPFLookups = got.Lookups
	facts.SPFLookupLimit = got.LookupLimit
	facts.SPFVoidLookups = got.VoidLookups
	facts.SPFVoidLimit = got.VoidLimit
	facts.SPFUsesPTR = got.UsesPTR
	facts.SPFIncludes = got.Includes
	facts.SPFReason = got.Reason
}

// readDMARC reads the policy at _dmarc, if there is one.
func (s *Scanner) readDMARC(ctx context.Context, r Resolver, domain string, facts *policy.MailFacts) {
	answer, err := r.LookupTXT(ctx, dmarcPrefix+domain)
	if err != nil {
		// Only the shape of the failure: the underlying error names resolvers
		// and addresses (I6).
		facts.DMARCReason = "the DMARC record could not be read"
		return
	}

	// A name that does not exist is a domain with no DMARC, which is a fact
	// about the domain rather than a failure to look.
	var records []string
	for _, v := range answer.Values {
		if isDMARC(v) {
			records = append(records, v)
		}
	}
	facts.DMARCRecords = len(records)

	if len(records) != 1 {
		// Two records is graded; zero is reported. Neither leaves a policy to
		// read, so nothing below applies.
		return
	}

	// 100 unless the record says otherwise, which is what RFC 7489 specifies
	// and is worth stating: a reader seeing "0%" in a report where the record
	// carried no pct= would be reading this program's default rather than the
	// domain's policy.
	facts.DMARCPercent = 100

	for _, tag := range strings.Split(records[0], ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(tag), "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = bound(strings.TrimSpace(value))

		switch name {
		case "p":
			facts.DMARCPolicy = strings.ToLower(value)
		case "pct":
			if n, err := strconv.Atoi(value); err == nil && n >= 0 && n <= 100 {
				facts.DMARCPercent = n
			}
		case "rua":
			facts.DMARCReporting = value != ""
		}
	}
}

// readTLSReporting asks whether the domain wants to hear about failed delivery
// over an encrypted connection.
func (s *Scanner) readTLSReporting(ctx context.Context, r Resolver, domain string, facts *policy.MailFacts) {
	answer, err := r.LookupTXT(ctx, tlsReportPrefix+domain)
	if err != nil {
		// Absent rather than unknown would be a claim; this one is small
		// enough that a failure and an absence lead to the same sentence, and
		// the note says the record was not found rather than that it does not
		// exist.
		return
	}

	for _, v := range answer.Values {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=tlsrptv1") {
			facts.TLSReporting = true
			return
		}
	}
}

// txtAdapter gives internal/spf the narrow lookup it asks for.
//
// Here rather than in spf, for the reason internal/verify's adapter lives in
// dnsclient: a package that walks a policy should be readable without reading a
// DNS client, and the shape it needs is three values rather than an answer
// type it would have to know about.
type txtAdapter struct{ client Resolver }

func (a txtAdapter) LookupTXT(ctx context.Context, name string) ([]string, bool, error) {
	answer, err := a.client.LookupTXT(ctx, name)
	if err != nil {
		return nil, answer.Existed, err
	}
	return answer.Values, answer.Existed, nil
}

// isDMARC reports whether a TXT value announces itself as a DMARC record.
//
// The version tag must be the first thing in the record, as RFC 7489 requires,
// and is compared case-insensitively. A record that merely mentions DMARC in
// passing is not one.
func isDMARC(value string) bool {
	first, _, _ := strings.Cut(strings.TrimSpace(value), ";")
	name, tag, ok := strings.Cut(strings.TrimSpace(first), "=")
	return ok &&
		strings.EqualFold(strings.TrimSpace(name), "v") &&
		strings.EqualFold(strings.TrimSpace(tag), "DMARC1")
}

// CheckDomain refuses anything that is not a bare domain name.
//
// Deliberately narrow: this check asks about a zone, so a scheme, a path or a
// port is a caller asking for a different measurement. An address is refused
// because there is no zone under an address to hold any of these records.
//
// Exported for the reason webprobe.CheckHostname is. A service that parses a
// target has to be able to ask the scanner what a target is, rather than
// keeping a second definition that agrees until somebody loosens one of them —
// and a target the parser accepts and the scanner refuses reaches a caller as a
// failed scan instead of as the rule they broke.
func CheckDomain(domain string) error {
	switch {
	case domain == "":
		return errNotADomain
	case len(domain) > 253:
		return errNotADomain
	case strings.ContainsAny(domain, "/\\ :@"):
		return errNotADomain
	case !strings.Contains(domain, "."):
		return errNotADomain
	}

	for _, r := range domain {
		if r < 0x20 || r == 0x7f {
			return errNotADomain
		}
	}
	return nil
}

// bound truncates a value read out of somebody else's zone.
//
// `>` and `>=` are the same program here: slicing a string of exactly
// maxTagLength to maxTagLength returns it unchanged. A sabotage flipping the
// comparison escaped every test on 2026-09-11 and that is why — there is no
// behaviour on the far side of it to catch, so nothing is missing. What is
// worth guarding is the other end, that an oversized value is shortened rather
// than emptied, and TestAnEnormousTagDoesNotTravel does.
func bound(s string) string {
	if len(s) > maxTagLength {
		return s[:maxTagLength]
	}
	return s
}

// fold reduces a name the way every other comparison in this project does (I7).
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// errNotADomain is returned for a target that is not a bare domain name.
//
// The message states the rule and never repeats what was given (I3): anything
// a caller sent that came back in a response is a reflection, and this check
// takes its input from the same places every other one does.
var errNotADomain = errors.New("mailscan: the target must be a domain name, such as example.com")

// isNilClient reports whether an interface holds a nil *dnsclient.Client.
//
// The one shape of nil that `resolver == nil` does not catch. An interface
// carrying a typed nil pointer is not nil, so a caller writing
//
//	Resolver: someScanner.Resolver   // a *dnsclient.Client that happens to be nil
//
// hands this package something that passes every nil test and dereferences
// nothing on first use. It panicked on the first real request to the mail
// endpoint on 2026-09-11, while every test passed, because every fixture
// supplies a resolver.
//
// The caller was fixed too. This is here because the trap is in the language
// rather than in that caller, and the next one will be written by somebody who
// has not read their comment either — and the cost of being wrong is a service
// that crashes on a request a stranger sends.
func isNilClient(r Resolver) bool {
	c, ok := r.(*dnsclient.Client)
	return ok && c == nil
}

// readExchangers reads which hosts accept mail for the domain.
//
// The list itself is worth reporting and is not graded: how many exchangers a
// domain has, and whose they are, is an operational decision no document calls
// right or wrong. What it settles is the question every rule below depends on —
// whether this domain receives mail at all.
func (s *Scanner) readExchangers(ctx context.Context, r Resolver, domain string, facts *policy.MailFacts) {
	answer, err := r.LookupMX(ctx, domain)
	if err != nil {
		// The shape of the failure only: the underlying error names resolvers
		// and addresses (I6).
		facts.MXReason = "the MX records could not be read"
		return
	}

	facts.MXRead = true
	for _, mx := range answer.Records {
		// RFC 7505: a single exchanger at "." is the domain stating that it
		// accepts no mail. Recorded as its own fact rather than as a host
		// nobody can resolve, because it is the answer to a different question
		// and it makes several of the rules below inapplicable rather than
		// unsatisfied.
		if mx.Host == "." {
			facts.NullMX = true
			continue
		}
		if mx.Host == "" {
			continue
		}
		facts.MXHosts = append(facts.MXHosts, mx.Host)
	}
}

// readTransportSecurity reads what the domain publishes about encrypting the
// mail path: an MTA-STS record, the policy behind it, and DANE beneath each
// exchanger.
//
// The record and the DANE bindings come from DNS. The policy is a file, and it
// is fetched only where the domain announced one and this deployment is
// configured to read it — see readSTSPolicy, which is where the whole of that
// argument lives.
func (s *Scanner) readTransportSecurity(ctx context.Context, r Resolver, domain string, facts *policy.MailFacts) {
	if answer, err := r.LookupTXT(ctx, stsPrefix+domain); err == nil {
		for _, v := range answer.Values {
			if isMTASTS(v) {
				facts.MTASTSRecords++
			}
		}
	}

	// Before DANE rather than after, so that a scan which spends its context
	// budget on TLSA lookups does not drop the one fact nothing else can supply.
	s.readSTSPolicy(ctx, domain, facts)

	// DANE is per exchanger, so a domain with none has nothing to ask about.
	// Bounded, because the list is written by whoever is being measured.
	hosts := facts.MXHosts
	if len(hosts) > maxExchangers {
		hosts = hosts[:maxExchangers]
		facts.DANEPartial = true
	}

	for _, host := range hosts {
		answer, err := r.LookupTLSA(ctx, danePrefix+host)
		if err != nil {
			// One exchanger that could not be asked about is not a domain
			// without DANE. Counted, so the report can say the picture is
			// incomplete rather than presenting it as complete (R4).
			facts.DANEUnread++
			continue
		}
		facts.DANEAsked++
		if len(answer.Records) > 0 {
			facts.DANEHosts = append(facts.DANEHosts, host)
		}
	}
}

// isMTASTS reports whether a TXT value announces itself as an MTA-STS record.
//
// The version tag must be first, as RFC 8461 requires, and is compared without
// regard to case. A record that merely mentions the name is not one.
func isMTASTS(value string) bool {
	first, _, _ := strings.Cut(strings.TrimSpace(value), ";")
	name, tag, ok := strings.Cut(strings.TrimSpace(first), "=")
	return ok &&
		strings.EqualFold(strings.TrimSpace(name), "v") &&
		strings.EqualFold(strings.TrimSpace(tag), "STSv1")
}

// readSTSPolicy fetches the policy the domain announced, and works out whether
// it covers the domain's own mail.
//
// # The conditions, and why each one is here
//
// **A record has to announce it.** Where the domain publishes no MTA-STS record
// this makes no request at all, and that is not an optimisation. A request to
// mta-sts.<domain> for a domain that announced nothing is this program picking an
// address and trying it, which is the thing N7 refuses. A record is the zone
// naming the address itself, so fetching it is following an instruction the
// domain published for every sending server on the internet to follow.
//
// **The deployment has to be allowed to.** ReadSTSPolicy is false unless a
// caller sets it, and a caller sets it where control of the domain has been
// proven. The request goes to a host in somebody's estate; the condition is that
// it is the estate of whoever asked.
//
// **A failure is never a finding.** A policy that could not be fetched is
// recorded with its reason and nothing about it is graded, because a fetch
// failing here looks identical to a domain whose policy host is broken and to
// this machine's egress being blocked. The first is theirs to fix and the second
// is not theirs at all, and no measurement available from here separates them.
func (s *Scanner) readSTSPolicy(ctx context.Context, domain string, facts *policy.MailFacts) {
	if facts.MTASTSRecords == 0 {
		return
	}
	if !s.ReadSTSPolicy {
		// Said rather than left blank. A deployment that does not fetch the
		// policy is a limit of the installation, and a report that showed an
		// empty mode without saying why would read as a policy that named none
		// — which is a finding (R4).
		facts.MTASTSPolicyReason = "this deployment reads the record and not the policy file"
		return
	}

	got := s.stsFetcher().Fetch(ctx, domain)
	if !got.Fetched {
		facts.MTASTSPolicyReason = got.Reason
		return
	}

	facts.MTASTSPolicyRead = true
	facts.MTASTSMode = string(got.Mode)
	facts.MTASTSMaxAge = got.MaxAge
	facts.MTASTSPolicyMX = got.MX

	// Which of the domain's exchangers the policy leaves out. Only where the MX
	// records were read: an empty list of uncovered hosts has to mean "the
	// policy covers everything" and never "nobody looked" (R4).
	//
	// A sabotage removing this guard escaped every test on 2026-09-13, and that
	// is not a missing test: readExchangers returns before it appends anything
	// when the lookup fails, so today the loop below has nothing to walk. The
	// guard is here so that stays true when somebody makes readExchangers keep a
	// partial answer — at which point a failed lookup would produce a coverage
	// verdict over half a list, and TestCoverageIsNotClaimedWhereTheExchangersWereNotRead
	// is the test that will say so.
	if !facts.MXRead || facts.MXReason != "" {
		return
	}
	for _, host := range facts.MXHosts {
		if !got.Covers(host) {
			facts.MTASTSUncovered = append(facts.MTASTSUncovered, host)
		}
	}
}

// stsFetcher is the fetcher this scan uses: the one supplied, or internal/mtasts
// judging certificates against this scanner's trust store.
//
// A method rather than two lines inside readSTSPolicy, because those two lines
// are where the store is handed over and nothing could see them there. A
// sabotage dropping Roots from the default escaped every test on 2026-09-13 —
// every test supplies its own fetcher, and a real fetch needs a network — and
// the consequence would have been a service whose policy fetch trusted whatever
// the platform picks rather than the store it resolved and checked (R7).
func (s *Scanner) stsFetcher() PolicyFetcher {
	if s.STS != nil {
		return s.STS
	}
	return &mtasts.Fetcher{Roots: s.Roots}
}

// DropLocalPart returns the domain half of a mail address, and discards the rest
// before anything can log, count or report it.
//
// Somebody checking a domain's mail policy has an address in front of them, and
// pasting it is the natural thing to do. Refusing it teaches nothing; accepting
// it and keeping the left half would be this project recording the one kind of
// value it undertakes never to hold. A local part is a person's identity, and
// nothing here has any use for it: every question this check asks is about the
// zone.
//
// So the split happens where the string arrives, at the last "@" — a local part
// may contain one when it is quoted, and the domain may not — and the left half
// is returned to the caller as a flag rather than as a value, so that the only
// thing that can reach a report is that an address was given.
//
// The page says this plainly rather than leaving somebody to trust it.
func DropLocalPart(target string) (domain string, wasAddress bool) {
	at := strings.LastIndex(target, "@")
	if at < 0 {
		return target, false
	}
	return target[at+1:], true
}

// readDKIM looks for signing keys under the selectors this scan was given.
//
// None by default. A key lives at <selector>._domainkey.<domain> and DNS offers
// no way to list what is beneath a name, so there is nothing to discover: a
// selector is either one the operator named or one a provider documents, and a
// scan given neither looks under nothing and says so rather than reporting an
// absence it never established (R4).
func (s *Scanner) readDKIM(ctx context.Context, r Resolver, domain string, facts *policy.MailFacts) {
	if len(s.DKIMSelectors) == 0 {
		return
	}

	got := dkim.Check(ctx, txtAdapter{r}, domain, s.DKIMSelectors)
	facts.DKIMLooked = got.Looked

	for _, k := range got.Keys {
		facts.DKIMKeys = append(facts.DKIMKeys, policy.DKIMKey{
			Selector:  k.Selector,
			Named:     k.Source == dkim.FromOperator,
			Found:     k.Found,
			Reason:    k.Reason,
			Describes: k.Describe(),
			Bits:      k.Bits,
			Revoked:   k.Revoked,
			Testing:   k.Testing,
			Weak:      k.Weak(),
		})
	}
}
