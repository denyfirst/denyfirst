// Package mailscan reads what a domain's DNS says about its mail and grades it.
//
// It is the third check, and the only one that connects to nothing. Every fact
// in a report from here came out of a DNS lookup: the sender policy, what it
// costs a receiver to evaluate, the DMARC instruction, and whether the domain
// asks for reports when transport security fails. No mail server is contacted,
// no message is composed, nothing is sent, and nothing that would change state
// at the other end is attempted.
//
// That is a property of what these records are rather than a restraint applied
// to them, and it makes this the strongest privacy story any check in this
// project has: the queries go to the resolver this machine already asks about
// every target, and the domain being examined learns nothing at all.
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
// **DKIM.** A key lives at <selector>._domainkey.<domain> and there is no way
// to enumerate selectors from DNS. Trying common ones — google, s1, selector1
// — is guessing, and guessing is what this project refuses everywhere else. So
// a report says DKIM was not checked rather than that it is missing, because
// those are different facts and only one of them is true (R4).
package mailscan

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/exclusion"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/spf"
	"github.com/denyfirst/denyfirst/internal/verify"
)

const (
	// dmarcPrefix is where a DMARC policy lives, beneath the domain.
	dmarcPrefix = "_dmarc."

	// tlsReportPrefix is where a TLS-RPT record lives.
	tlsReportPrefix = "_smtp._tls."

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

	domain = fold(domain)
	if err := checkDomain(domain); err != nil {
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
	if resolver == nil {
		resolver = &dnsclient.Client{}
	}

	facts := policy.MailFacts{}
	s.readSPF(ctx, resolver, domain, &facts)
	s.readDMARC(ctx, resolver, domain, &facts)
	s.readTLSReporting(ctx, resolver, domain, &facts)

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

// checkDomain refuses anything that is not a bare domain name.
//
// Deliberately narrow, and exported nowhere: this check asks about a zone, so a
// scheme, a path or a port is a caller asking for a different measurement. An
// address is refused because there is no zone under an address to hold any of
// these records.
func checkDomain(domain string) error {
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
