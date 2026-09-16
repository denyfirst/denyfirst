package policy

import (
	"slices"
	"strconv"
	"strings"
)

// The rules for a domain's mail policy.
//
// What is graded here is narrow on purpose, and the line is the one the cookie
// rules drew: grade where a specification calls something an error, or where the
// configuration authorises everybody, and report everything else.
//
// There is a great deal of advice about mail policy and most of it is advice. A
// domain sitting at "~all" while it works out which of its departments still
// send through a forgotten relay is doing the right thing in the right order,
// and a scanner that marked it down would be penalising a correct decision —
// which is the failure R6 and R21 are about, and the one this project objects
// to in other tools.
//
// What is not advice is a permanent error. RFC 7208 says a policy with more
// than ten resolving terms, more than two void lookups, or more than one record
// is a permerror; receivers that hit one act as though the domain published
// nothing. The domain believes it has a policy. It does not. That is a
// measurement, not an opinion, and every graded rule below is one of those.

// MailVersion identifies the mail rule set.
//
// A name of its own rather than a number shared with the others, for the reason
// the TLS name carries its check: "denyfirst-v1" over a mail report and over a
// TLS report would be one name for two rule sets, which is exactly the
// confusion the naming exists to prevent.
const MailVersion = "porch-mail-v1"

var (
	rfc7208 = Reference{
		"RFC 7208 — Sender Policy Framework (SPF)",
		"https://www.rfc-editor.org/rfc/rfc7208",
	}
	rfc7489 = Reference{
		"RFC 7489 — Domain-based Message Authentication, Reporting and Conformance (DMARC)",
		"https://www.rfc-editor.org/rfc/rfc7489",
	}
	rfc8301 = Reference{
		"RFC 8301 — Cryptographic Algorithm and Key Usage Update to DKIM",
		"https://www.rfc-editor.org/rfc/rfc8301",
	}
	rfc8461 = Reference{
		"RFC 8461 — SMTP MTA Strict Transport Security (MTA-STS)",
		"https://www.rfc-editor.org/rfc/rfc8461",
	}
	rfc7672 = Reference{
		"RFC 7672 — SMTP Security via Opportunistic DANE TLS",
		"https://www.rfc-editor.org/rfc/rfc7672",
	}
	nist800177 = Reference{
		"NIST SP 800-177 Rev. 1 — Trustworthy Email",
		"https://csrc.nist.gov/pubs/sp/800/177/r1/final",
	}
)

// MailFacts is what reading a domain's DNS established about its mail policy.
//
// Every field comes from a DNS lookup. Nothing here was measured by connecting
// to a mail server, because nothing here needs to be.
type MailFacts struct {
	// SPF

	// SPFRecords is how many TXT records at the domain announce themselves as
	// SPF. More than one is a permanent error.
	SPFRecords int `json:"spfRecords"`

	// SPFAll is the qualifier on the all mechanism: "-", "~", "?", "+", or
	// empty when the record has none.
	SPFAll string `json:"spfAll"`

	// SPFLookups is how many DNS-resolving terms a receiver would evaluate,
	// counted through every include and redirect.
	SPFLookups int `json:"spfLookups"`

	// SPFLookupLimit and SPFVoidLimit are true when RFC 7208's limits were
	// exceeded, which makes the policy a permanent error.
	SPFLookupLimit bool `json:"spfLookupLimit"`
	SPFVoidLimit   bool `json:"spfVoidLimit"`

	// SPFVoidLookups is how many lookups found nothing.
	SPFVoidLookups int `json:"spfVoidLookups"`

	// SPFLookupsAtLeast is true when SPFLookups is a lower bound: the walk
	// stopped past the limit, or a policy it pulls in could not be read.
	SPFLookupsAtLeast bool `json:"spfLookupsAtLeast,omitempty"`

	// SPFUnreadIncludes is how many policies this one pulls in could not be
	// read. They are not void lookups, and while any is unread the counts
	// above are lower bounds.
	SPFUnreadIncludes int `json:"spfUnreadIncludes,omitempty"`

	// SPFUsesPTR is true when any record in the chain uses ptr.
	SPFUsesPTR bool `json:"spfUsesPTR"`

	// SPFIncludes names the domains the policy pulls in, which is what an
	// operator works from when the count is too high.
	SPFIncludes []string `json:"spfIncludes,omitempty"`

	// SPFReason says why the policy could not be read at all. A failure to
	// read is not a domain without a policy, and the two lead a reader to
	// opposite places.
	SPFReason string `json:"spfReason,omitempty"`

	// DMARC

	// DMARCRecords is how many TXT records at _dmarc announce themselves as
	// DMARC. More than one and the domain has no policy: RFC 7489 says a
	// receiver applies none.
	DMARCRecords int `json:"dmarcRecords"`

	// DMARCPolicy is what p= says: "none", "quarantine", "reject", or empty
	// when the record carries no p= at all — which makes it invalid.
	DMARCPolicy string `json:"dmarcPolicy"`

	// DMARCPercent is what pct= says, defaulting to 100. A policy applied to
	// some of the mail is a policy in a rollout.
	DMARCPercent int `json:"dmarcPercent"`

	// DMARCReporting is true when the record names somewhere to send aggregate
	// reports. Without one an operator cannot see what their policy is doing,
	// which is what makes moving off p=none unsafe.
	DMARCReporting bool `json:"dmarcReporting"`

	// DMARCReason says why the policy could not be read.
	DMARCReason string `json:"dmarcReason,omitempty"`

	// TLSReporting is true when the domain publishes a TLS-RPT record saying
	// where to send reports about failed transport security.
	TLSReporting bool `json:"tlsReporting"`

	// Mail exchangers

	// MXRead records that the MX lookup answered at all. Without it an empty
	// MXHosts is silence rather than a domain with no exchangers (R4).
	MXRead bool `json:"mxRead"`

	// MXReason says why the exchangers could not be read.
	MXReason string `json:"mxReason,omitempty"`

	// MXHosts are the hosts that accept mail, in the order the zone gave them.
	MXHosts []string `json:"mxHosts,omitempty"`

	// NullMX is true when the domain publishes RFC 7505's single "." record,
	// which states that it accepts no mail at all. A statement rather than an
	// absence, and it makes several questions below inapplicable rather than
	// unsatisfied.
	NullMX bool `json:"nullMX,omitempty"`

	// Transport security on the mail path

	// MTASTSRecords is how many records announce an MTA-STS policy. The record
	// only: it says a policy exists and never what the policy is.
	MTASTSRecords int `json:"mtaStsRecords"`

	// MTASTSPolicyRead is whether the policy file itself was fetched.
	//
	// The field the rest of this group depends on, and the reason it exists is
	// R4. A deployment may not fetch the policy at all — the fetch is one HTTPS
	// request, so it runs only where control of the domain has been proven —
	// and without this flag an empty MTASTSMode would be a domain whose policy
	// names no mode, which is a finding, rather than a scan that never looked.
	MTASTSPolicyRead bool `json:"mtaStsPolicyRead"`

	// MTASTSPolicyReason says why the policy was not read: because this
	// deployment does not fetch it, or because the fetch did not succeed.
	//
	// Those two are different and the report says which. One is a limit of the
	// installation and the other may be a fault in the domain — but only may
	// be, because a fetch failing here is also what a blocked egress looks
	// like, which is why nothing about it is graded.
	MTASTSPolicyReason string `json:"mtaStsPolicyReason,omitempty"`

	// MTASTSMode is what the policy's mode= said: "enforce", "testing",
	// "none", or empty where the file carried no mode it recognised.
	//
	// The single most valuable fact this check reads, and the one that was
	// missing for the whole life of the mail rule set. A policy in testing mode
	// tells a sending server to deliver anyway when TLS fails and to send a
	// report about it; from DNS it is indistinguishable from one in enforce
	// mode. An operator who switched to testing during a rollout and never
	// came back has the appearance of protection and none of it.
	MTASTSMode string `json:"mtaStsMode,omitempty"`

	// MTASTSMaxAge is what max_age= said, in seconds: how long a sending
	// server may cache the policy.
	//
	// Reported and never compared against anything. RFC 8461 sets no floor a
	// scanner could hold a domain to, so a number this project called too short
	// would be a threshold it invented (R21).
	MTASTSMaxAge int `json:"mtaStsMaxAge,omitempty"`

	// MTASTSPolicyMX are the host patterns the policy permits, as written —
	// including a leading "*." where the policy used one.
	MTASTSPolicyMX []string `json:"mtaStsPolicyMX,omitempty"`

	// MTASTSUncovered are exchangers published in DNS that no pattern in the
	// policy matches.
	//
	// Empty where the policy was not read, and empty where the MX records were
	// not read — in neither case has anything been established, and a rule
	// below has to be able to tell that from a policy that covers everything.
	MTASTSUncovered []string `json:"mtaStsUncovered,omitempty"`

	// DANEHosts are the exchangers publishing a TLSA record, DANEAsked is how
	// many were asked about, and DANEUnread is how many could not be.
	//
	// Three fields because "no DANE" and "we could not find out" are different
	// answers, and a domain where half the exchangers answered is a third.
	DANEHosts  []string `json:"daneHosts,omitempty"`
	DANEAsked  int      `json:"daneAsked"`
	DANEUnread int      `json:"daneUnread,omitempty"`

	// DANEPartial is true when there were more exchangers than were asked
	// about, so an empty DANEHosts covers only the ones that were.
	DANEPartial bool `json:"danePartial,omitempty"`

	// Signing keys

	// DKIMLooked is true when any selector was asked about. Without it an empty
	// DKIMKeys is silence rather than a domain with no keys, and DKIM is the
	// one record here where the difference is unavoidable: DNS cannot list what
	// is beneath a name, so a scan given no selector has looked nowhere.
	DKIMLooked bool `json:"dkimLooked"`

	// DKIMKeys is one entry per selector asked about.
	DKIMKeys []DKIMKey `json:"dkimKeys,omitempty"`

	// The exchangers themselves

	// ExchangersContacted is true when the exchangers were spoken to at all.
	// Without it an empty Exchangers is silence rather than a domain whose
	// exchangers offer nothing (R4).
	ExchangersContacted bool `json:"exchangersContacted"`

	// ExchangersReason says why they were not: a deployment that does not
	// contact mail servers is a limit of the installation, and says so.
	ExchangersReason string `json:"exchangersReason,omitempty"`

	// ExchangersPartial is true when the domain publishes more exchangers than
	// were contacted, so what is said below covers only the first few.
	ExchangersPartial bool `json:"exchangersPartial,omitempty"`

	// Exchangers is what each one answered.
	Exchangers []ExchangerTLS `json:"exchangers,omitempty"`

	// DANEBindings is what each contacted exchanger's DANE records made of the
	// certificate it presented, for the exchangers publishing any.
	DANEBindings []DANEBinding `json:"daneBindings,omitempty"`
}

// What an exchanger's DANE records made of what it presented. The first four
// are internal/dane's words; the last two are the states before a certificate.
const (
	DANEMatched         = "matched"
	DANEMismatched      = "mismatched"
	DANENoUsableRecords = "no-usable-records"
	DANEUndetermined    = "undetermined"
	DANENoSTARTTLS      = "no-starttls"
	DANENotChecked      = "not-checked"
)

// DANEBinding is one exchanger's DANE records checked against its certificate.
type DANEBinding struct {
	Host string `json:"host"`

	// Validated is the AD bit on the TLSA answer: the resolver's claim that the
	// records passed DNSSEC. RFC 7672 has a sender apply only records that
	// validate, so it decides whether a failure is one a sender acts on.
	Validated bool `json:"validated"`

	// Usable is how many of the records a sender uses for SMTP.
	Usable int `json:"usable"`

	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// ExchangerTLS is what one mail exchanger answered when asked for encryption.
//
// Reduced to what a report says, and filled from internal/smtptls where it was
// measured; this package does not import that one, for the reason every other
// fact type here is its own: a rule is readable without reading a network
// client.
type ExchangerTLS struct {
	Host string `json:"host"`

	Connected bool `json:"connected"`
	Measured  bool `json:"measured"`
	Offered   bool `json:"offered"`
	Upgraded  bool `json:"upgraded"`

	Version string `json:"version,omitempty"`
	Suite   string `json:"suite,omitempty"`

	Trusted           bool   `json:"trusted"`
	NameMatches       bool   `json:"nameMatches"`
	CertificateReason string `json:"certificateReason,omitempty"`

	Reason          string `json:"reason,omitempty"`
	ConnectTimedOut bool   `json:"connectTimedOut,omitempty"`
}

// MailFinding is the graded result.
type MailFinding struct {
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`
	Notes    []Note    `json:"notes,omitempty"`
}

// GradeMail applies the rules above.
func GradeMail(f MailFacts) MailFinding {
	out := MailFinding{Verdict: Strong}

	add := func(id string, v Verdict, title, rationale string, refs ...Reference) {
		out.Findings = append(out.Findings, Finding{
			RuleID:     id,
			Verdict:    v,
			Title:      title,
			Rationale:  rationale,
			References: refs,
			Policy:     MailVersion,
		})
		out.Verdict = Worst(out.Verdict, v)
	}

	// ── Graded: the specification calls these errors ─────────────────

	// Two records is the commonest way to break SPF while appearing to
	// strengthen it. Somebody adds a provider by publishing a second record,
	// and RFC 7208 §3.2 makes the whole thing a permanent error.
	if f.SPFRecords > 1 {
		add("mail.spf-duplicate", Insecure,
			"The domain publishes more than one SPF record",
			"RFC 7208 permits exactly one. A domain with "+strconv.Itoa(f.SPFRecords)+
				" produces a permanent error, and receivers that hit one act as though no policy "+
				"were published at all. This is usually an attempt to authorise an additional "+
				"sender, and it switches the entire policy off instead.",
			rfc7208)
	}

	// The finding this whole check was built around. Invisible in the record:
	// a policy with three includes can be over the limit because one provider
	// has eight of its own.
	if f.SPFLookupLimit {
		add("mail.spf-lookup-limit", Insecure,
			"Evaluating this SPF policy takes more DNS lookups than are allowed",
			"RFC 7208 allows at most ten DNS-resolving terms across everything a policy pulls in; "+
				"this one takes "+atLeast(f.SPFLookupsAtLeast)+strconv.Itoa(f.SPFLookups)+". Over the limit the policy is a "+
				"permanent error, and receivers treat that as no policy. Nothing in the record "+
				"shows this: the cost is mostly inside the providers it includes.",
			rfc7208)
	}

	if f.SPFVoidLimit {
		add("mail.spf-void-lookups", Weak,
			"The SPF policy relies on names that no longer resolve",
			strconv.Itoa(f.SPFVoidLookups)+" of the lookups this policy requires return nothing. "+
				"RFC 7208 allows two; beyond that the evaluation is a permanent error. A policy "+
				"resting on names that have gone is a policy nobody is maintaining.",
			rfc7208)
	}

	// The one place a configuration authorises everybody. Not a matter of
	// degree and not a staging position: there is no arrangement that wants
	// this, which is the same argument the cookie rules use.
	if f.SPFAll == "+" {
		add("mail.spf-allows-everybody", Insecure,
			"The SPF policy authorises every sender",
			"The policy ends in +all, which tells every receiver that any server on the internet "+
				"may send mail claiming to be from this domain. It is weaker than publishing no "+
				"policy, because a receiver that would otherwise be suspicious has been told not "+
				"to be.",
			rfc7208, nist800177)
	}

	// A DMARC record with no p= is not a policy. RFC 7489 §6.3 requires it,
	// and a record without one is discarded.
	if f.DMARCRecords == 1 && f.DMARCPolicy == "" && f.DMARCReason == "" {
		add("mail.dmarc-no-policy", Weak,
			"The DMARC record names no policy",
			"RFC 7489 requires a p= tag. A record without one is not a policy a receiver can "+
				"apply, so the domain appears to have DMARC and has none.",
			rfc7489)
	}

	if f.DMARCRecords > 1 {
		add("mail.dmarc-duplicate", Weak,
			"The domain publishes more than one DMARC record",
			"RFC 7489 says a receiver finding more than one applies no policy at all. The domain "+
				"appears to have DMARC and does not.",
			rfc7489)
	}

	// An MTA-STS policy a sending server cannot apply.
	//
	// RFC 8461 §3.2 requires mode, and requires at least one mx for a policy in
	// enforce or testing mode — a policy in either of those with nothing to
	// match against permits no host at all. A sender that cannot parse the
	// policy falls back to whatever it had before, which for most senders is
	// nothing, so the domain has the record, the file, and no protection.
	//
	// Only where the file was read. Where it was not, nothing about it is
	// graded: see MTASTSPolicyReason.
	if f.MTASTSPolicyRead {
		switch {
		case f.MTASTSMode == "":
			add("mail.mta-sts-policy-invalid", Weak,
				"The MTA-STS policy names no mode",
				"RFC 8461 requires a mode field, and the policy served at mta-sts."+
					"<domain>/.well-known/mta-sts.txt carries none that this scan recognised. A "+
					"sending server that cannot read the policy applies no MTA-STS at all, so the "+
					"domain announces protection it does not have.",
				rfc8461)

		case (f.MTASTSMode == "enforce" || f.MTASTSMode == "testing") && len(f.MTASTSPolicyMX) == 0:
			add("mail.mta-sts-policy-invalid", Weak,
				"The MTA-STS policy names no mail exchangers",
				"RFC 8461 requires at least one mx entry in a policy that is enforcing or testing. "+
					"This one is in "+f.MTASTSMode+" mode and lists none, so there is no host a "+
					"sending server could match — the policy permits nothing rather than "+
					"protecting anything.",
				rfc8461)
		}
	}

	// The policy is enforcing and excludes the domain's own mail.
	//
	// RFC 8461 §5: a sending server applying an enforcing policy MUST NOT
	// deliver to a host that no mx entry matches. So every sender that honours
	// MTA-STS — which includes the largest of them — queues this domain's mail
	// and then returns it.
	//
	// Weak rather than Insecure, and the distinction is worth writing down
	// because it is arguable. The break is definite, specified, and worse in
	// its consequences than several things this file grades Insecure. But it
	// fails *closed*: mail stops rather than crossing the network unprotected,
	// and Insecure in every other rule here means a sender or a receiver is
	// induced to accept something it should not. One word cannot mean both
	// without making a report harder to read than the configuration it
	// describes. The consequence is carried by the sentence instead (R17).
	if f.MTASTSPolicyRead && f.MTASTSMode == "enforce" && len(f.MTASTSUncovered) > 0 {
		add("mail.mta-sts-uncovered-exchanger", Weak,
			"The enforcing MTA-STS policy does not cover this domain's own mail exchangers",
			"The policy is in enforce mode and names no pattern matching "+
				namedHosts(f.MTASTSUncovered)+", which the domain publishes as "+
				plainCount(len(f.MTASTSUncovered), "mail exchanger")+". RFC 8461 says a sending "+
				"server applying an enforcing policy must not deliver to a host the policy does "+
				"not match, so mail routed to "+thatHost(len(f.MTASTSUncovered))+" is refused by "+
				"every sender that honours MTA-STS rather than delivered. This is what an "+
				"exchanger added to DNS and not to the policy looks like.",
			rfc8461)
	}

	// An exchanger the enforcing policy covers, and cannot satisfy.
	//
	// RFC 8461 asks two things of an exchanger under a policy in enforce mode:
	// that it offer STARTTLS, and that the certificate it presents validate for
	// its own name. A sending server that finds either missing must not
	// deliver. So this is the same break as the uncovered exchanger above,
	// found a step later — the policy names the host and the host cannot keep
	// the promise — and it is graded the same, weak, for the same reason: it
	// fails closed.
	//
	// Only what was measured. An exchanger that advertised STARTTLS and could
	// not negotiate with this client is not graded, because a TLS stack that
	// shares nothing with Go's is a limit of this client before it is a fault
	// of the server (R4). And an exchanger the policy does not cover is already
	// the finding above, so it is not raised twice.
	if f.MTASTSPolicyRead && f.MTASTSMode == "enforce" {
		for _, x := range f.Exchangers {
			if !x.Measured || slices.Contains(f.MTASTSUncovered, x.Host) {
				continue
			}

			var fails string
			switch {
			case !x.Offered:
				fails = "does not offer STARTTLS"
			case !x.Upgraded:
				continue
			case !x.Trusted:
				fails = "presents a certificate that does not verify: " + x.CertificateReason
			case !x.NameMatches:
				fails = "presents a certificate that does not name it"
			default:
				continue
			}

			add("mail.mta-sts-exchanger-fails-policy", Weak,
				"An exchanger the enforcing MTA-STS policy covers cannot satisfy it",
				x.Host+" "+fails+". The domain's MTA-STS policy is in enforce mode, and RFC 8461 says a "+
					"sending server applying it must not deliver to an exchanger that does not offer "+
					"STARTTLS with a certificate valid for its own name — so mail routed there is refused "+
					"by every sender that honours MTA-STS rather than delivered.",
				rfc8461)
		}
	}

	// An exchanger failing the DANE binding it publishes.
	//
	// Graded, and for the reason the enforcing MTA-STS rule is: a document says
	// what a sender does. RFC 7672 has a sender that finds usable TLSA records
	// which validate require TLS and a matching certificate, and hold the mail
	// rather than deliver it when it finds neither. So this fails closed, and it
	// is weak for the same reason.
	//
	// Only where the resolver reported the records validated. Without that a
	// sender applying RFC 7672 ignores them, and a report grading them would be
	// grading records no sender acts on. The bit is the resolver's claim rather
	// than this program's check, and the rationale says so. And only a
	// certificate that was obtained and does not match, or an exchanger that was
	// measured and offers no STARTTLS: anything this client could not establish
	// is described, never graded (R4).
	for _, b := range f.DANEBindings {
		if !b.Validated || b.Usable == 0 {
			continue
		}
		var fails string
		switch b.Outcome {
		case DANENoSTARTTLS:
			fails = "does not offer STARTTLS"
		case DANEMismatched:
			fails = "presents a certificate its DANE records do not match: " + b.Reason
		default:
			continue
		}
		add("mail.dane-exchanger-fails-binding", Weak,
			"An exchanger fails the DANE binding it publishes",
			b.Host+" "+fails+". Its TLSA records were reported validated by the resolver this scan asked, "+
				"and RFC 7672 says a sending server that finds usable, validated TLSA records must not deliver "+
				"to an exchanger that cannot match them — so mail routed there is held rather than delivered "+
				"by every sender that applies DANE.",
			rfc7672)
	}

	// A signing key a receiver is entitled to ignore.
	//
	// Graded, and it is the only thing about DKIM that is. RFC 8301 raised the
	// floor to 1024 bits and says a verifier MAY treat a shorter key as
	// insecure — so a domain signing with one has a signature receivers are
	// entitled to discard, which is a measurement rather than an opinion. Every
	// other question about DKIM is one no document settles.
	for _, k := range f.DKIMKeys {
		if !k.Weak {
			continue
		}
		add("mail.dkim-weak-key", Weak,
			"A DKIM signing key is shorter than RFC 8301 allows",
			"The key at selector "+k.Selector+" is "+strconv.Itoa(k.Bits)+" bits. RFC 8301 raised "+
				"the floor to 1024 and says a verifier may treat anything shorter as insecure, so "+
				"mail signed with this key can be discarded by a receiver that applies the rule — "+
				"and a key this size is old enough that nobody has looked at it since it was made.",
			rfc8301)
	}

	// A domain whose principal records could not be read is not strong.
	//
	// Strong is the verdict that claims nothing above fell short, and the
	// rules above can only fall short of what was read. A sender policy, a
	// DMARC record or an exchanger list that could not be read leaves every
	// rule about it silent — which is not the same as passing it. Until the
	// 2026-09-16 audit (A11) a domain whose three lookups all failed came
	// back strong. Only Strong is withdrawn: a finding raised from what was
	// read stays.
	if out.Verdict == Strong && principalUnread(f) {
		out.Verdict = Ungraded
	}

	out.Notes = append(out.Notes, describeMail(f)...)
	out.Notes = append(out.Notes, describeDKIM(f)...)
	return out
}

// principalUnread reports whether a record every mail rule rests on could not
// be read. The records themselves being absent is not this: an absence was
// read, and is described.
func principalUnread(f MailFacts) bool {
	return f.SPFReason != "" || f.SPFUnreadIncludes > 0 || f.DMARCReason != "" || f.MXReason != ""
}

// describeMail says what was established and deliberately not graded.
func describeMail(f MailFacts) []Note {
	var out []Note

	if f.SPFReason != "" {
		out = append(out, Unsettled("The SPF policy was not read: "+f.SPFReason+
			". That is a limit of this scan rather than a fact about the domain."))
	} else if f.SPFRecords == 0 {
		// Reported rather than graded, and the reason is that this scan does
		// not know whether the domain sends mail. A domain that sends none and
		// says so with a null MX is correctly configured without SPF, and
		// grading it would be penalising a correct decision (R6).
		out = append(out, Observed("The domain publishes no SPF record, so a receiver has "+
			"nothing to check a sending server against. Whether that matters depends on "+
			"whether this domain sends mail, which this scan did not establish."))
	}

	// The qualifier, described rather than graded except for +all above. A
	// domain at ~all while it finds the last department still using a
	// forgotten relay is doing the right thing in the right order.
	switch f.SPFAll {
	case "-":
		out = append(out, Observed("The SPF policy ends in -all, so a receiver is told it may "+
			"reject mail from a server the policy does not list. That is the position these "+
			"records exist to reach."))
	case "~":
		out = append(out, Observed("The SPF policy ends in ~all, which asks a receiver to accept "+
			"mail from unlisted servers and mark it. It is the staging position on the way to "+
			"-all and is not graded here: moving before the list is complete rejects real mail."))
	case "?":
		out = append(out, Observed("The SPF policy ends in ?all, which tells a receiver the "+
			"domain declines to say. A receiver treats it as it would treat no policy."))
	case "":
		if f.SPFRecords == 1 {
			out = append(out, Observed("The SPF record has no all mechanism, so a receiver falls "+
				"back to neutral — the same outcome as publishing nothing."))
		}
	}

	// The count, always, and not only when it is over. A domain at nine is one
	// provider away from switching its policy off and has no other way to find
	// that out.
	if f.SPFRecords == 1 && !f.SPFLookupLimit {
		out = append(out, Observed("Evaluating this policy takes "+atLeast(f.SPFLookupsAtLeast)+strconv.Itoa(f.SPFLookups)+
			" of the ten DNS lookups RFC 7208 allows."+includeList(f.SPFIncludes)))
	}
	if f.SPFUnreadIncludes > 0 {
		out = append(out, Unsettled(policiesPulledIn(f.SPFUnreadIncludes)+" could not be read, "+
			"so the lookup counts above are lower bounds and what those policies allow is not established."))
	}

	if f.SPFUsesPTR {
		out = append(out, Observed("The policy uses the ptr mechanism, which RFC 7208 says SHOULD "+
			"NOT be used: it is slow, it puts the work on the receiver, and several large "+
			"receivers ignore it."))
	}

	switch {
	case f.DMARCReason != "":
		out = append(out, Unsettled("The DMARC policy was not read: "+f.DMARCReason+"."))
	case f.DMARCRecords == 0:
		out = append(out, Observed("The domain publishes no DMARC record. Without one a receiver "+
			"has no instruction about what to do with mail that fails SPF, and the domain gets "+
			"no reports about who is sending as it."))
	case f.DMARCPolicy == "none":
		out = append(out, Observed("The DMARC policy is p=none, which asks receivers to do nothing "+
			"differently. It is the monitoring position and it protects nobody yet; it is not "+
			"graded because moving off it before the reports are understood rejects real mail."))
	case f.DMARCPolicy == "quarantine" || f.DMARCPolicy == "reject":
		if f.DMARCPercent > 0 && f.DMARCPercent < 100 {
			out = append(out, Observed("The DMARC policy is p="+f.DMARCPolicy+" and applies to "+
				strconv.Itoa(f.DMARCPercent)+"% of mail, so most of what fails is still delivered. "+
				"A rollout in progress looks exactly like this."))
		} else {
			out = append(out, Observed("The DMARC policy is p="+f.DMARCPolicy+
				", so a receiver is told what to do with mail that fails."))
		}
	}

	if f.DMARCRecords >= 1 && !f.DMARCReporting {
		out = append(out, Observed("The DMARC record names nowhere to send aggregate reports. "+
			"Those reports are how a domain finds out who is sending as it, and without them "+
			"moving to a stricter policy is done blind."))
	}

	if !f.TLSReporting {
		out = append(out, Observed("The domain publishes no TLS-RPT record, so it receives no "+
			"reports when another server fails to deliver to it over an encrypted connection. "+
			"Nothing is wrong without one; it is the only way to find out that something is."))
	}

	out = append(out, describeMailPath(f)...)
	out = append(out, describeExchangers(f)...)

	// The limits of the method, from the one place that declares them. A
	// report that wrote its own would drift from the page explaining them, and
	// the sentence a reader is asked to trust would exist in two versions.
	for _, l := range MailStandingLimits() {
		out = append(out, l.Note())
	}

	return out
}

// includeList names the domains a policy pulls in, when there are any.
func includeList(includes []string) string {
	if len(includes) == 0 {
		return ""
	}
	if len(includes) == 1 {
		return " It pulls in " + includes[0] + "."
	}

	out := " It pulls in "
	for i, name := range includes {
		switch {
		case i == 0:
			out += name
		case i == len(includes)-1:
			out += " and " + name
		default:
			out += ", " + name
		}
	}
	return out + "."
}

// LimitMailSendsNothing is what a mail report cannot see and did not do, and it
// is true of every one of them.
//
// Stated as a limit rather than left out, for the reason R4 gives about every
// other silence: a report that lists what a domain publishes and says nothing
// about the rest reads as a complete picture of the domain's mail.
//
// It was LimitMailIsDNSOnly, titled "No mail server was contacted", until the
// exchangers could be asked for encryption. That sentence is no longer true of
// every deployment, so it went — see the note inside for the same move made
// once before, when the MTA-STS policy became readable.
var LimitMailSendsNothing = StandingLimit{
	ID:    "mail-sends-nothing",
	Title: "No message was sent",

	// This said "Everything here was read from DNS" and carried a sentence
	// about the MTA-STS policy not being read, until the policy could be read.
	// Both had to go rather than be reworded, and for the reason
	// LimitWebRootOnly gives at length: a standing limit is the same sentence on
	// every report and on the method page, and whether the policy is fetched
	// now differs by deployment — one runs behind proof of control and fetches
	// it, one requires no proof and must not. A single sentence covering both
	// would have been false for one of them, and the false one would have been
	// the reassuring one.
	//
	// So what is true of every mail scan stays here, and what this particular
	// scan read about the policy is said by the report that read it. describeSTS
	// names the reason where there is one.
	Text: "No message was composed or sent, and nothing that would change state at the other end " +
		"was attempted. Where a mail exchanger was contacted, the conversation ended once encryption " +
		"had been negotiated or declined: no sender, recipient or message was ever named. Where DANE " +
		"is published, a binding is checked only against a certificate an exchanger presented to this " +
		"scan, and DNSSEC is not validated here: whether the records validated is the resolver's word. " +
		"And a DKIM signing key is read " +
		"only under a selector this scan was told to look under: DNS cannot list what is beneath a " +
		"name, so which selectors were tried — if any — is said in the report itself rather than here.",
}

// MailStandingLimits are true of every mail check this program runs.
func MailStandingLimits() []StandingLimit {
	return []StandingLimit{LimitMailSendsNothing}
}

// describeMailPath says what the domain publishes about where its mail goes and
// how it is protected in transit.
//
// None of it is graded, and the line is the one the rest of this file draws. No
// document calls a particular number of exchangers wrong, and neither MTA-STS
// nor DANE is required by anything — they are two competing answers to the same
// problem, an operator may reasonably deploy either, both, or neither, and a
// scanner marking down the choice would be inventing a threshold (R21).
//
// What is worth saying is what each one is for, and what this scan could not
// see, because the second is the part a reader would otherwise fill in wrongly.
func describeMailPath(f MailFacts) []Note {
	var out []Note

	switch {
	case f.MXReason != "":
		out = append(out, Unsettled("The mail exchangers were not read: "+f.MXReason+
			". Everything below about the mail path is therefore about a list this scan does "+
			"not have."))
		return out

	case f.NullMX:
		// A domain saying it receives no mail is correctly configured without
		// any of the rest, and telling it otherwise would be the clearest case
		// of penalising a right decision (R6).
		out = append(out, Observed("The domain publishes a null MX, which is RFC 7505's way of "+
			"stating that it accepts no mail at all. A receiver is told not to try, which is "+
			"the strongest thing a domain that does not receive mail can say. Nothing below "+
			"about delivery applies to it."))
		return out

	case !f.MXRead:
		return out

	case len(f.MXHosts) == 0:
		out = append(out, Observed("The domain publishes no MX record. A sender falls back to "+
			"the domain's own address record, so mail may still be delivered somewhere — and a "+
			"domain that does not receive mail says so with a null MX rather than by silence, "+
			"which is a fact a receiver can act on."))
		return out
	}

	out = append(out, Observed("Mail for this domain is accepted by "+
		count(len(f.MXHosts), "host")+": "+namedHosts(f.MXHosts)+". Which hosts those are, and "+
		"how many, is an operational decision no specification settles, so it is named rather "+
		"than graded."))

	out = append(out, describeSTS(f)...)

	// DANE, with the three states kept apart.
	switch {
	case f.DANEAsked == 0 && f.DANEUnread == 0:
		// Nothing was asked, which happens only where there were no hosts —
		// already covered above. Silence rather than a sentence claiming
		// something about a question nobody put.

	case len(f.DANEHosts) == len(f.MXHosts) && f.DANEUnread == 0 && !f.DANEPartial:
		out = append(out, Observed("Every mail exchanger publishes a DANE record, so a sending "+
			"server that checks them will refuse to deliver to a host presenting the wrong "+
			"certificate. "+daneCheckedSentence(f)))

	case len(f.DANEHosts) > 0:
		out = append(out, Observed("DANE records are published for "+
			exchangerCount(len(f.DANEHosts), len(f.MXHosts))+" — "+namedHosts(f.DANEHosts)+
			" — and not for the rest. A sender checking DANE gets the guarantee for some "+
			"deliveries and not others, which is usually a migration in progress rather than a "+
			"decision."))

	default:
		out = append(out, Observed("No mail exchanger publishes a DANE record. DANE and MTA-STS "+
			"are two answers to the same problem and a domain needs neither, so this is named "+
			"rather than graded; it is here because an operator choosing between them is owed "+
			"the fact that at present they have picked neither."))
	}

	if f.DANEUnread > 0 {
		out = append(out, Unsettled("DANE could not be read for "+
			plainCount(f.DANEUnread, "mail exchanger")+", so the sentence above covers only "+
			"the ones that answered."))
	}
	if f.DANEPartial {
		out = append(out, Unsettled("The domain publishes more mail exchangers than this scan "+
			"asks about, so DANE was checked for the first few only. A list long enough to hit "+
			"that bound is itself unusual."))
	}

	return out
}

// describeSTS says what the domain publishes about MTA-STS, and — where the
// policy was read — what it actually says.
//
// The mode is the point. Everything a domain can be said to have done about
// MTA-STS from DNS alone is "announced a policy", and that sentence is true of
// a domain fully protected and of a domain that has been rehearsing for two
// years. Only the file separates them, which is why it is fetched.
//
// Almost none of this is graded, and the reason is the one the rest of the file
// gives. testing mode is the staging position on the way to enforce, exactly as
// p=none is for DMARC and ~all is for SPF, and a scanner marking it down would
// be penalising an operator doing the right thing in the right order (R6).
// What is owed to them is the sentence.
func describeSTS(f MailFacts) []Note {
	var out []Note

	if f.MTASTSRecords == 0 {
		return append(out, Observed("The domain announces no MTA-STS policy. Without one, a "+
			"sending server that cannot negotiate TLS with these hosts may deliver in the clear "+
			"rather than refuse, because nothing told it not to."))
	}

	if !f.MTASTSPolicyRead {
		// Announced, and what it says is unknown. Unsettled rather than
		// Observed: a reader who takes "a policy is announced" as "the mail
		// path is protected" has completed the sentence in the stronger
		// direction, and this is the kind under which that completion is
		// refused (R4).
		reason := f.MTASTSPolicyReason
		if reason == "" {
			reason = "this scan did not fetch it"
		}
		return append(out, Unsettled("An MTA-STS policy is announced and what it says "+
			"was not read: "+reason+". A policy in testing mode asks a sending server to deliver "+
			"anyway when TLS fails and to send a report about it, and from DNS it looks exactly "+
			"like one in enforce mode — so an announcement on its own establishes that a policy "+
			"exists and nothing about whether it protects anything."))
	}

	switch f.MTASTSMode {
	case "enforce":
		out = append(out, Observed("The MTA-STS policy is in enforce mode, so a sending server "+
			"that honours it will refuse to deliver to these hosts rather than fall back to an "+
			"unprotected connection. That is the position MTA-STS exists to reach."))

	case "testing":
		// Not graded, and this is the sentence that carries the whole check.
		out = append(out, Observed("The MTA-STS policy is in testing mode. A sending server is "+
			"asked to deliver as it would have anyway when TLS fails, and to send a report about "+
			"it — so the policy is measuring the problem rather than preventing it. That is the "+
			"right setting while the reports are being read and the wrong one to leave behind, "+
			"and it is not graded here because moving to enforce before the policy is known to "+
			"be complete stops real mail."))

	case "none":
		out = append(out, Observed("The MTA-STS policy is in none mode, which RFC 8461 defines "+
			"as withdrawing a policy: a sending server holding a cached one is told to stop "+
			"applying it. The record is still published, so this is a deliberate teardown rather "+
			"than an absence — which is what it should look like, and what a switch-off somebody "+
			"forgot to finish also looks like."))

	case "":
		// Graded above as an invalid policy. Nothing to describe: the finding
		// says it, and a note repeating it would be the same fact twice.
	}

	if f.MTASTSMaxAge > 0 {
		// The number, and nothing compared to it. RFC 8461 recommends a large
		// value and sets no floor a scanner could hold a domain to, so a
		// judgement here would be one this project invented (R21).
		out = append(out, Observed("A sending server may cache this policy for "+
			describeSeconds(f.MTASTSMaxAge)+" (max_age). A long cache is what makes MTA-STS "+
			"resistant to an attacker who can interfere with DNS, and it is also how long a "+
			"change to the policy takes to reach everybody."))
	}

	switch {
	case len(f.MTASTSPolicyMX) == 0:
		// Either graded above, or a none-mode policy where no mx is expected.

	case f.MXReason != "" || !f.MXRead:
		out = append(out, Unsettled("The policy names "+namedHosts(f.MTASTSPolicyMX)+". Whether "+
			"that covers the domain's own mail exchangers was not established, because the MX "+
			"records were not read."))

	case len(f.MTASTSUncovered) == 0 && len(f.MXHosts) > 0:
		out = append(out, Observed("Every mail exchanger the domain publishes is matched by the "+
			"policy, so an enforcing sender has a host it is permitted to deliver to."))

	case len(f.MTASTSUncovered) > 0 && f.MTASTSMode == "testing":
		// The most useful sentence this check produces, and it is a note
		// because in testing mode nothing is broken yet. It will be the day
		// the operator does the thing the mode exists to lead them towards.
		out = append(out, Observed("The policy does not match "+namedHosts(f.MTASTSUncovered)+
			", which the domain publishes as "+plainCount(len(f.MTASTSUncovered), "mail exchanger")+
			". In testing mode a sending server delivers anyway, so nothing is failing now — but "+
			"an enforcing policy must not deliver to a host it does not match, so moving this "+
			"policy to enforce as it stands would refuse mail routed to "+
			thatHost(len(f.MTASTSUncovered))+"."))

	case len(f.MTASTSUncovered) > 0:
		// enforce is graded; none mode means no sender applies the policy at
		// all, so an uncovered host has no consequence to report.
	}

	return out
}

// describeSeconds writes a cache lifetime the way somebody would say it.
//
// The number in seconds is what the file carries and is what the JSON keeps;
// "1209600 seconds" in a sentence is a number a reader has to do arithmetic on
// to understand, and a report that makes a reader do arithmetic is a report
// they skim.
func describeSeconds(n int) string {
	switch {
	case n%86400 == 0 && n >= 86400:
		return plainCount(n/86400, "day")
	case n%3600 == 0 && n >= 3600:
		return plainCount(n/3600, "hour")
	default:
		return plainCount(n, "second")
	}
}

// exchangerCount writes "two of the four mail exchangers", which is the shape
// this sentence needs and the one count() does not produce: count() pluralises
// by adding an "s", so a noun phrase ending in one comes back doubled.
func exchangerCount(some, all int) string {
	return strconv.Itoa(some) + " of the " + strconv.Itoa(all) + " mail exchangers"
}

// plainCount writes "one mail exchanger" or "3 mail exchangers".
func plainCount(n int, noun string) string {
	if n == 1 {
		return "one " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// describeExchangers says what the exchangers answered when asked for
// encryption, and what could not be established.
//
// Almost nothing here is graded. RFC 3207 makes STARTTLS optional, and a sender
// delivering opportunistically encrypts without checking the certificate, so an
// exchanger offering no STARTTLS or a certificate that does not verify is a fact
// a reader needs rather than an error a document names (R21). Where a document
// does make it one — an enforcing MTA-STS policy — GradeMail grades it.
func describeExchangers(f MailFacts) []Note {
	var out []Note
	if !f.MXRead || f.MXReason != "" || f.NullMX || len(f.MXHosts) == 0 {
		return out
	}

	if !f.ExchangersContacted {
		reason := f.ExchangersReason
		if reason == "" {
			reason = "this scan did not contact them"
		}
		return append(out, Unsettled("Whether the mail exchangers accept encrypted connections was not "+
			"measured: "+reason+". That needs a conversation with each of them on port 25, and DNS cannot "+
			"answer it."))
	}

	var (
		verified, plain, badCertificate, unmeasured []string
		timedOut                                    int
	)
	for _, x := range f.Exchangers {
		switch {
		case !x.Measured || (x.Offered && !x.Upgraded):
			unmeasured = append(unmeasured, x.Host+": "+x.Reason)
			if x.ConnectTimedOut {
				timedOut++
			}
		case !x.Offered:
			plain = append(plain, x.Host)
		case !x.Trusted:
			badCertificate = append(badCertificate, x.Host+" ("+x.CertificateReason+")")
		case !x.NameMatches:
			badCertificate = append(badCertificate, x.Host+" (it does not name that exchanger)")
		default:
			verified = append(verified, x.Host)
		}
	}

	if len(verified) > 0 {
		out = append(out, Observed("STARTTLS is offered by "+namedHosts(verified)+", and the certificate "+
			"presented verifies for the exchanger's own name against this deployment's trust store."))
	}

	if len(plain) > 0 {
		verb := "does"
		if len(plain) > 1 {
			verb = "do"
		}
		out = append(out, Observed(namedHosts(plain)+" "+verb+" not offer STARTTLS, so mail delivered to "+
			thatHost(len(plain))+" crosses the network unencrypted. RFC 3207 makes STARTTLS optional, so "+
			"this is named rather than graded; an MTA-STS policy in enforce mode refuses delivery to an "+
			"exchanger like this, and so does DANE."))
	}

	if len(badCertificate) > 0 {
		out = append(out, Observed("The certificate presented after STARTTLS does not verify for "+
			strings.Join(badCertificate, "; ")+". A sender delivering opportunistically still encrypts and "+
			"does not check the certificate, so this is not graded on its own; it is what makes MTA-STS and "+
			"DANE fail for "+thatHost(len(badCertificate))+"."))
	}

	switch {
	case len(unmeasured) > 0 && timedOut == len(f.Exchangers):
		// Every exchanger, and every one of them the same way: this is the
		// shape a network blocking outbound port 25 produces, and it is said as
		// a likely fact about where the scan ran rather than about the servers
		// (R3d).
		out = append(out, Unsettled("No mail exchanger could be reached on port 25 before the time ran out. "+
			"Many networks, residential connections and hosting providers among them, block outbound port "+
			"25, so this most likely describes where this scan ran rather than the exchangers. Run it from a "+
			"network that allows port 25 to have them measured."))
	case len(unmeasured) > 0:
		out = append(out, Unsettled("For "+plainCount(len(unmeasured), "exchanger")+", whether encrypted "+
			"connections are accepted was not established — "+strings.Join(unmeasured, "; ")+". None of that "+
			"is a refusal."))
	}

	if f.ExchangersPartial {
		out = append(out, Unsettled("The domain publishes more mail exchangers than this scan contacts, so "+
			"only the first few were asked about encryption."))
	}

	return append(out, describeDANE(f)...)
}

// daneCheckedSentence says where the answer to "does each binding hold" is.
func daneCheckedSentence(f MailFacts) string {
	if f.ExchangersContacted {
		return "Whether each binding holds is said below, from the certificate each exchanger presented."
	}
	return "Whether each binding holds was not checked: that needs the certificate each exchanger " +
		"presents, and this scan did not contact them."
}

// describeDANE says what each exchanger's DANE records made of the certificate
// it presented.
//
// A failure a sender acts on is graded in GradeMail and not said again here.
// What is left is said: a match; a failure in records the resolver did not
// report validated, which a sender applying RFC 7672 ignores; records no sender
// uses for SMTP; and what could not be established.
func describeDANE(f MailFacts) []Note {
	var (
		out                                          []Note
		matched, matchedUnvalidated, ignored, unused []string
		open                                         []string
	)
	for _, b := range f.DANEBindings {
		switch b.Outcome {
		case DANEMatched:
			matched = append(matched, b.Host)
			if !b.Validated {
				matchedUnvalidated = append(matchedUnvalidated, b.Host)
			}
		case DANEMismatched, DANENoSTARTTLS:
			if !b.Validated {
				ignored = append(ignored, b.Host+" ("+daneFailure(b)+")")
			}
		case DANENoUsableRecords:
			unused = append(unused, b.Host)
		default:
			open = append(open, b.Host+": "+b.Reason)
		}
	}

	if len(matched) > 0 {
		out = append(out, Observed("The certificate presented by "+namedHosts(matched)+" matches the "+
			"DANE records published for "+thatHost(len(matched))+", so a sender applying DANE delivers there."))
	}
	if len(matchedUnvalidated) > 0 {
		out = append(out, Unsettled("The resolver this scan asked did not report the DANE records of "+
			namedHosts(matchedUnvalidated)+" validated. A sender applies DANE only to records that validate, "+
			"and from here an unsigned zone and a resolver that does not validate look the same, so whether "+
			"those bindings protect anything is not established."))
	}
	if len(ignored) > 0 {
		out = append(out, Observed("The DANE records do not hold for "+strings.Join(ignored, "; ")+". The "+
			"resolver this scan asked did not report those records validated, and RFC 7672 has a sender apply "+
			"only records that validate, so this is named rather than graded: if the zone is signed and this "+
			"resolver simply does not validate, mail there is being held."))
	}
	if len(unused) > 0 {
		out = append(out, Observed("The DANE records published for "+namedHosts(unused)+" are none of them "+
			"records a sender uses for SMTP — the PKIX usages RFC 7672 sets aside, or a selector, matching "+
			"type or digest length nothing can match — so DANE authenticates nothing there, and a sender "+
			"encrypts without checking the certificate."))
	}
	if len(open) > 0 {
		out = append(out, Unsettled("Whether the DANE records hold was not established for "+
			strings.Join(open, "; ")+"."))
	}
	return out
}

// daneFailure is the phrase for a binding that does not hold.
func daneFailure(b DANEBinding) string {
	if b.Outcome == DANENoSTARTTLS {
		return "it does not offer STARTTLS"
	}
	return b.Reason
}

// thatHost agrees with a count that has already been written out.
func thatHost(n int) string {
	if n == 1 {
		return "that host"
	}
	return "those hosts"
}

// DKIMKey is what one selector held, reduced to what a report may say.
//
// Named records whether the operator gave this selector or whether it came from
// a provider's documentation, because it decides what an absence means. Nothing
// at a selector somebody named is worth saying — they said it should be there.
// Nothing at one of several provider defaults says only that this name holds
// nothing.
type DKIMKey struct {
	Selector string `json:"selector"`
	Named    bool   `json:"named"`

	Found  bool   `json:"found"`
	Reason string `json:"reason,omitempty"`

	// Describes is how the key is written in a report: "RSA 2048", "Ed25519",
	// "revoked". Rendered where the record was read rather than here, so a
	// report and the JSON say the same words.
	Describes string `json:"describes,omitempty"`

	Bits    int  `json:"bits,omitempty"`
	Revoked bool `json:"revoked,omitempty"`
	Testing bool `json:"testing,omitempty"`

	// Weak is true for an RSA key under the floor RFC 8301 sets, which is a
	// key a verifier is entitled to treat as insecure.
	Weak bool `json:"weak,omitempty"`
}

// describeDKIM says what looking under a set of selectors found, and — the part
// that matters most — what it did not look under.
//
// DKIM is the one record here where silence is unavoidable. DNS cannot list
// what is beneath a name, so a scan is only ever told where to look, and a
// report that said "no DKIM" would be stating something no scan of this kind
// can establish. Everything below therefore names the selectors it tried.
func describeDKIM(f MailFacts) []Note {
	var out []Note

	if !f.DKIMLooked {
		out = append(out, Unsettled("DKIM was not checked. A signing key lives under a selector "+
			"and DNS cannot list what is beneath a name, so a scan has to be told where to look. "+
			"Name your selectors to have them read; there is no way to discover them, and this "+
			"report says nothing about whether the domain signs its mail."))
		return out
	}

	var (
		found, named, missing []string
		unread                int
	)
	for _, k := range f.DKIMKeys {
		switch {
		case k.Reason != "":
			unread++
		case k.Found:
			found = append(found, k.Selector+" ("+k.Describes+")")
		case k.Named:
			named = append(named, k.Selector)
		default:
			missing = append(missing, k.Selector)
		}
	}

	if len(found) > 0 {
		out = append(out, Observed("Signing keys were found at "+namedHosts(found)+"."))
	}

	// A selector the operator named and which holds nothing is worth saying:
	// they said it should be there.
	if len(named) > 0 {
		out = append(out, Observed("No key is published at "+namedHosts(named)+", which you named. "+
			"A signature made with a selector that publishes no key cannot be verified by anybody, "+
			"so mail signed under it is treated as unsigned."))
	}

	// A provider default that holds nothing is not a finding about the domain.
	if len(missing) > 0 && len(found) == 0 {
		out = append(out, Unsettled("None of the selectors tried holds a key: "+
			namedHosts(missing)+". These are names mail providers document for their own service, "+
			"not names this domain has to use, so this establishes that these particular names "+
			"hold nothing and not that the domain publishes no key. Name your own selectors to "+
			"settle it."))
	}

	if unread > 0 {
		out = append(out, Unsettled(plainCount(unread, "selector")+" could not be read, so the "+
			"sentences above cover only the ones that answered."))
	}

	// Reported and not graded: a key left in testing after a rollout is a
	// common state and no document calls it an error, but a verifier is told
	// not to act on a failure under one — so a domain that thinks it is
	// protected is not.
	for _, k := range f.DKIMKeys {
		if k.Found && k.Testing {
			out = append(out, Observed("The key at "+k.Selector+" is marked as testing (t=y). "+
				"RFC 6376 tells a verifier not to treat a failure under a testing key as a reason "+
				"to reject, so signatures made with it protect nothing yet. That is the right "+
				"setting during a rollout and the wrong one to leave behind."))
		}
		if k.Found && k.Revoked {
			out = append(out, Observed("The key at "+k.Selector+" is revoked: the record is "+
				"published with an empty key, which RFC 6376 defines as withdrawing it. Mail "+
				"signed with it cannot verify, which is what revoking is for — this is named "+
				"because a selector left revoked by accident looks exactly the same."))
		}
	}

	return out
}

// atLeast is the words a lower bound needs in front of it.
func atLeast(bound bool) string {
	if bound {
		return "at least "
	}
	return ""
}

// policiesPulledIn opens the sentence about included policies nobody could read.
func policiesPulledIn(n int) string {
	if n == 1 {
		return "One policy this one pulls in"
	}
	return strconv.Itoa(n) + " policies this one pulls in"
}
