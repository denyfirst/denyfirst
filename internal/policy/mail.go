package policy

import "strconv"

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

	// MTASTSRecords is how many records announce an MTA-STS policy. The policy
	// itself was not fetched: it lives in a file, and fetching it would be a
	// connection on the mail path (N13).
	MTASTSRecords int `json:"mtaStsRecords"`

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
				"this one takes "+strconv.Itoa(f.SPFLookups)+". Over the limit the policy is a "+
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

	out.Notes = append(out.Notes, describeMail(f)...)
	return out
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
		out = append(out, Observed("Evaluating this policy takes "+strconv.Itoa(f.SPFLookups)+
			" of the ten DNS lookups RFC 7208 allows."+includeList(f.SPFIncludes)))
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

// LimitMailIsDNSOnly is what a mail report cannot see, and it is true of every
// one of them.
//
// Stated as a limit rather than left out, for the reason R4 gives about every
// other silence: a report that lists what a domain publishes and says nothing
// about the rest reads as a complete picture of the domain's mail. It is a
// complete picture of the domain's *DNS*, which is a different thing.
var LimitMailIsDNSOnly = StandingLimit{
	ID:    "mail-is-dns-only",
	Title: "Everything here was read from DNS",
	Text: "No mail server was contacted, no message was composed or sent, and nothing that would " +
		"change state at the other end was attempted. Four things follow. Whether this domain's " +
		"mail servers actually accept encrypted connections, and what certificates they present, " +
		"was not measured — that needs a connection on the mail path. Where an MTA-STS policy is " +
		"announced, what it says was not read: the record is in DNS and the policy is a file " +
		"served over HTTPS, so a report here establishes that a policy exists and never what mode " +
		"it is in. Where DANE is published, that the binding is correct was not checked, which " +
		"needs a certificate from the host. And DKIM was not checked at all: a key lives under a " +
		"selector, there is no way to list selectors from DNS, and trying likely ones is guessing " +
		"rather than measuring. A report that said DKIM was missing would be stating something " +
		"this scan did not establish.",
}

// MailStandingLimits are true of every mail check this program runs.
func MailStandingLimits() []StandingLimit {
	return []StandingLimit{LimitMailIsDNSOnly}
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

	// MTA-STS, and the part of it this scan deliberately did not read.
	switch {
	case f.MTASTSRecords == 0:
		out = append(out, Observed("The domain announces no MTA-STS policy. Without one, a "+
			"sending server that cannot negotiate TLS with these hosts may deliver in the clear "+
			"rather than refuse, because nothing told it not to."))
	default:
		out = append(out, Observed("The domain announces an MTA-STS policy. What the policy "+
			"says — whether it is in testing or enforcing mode, and which hosts it names — was "+
			"not read: that lives in a file served over HTTPS, and this check makes no "+
			"connection on the mail path. A policy announced and a policy enforced are "+
			"different things, and only the first was established here."))
	}

	// DANE, with the three states kept apart.
	switch {
	case f.DANEAsked == 0 && f.DANEUnread == 0:
		// Nothing was asked, which happens only where there were no hosts —
		// already covered above. Silence rather than a sentence claiming
		// something about a question nobody put.

	case len(f.DANEHosts) == len(f.MXHosts) && f.DANEUnread == 0 && !f.DANEPartial:
		out = append(out, Observed("Every mail exchanger publishes a DANE record, so a sending "+
			"server that checks them will refuse to deliver to a host presenting the wrong "+
			"certificate. Whether each binding is correct was not checked: that needs a "+
			"certificate from the host, and this check connects to none."))

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
