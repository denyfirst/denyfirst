package policy

import (
	"fmt"
	"strings"
)

// Certificate authority authorisation, described rather than graded.
//
// A CAA record names the authorities allowed to issue for a domain. Without
// one, any publicly trusted authority may — and there are around a hundred, so
// the weakest of them sets the standard for everyone. Checking the record is
// mandatory for authorities under CA/Browser Forum rules, which makes it one
// of the few controls a domain owner can apply to authorities they have no
// relationship with.
//
// It is not graded, and the reason is where it comes from rather than what it
// says.
//
// Everything else this policy grades arrives in the handshake: a cipher suite,
// a protocol version, a certificate. CAA arrives from a resolver, over a path
// nothing here authenticates, describing a system the person who configured
// the server often does not administer. A verdict on the transport that moved
// because of a DNS record would be a verdict about somebody else's zone.
//
// So it is reported on a line of its own rather than folded into a note. That
// distinction matters more than it sounds: the notes fold shut under every
// verdict but ungraded, and for a name with no CAA this is likely the most
// useful sentence in the report — one DNS record, no risk in adding it, and a
// hundred authorities that stop being able to issue.
//
// # Prevention and detection
//
// CAA and certificate transparency answer two halves of one question: can
// somebody else obtain a certificate for this name, and would anybody find
// out. CAA acts before issuance and transparency after, and neither replaces
// the other. An authority checks CAA at the moment it issues, so a resolver
// poisoned at that moment lets the request through; and an authority that is
// itself compromised permits whatever it likes. The logs record the result
// either way.
//
// The two lines sit next to each other in the report for that reason.

// IssuanceFacts is what a resolver answered about a name.
type IssuanceFacts struct {
	// Checked is false when no lookup happened at all — no resolver
	// configured, or the scan's budget spent before it got here. Reported
	// rather than presented as an absence of records, which is a different
	// fact entirely.
	Checked bool `json:"checked"`

	// Authorities are the values of issue properties: the authorities allowed
	// to issue for this name.
	Authorities []string `json:"authorities,omitempty"`

	// Wildcards are the values of issuewild properties. Separate because they
	// govern separately: a name with issue but no issuewild allows wildcard
	// issuance by the same authorities, and one with both may allow different
	// sets.
	Wildcards []string `json:"wildcards,omitempty"`

	// Other counts properties that are neither, such as iodef or
	// contactemail. They matter for one reason: a record set containing them
	// and no issue property restricts nothing, and reporting that name as
	// having CAA would be true and useless.
	Other int `json:"otherProperties"`

	// FoundAt is the name the records were found at, which may be a parent:
	// CAA is inherited, so a policy on example.com governs www.example.com.
	// Empty when nothing was found anywhere up the tree.
	FoundAt string `json:"foundAt,omitempty"`

	// SearchedTo is the highest name the walk reached.
	SearchedTo string `json:"searchedTo,omitempty"`

	// SearchComplete is false when the walk ran out of budget before reaching
	// the top of the name, so the names above SearchedTo were never asked.
	//
	// Without it the empty answer has two readings and this package publishes
	// the wrong one: "no CAA record was found for this name or for any parent"
	// is a claim about every parent, and a walk cut short did not visit them.
	SearchComplete bool `json:"searchComplete"`

	// Validated is the AD bit from the answer the records came from.
	//
	// It is the resolver's claim that it verified the DNSSEC chain, not this
	// service's. False is ambiguous by construction: an unsigned zone and an
	// answer nobody validated are the same bit from here, and most zones are
	// unsigned.
	Validated bool `json:"validated"`

	// Exists is false when the resolver said the name itself does not exist.
	Exists bool `json:"exists"`
}

// Issuance is what a report should show and say.
type Issuance struct {
	// Facts is what the resolver answered, structured.
	//
	// Carried alongside the prose because the prose is English and a caller
	// reading this over the API should not have to parse a sentence to learn
	// which authorities are named.
	Facts IssuanceFacts `json:"facts"`

	// Line is the one-sentence summary for the report, phrased as what was
	// found rather than as a judgement.
	Line string `json:"line"`

	// Notes carries the detail: where the answer came from, how far the walk
	// went, and what the answer does and does not establish.
	Notes []Note `json:"notes,omitempty"`
}

// DescribeIssuance turns a resolver's answer into what a reader should see.
func DescribeIssuance(f IssuanceFacts) Issuance {
	if !f.Checked {
		return Issuance{
			Facts: f,
			Line:  "not checked",
			Notes: []Note{Unsettled(
				"Whether any authority is restricted from issuing certificates for this name was not " +
					"checked. That takes a DNS lookup, and none was made: either no resolver was " +
					"configured or the time this scan had was spent elsewhere. It is not a finding " +
					"about the name.")},
		}
	}

	if !f.Exists {
		return Issuance{
			Facts: f,
			Line:  "the name does not resolve",
			Notes: []Note{Observed(
				"The resolver said this name does not exist, so there is nothing for an authority to " +
					"issue a certificate for and nothing to restrict.")},
		}
	}

	// Where the answer came from, and what about it was taken on trust. This
	// qualifies the line above it rather than adding to it, so it is not an
	// observation: the resolver's word is what stands in for a check here.
	provenanceText := "This came from the resolver this machine is configured to use, over a path nothing " +
		"here authenticates. "
	if f.Validated {
		provenanceText += "The resolver reported the answer as DNSSEC-validated, which is its claim rather " +
			"than a check this service performed."
	} else {
		provenanceText += "The answer was not marked as DNSSEC-validated, which means either that the zone " +
			"is not signed — most are not — or that it was not verified. Those look the same from here."
	}
	provenance := Unsettled(provenanceText)

	// The pairing with certificate transparency, which sits on the next line
	// of the report. Stated on every branch, because a reader who has just
	// been told issuance is restricted is exactly the reader most likely to
	// stop reading.
	const pairing = "A restriction is checked by an authority at the moment it issues, so it does not " +
		"help against a resolver poisoned at that moment or an authority that has itself been " +
		"compromised. Certificate transparency, on the line below, is what records the result either " +
		"way. The record format is RFC 8659."

	switch {
	case len(f.Authorities) == 0 && len(f.Wildcards) == 0 && f.Other > 0:
		// The case that reads as protection and is not. microsoft.com
		// publishes contactemail and nothing else: a record set exists, and
		// no authority is restricted by it.
		return Issuance{
			Facts: f,
			Line:  fmt.Sprintf("CAA present at %s, and none of it restricts issuance", f.FoundAt),
			Notes: []Note{
				Observed(fmt.Sprintf("A CAA record set exists at %s and carries no issue property, so it names "+
					"nobody and restricts nobody: any publicly trusted authority may still issue for "+
					"this name. Whoever published it knows what CAA is, which makes this more likely "+
					"to be a step not finished than a decision. %s", f.FoundAt, pairing)),
				provenance,
			},
		}

	case len(f.Authorities) == 0 && len(f.Wildcards) == 0 && !f.SearchComplete:
		// The walk stopped before the top, so the names above it were never
		// asked, and one of them is where a policy for the whole tree would
		// live. Saying nothing restricts issuance here would be reporting an
		// absence that was not looked for.
		return Issuance{
			Facts: f,
			Line:  fmt.Sprintf("no CAA found, but the search stopped at %s before reaching the top", f.SearchedTo),
			Notes: []Note{
				Unsettled("No CAA record was found between this name and " + f.SearchedTo + ", and the search " +
					"stopped there rather than continuing towards the root. CAA is inherited, so a " +
					"policy published on a shorter name would govern this one and would not have been " +
					"seen. Whether any authority is restricted from issuing for this name is therefore " +
					"not established either way. " + pairing),
				provenance,
			},
		}

	case len(f.Authorities) == 0 && len(f.Wildcards) == 0:
		return Issuance{
			Facts: f,
			Line:  fmt.Sprintf("no CAA at this name or above it, searched to %s", f.SearchedTo),
			Notes: []Note{
				Observed("No CAA record was found for this name or for any parent up to " + f.SearchedTo + ". " +
					"Any publicly trusted certificate authority may therefore issue for it, and there " +
					"are around a hundred of them, so the weakest sets the standard. Publishing one " +
					"record naming the authorities actually used tells the rest to refuse; checking it " +
					"has been mandatory for authorities since 2017. " + pairing),
				provenance,
			},
		}
	}

	return Issuance{
		Facts: f,
		Line:  describeAuthorities(f),
		Notes: []Note{
			Observed(fmt.Sprintf("Issuance for this name is restricted by the CAA record set at %s. %s",
				f.FoundAt, pairing)),
			provenance,
		},
	}
}

// describeAuthorities writes the summary line for a name that restricts.
//
// The authorities are named rather than counted. They are the point: an
// operator reading their own report wants to see the authority they use, and
// somebody reading a report about a third party learns which authorities that
// party trusts, which is public information the moment a certificate is
// issued.
//
// The values are taken from the zone, so a hostile target chooses them.
// dnsclient refuses anything not printable before they reach here, and they
// go to the page as text rather than to a parser.
func describeAuthorities(f IssuanceFacts) string {
	var parts []string

	switch {
	case len(f.Authorities) == 1 && f.Authorities[0] == ";":
		// A single semicolon is the way a zone says nobody may issue.
		parts = append(parts, "no authority is permitted to issue")
	case len(f.Authorities) > 0:
		parts = append(parts, "issuance limited to "+list(readable(f.Authorities)))
	default:
		// issuewild without issue. RFC 8659 leaves ordinary issuance
		// unrestricted here, which is worth saying rather than implying.
		parts = append(parts, "ordinary issuance is not restricted")
	}

	switch {
	case len(f.Wildcards) == 1 && f.Wildcards[0] == ";":
		parts = append(parts, "wildcards refused")
	case len(f.Wildcards) > 0:
		parts = append(parts, "wildcards limited to "+list(readable(f.Wildcards)))
	}

	if f.FoundAt != "" {
		return strings.Join(parts, "; ") + " (from " + f.FoundAt + ")"
	}
	return strings.Join(parts, "; ")
}

// readable separates each CAA value into the authority it names and the
// parameters that follow it.
//
// RFC 8659 §4.2 puts parameters after the domain, separated by semicolons:
// `pki.goog; cansignhttpexchanges=yes` is one value naming one authority. The
// whole string used to go into the list unchanged, and the list is joined with
// commas while the clauses around it are joined with semicolons — so a real
// record set came out as
//
//	issuance limited to comodoca.com, digicert.com; cansignhttpexchanges=yes,
//	letsencrypt.org, pki.goog; cansignhttpexchanges=yes and ssl.com
//
// which a reader cannot parse and might read as naming an authority called
// cansignhttpexchanges=yes. Measured on kapitalbank.az, 2026-08-23.
//
// The parameter is worth showing rather than dropping. cansignhttpexchanges
// authorises that authority to sign Signed HTTP Exchanges, which is a wider
// power than issuing an ordinary certificate, and a reader deciding whether a
// zone's restrictions are tight enough needs to see it.
func readable(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		domain, params, found := strings.Cut(value, ";")
		domain = strings.TrimSpace(domain)

		if domain == "" {
			// An empty value permits nobody, which is meaningful on its own
			// and must not silently vanish from a list.
			out = append(out, "an empty value, which names no authority")
			continue
		}
		if !found {
			out = append(out, domain)
			continue
		}

		var settings []string
		for _, p := range strings.Split(params, ";") {
			if p = strings.TrimSpace(p); p != "" {
				settings = append(settings, p)
			}
		}
		if len(settings) == 0 {
			out = append(out, domain)
			continue
		}
		out = append(out, domain+" ("+strings.Join(settings, ", ")+")")
	}
	return out
}

// list writes names as prose, so a report does not read like a data structure.
func list(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}
