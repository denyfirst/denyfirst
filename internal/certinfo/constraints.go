package certinfo

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// What an authority in this chain is not allowed to do.
//
// Two extensions bound an issuer. Name constraints say which names it may
// issue for; a path length says how many further authorities it may create
// beneath itself. Both are limits the authority accepted when it was signed,
// and both are enforced by the verifier rather than by anyone's good
// intentions — Go enforces them, and so do the browsers.
//
// They are worth reporting because of what they mean if the key is stolen. An
// unconstrained intermediate that is compromised issues certificates for any
// name on the internet. One constrained to a handful of domains issues
// certificates for those domains and nothing else, and the difference is the
// difference between an incident and a catastrophe.
//
// # Only the positive case is reported
//
// An issuer with no constraints produces no sentence. That is deliberate and
// it is not the kind of silence this project has spent its time closing.
//
// The silences that mattered — one hop, one address, one root store — changed
// what the report's claims meant: a reader took a measurement to cover more
// than it did. This one does not. An unconstrained issuer is the ordinary
// state of nearly every certificate on the internet, and a sentence saying so
// would appear on almost every report, be true, add nothing, and teach the
// reader to skip the block it sits in. That is exactly how the old "What this
// did not measure" heading stopped being read.
//
// So the exception is reported and the norm is not. This is also, for once, a
// report with something good to say: it has spent its life listing what a
// server falls short of.
//
// # And not for a root
//
// A root's constraints are skipped for the same reason its signature is not
// graded. The root a client uses is the copy in its own store, not the one
// the server sent, and the two need not carry the same extensions. Reading
// constraints off the server's copy and reporting them as binding would be
// describing a limit no client is necessarily applying.

// issuerConstraints describes the limits on one issuer, or returns empty when
// it carries none this report can state.
//
// The subject and the names are put through the caller's trimmer: every one of
// them is text the scanned server chose, and all of them reach a sentence. R10.
func issuerConstraints(c *x509.Certificate, subject string, trim *trimmer) string {
	if c == nil {
		return ""
	}

	var clauses []string

	if names := trim.list(c.PermittedDNSDomains, maxListEntries); len(names) > 0 {
		clauses = append(clauses, "may issue only for names under "+namesAnd(names))
	}
	if names := trim.list(c.ExcludedDNSDomains, maxListEntries); len(names) > 0 {
		clauses = append(clauses, "may not issue for names under "+namesAnd(names))
	}

	switch {
	case c.MaxPathLenZero:
		clauses = append(clauses, "may not create further authorities")
	case c.MaxPathLen > 0:
		clauses = append(clauses, fmt.Sprintf("may create at most %s beneath it",
			plural(c.MaxPathLen, "further authority", "further authorities")))
	}

	if len(clauses) == 0 {
		return ""
	}

	// Said rather than left out, because a reader who sees only the DNS
	// clause would take the certificate to be constrained in that one way.
	other := ""
	if hasOtherConstraints(c) {
		other = " It also carries constraints on other kinds of name, which this report does not list."
	}

	return fmt.Sprintf("%s %s. A constrained authority bounds what a stolen key could do: "+
		"an unconstrained one issues for any name at all.%s",
		subject, joinClauses(clauses), other)
}

// hasOtherConstraints reports whether anything beyond DNS names is bounded.
func hasOtherConstraints(c *x509.Certificate) bool {
	return len(c.PermittedIPRanges) > 0 || len(c.ExcludedIPRanges) > 0 ||
		len(c.PermittedEmailAddresses) > 0 || len(c.ExcludedEmailAddresses) > 0 ||
		len(c.PermittedURIDomains) > 0 || len(c.ExcludedURIDomains) > 0
}

// namesAnd lists names the way a sentence does.
//
// Bounded by the caller's trimmer before it gets here, so the length is
// already what the report will carry; this only decides the commas.
func namesAnd(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}

// joinClauses reads as English at one, two and three.
func joinClauses(clauses []string) string {
	switch len(clauses) {
	case 1:
		return clauses[0]
	case 2:
		return clauses[0] + ", and " + clauses[1]
	default:
		return strings.Join(clauses[:len(clauses)-1], ", ") + ", and " + clauses[len(clauses)-1]
	}
}

// plural picks the form, because "1 further authorities" is the sort of thing
// a reader stops trusting a report over.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
