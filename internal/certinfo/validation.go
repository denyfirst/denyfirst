package certinfo

import "crypto/x509"

// What the issuer says it checked before signing.
//
// A certificate names the policy it was issued under, and the CA/Browser
// Forum reserves four identifiers for the levels every public authority
// issues at. They differ in what was verified about the applicant, and in
// nothing else: the key, the algorithms and the transport are the same at
// every level.
//
// It is worth showing because it is the one thing about a certificate a
// reader cannot infer from anything else on the page, and because browsers
// stopped distinguishing them. A visitor to a bank cannot tell from the
// address bar whether that certificate cost nothing and proves only control
// of a domain name, or whether an authority checked the company exists. The
// certificate says. Nobody was showing it.
//
// It is reported and never graded, for the reason R9 gives about issuance
// policy: which level to buy is the operator's decision and a cheaper one is
// not a fault. A domain-validated certificate protects the connection exactly
// as well as an extended-validation one.
//
// And it is what the certificate asserts, not something this scan confirmed.
// Verifying it would mean auditing the authority, which is what the root
// programmes exist for. Everything in the certificate block is what the
// certificate says; this row is no different.

// The four identifiers, from the CA/Browser Forum's Baseline Requirements
// (§7.1.6.1) and its EV Guidelines. Ordered strongest first: a certificate
// carrying more than one is described by the strongest, which is the claim
// its issuer is standing behind.
var validationLevels = []struct {
	oid   string
	level string
}{
	{"2.23.140.1.1", "extended validation"},
	{"2.23.140.1.2.2", "organisation validated"},
	{"2.23.140.1.2.3", "individual validated"},
	{"2.23.140.1.2.1", "domain validated"},
}

// validationLevel names the CA/Browser Forum policy a certificate carries, or
// returns empty where it carries none.
//
// Empty rather than a guess. A private authority issues under its own policy
// identifiers, which say nothing this list can read, and an older public
// certificate may predate the requirement. Neither is a level, and printing
// "unknown" would put a word where a measurement is missing.
func validationLevel(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	for _, known := range validationLevels {
		for _, policy := range c.Policies {
			if policy.String() == known.oid {
				return known.level
			}
		}
	}
	return ""
}
