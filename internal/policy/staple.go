package policy

// Certificate status stapling, graded.
//
// This rule set is unusual in that its most obvious rule is deliberately not
// written. Most scanners mark a server down for not stapling an OCSP
// response, and until recently that was defensible. It is not any more.
//
// The CA/Browser Forum made OCSP optional for certificate authorities and
// required CRLs instead, and authorities have taken them up on it: a
// certificate issued today may name no OCSP responder at all. Grading a
// server as weak for failing to staple a response that nothing exists to
// produce would penalise a current, correct configuration — which is the
// exact failure this project objects to in other tools, and which the version
// rules already avoid by grading only what a server accepts rather than what
// it refuses.
//
// So absence of a staple is reported as a fact and explained in a note, and
// only one thing here is graded: a certificate that demands stapling and does
// not get it. That is not a matter of opinion. A client honouring RFC 7633
// closes the connection.
//
// If this project later decides that a missing staple deserves a verdict, the
// place to add it is marked below. Adding it is a policy change and belongs in
// a new policy version, not in a patch to this one — a user who scans an
// unchanged server twice and gets two grades has been given a reason to
// distrust both.

var (
	rfc6960 = Reference{
		"RFC 6960 — X.509 Internet PKI Online Certificate Status Protocol",
		"https://www.rfc-editor.org/rfc/rfc6960",
	}
	rfc7633 = Reference{
		"RFC 7633 — X.509v3 TLS Feature Extension",
		"https://www.rfc-editor.org/rfc/rfc7633",
	}
)

// StapleFacts is what the handshake and the certificate together establish.
//
// The two halves arrive from different places, which is why this is graded
// separately from the transport and from the leaf. The request lives in the
// certificate; the answer arrives in the handshake; neither half means
// anything without the other.
type StapleFacts struct {
	// Stapled is true when the server sent a certificate status response.
	//
	// It says a response arrived. It does not say the response was
	// well-formed, current, signed by the issuer, or about this certificate,
	// because none of that is checked. See the notes this produces.
	Stapled bool

	// MustStaple is true when the leaf carries the RFC 7633 TLS Feature
	// extension asking for status_request.
	MustStaple bool

	// HasResponder is true when the leaf names at least one OCSP responder in
	// its Authority Information Access extension. False means the issuing
	// authority published no OCSP for this certificate, so there is nothing
	// for the server to fetch and nothing for it to staple.
	HasResponder bool

	// HasCRL is true when the leaf names at least one CRL distribution point.
	//
	// Without this, the note for a certificate that names no responder has to
	// guess. Saying revocation is published as a list instead is true of
	// almost every certificate issued now and false of the few that name
	// neither, and those few are the ones a reader most needs told about: a
	// certificate with no responder and no distribution point has no
	// published way to be checked at all.
	HasCRL bool
}

// StapleFinding is the graded result.
type StapleFinding struct {
	Verdict  Verdict   `json:"verdict"`
	Findings []Finding `json:"findings,omitempty"`

	// Notes explains what was established and, more importantly, what was
	// not. A reader who is told a response was stapled and not told it went
	// unverified will read the first as the second.
	Notes []string `json:"notes,omitempty"`
}

// GradeStapling applies the rules above.
func GradeStapling(f StapleFacts) StapleFinding {
	out := StapleFinding{Verdict: Strong}

	add := func(id string, v Verdict, title, rationale string, refs ...Reference) {
		out.Findings = append(out.Findings, Finding{
			RuleID:     id,
			Verdict:    v,
			Title:      title,
			Rationale:  rationale,
			References: refs,
			Policy:     Version,
		})
	}

	// ── The one graded rule ──────────────────────────────────────────
	//
	// The certificate carries an instruction to the client: refuse this
	// connection unless a status response accompanies it. The server did not
	// send one. Every client that implements the extension will fail the
	// handshake, and the ones that do not will connect while believing they
	// have a guarantee they are not getting.
	//
	// This is graded insecure rather than weak because it breaks connections
	// today rather than weakening them in principle, and because the
	// requirement was placed there by whoever requested the certificate. The
	// server is not falling short of an outside recommendation; it is falling
	// short of its own.
	if f.MustStaple && !f.Stapled {
		add("cert.must-staple-not-stapled", Insecure,
			"Certificate requires stapling and none was sent",
			"The certificate carries the TLS Feature extension asking for a stapled status response, and the handshake carried none. Clients that honour the extension will refuse the connection; the rest will connect believing a revocation check took place that did not.",
			rfc7633, rfc6960, rfc9325)
	}

	// ── Notes ────────────────────────────────────────────────────────
	switch {
	case f.Stapled:
		// The most important sentence in this file. A report that says a
		// response was stapled, and stops there, has told a reader that
		// revocation was checked. It was not.
		out.Notes = append(out.Notes,
			"A certificate status response was stapled into the handshake, and it was not read. "+
				"Its signature was not verified, its dates were not compared against the clock, and "+
				"the serial it describes was not matched against this certificate. What this shows is "+
				"that the server is stapling, not that the certificate is good.")

	case f.HasResponder:
		// Not a finding. See the reasoning at the top of this file; this is
		// the branch to change if that reasoning ever stops holding.
		out.Notes = append(out.Notes,
			"No status response was stapled, and the certificate names a responder. A client that "+
				"checks revocation therefore has to ask the certificate authority directly, which tells "+
				"that authority which site is being visited. Stapling would answer the same question "+
				"without disclosing the visit. This is not graded: the authority, not the server, "+
				"decides whether a response exists to staple.")

	case f.HasCRL:
		// The common case for a certificate issued now, and the one every
		// scanner that still grades this gets wrong.
		out.Notes = append(out.Notes,
			"No status response was stapled, and the certificate names no responder to fetch one from. "+
				"The CA/Browser Forum no longer requires certificate authorities to run OCSP, and several "+
				"have withdrawn it, so there is nothing here for the server to have sent. Revocation for "+
				"this certificate is published as a list instead, which clients fetch on their own "+
				"schedule rather than per connection.")

	default:
		// Neither mechanism. This is rare and it is worth saying plainly,
		// because the sentence above would be a guess here: there is no list
		// to point a reader at.
		//
		// Not graded. A certificate issued by a public authority is required
		// to carry one or the other, so this usually means a private or
		// self-signed certificate, and grading an internal certificate as
		// faulty for lacking a public revocation channel would be wrong. The
		// consequence is stated and the reader decides whether it applies.
		out.Notes = append(out.Notes,
			"No status response was stapled, and the certificate names neither an OCSP responder nor a "+
				"CRL distribution point. There is no published way to learn whether it has been revoked: "+
				"a client that wanted to check has nowhere to ask. Withdrawing this certificate before it "+
				"expires would mean reaching every client another way.")
	}

	verdicts := make([]Verdict, 0, len(out.Findings))
	for _, finding := range out.Findings {
		verdicts = append(verdicts, finding.Verdict)
	}
	if v := Worst(verdicts...); v != Ungraded {
		out.Verdict = v
	}

	return out
}
