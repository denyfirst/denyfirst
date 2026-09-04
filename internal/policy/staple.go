package policy

import "time"

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
	// It says a response arrived, and nothing more. The fields below say what
	// reading it established.
	Stapled bool

	// Validated is true when the response was parsed, matched against this
	// certificate by issuer name hash, issuer key hash and serial number,
	// found to be current, and verified against the issuer's signature or a
	// responder the issuer delegated to.
	//
	// Until 2026-08-22 there was no such field, and a stapled response was
	// reported as a fact about revocation. A server can staple anything: an
	// empty file, a year-old response, a response about another certificate,
	// or one signed by nobody. All of them produced the same sentence, and a
	// reader takes that sentence to mean revocation was checked.
	Validated bool

	// Status is what a validated response says: "good", "revoked" or
	// "unknown". Empty when Validated is false, because a status read out of
	// a response nobody could verify is a number a stranger chose.
	Status string

	// RevokedAt is when the responder says the certificate was withdrawn.
	RevokedAt time.Time

	// Unverifiable explains why a stapled response established nothing. It is
	// this project's own sentence rather than anything the server sent.
	Unverifiable string

	// IssuerMissing is true when the chain did not include the certificate
	// that issued the leaf, so nothing could be verified.
	//
	// Kept apart from Unverifiable because it is not a fault of the response
	// and not an answer about revocation: cert.chain-incomplete already
	// grades it, and charging the same omission twice would report one
	// mistake as two.
	IssuerMissing bool

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

	// Stapled, Validated and Status carry the facts a front end needs to say
	// which of the three things happened, rather than inferring it from the
	// presence of a finding.
	//
	// Serialised because the page has to distinguish them. Reading a rule
	// identifier out of the findings list would work until a rule is renamed,
	// and the sentence a reader sees would then quietly stop matching what
	// was measured — which is how the page came to be still saying "a status
	// response was stapled" a policy version after that stopped being the
	// whole story.
	Stapled   bool   `json:"stapled"`
	Validated bool   `json:"validated"`
	Status    string `json:"status,omitempty"`

	// Notes explains what was established and, more importantly, what was
	// not. A reader who is told a response was stapled and not told it went
	// unverified will read the first as the second.
	Notes []Note `json:"notes,omitempty"`
}

// GradeStapling applies the rules above.
func GradeStapling(f StapleFacts) StapleFinding {
	out := StapleFinding{
		Verdict:   Strong,
		Stapled:   f.Stapled,
		Validated: f.Validated,
		Status:    f.Status,
	}

	add := func(id string, v Verdict, title, rationale string, refs ...Reference) {
		out.Findings = append(out.Findings, Finding{
			RuleID:     id,
			Verdict:    v,
			Title:      title,
			Rationale:  rationale,
			References: refs,
			Policy:     TLSVersion,
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
	// A response that cannot be verified is, to a client honouring the
	// extension, the same outcome as no response: the handshake fails. This
	// rule used to fire only on an absent one, so a certificate demanding a
	// staple and getting sixteen bytes of rubbish passed it.
	if f.MustStaple && !(f.Stapled && f.Validated) {
		what := "and the handshake carried none"
		if f.Stapled {
			what = "and the response it carried could not be verified"
		}
		add("cert.must-staple-not-stapled", Insecure,
			"Certificate requires stapling and no valid response was sent",
			"The certificate carries the TLS Feature extension asking for a stapled status response, "+what+
				". Clients that honour the extension will refuse the connection; the rest will connect believing a revocation check took place that did not.",
			rfc7633, rfc6960, rfc9325)
	}

	// ── What a verified response said ────────────────────────────────
	//
	// The finding this whole path exists for. A revoked certificate is not a
	// weakness to weigh against others: the authority has withdrawn it, every
	// client that checks will refuse it, and the ones that do not are
	// trusting a key somebody asked to have untrusted.
	if f.Validated && f.Status == "revoked" {
		when := ""
		if !f.RevokedAt.IsZero() {
			when = " on " + f.RevokedAt.UTC().Format("2006-01-02")
		}
		add("cert.revoked", Insecure,
			"The certificate has been revoked",
			"The stapled status response, verified against the issuing authority, says this certificate was revoked"+when+
				". Revocation is how a certificate is withdrawn before it expires, usually because its key was exposed or it was issued in error. Clients that check will refuse the connection.",
			rfc6960, rfc9325)
	}

	// A responder that has never heard of a certificate it should be
	// authoritative for is not reassurance, and reading it as "not revoked"
	// is the mistake RFC 6960 warns about directly.
	if f.Validated && f.Status == "unknown" {
		add("cert.revocation-unknown", Weak,
			"The authority does not recognise this certificate",
			"The stapled response verifies against the issuing authority and says the status of this certificate is unknown. That is not the same as not revoked: the responder is authoritative for this issuer and does not have a record of this serial.",
			rfc6960)
	}

	// Bytes that claim to be an authority's statement and are not one.
	//
	// Weak rather than insecure, and the distinction is R6's. The certificate
	// may be perfectly good; what is broken is the server's stapling, and the
	// harm is that a reader — and a client that does not hard-fail — is shown
	// a revocation check that did not happen. A certificate that demands
	// stapling is covered above, where the consequence is a refused
	// connection rather than a false reassurance.
	if f.Stapled && !f.Validated && !f.IssuerMissing {
		add("cert.staple-unverifiable", Weak,
			"The stapled status response could not be verified",
			"A certificate status response was stapled into the handshake and it does not establish anything: "+f.Unverifiable+
				". A response that cannot be verified is not a revocation check, and a client that does not insist on one will connect believing it got a guarantee it did not.",
			rfc6960, rfc7633)
	}

	// ── Notes ────────────────────────────────────────────────────────

	// Said on every branch, because it is true on every branch: nothing here
	// asks a certificate authority anything. That question would tell the
	// authority which certificate somebody is looking at, which is the one
	// thing this service undertakes not to let happen. What can be read is a
	// response the server itself stapled, and the sentences below say what
	// that response did or did not establish.
	//
	// This half used to live in internal/certinfo, joined to a claim that
	// revocation had not been checked — a claim that contradicted the
	// verified case sitting directly beneath it. The standing policy is true
	// always; the outcome is known only here.
	out.standing(LimitNoAuthorityAsked)
	switch {
	case f.Stapled && f.IssuerMissing:
		out.unsettled(
			"A certificate status response was stapled and could not be checked, because the server did not " +
				"send the certificate that issued this one. Every check a response needs is against the issuer: " +
				"matching it to this certificate, and verifying its signature. This is not held against the " +
				"response — the incomplete chain is reported separately — but nothing about revocation was established.")

	case f.Stapled && f.Validated:
		// This sentence used to say the response was not read, and it was
		// the most important sentence in the file for exactly that reason.
		// It is now the other half: what was checked, and what still is not.
		out.observe(
			"The stapled response was read and verified: it describes this certificate by issuer and serial, " +
				"it is current, and its signature checks out against the issuing authority. What is still not " +
				"checked is the responder's own revocation status, which would need a second request over the " +
				"network; RFC 6960 lets an issuer waive that, and responder certificates are short-lived for " +
				"the same reason.")

	case f.Stapled:
		out.unsettled(
			"A certificate status response was stapled and it established nothing. Reading it is what tells " +
				"a stapling server apart from a server stapling whatever it has: the response has to describe " +
				"this certificate, be current, and carry the issuing authority's signature.")

	case f.HasResponder:
		// Not a finding. See the reasoning at the top of this file; this is
		// the branch to change if that reasoning ever stops holding.
		out.observe(
			"No status response was stapled, and the certificate names a responder. A client that " +
				"checks revocation therefore has to ask the certificate authority directly, which tells " +
				"that authority which site is being visited. Stapling would answer the same question " +
				"without disclosing the visit. This is not graded: the authority, not the server, " +
				"decides whether a response exists to staple.")

	case f.HasCRL:
		// The common case for a certificate issued now, and the one every
		// scanner that still grades this gets wrong.
		out.observe(
			"No status response was stapled, and the certificate names no responder to fetch one from. " +
				"The CA/Browser Forum no longer requires certificate authorities to run OCSP, and several " +
				"have withdrawn it, so there is nothing here for the server to have sent. Revocation for " +
				"this certificate is published as a list instead, which clients fetch on their own " +
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
		out.observe(
			"No status response was stapled, and the certificate names neither an OCSP responder nor a " +
				"CRL distribution point. There is no published way to learn whether it has been revoked: " +
				"a client that wanted to check has nowhere to ask. Withdrawing this certificate before it " +
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

// observe, unsettled and standing add a note of each kind.
//
// They exist so that writing a note means choosing what kind of claim it is,
// at the point where that is known. A plain append would let a sentence reach
// the report with no kind at all, and a note with no kind is filed under
// whichever heading comes first — which is the defect these replaced.
func (r *StapleFinding) observe(text string) { r.Notes = append(r.Notes, Observed(text)) }

func (r *StapleFinding) unsettled(text string) { r.Notes = append(r.Notes, Unsettled(text)) }

// standing takes a limit rather than a sentence: see policy/standing.go.
func (r *StapleFinding) standing(l StandingLimit) { r.Notes = append(r.Notes, l.Note()) }
