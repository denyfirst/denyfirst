package policy

import (
	"fmt"
	"strconv"
)

// The two sentences the certificate section shows about revocation and
// transparency.
//
// They were composed in JavaScript, in app.js, and only there. That put them
// out of reach of the terminal report, which is why it showed neither, and out
// of reach of every test that could execute them, which is why the revocation
// sentence went on saying "a status response was stapled" for a whole policy
// version after the service had begun parsing that response, matching it to
// the certificate, checking its freshness and verifying the issuer's
// signature. The section a reader consults for exactly that went on reporting
// a byte count.
//
// Writing a second copy in Go would have been worse than leaving it: two
// renderers composing one claim from the same facts is how the two come to
// disagree, and this report has already been through that. So the sentence
// moved here, where every other sentence in this report is built, and both
// faces read the one string.

// RevocationLine describes what is known about revocation in one sentence.
//
// Built from the facts GradeStapling already grades, so the sentence and the
// verdict cannot describe different states.
func RevocationLine(f StapleFacts) string {
	// Demanded and not delivered. First, because a certificate carrying
	// must-staple is making a promise on behalf of the server, and a reader
	// needs to know it was not kept before anything else about the response.
	if f.MustStaple && !(f.Stapled && f.Validated) {
		if f.Stapled {
			return "the certificate requires a stapled response and the one sent could not be verified"
		}
		return "the certificate requires a stapled response and none was sent"
	}

	if f.Stapled && f.Validated {
		// "good" is the ordinary answer and saying it adds nothing; anything
		// else is the point of having asked.
		said := ", and verified against the issuing authority"
		unusual := f.Status != "" && f.Status != "good"
		if unusual {
			said = ", and the authority says the status is " + f.Status
		}
		if f.MustStaple {
			if unusual {
				return "stapled and verified, and the certificate requires it" + said
			}
			return "stapled and verified, and the certificate requires it"
		}
		return "a status response was stapled" + said
	}

	if f.Stapled {
		return "a status response was stapled and it establishes nothing; the findings say why"
	}

	// Nothing arrived in the handshake. What a list established, where one was
	// read, is the rest of the answer — and for most certificates issued now it
	// is the whole of it, since the authority publishes no responder for
	// anything to be stapled from.
	if line := listLine(f); line != "" {
		return line
	}

	if f.HasResponder {
		return "not stapled; the certificate names a responder a client would have to ask"
	}

	return "not stapled; the certificate names no responder, so there is none to send"
}

// listLine says what a revocation list established, or nothing at all when none
// was read.
//
// Empty rather than a sentence about the absence, so that the caller falls
// through to what it said before this existed. A deployment that does not fetch
// lists — the demonstration, where the code is not compiled in — reads exactly
// as it always did rather than acquiring a sentence about a check it does not
// run.
func listLine(f StapleFacts) string {
	switch f.ListStatus {
	case "revoked":
		when := ""
		if !f.ListRevokedAt.IsZero() {
			when = " on " + f.ListRevokedAt.UTC().Format("2006-01-02")
		}
		return "the authority's revocation list says this certificate was revoked" + when

	case "good":
		// The date matters more than the word. A list is a snapshot an
		// authority publishes on a schedule, so "not revoked" is true as of
		// then and not as of now, and a reader acting on it needs to know
		// which. A stapled response carries its own freshness; this does not.
		asOf := ""
		if !f.ListAsOf.IsZero() {
			asOf = ", published " + f.ListAsOf.UTC().Format("2006-01-02") + ","
		}
		if f.Stapled {
			return "the stapled response established nothing; the authority's revocation list" +
				asOf + " does not name this certificate"
		}
		return "not stapled; the authority's revocation list" + asOf + " does not name this certificate"
	}

	// A list was attempted and answered nothing. Said rather than swallowed:
	// the reason is this project's own sentence, and a reader who is told the
	// check did not happen can act on it, while silence reads as a pass (R4).
	if f.ListReason != "" && f.HasCRL {
		return "not stapled, and revocation was not established from a list: " + f.ListReason
	}
	return ""
}

// TransparencyLine describes the receipts in one sentence.
//
// From the same facts DescribeTransparency writes its notes from, and FromLogs
// is already the union across both delivery routes rather than a sum: a
// certificate logged in two places was otherwise described as logged in four.
func TransparencyLine(f TransparencyFacts) string {
	total := f.Embedded + f.InHandshake
	if total == 0 {
		return "no timestamps in the certificate or the handshake"
	}
	logs := f.FromLogs

	stamps := strconv.Itoa(total) + " timestamps"
	if total == 1 {
		stamps = "1 timestamp"
	}

	// Receipts that arrived and could not be read. A timestamp too short to
	// hold a log identifier, or announcing a version this does not know, is
	// counted in the total and contributes no log. With every one of them
	// unreadable the two numbers gave "3 timestamps from 0 logs", which is
	// not a fact about the certificate: it is this scanner saying it could
	// not read what it was sent, in a sentence shaped like a measurement.
	if logs == 0 {
		return stamps + ", none of which could be read well enough to say which log issued it"
	}

	from := strconv.Itoa(logs) + " logs"
	if logs == 1 {
		from = "1 log"
	}

	// The caveat about verification lives in the note, not here. A count of
	// receipts is something this service measured accurately; that they were
	// not checked against the issuing log's key is something it did not do,
	// and putting the second on the same line as the first reads as though
	// the count itself were uncertain, which it is not.
	if f.InHandshake > 0 && f.Embedded > 0 {
		return fmt.Sprintf("%s from %s (%d embedded, %d in the handshake)",
			stamps, from, f.Embedded, f.InHandshake)
	}
	return stamps + " from " + from
}

// PostQuantumFacts is what one extra handshake established about the key
// exchange.
type PostQuantumFacts struct {
	// Measured is false when the question could not be put or answered.
	Measured bool

	// Offered is true when the server completed a handshake with the hybrid
	// group as the only one on the table.
	Offered bool

	// Group names what was offered, so this reads correctly when the name
	// changes.
	Group string

	// Reason says why nothing was measured.
	Reason string
}

// PostQuantumLine describes the key exchange in one sentence.
func PostQuantumLine(f PostQuantumFacts) string {
	if !f.Measured {
		if f.Reason == "" {
			return "not measured"
		}
		return "not measured: " + f.Reason
	}
	if f.Offered {
		return "the hybrid post-quantum group " + f.Group + " was accepted"
	}
	return "the hybrid post-quantum group " + f.Group + " was declined"
}

// DescribePostQuantum says why the answer matters.
//
// Reported and not graded. No document this rule set follows requires a hybrid
// key exchange, and a verdict invented here would be this project grading
// against its own opinion — the thing it says other tools do. What it can do
// is state the measurement and the reason somebody would act on it.
func DescribePostQuantum(f PostQuantumFacts) []Note {
	const why = "Traffic recorded today can be kept and decrypted by whoever first builds a quantum " +
		"computer large enough to break the key exchange, which is why the attack is called harvest " +
		"now, decrypt later. Forward secrecy does not prevent it: forward secrecy protects against a " +
		"private key stolen afterwards, not against the exchange itself being broken."

	switch {
	case !f.Measured:
		if f.Reason == "" {
			return []Note{Unsettled("Whether the key exchange resists a future quantum computer was not established.")}
		}
		return []Note{Unsettled("Whether the key exchange resists a future quantum computer was not established: " +
			f.Reason + ". " + why)}

	case f.Offered:
		// Established, and deliberately not graded. Filed as a limit until
		// 2026-09-01, under a heading that told the reader it had not been
		// measured — of everything in that list this was the sentence the
		// framing damaged most, because it is the strongest result a server
		// can earn here.
		return []Note{Observed(fmt.Sprintf(
			"%s combines X25519 with ML-KEM-768, so recovering the session key means breaking both, and "+
				"the second has no known quantum attack. %s A recording of this connection is not "+
				"exposed to that. This is not graded — no document this rule set follows requires it — "+
				"and it is the strongest thing a server can do about it today.", f.Group, why))}

	default:
		return []Note{Observed(fmt.Sprintf(
			"%s was offered and the server did not take it. %s Nothing is wrong with this connection "+
				"today and no client fails because of this: a client that offers the hybrid falls back "+
				"to X25519 and the handshake succeeds. It is not graded, because no document this rule "+
				"set follows requires it yet, and it is reported because the traffic being recorded now "+
				"is what the decision is about.", f.Group, why))}
	}
}

// TrustStoreUnreadable is what a report says when this machine's certificate
// store could not be read.
//
// One sentence for both checks. It was written inline in internal/certinfo
// until 2026-09-11, which was fine while one check verified a chain; the web
// check verifies one too, and a claim about whose store decided the word
// "trusted" existing in two places is two claims that drift (R16).
//
// Unsettled rather than a finding, and the distinction is the whole point. The
// chain was not judged untrusted — nothing judged it at all, because the store
// that would have done the judging could not be read. Saying "untrusted" here
// would be a finding about somebody else's certificate produced by a local
// failure, which is what R4 forbids.
//
// It names the machine running the scan explicitly, because a reader holding a
// report has no other way to tell a fault on their server from a fault on the
// one that looked at it.
func TrustStoreUnreadable() Note {
	return Unsettled("The trust store on this machine could not be read, so whether the " +
		"certificates presented reach a trusted root was not established. That is a fact about " +
		"the machine running this scan and not about the server it looked at.")
}

// LogFacts is what a search of the public certificate logs established.
//
// Reported and never graded, and that line is the whole of the design. A
// certificate in a log is a fact; whether it should exist is a question about
// somebody's purchasing that no scan can answer. A colleague renewing early, a
// content delivery network issuing on the customer's behalf and a certificate
// obtained by somebody who should not have one all look identical from here, so
// grading would mean inventing a threshold nobody can argue with — which is
// what R21 is written against, and what R17 forbids in a different word: say
// what was measured, not what it implies.
//
// What the report can do is put the operator in front of the list. They know
// what they ordered, and nobody else does.
type LogFacts struct {
	// Searched is false when no search was made: a deployment that does not
	// query logs, which is the demonstration.
	Searched bool

	// Distinct is how many distinct certificates the logs hold for this name,
	// after the precertificate and the certificate have been counted once.
	Distinct int

	// Unseen is how many of those are valid at this moment and are not the
	// certificate this scan was served.
	//
	// The number worth looking at. A certificate that has expired is history;
	// one that is valid now and is not the one in use is a key somebody can
	// present for this name today.
	Unseen int

	// Truncated is true when more exist than were listed.
	Truncated bool

	// SubdomainsSearched is false while the search is by exact name. A
	// certificate obtained for a subdomain is a real way to be attacked and is
	// not covered, so a report says so rather than letting a clean answer read
	// as a clean estate (R4).
	SubdomainsSearched bool

	// Reason says why nothing was established.
	Reason string
}

// LoggedLine describes what the logs hold, in one sentence.
func LoggedLine(f LogFacts) string {
	switch {
	case !f.Searched:
		return ""
	case f.Reason != "":
		return "not established: " + f.Reason
	case f.Distinct == 0:
		// Odd rather than reassuring, and said as such. A publicly trusted
		// certificate has to be logged before a browser will accept it, so a
		// name being served over TLS with nothing in the logs means the search
		// did not see what the handshake did.
		return "no certificates for this exact name were found, which is unusual for a name served over TLS"
	case f.Unseen == 0:
		if f.Distinct == 1 {
			return "one certificate for this exact name, and it is the one this server presented"
		}
		return plural(f.Distinct, "certificate") + " for this exact name, and none valid today is unaccounted for"
	case f.Distinct == 1:
		// One certificate, and it is not the one in use. The sharpest shape
		// this check produces, and it deserves its own sentence rather than
		// the "one of which" construction, which reads as though there were
		// several.
		return "one certificate for this exact name, valid today, and it is not the one this server presented"

	case f.Unseen == 1:
		return plural(f.Distinct, "certificate") +
			" for this exact name, one of which is valid today and was not the one presented here"

	default:
		return plural(f.Distinct, "certificate") + " for this exact name, " +
			strconv.Itoa(f.Unseen) +
			" of which are valid today and were not the one presented here"
	}
}

// DescribeLogged says what the number means and what it does not.
func DescribeLogged(f LogFacts) []Note {
	if !f.Searched {
		return nil
	}
	if f.Reason != "" {
		return []Note{Unsettled("Which certificates public logs hold for this name was not " +
			"established: " + f.Reason + ". That is a limit of this scan rather than a fact " +
			"about the server.")}
	}

	var out []Note

	if f.Unseen > 0 {
		out = append(out, Observed("Every publicly trusted certificate is recorded in append-only "+
			"logs before a browser will accept it, so a certificate obtained for this name by "+
			"anybody, from any authority, appears there. "+plural(f.Unseen, "certificate")+
			" valid today was not the one this server presented. That is not a finding: an early "+
			"renewal, a content delivery network issuing on your behalf, and a second server all "+
			"look the same from here. It is a list only you can check, and the reason to check it "+
			"is that a certificate somebody else obtained looks exactly like one you did."))
	}

	if f.Truncated {
		out = append(out, Unsettled("More certificates exist for this name than are listed here. "+
			"The count is complete; the list is not."))
	}

	if !f.SubdomainsSearched {
		out = append(out, Unsettled("Only this exact name was searched for. A certificate "+
			"obtained for a subdomain would not appear above, and obtaining one for a subdomain "+
			"is a way this is done."))
	}

	return out
}
