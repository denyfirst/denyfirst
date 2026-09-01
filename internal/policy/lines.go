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

	if f.HasResponder {
		return "not stapled; the certificate names a responder a client would have to ask"
	}

	return "not stapled; the certificate names no responder, so there is none to send"
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
