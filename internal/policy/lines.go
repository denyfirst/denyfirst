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
