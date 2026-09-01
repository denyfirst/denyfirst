package policy

import "strings"

// What the scan reached, in one line.
//
// This began as a block called "What holds": nine sentences stating what a
// well configured server got right. It was added because a report's prose
// described only absences — rules unbroken and things a server does not do —
// so a good configuration read as a list of shortcomings.
//
// Read on the live site, seven of the nine restated something already on the
// page. TLS 1.3 accepted and preferred is in the version table. Two
// transparency timestamps from two logs is a certificate row, word for word.
// The server imposes its own cipher order was printed under the cipher table
// already. A block that is three-quarters restatement does not earn a screen,
// and the reader who scrolls past it twice has learned to skip the one part
// that was not a repeat.
//
// What none of the tables say is how much of the picture the scan actually
// reached — and that is what a verdict rests on. The cipher table shows four
// rows whether four was all of them or whether the host stopped answering
// after four, and those two reports mean opposite things: strong is the
// verdict that claims an absence, and an absence can only be claimed from a
// complete look.
//
// So this says what was reached and nothing else. Not what was found, which
// is below; not what was graded, which is above; and never what was missed,
// which belongs once to the unsettled notes and would otherwise be said in
// two places that can disagree.
//
// It is not a checklist and carries no marks. A row of green ticks beside an
// insecure verdict reads as approval — kapitalbank.az is graded insecure and
// every one of these was reached — and a red mark against a name with no CAA
// record would be a grade this rule set deliberately does not give (R9).
// Colour would invent a second opinion that contradicts the first.

// CoverageFacts is what the scan managed to read.
//
// Every field answers "was this reached", never "was it any good". The
// outcome is what the rest of the report is for.
type CoverageFacts struct {
	// SuitesGraded and CipherListComplete are the pair that matters most:
	// enumeration makes one handshake per suite, and a host that stops
	// answering leaves a list that looks complete and is not.
	SuitesGraded       int
	CipherListComplete bool

	// ChainRead is true when a chain arrived and was checked against the
	// trust store, whatever the check concluded.
	ChainRead bool

	// RevocationRead is true only for a stapled response that verified. A
	// response that could not be read established nothing, and no authority
	// is ever asked.
	RevocationRead bool

	TransparencyRead bool

	// IssuanceAnswered is true when the CAA walk produced an answer, which
	// includes an answer of "no record anywhere". Not whether it restricts.
	IssuanceAnswered bool
}

// Coverage is one sentence, or the empty string when a scan reached nothing
// worth saying it reached.
func Coverage(f CoverageFacts) string {
	var reached []string

	if f.CipherListComplete && f.SuitesGraded > 0 {
		reached = append(reached, "every cipher suite this server accepts was enumerated")
	}
	if f.ChainRead {
		reached = append(reached, "the chain was checked against the trust store")
	}
	if f.RevocationRead {
		reached = append(reached, "revocation was read from a stapled response")
	}
	if f.TransparencyRead {
		reached = append(reached, "transparency receipts were counted")
	}
	if f.IssuanceAnswered {
		reached = append(reached, "issuance policy was answered")
	}

	switch len(reached) {
	case 0:
		return ""
	case 1:
		return upperFirst(reached[0])
	}
	return upperFirst(strings.Join(reached[:len(reached)-1], ", ") + ", and " + reached[len(reached)-1])
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// WorstCase is what a weak or insecure verdict means, said where the verdict
// is shown.
//
// It is the report's most likely misreading. kapitalbank.az is graded
// insecure and almost everything about it is right: TLS 1.3 preferred, a
// trusted chain, a verified staple, transparency, CAA, the post-quantum
// hybrid accepted. A reader meets a red stamp beside all of that and has no
// way to know why one outweighs the rest.
//
// Grading is worst-case because an attacker chooses which option to
// negotiate, so the weakest thing a server will agree to is the thing that
// decides. That reasoning is on /method in full; this is the clause that
// stops a reader needing it.
const WorstCase = "Worst case: an attacker chooses which option to negotiate, " +
	"so the weakest one a server accepts is the one that decides."
