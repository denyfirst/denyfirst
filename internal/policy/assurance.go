package policy

import "fmt"

// What a report never said out loud.
//
// Read against a live scan of a bank on 2026-09-01, every sentence in the
// report was either a rule that had not been broken — "Nothing here fell
// short of the rules", which is two negatives — or one of five observations,
// four of which named something the server does not do: no stapled response,
// no CAA record, the post-quantum group declined.
//
// Nothing there was wrong. The verdict was strong and the tables were full of
// suites graded strong. But a reader's eye lands on the prose, and the prose
// only ever described absences, so a report on a well configured server read
// as a list of its shortcomings.
//
// These are the other half, and they cost nothing to produce: every one is a
// fact this scan already established and already used to reach its verdict.
// No handshake is added and no verdict is invented.
//
// Two rules keep them honest.
//
// Each states what was measured rather than what follows from it. "Every
// suite was graded strong" and not "this server has forward secrecy": the
// second is an inference from the current rule set, and rule sets move.
//
// And no threshold is repeated here. Where a claim would need one — whether
// 4096 bits is enough, whether thirty days is soon — the rules already own
// that number, and a second copy of it is a second thing to keep in step.
// Those facts are on the certificate line, where they are shown rather than
// judged twice.

// Assurance is one measured fact stated in the affirmative.
type Assurance struct {
	// ID is stable, so a caller can suppress or track one by identifier
	// rather than by matching prose.
	ID string `json:"id"`

	Text string `json:"text"`
}

// AssuranceFacts is what a scan established, in the shape these sentences
// need. Every field is copied from a measurement; none is derived from a
// finding, so an assurance cannot be produced by a rule failing to fire.
type AssuranceFacts struct {
	// TLS13Accepted and TLS13Preferred come from the version walk.
	TLS13Accepted  bool
	TLS13Preferred bool

	// ObsoleteAccepted is true when a handshake completed at TLS 1.0 or 1.1.
	//
	// The negative case is stated as what was measured — that no handshake
	// completed — rather than as the server refusing. A server that speaks a
	// version but shares no suite with this client answers exactly as one
	// that refuses it, which is a standing limit of this method, and an
	// assurance is the last place to forget it.
	ObsoleteAccepted bool

	// SuitesGraded counts the suites reached across every accepted version,
	// and CipherListComplete is false if enumeration was cut short at any of
	// them. AllSuitesStrong is only meaningful with a complete list: strong
	// is the verdict that claims an absence.
	SuitesGraded       int
	CipherListComplete bool
	AllSuitesStrong    bool

	PreferenceKnown  bool
	ServerPreference bool

	ChainTrusted  bool
	ChainComplete bool
	ChainLength   int

	// NameMatches and CertificateInDate are what "trusted" does not cover,
	// and without them the chain sentence was true and read as a
	// reassurance on exactly the reports where identity had failed.
	//
	// Measured on 2026-09-01: expired.badssl.com, whose certificate expired
	// 4159 days ago, and wrong.host.badssl.com, whose certificate is for
	// another name, both carried "the chain is complete and reaches a root"
	// under a heading called What holds, above a verdict of insecure.
	NameMatches       bool
	CertificateInDate bool

	// RevocationVerified is true only for a stapled response that verified
	// against the issuer. Nothing here is ever asked of an authority.
	RevocationVerified bool

	TransparencyCount int
	TransparencyLogs  int

	PostQuantumOffered bool
	PostQuantumGroup   string

	IssuanceRestricted bool
	IssuanceFoundAt    string
}

// Assurances is what holds, in the order a reader meets it: how the
// connection is negotiated, then what the certificate is, then what stands
// behind it.
func Assurances(f AssuranceFacts) []Assurance {
	var out []Assurance
	add := func(id, text string) { out = append(out, Assurance{ID: id, Text: text}) }

	if f.TLS13Accepted {
		if f.TLS13Preferred {
			add("tls13", "TLS 1.3 is accepted, and it is what this server picks.")
		} else {
			add("tls13", "TLS 1.3 is accepted.")
		}
	}

	if !f.ObsoleteAccepted {
		add("no-obsolete", "No handshake completed at TLS 1.0 or TLS 1.1.")
	}

	// Only from a complete list. A truncated one supports "something weak is
	// here" and never "nothing weak is here", and this sentence is the second.
	if f.CipherListComplete && f.AllSuitesStrong && f.SuitesGraded > 0 {
		add("suites", fmt.Sprintf(
			"Every one of the %s this server accepts was graded strong.",
			plural(f.SuitesGraded, "cipher suite")))
	}

	if f.PreferenceKnown && f.ServerPreference {
		add("server-order", "The server imposes its own cipher order, so a client with an "+
			"outdated preference list cannot steer the connection towards a weaker suite.")
	}

	// Four conditions, because the sentence is read as one claim about
	// identity and "reaches a root" is only a quarter of it.
	if f.ChainTrusted && f.ChainComplete && f.NameMatches && f.CertificateInDate {
		add("chain", fmt.Sprintf(
			"The chain is complete, reaches a root in this machine's trust store, and covers the "+
				"name that was asked for: %s.",
			plural(f.ChainLength, "certificate")))
	}

	if f.RevocationVerified {
		add("revocation", "Revocation was checked from the response the server stapled, and that "+
			"response verified against the issuing authority. No authority was asked anything.")
	}

	if f.TransparencyCount > 0 {
		add("transparency", fmt.Sprintf(
			"The certificate carries %s from %s, so its issuance is on public record.",
			plural(f.TransparencyCount, "transparency timestamp"), plural(f.TransparencyLogs, "log")))
	}

	if f.PostQuantumOffered && f.PostQuantumGroup != "" {
		add("post-quantum", fmt.Sprintf(
			"The hybrid post-quantum group %s was accepted, so a recording of this connection is "+
				"not exposed to a quantum computer built later.", f.PostQuantumGroup))
	}

	if f.IssuanceRestricted && f.IssuanceFoundAt != "" {
		add("issuance", fmt.Sprintf(
			"Issuance is restricted by the CAA record set at %s.", f.IssuanceFoundAt))
	}

	return out
}
