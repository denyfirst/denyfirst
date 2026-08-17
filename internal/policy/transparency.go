package policy

import "fmt"

// Certificate transparency, described rather than graded.
//
// A publicly trusted certificate has to be recorded in append-only logs, and
// each log answers with a signed receipt. Browsers refuse a certificate that
// arrives without enough of them. That sounds like something to grade, and it
// is not, for two reasons.
//
// The receipts reach a client three ways: embedded in the certificate, sent as
// a handshake extension, or carried inside a stapled status response. Nothing
// here reads a status response, so a certificate showing none of the first two
// may still be presenting them by the third. Grading on two channels out of
// three would fail a working configuration, which is the mistake the version
// rules and the stapling rules both exist to avoid.
//
// And the requirement itself is not ours to enforce. How many receipts, from
// how many logs, and which logs count are decided by each browser and revised
// on their schedule. A rule here would either copy a policy that moves without
// us or invent one nobody follows.
//
// So the numbers are reported, what they exclude is stated, and the reader is
// left to compare them against whichever client they care about.

// TransparencyFacts is what the certificate and the handshake each carried.
type TransparencyFacts struct {
	// Embedded is how many timestamps the leaf carries, and FromLogs how many
	// distinct logs issued them.
	Embedded int
	FromLogs int

	// InHandshake is how many arrived as a TLS extension. Almost always zero,
	// because almost every authority embeds them instead.
	InHandshake int

	// Stapled reports whether a status response accompanied the handshake.
	//
	// It is the third delivery channel, and this is the only thing said about
	// it here: a report claiming a certificate carries no receipts, while
	// holding an unread response that may contain them, would be stating as
	// fact something it declined to look at.
	Stapled bool

	// Trusted reports whether the chain reached a root in the trust store.
	//
	// A certificate outside it — self-signed, or issued by a private
	// authority — is under no obligation to be logged at all, and saying
	// nothing was found would read as a fault where there is none.
	Trusted bool
}

// DescribeTransparency returns the sentences a report should carry.
//
// Notes rather than findings. Nothing here is graded; see the reasoning above.
func DescribeTransparency(f TransparencyFacts) []string {
	total := f.Embedded + f.InHandshake

	if total > 0 {
		note := fmt.Sprintf(
			"%s, from %s. The certificate is therefore recorded where anybody, including its "+
				"domain's owner, can find it — which is how an authority that issued a certificate "+
				"it should not have gets caught. The receipts were counted and not verified: "+
				"checking one needs the log's public key, and this service carries no copy of that list.",
			plural(total, "transparency timestamp"), plural(f.FromLogs, "log"))

		if f.InHandshake > 0 && f.Embedded > 0 {
			note += fmt.Sprintf(" %d arrived embedded in the certificate and %d in the handshake.",
				f.Embedded, f.InHandshake)
		}
		return []string{note}
	}

	if !f.Trusted {
		// Not a fault. A private authority answers to whoever runs it.
		return []string{
			"No transparency timestamps were found, and this chain does not reach a root in the " +
				"trust store. A certificate outside the public authorities is under no obligation to " +
				"appear in a transparency log.",
		}
	}

	if f.Stapled {
		// The one case where silence would be a false accusation.
		return []string{
			"No transparency timestamps were found in the certificate or the handshake. They may " +
				"still be present: a status response was stapled, timestamps can travel inside one, " +
				"and this service does not read it. What can be said is that none arrived by the two " +
				"routes that were examined.",
		}
	}

	return []string{
		"No transparency timestamps were found in the certificate or the handshake, and no status " +
			"response was stapled that might have carried them. A publicly trusted certificate is " +
			"expected to be logged, and browsers refuse one that is not, so a client may well decline " +
			"this connection where this report does not.",
	}
}

// plural writes a count with its noun, so a report does not say "1 logs".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
