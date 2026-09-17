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

	// Checked is true when the receipts were checked against a log list
	// whose own signature verified. Without it the counts below are silence
	// rather than receipts that failed (R4).
	Checked bool

	// ListReason says why they were not checked.
	ListReason string

	// ListVersion and ListDate name the list they were checked against, so a
	// reader can see how old the judgement is.
	ListVersion string
	ListDate    string

	// What checking found, one count per receipt: its log signed this
	// certificate; the log's key does not verify it; the list names no such
	// log; or it could not be checked at all.
	Verified     int
	BadSignature int
	UnknownLog   int
	Unreadable   int
}

// DescribeTransparency returns the sentences a report should carry.
//
// Notes rather than findings. Nothing here is graded; see the reasoning above.
func DescribeTransparency(f TransparencyFacts) []Note {
	total := f.Embedded + f.InHandshake

	if total > 0 {
		note := fmt.Sprintf(
			"%s, from %s. The certificate is therefore recorded where anybody, including its "+
				"domain's owner, can find it — which is how an authority that issued a certificate "+
				"it should not have gets caught.",
			plural(total, "transparency timestamp"), plural(f.FromLogs, "log"))

		if f.InHandshake > 0 && f.Embedded > 0 {
			note += fmt.Sprintf(" %d arrived embedded in the certificate and %d in the handshake.",
				f.Embedded, f.InHandshake)
		}

		// Separate sentences, separate claims. How many receipts arrived is a
		// fact about this certificate; what checking them found is another;
		// and which list they can be checked against is true of every scan,
		// so it is the standing limit rather than part of either.
		out := []Note{Observed(note)}
		out = append(out, describeReceipts(f, total)...)
		return append(out, LimitTransparencyReceipts.Note())
	}

	if !f.Trusted {
		// Not a fault. A private authority answers to whoever runs it.
		return []Note{Observed(
			"No transparency timestamps were found, and this chain does not reach a root in the " +
				"trust store. A certificate outside the public authorities is under no obligation to " +
				"appear in a transparency log.")}
	}

	if f.Stapled {
		// The one case where silence would be a false accusation.
		return []Note{Unsettled(
			"No transparency timestamps were found in the certificate or the handshake. They may " +
				"still be present: a status response was stapled, timestamps can travel inside one, " +
				"and this service does not read it. What can be said is that none arrived by the two " +
				"routes that were examined.")}
	}

	return []Note{Observed(
		"No transparency timestamps were found in the certificate or the handshake, and no status " +
			"response was stapled that might have carried them. A publicly trusted certificate is " +
			"expected to be logged, and browsers refuse one that is not, so a client may well decline " +
			"this connection where this report does not.")}
}

// describeReceipts says what checking the receipts found.
//
// Nothing here is graded, for the reason nothing above is: how many receipts a
// certificate needs, and from which logs, is each browser's policy (R21). What
// checking adds is the difference between a receipt that is present and one that
// is genuine.
//
// The four outcomes are kept apart because they send a reader to different
// places. A receipt that does not verify vouches for nothing. A receipt from a
// log the carried list does not name is not false — a log newer than the list, or
// one another browser trusts, looks exactly like that — and saying otherwise
// would accuse a certificate on the strength of an old list.
func describeReceipts(f TransparencyFacts, total int) []Note {
	if !f.Checked {
		reason := f.ListReason
		if reason == "" {
			reason = "this scan did not check them"
		}
		return []Note{Unsettled("The receipts were not verified: " + reason + ". An unchecked receipt is a " +
			"claim that a log recorded this certificate, not proof of it.")}
	}

	list := "Chrome's log list of " + f.ListDate
	if f.ListVersion != "" {
		list += " (version " + f.ListVersion + ")"
	}

	var out []Note
	switch {
	case f.Verified == total:
		// A receipt is a log's signed promise, and a verified one proves the
		// promise was made. That the log kept it is a separate proof. The
		// sentence said "really did record" until the 2026-09-16 audit (A20).
		out = append(out, Observed("Every receipt was checked against the key "+list+" gives its log, and "+
			"every signature verifies: each log named signed a promise to include this certificate. "+
			"Whether it did is shown by an inclusion proof, which this scan did not ask for."))
	case f.Verified > 0:
		out = append(out, Observed(fmt.Sprintf("%s of the %d verify against the key %s gives its log.",
			plural(f.Verified, "receipt"), total, list)))
	}

	if f.BadSignature > 0 {
		out = append(out, Observed(fmt.Sprintf("%s did not verify against the key %s gives its log, so it "+
			"vouches for nothing about this certificate. A browser checking receipts discounts one like this.",
			plural(f.BadSignature, "receipt"), list)))
	}
	if f.UnknownLog > 0 {
		out = append(out, Unsettled(fmt.Sprintf("%s came from a log %s does not name, so there was no key to "+
			"check against. A log newer than the list, or one another browser trusts, looks exactly like "+
			"this, so it is not established that the receipt is false.", plural(f.UnknownLog, "receipt"), list)))
	}
	if f.Unreadable > 0 {
		out = append(out, Unsettled(fmt.Sprintf("%s could not be checked: the receipt could not be read, or the "+
			"certificate that issued this one was not in the chain to check against.", plural(f.Unreadable, "receipt"))))
	}
	return out
}

// plural writes a count with its noun, so a report does not say "1 logs".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
