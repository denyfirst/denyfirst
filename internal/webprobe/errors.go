package webprobe

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/denyfirst/denyfirst/internal/safedial"
)

// classifyProbeError turns a failed hop into a phrase written here, and says
// whether the failure was this service declining to dial.
//
// Every branch returns a string from this function. There is no pass-through,
// and the default case is a phrase rather than the error, for the reason I6
// gives: an unrecognised failure is the one most likely to carry an address,
// and the one nobody has reviewed.
//
// The leak this closes arrives from the standard library rather than from any
// formatting of ours. Go writes network errors for an operator reading a
// terminal, so they name whatever helps there. A DNS failure reads "lookup
// example.com on 10.0.0.1:53: no such host" — the resolver's address belongs
// to whoever runs this machine. safedial's own refusals name the address that
// was rejected. Both were being written into Hop.Err, which is serialised
// into a report; on the command line only the operator read it, and the day
// this check has an address on the service that report is a reply to a
// stranger.
//
// The TLS check has had this since I6 was written, in
// tlsprobe.classifyHandshakeError. This is the same rule applied to the other
// probe, and the phrases differ only where the two checks differ: a hop is an
// HTTP request rather than a handshake, and a certificate that fails
// verification stops it, because unlike the TLS probe this client verifies.
func classifyProbeError(err error) (text string, blocked bool) {
	if err == nil {
		return "", false
	}

	// Matched on the unwrapped message rather than on err.Error(). A
	// *url.Error prints the address it was fetching, so every string test
	// below would otherwise be reading the target's own URL as well as the
	// failure, and a match on it would be a match on attacker-chosen text.
	msg := unwrapURLError(err)

	switch {
	// Refused by policy before anything was dialled. The reason belongs in
	// the report; the address that triggered it does not.
	//
	// Checked before every message test below, because this is the branch
	// whose underlying text is certain to carry an address.
	//
	// Nothing today depends on that order: no message ErrBlocked carries
	// contains a phrase a later branch matches, and safedial builds
	// SingleFamilyError only where a dial failed, so a refusal is never also
	// a single-family error. Both of those are facts about safedial's current
	// wording rather than properties of this function, which is why the order
	// is held by TestAPolicyRefusalIsRecognisedWhateverItSays instead of by
	// this comment.
	case errors.Is(err, safedial.ErrBlocked):
		return "not fetched: this is not a destination the service will connect to", true

	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "server misbehaving"),
		strings.Contains(msg, "no addresses"):
		return "the name did not resolve", false

	case errors.Is(err, context.DeadlineExceeded),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "Client.Timeout"):
		return "the request timed out", false

	case errors.Is(err, context.Canceled):
		return "the scan was cancelled before this address was reached", false

	case strings.Contains(msg, "connection refused"):
		return "the connection was refused", false

	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "EOF"):
		return "the connection closed before a response arrived", false

	case strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "host is down"),
		strings.Contains(msg, "address family not supported"):
		// The same distinction tlsprobe draws, and for the same reason: a
		// name publishing only AAAA records is unreachable from a scanner
		// with no IPv6 route however healthy the server is, and reporting
		// "the host could not be reached" states something about somebody
		// else's server on the strength of a fact about this one. The family
		// is published in the name's own DNS and checkable in a second, so
		// naming it says what happened without describing this machine.
		var family *safedial.SingleFamilyError
		if errors.As(err, &family) {
			return "the host could not be reached, and every address published for this name is " +
				family.Family + "; a scanner with no " + family.Family + " route reaches none of them", false
		}
		return "the host could not be reached", false

	// This client verifies, which the TLS probe deliberately does not. So a
	// certificate a browser would refuse stops the hop here, and that is a
	// finding rather than an accident: it is how the secure address of a host
	// with an expired or misissued certificate actually behaves for a
	// visitor. What it is not is a response with no headers, and R23 turns on
	// keeping those two apart.
	//
	// The library's text carries the certificate's own names and dates. They
	// are the scanned party's rather than ours, so this is not the leak I6
	// names — but the TLS check is where a certificate is described, in a
	// section built for it, and a second half-description arriving through an
	// error string is how two faces of one report come to disagree.
	case strings.Contains(msg, "x509:"),
		strings.Contains(msg, "tls: failed to verify certificate"):
		return "the secure connection failed while the certificate was being checked", false

	case strings.Contains(msg, "server gave HTTP response to HTTPS client"):
		return "the port answered in plaintext to a request made over TLS", false

	case strings.Contains(msg, "tls:"):
		return "the secure connection could not be established", false

	default:
		// Deliberately not the error. See the doc comment: this is the branch
		// that would carry the resolver's address the day the standard
		// library words a failure differently.
		return "the request did not complete", false
	}
}

// blockedDestination reports that nothing was fetched because every address
// this name resolves to is one the service refuses.
//
// True only when at least one hop was attempted and every one of them was
// refused by safedial. A name that answers on one port and is refused on the
// other has been reached, and describing it as a blocked destination would
// hide a measurement that succeeded.
//
// A field rather than a phrase to be matched, for the reason A7 gives: the
// count is the only sign an operator has that somebody is aiming this service
// at the network it runs in, and a count built by matching prose breaks
// silently the first time the prose is improved.
func blockedDestination(chains ...*Chain) bool {
	hops := 0
	for _, c := range chains {
		if c == nil {
			continue
		}
		for _, h := range c.Hops {
			hops++
			if !h.blocked {
				return false
			}
		}
	}
	return hops > 0
}

// unwrapURLError removes the wrapper the http client adds.
//
// url.Error prints the method and the whole address in front of every
// failure, and the address is already the URL field of the hop this error
// belongs to. Read as it comes, every string test in classifyProbeError would
// be matching the target's own URL as well as the fault, and a report built
// from it would say the same address twice with the reason at the end of a
// long line.
func unwrapURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}
