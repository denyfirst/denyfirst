package policy

// The limits of the instrument, in one place.
//
// A standing limit is true of every scan this program runs. It says nothing
// about the host in front of it, which is exactly why repeating it on every
// report is how it stops being read — and why, when it sat under the same
// heading as everything else a report could not settle, it made each scan
// look as though it had failed at something.
//
// They are declared here rather than at the places that mention them so
// that the page explaining them and the reports referring to them cannot say
// different things. That is R16's argument applied to a third renderer: one
// set of facts, however many faces read it.
//
// The identifiers are stable. They are the anchors on the page, so a report
// that points at one is pointing somewhere that will still exist.

// StandingLimit is one property of this program that no host can change.
type StandingLimit struct {
	// ID is the anchor on the page that explains it. Stable across releases.
	ID string

	// Title is the heading it appears under.
	Title string

	// Text is the sentence itself, in the words a report used to carry.
	Text string
}

// Note renders the limit as a note, so that a caller cannot write a standing
// sentence that is not one of these.
func (l StandingLimit) Note() Note { return Note{Kind: KindStanding, Text: l.Text} }

// The set. Adding one means adding it here and nowhere else; the page picks
// it up, and a test fails if a report carries a standing sentence this list
// does not contain.
//
// Nothing here names how many there are. The count is read from the list at
// render time on both faces, because a sentence saying "four" is a sentence
// that goes stale the day a fifth is written — the same defect as a change
// log section that still says "Unreleased" five releases after it shipped.
var (
	LimitFirstHop = StandingLimit{
		ID:    "first-hop-only",
		Title: "Only the first hop was measured",
		Text: "Everything here describes the endpoint that answered on the address named at the top of " +
			"this report. Where a content delivery network, a reverse proxy or a load balancer terminates " +
			"TLS, that endpoint is the one measured: the link from it to the server behind it is not " +
			"visible from here, and may negotiate other versions, other suites and another key exchange. " +
			"A name that resolves to several addresses was measured at one of them.",
	}

	LimitCipherSuitesOffered = StandingLimit{
		ID:    "cipher-suites-offered",
		Title: "Only the suites this client can offer were offered",
		Text: "Only cipher suites implemented by Go's TLS stack were offered. Suites outside it, " +
			"and SSLv2 or SSLv3, are not covered. A server that speaks a version but shares no " +
			"suite with this client answers a handshake the same way as one that refuses the " +
			"version, so a refusal here is not proof the version is switched off.",
	}

	LimitTLS13Suites = StandingLimit{
		ID:    "tls13-suites",
		Title: "TLS 1.3 suites cannot be enumerated",
		Text: "For TLS 1.3 only the negotiated suite is listed. Go gives a client no way to " +
			"choose among TLS 1.3 suites, so the rest could not be enumerated.",
	}

	LimitOneTrustStore = StandingLimit{
		ID:    "one-trust-store",
		Title: "Trust is decided by one root store",
		Text: "A chain reported as trusted was verified against the root store of the machine that ran " +
			"this scan, which is one store among several. Chrome, Apple and Microsoft each ship their " +
			"own, remove authorities on their own timetables, and a packaged store lags the programme " +
			"it is built from. So this says a chain verified here: not that every client will accept " +
			"it, and not that none will.",
	}

	LimitNoAuthorityAsked = StandingLimit{
		ID:    "no-authority-asked",
		Title: "No certificate authority is ever asked",
		Text: "No certificate authority is asked anything by this scan: that question would tell " +
			"the authority which certificate is being looked at. Revocation is read only from a " +
			"response the server stapled into the handshake, so where none was stapled it has not " +
			"been established here by any means. A chain reported as trusted reaches a root and is " +
			"in date; it may still have been withdrawn.",
	}

	LimitTransparencyReceipts = StandingLimit{
		ID:    "transparency-receipts",
		Title: "Transparency receipts are counted, not verified",
		Text: "Transparency receipts are counted and not verified: checking one needs the log's " +
			"public key, and this service carries no copy of that list.",
	}
)

// StandingLimits is the whole set, in the order the page shows them.
func StandingLimits() []StandingLimit {
	return []StandingLimit{
		// First because it bounds every other measurement on the page: what
		// answered, rather than what was asked of it.
		LimitFirstHop,
		LimitCipherSuitesOffered,
		LimitTLS13Suites,
		LimitOneTrustStore,
		LimitNoAuthorityAsked,
		LimitTransparencyReceipts,
	}
}

// IsStandingLimit reports whether a sentence is one of them.
//
// Used by the test that runs a whole scan and checks that every standing note
// it produced came from this list, which is what stops a fifth limit being
// written inline and never reaching the page that is supposed to explain it.
func IsStandingLimit(text string) bool {
	for _, l := range StandingLimits() {
		if l.Text == text {
			return true
		}
	}
	return false
}
