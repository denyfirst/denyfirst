// Package tlsprobe determines which TLS protocol versions and cipher suites
// a server accepts, and collects the certificate chain it presents.
//
// The probe performs real handshakes rather than reading a banner, so the
// results describe what the server will actually negotiate rather than what
// it claims to support.
//
// Three design points are deliberate.
//
// Connections default to the SSRF-safe dialer. Leaving Prober.Dial nil
// selects safedial, so refusing private destinations is the default and
// bypassing it requires an explicit decision. The reverse arrangement — safe
// only when configured — fails open the first time someone forgets.
//
// This package measures; it does not judge. Every verdict comes from the
// policy package, which carries the rules and the documents behind them. That
// keeps the answer reproducible: the same server graded by the same policy
// version yields the same result, whatever crypto/tls decides about a suite
// between Go releases.
//
// Interpretation of the certificate chain belongs in certinfo, which takes
// []*x509.Certificate and computes, so it can be tested without a server.
//
// # Known limitation
//
// Go's crypto/tls will only offer cipher suites it implements, roughly
// twenty-seven of the three hundred or so in the IANA registry. Suites Go has
// never carried — Camellia, ARIA, GOST — cannot be detected here even if the
// server supports them, and the same applies to SSLv2 and SSLv3. TLS 1.3
// suites are not configurable at all in Go, so for that version the probe
// reports the negotiated suite rather than enumerating.
//
// Callers must surface this. A report that silently omits what it could not
// test is worse than one that tests less and says so.
package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/safedial"
)

// DialFunc matches net.Dialer.DialContext and safedial.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

const (
	defaultHandshakeTimeout = 5 * time.Second
	defaultTotalTimeout     = 30 * time.Second

	// maxEnumerationRounds stops a misbehaving server from holding the probe
	// in a loop. No real server offers anything close to this many suites.
	maxEnumerationRounds = 40
)

// probedVersions is ordered newest first so the certificate chain is taken
// from the most modern handshake that succeeds.
var probedVersions = []uint16{
	tls.VersionTLS13,
	tls.VersionTLS12,
	tls.VersionTLS11,
	tls.VersionTLS10,
}

// Prober runs TLS handshakes against a host. The zero value is usable.
type Prober struct {
	// Dial opens the TCP connection. Nil selects safedial, which refuses
	// private, loopback, link-local, and reserved destinations.
	Dial DialFunc

	// HandshakeTimeout bounds one handshake. Zero means five seconds.
	HandshakeTimeout time.Duration

	// TotalTimeout bounds the whole probe. Zero means thirty seconds. A
	// tighter deadline on the caller's context takes precedence.
	TotalTimeout time.Duration
}

// Report is the outcome of probing one host.
type Report struct {
	Host string `json:"host"`
	Port string `json:"port"`

	// Address is the IP actually connected to. Recorded because a hostname
	// with several addresses may not answer identically on each.
	Address string `json:"address,omitempty"`

	// Policy names the rule set that produced every verdict below, so a
	// result can be reproduced after the rules move on.
	Policy string `json:"policy"`

	// Verdict is the worst verdict across everything the server accepts.
	// Empty when nothing could be measured, which is not the same as passing.
	Verdict policy.Verdict `json:"verdict,omitempty"`

	// Findings collects each distinct problem once, so a caller can present
	// them without walking the version and cipher trees.
	Findings []policy.Finding `json:"findings,omitempty"`

	Versions []VersionResult `json:"versions"`

	// Certificates is the chain as presented, leaf first, from the newest
	// protocol version that completed a handshake. Empty if none did.
	Certificates []*x509.Certificate `json:"-"`

	// AlternateChains holds a chain presented at some other version whose
	// leaf is not the leaf above.
	//
	// Serving different certificates at different protocol versions is a real
	// configuration rather than a curiosity: a server picks by the signature
	// algorithms the client offered, and an old client offers a smaller set.
	// Describing only the newest handshake therefore misses exactly the chain
	// an old client gets, which is the chain most likely to be the weak one —
	// a SHA-1 certificate kept for compatibility and reachable only at
	// TLS 1.0 was invisible to this report while it described the modern one
	// beside it.
	//
	// Compared by the leaf's own bytes. Two handshakes to the same server
	// normally return the identical certificate, so this is empty in the
	// ordinary case and costs nothing.
	AlternateChains []AlternateChain `json:"-"`

	// ServerPreference reports whether the server imposes its own cipher
	// ordering. False means it follows the client's order, which lets an
	// outdated client steer the connection towards a weaker suite.
	ServerPreference bool `json:"serverPreference"`

	// PreferenceKnown is false when the question could not be settled,
	// typically because fewer than two suites were available to compare.
	PreferenceKnown bool `json:"preferenceKnown"`

	ALPN string `json:"alpn,omitempty"`
	// PostQuantum is the answer to the one extra handshake this probe makes
	// beyond version and suite enumeration.
	PostQuantum PostQuantum `json:"postQuantum"`

	OCSPStapled bool `json:"ocspStapled"`

	// OCSPResponse is the stapled certificate status response, as sent.
	//
	// Kept because observing that bytes arrived is not the same as reading
	// them, and the difference is the difference between "the server is
	// stapling" and "the certificate is not revoked". Not serialised: it is
	// input to a check rather than a fact about the server, and the check's
	// result is what a reader needs.
	OCSPResponse []byte `json:"-"`
	SCTCount     int    `json:"sctCount"`

	// BlockedDestination reports that every attempt was refused by safedial
	// before anything was dialled: the name resolved only to private,
	// loopback, link-local or reserved addresses.
	//
	// A field rather than a phrase in Notes, because a caller has to be able
	// to count this. An operator running a public scanner needs to see the
	// shape of what arrives — "attempts at private addresses rose from two a
	// day to eight thousand" is the sentence that says somebody is using this
	// as an SSRF proxy — and a count built by matching prose breaks silently
	// the first time the prose is improved.
	//
	// Not serialised: it is a fact about why this service declined, not a
	// measurement of the host, and internal/httpapi turns it into a refusal
	// with its own status code rather than passing it through.
	BlockedDestination bool `json:"-"`

	// SCTLogIDs identifies the logs behind the handshake timestamps, hex
	// encoded. Reported alongside the count because the same logs may also
	// appear embedded in the certificate, and adding two counts would report
	// one log twice.
	SCTLogIDs []string `json:"sctLogIds,omitempty"`

	// Duration is the wall time the probe took, for Go callers.
	//
	// It is not serialised directly: time.Duration marshals as nanoseconds,
	// so a field labelled milliseconds would carry a number a thousand times
	// too large. A tool that reports other people's mistakes cannot ship a
	// unit error of its own.
	Duration time.Duration `json:"-"`

	// DurationMs is the same value in milliseconds, for JSON consumers.
	DurationMs int64 `json:"durationMs"`

	// Notes records what the probe could not establish. It is part of the
	// result, not a debug aid: an unexplained gap reads as an absence.
	Notes []policy.Note `json:"notes,omitempty"`
}

// VersionResult describes one protocol version.
type VersionResult struct {
	Version   uint16 `json:"-"`
	Name      string `json:"name"`
	Supported bool   `json:"supported"`

	// Grade is populated only when Supported is true. A server that refuses
	// TLS 1.0 has done the right thing, and attaching the deprecation finding
	// to that refusal would penalise a correct configuration.
	Grade policy.VersionFinding `json:"grade,omitzero"`

	Ciphers []CipherResult `json:"ciphers,omitempty"`

	// CipherListComplete is false when enumeration stopped for a reason other
	// than the server running out of suites it shares with this client.
	//
	// The distinction decides whether Ciphers is a measurement or a lower
	// bound, and the difference is not cosmetic. Enumeration makes one
	// handshake per suite the server accepts — up to twenty-two at TLS 1.2 —
	// and a host that rate-limits, resets, or simply gets tired will cut that
	// short. Go's server preference answers with its strongest suite first,
	// so what a truncated list loses is the weak end: the suites that would
	// have set the verdict. Measured on 2026-08-22, a server accepting two
	// GCM suites and two CBC suites was graded strong instead of weak when
	// the connection stopped answering after the second handshake.
	//
	// That also makes it something the scanned host can choose. Answer twice,
	// then go quiet, and the report says strong.
	CipherListComplete bool `json:"cipherListComplete"`

	// Refused is true only when the server answered and declined this
	// version.
	//
	// "Refused" is a claim about the server, and most of the ways a probe
	// fails are not: our own client declining to offer a version, a name that
	// did not resolve, a timeout, a reset, a connection the policy would not
	// make. Every one of those leaves Supported false too, so a front end
	// that prints "refused" whenever Supported is false reports a server as
	// having turned down an obsolete version it may in fact still accept.
	//
	// That is the flattering direction, and it is the one this project has to
	// be most careful about — a scan that could not measure TLS 1.0 must not
	// read as a scan that found it switched off. The bit is therefore set
	// where the failure is classified rather than inferred from the absence
	// of success, and both front ends say "not measured" when it is false.
	//
	// No omitempty. False is the answer in every case but one, and a field
	// that disappears when it matters is a field a reader has to know about
	// in advance.
	Refused bool `json:"refused"`

	// Error explains a failed handshake. A refusal by the server and a
	// refusal by our own client are different findings, and the text
	// distinguishes them.
	Error string `json:"error,omitempty"`

	// Blocked records that safedial refused this attempt by policy rather
	// than the network failing it. Kept beside Error because Error is a
	// sentence written for a reader and this is a fact written for a caller;
	// deriving the second from the first would mean parsing our own prose.
	Blocked bool `json:"-"`
}

// AlternateChain is a certificate chain served at one protocol version that
// differs from the chain the report describes.
// PostQuantum is what one extra handshake established about the key exchange.
//
// The question is whether the server will negotiate X25519MLKEM768, a hybrid
// of X25519 and ML-KEM-768. It matters for a reason none of the other
// measurements cover: traffic recorded today can be kept and decrypted by
// whoever first builds a quantum computer large enough, and forward secrecy
// does not help — that protects against a key stolen later, not against the
// key exchange itself being broken.
//
// Three states, not two. A server that says no and a question that could not
// be asked are different answers, and reporting the second as the first would
// be R12 in a new place.
type PostQuantum struct {
	// Measured is false when the question could not be put or answered.
	Measured bool `json:"measured"`

	// Offered is true when the server completed the handshake with the
	// hybrid group as the only one on the table.
	Offered bool `json:"offered"`

	// Group names what was offered, so the report is still true when the
	// name of the group changes.
	Group string `json:"group,omitempty"`

	// Reason says why nothing was measured. Empty when something was.
	Reason string `json:"reason,omitempty"`
}

type AlternateChain struct {
	// Version is the human-readable protocol version it was served at.
	Version string

	// Certificates is the chain as presented, leaf first.
	Certificates []*x509.Certificate
}

// CipherResult is one negotiated suite together with its grade.
type CipherResult struct {
	ID uint16 `json:"-"`
	policy.CipherFinding
}

// Probe runs the full sequence against host:port.
func (p *Prober) Probe(ctx context.Context, host, port string) (*Report, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, p.totalTimeout())
	defer cancel()

	report := &Report{Host: host, Port: port, Policy: policy.Version}

	// Versions are independent, so probe them concurrently. Cipher
	// enumeration within a version is inherently sequential: each round
	// depends on what the previous one removed.
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make([]VersionResult, len(probedVersions))
		states  = make([]*tls.ConnectionState, len(probedVersions))
		addrs   = make([]string, len(probedVersions))
	)

	for i, version := range probedVersions {
		wg.Add(1)
		go func() {
			defer wg.Done()

			state, addr, err := p.handshake(ctx, host, port, version, nil, nil)
			result := VersionResult{Version: version, Name: versionName(version)}

			if err != nil {
				result.Error, result.Refused = classifyHandshakeError(err, version)
				result.Blocked = errors.Is(err, safedial.ErrBlocked)
				mu.Lock()
				results[i] = result
				mu.Unlock()
				return
			}

			result.Supported = true
			result.Grade = policy.GradeVersion(version)

			if version == tls.VersionTLS13 {
				// Go does not expose TLS 1.3 suite selection, so report what
				// was negotiated instead of enumerating. One suite is all
				// there is to have, so the list is as complete as it can be;
				// the note below says what that means.
				result.Ciphers = []CipherResult{gradeCipher(state.CipherSuite)}
				result.CipherListComplete = true
			} else {
				result.Ciphers, result.CipherListComplete = p.enumerateCiphers(ctx, host, port, version)
			}

			mu.Lock()
			results[i] = result
			states[i] = state
			addrs[i] = addr
			mu.Unlock()
		}()
	}
	wg.Wait()

	report.Versions = results

	// Take the certificate chain and connection details from the newest
	// version that answered. probedVersions is ordered newest first.
	for i := range states {
		if states[i] == nil {
			continue
		}
		state := states[i]
		report.Certificates = state.PeerCertificates
		report.AlternateChains = differingChains(states, results, i)
		report.Address = addrs[i]
		report.ALPN = state.NegotiatedProtocol
		report.OCSPStapled = len(state.OCSPResponse) > 0
		report.OCSPResponse = state.OCSPResponse
		report.SCTCount = len(state.SignedCertificateTimestamps)
		var unreadable int
		report.SCTLogIDs, unreadable = handshakeLogIDs(state.SignedCertificateTimestamps)
		if unreadable > 0 {
			// Said rather than left as a difference between two numbers.
			// certinfo raises a note when an embedded list cannot be parsed;
			// this is the same fact arriving by the other route, and the
			// reader who has to subtract one field from another to notice it
			// is the reader who does not notice it.
			report.unsettled(fmt.Sprintf(
				"%d of the %d transparency timestamps in the handshake could not be read, so the logs "+
					"behind them are not counted. The total still includes them.",
				unreadable, report.SCTCount))
		}
		break
	}

	report.Verdict, report.Findings = summarise(results)
	report.BlockedDestination = blockedDestination(results)

	// Said plainly, because the alternative is a list that reads as the whole
	// answer. A reader who is not told the enumeration stopped early will take
	// the suites shown for the suites accepted, which is the reading this
	// project objects to in other tools.
	for _, v := range results {
		if !v.Supported || v.CipherListComplete {
			continue
		}
		report.unsettled(fmt.Sprintf(
			"The cipher suite list for %s is incomplete. Enumeration needs one handshake per suite "+
				"the server accepts, and this host stopped answering before the list ran out, so what "+
				"is shown is what was reached rather than everything accepted. Suites are found "+
				"strongest first, so the ones missing are the ones that would have lowered the grade.",
			v.Name))
	}

	if len(report.Certificates) == 0 {
		report.unsettled(
			"No handshake completed, so no certificate chain was retrieved.")
	}

	for _, alt := range report.AlternateChains {
		report.observe(fmt.Sprintf(
			"%s is served a different certificate from the one described above. Both were graded and the "+
				"worse of the two set the verdict; the details shown are the newest handshake's.", alt.Version))
	}

	// One extra handshake, and only where the question exists.
	//
	// X25519MLKEM768 is defined for TLS 1.3 alone, so a server that does not
	// speak it is not asked and pays nothing. Measured on a synthetic server:
	// a full scan of a modern host costs twelve connections and this makes it
	// thirteen, which is the whole price of the answer.
	if idx := slices.IndexFunc(results, func(v VersionResult) bool {
		return v.Supported && v.Version == tls.VersionTLS13
	}); idx >= 0 {
		report.PostQuantum = p.postQuantum(ctx, host, port)
	} else {
		report.PostQuantum = PostQuantum{
			Reason: "no TLS 1.3 handshake completed, and the hybrid group is defined for TLS 1.3 alone",
		}
	}

	// Preference detection needs a version where we control the ordering.
	if idx := slices.IndexFunc(results, func(v VersionResult) bool {
		return v.Supported && v.Version != tls.VersionTLS13 && len(v.Ciphers) >= 2
	}); idx >= 0 {
		known, prefers := p.detectServerPreference(ctx, host, port, results[idx])
		report.PreferenceKnown = known
		report.ServerPreference = prefers

		if !known {
			// Attempted and failed, which is not the same as not attempted,
			// and the field alone cannot tell a reader which happened.
			report.unsettled(
				"Cipher preference could not be determined: the two handshakes it needs did not both complete.")
		} else if !results[idx].CipherListComplete {
			// Answered from a list that was cut short, so the pair compared
			// may not include the suite the server would really have chosen.
			report.unsettled(
				"Cipher preference was determined from an incomplete suite list, so it describes the suites that were reached rather than everything the server accepts.")
		}
	} else {
		report.unsettled(
			"Cipher preference could not be determined: it requires a pre-1.3 version offering at least two suites.")
	}

	// What answered, before anything about what it answered.
	//
	// Every measurement above describes the endpoint reached at report.Address
	// and nothing further along the path. Where a content delivery network or
	// a reverse proxy terminates TLS, that is the machine measured, and the
	// link from it to the server behind it is invisible from here — which is
	// exactly where a hybrid post-quantum group accepted at the edge stops
	// meaning what a reader takes it to mean.
	//
	// Raised only when something answered. On a report where nothing did,
	// "everything here was measured at one hop" describes an empty set and
	// would be a sentence about nothing.
	if report.Address != "" {
		report.standing(policy.LimitFirstHop)
	}

	// The two notes below describe different gaps and both belong in a
	// report. The first bounds what was offered at all; the second explains
	// why one version shows a single suite. Dropping either leaves the reader
	// to assume the list is exhaustive.
	if suiteCoverageApplies(results) {
		report.standing(policy.LimitCipherSuitesOffered)
	}

	if slices.ContainsFunc(results, func(v VersionResult) bool {
		return v.Supported && v.Version == tls.VersionTLS13
	}) {
		report.standing(policy.LimitTLS13Suites)
	}

	report.Duration = time.Since(start)
	report.DurationMs = report.Duration.Milliseconds()
	return report, nil
}

// suiteCoverageApplies reports whether the sentence bounding what this client
// offered belongs in the report.
//
// A refusal counts as well as a success, and that half was missing.
//
// "handshake failure" is what a server sends when it will not speak a
// version, and it is also what it sends when it speaks the version and shares
// no suite with this client. The two are indistinguishable from the outside,
// so a host configured for suites Go does not implement is reported as
// refusing every version. The note was attached to success alone, so in that
// case — every row a refusal, verdict ungraded, nothing measured — it was
// dropped, which is exactly the report that most needs it.
//
// Nothing at all answering is the one case it stays out of. A name that did
// not resolve was never offered anything, and a sentence about which suites
// were offered would be describing a conversation that never happened.
func suiteCoverageApplies(results []VersionResult) bool {
	return slices.ContainsFunc(results, func(v VersionResult) bool {
		return v.Supported || v.Refused
	})
}

// differingChains returns every chain served at a version other than primary
// whose leaf is not the primary leaf.
//
// The comparison is over the leaf's own DER bytes. Anything less — a subject,
// a serial, a set of names — is a field a server can repeat across two
// genuinely different certificates, and the question here is whether the
// bytes an old client is handed are the bytes this report describes.
//
// One entry per distinct leaf. A server that serves the same second
// certificate to TLS 1.1 and TLS 1.0 has one alternate configuration, not
// two, and grading it twice would say the same thing twice.
func differingChains(states []*tls.ConnectionState, results []VersionResult, primary int) []AlternateChain {
	if states[primary] == nil || len(states[primary].PeerCertificates) == 0 {
		return nil
	}

	seen := map[[sha256.Size]byte]bool{
		sha256.Sum256(states[primary].PeerCertificates[0].Raw): true,
	}

	var out []AlternateChain
	for i, state := range states {
		if i == primary || state == nil || len(state.PeerCertificates) == 0 {
			continue
		}
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		out = append(out, AlternateChain{
			Version:      results[i].Name,
			Certificates: state.PeerCertificates,
		})
	}
	return out
}

// blockedDestination reports that the name was refused by policy rather than
// by anything on the network.
//
// Every version has to have been refused, and every refusal has to have been
// a block. One version failing for another reason means something answered,
// or tried to, and calling that a blocked destination would put a resolver
// failure and an attempt at 169.254.169.254 in the same counter. The whole
// value of that counter is that a change in it means one specific thing.
func blockedDestination(results []VersionResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, v := range results {
		if v.Supported || !v.Blocked {
			return false
		}
	}
	return true
}

// summarise reduces the per-version results to one verdict and a deduplicated
// finding list.
//
// Only versions the server actually accepts contribute. Refusing an obsolete
// version is correct behaviour, and grading the refusal would report a
// well-configured server as insecure.
func summarise(results []VersionResult) (policy.Verdict, []policy.Finding) {
	var (
		verdicts []policy.Verdict
		findings []policy.Finding
		seen     = map[string]bool{}
	)

	collect := func(fs []policy.Finding) {
		for _, f := range fs {
			if seen[f.RuleID] {
				continue
			}
			seen[f.RuleID] = true
			findings = append(findings, f)
		}
	}

	for _, v := range results {
		if !v.Supported {
			continue
		}

		verdicts = append(verdicts, v.Grade.Verdict)
		collect(v.Grade.Findings)

		for _, c := range v.Ciphers {
			verdicts = append(verdicts, c.Verdict)
			collect(c.Findings)
		}
	}

	// Most severe first, so a caller showing only the top item shows the
	// thing that matters.
	slices.SortStableFunc(findings, func(a, b policy.Finding) int {
		return b.Verdict.Rank() - a.Verdict.Rank()
	})

	worst := policy.Worst(verdicts...)

	// A list that was cut short can support "something weak is here" and
	// cannot support "nothing weak is here".
	//
	// The asymmetry is the same one R5 already rests on. Worst-case
	// aggregation only ever moves one way, so a suite that was seen stays
	// seen however the enumeration ended; what an unfinished list cannot do is
	// carry the absence of anything worse. Strong is precisely the verdict
	// that claims an absence, so it is the one an unfinished list forfeits.
	//
	// Ungraded rather than weak. The server has not been shown to be doing
	// anything wrong — the measurement did not finish — and grading a correct
	// configuration down for a connection that dropped is the failure R6
	// exists to prevent. Ungraded says what happened: no verdict was reached.
	if worst == policy.Strong {
		for _, v := range results {
			if v.Supported && !v.CipherListComplete {
				return policy.Ungraded, findings
			}
		}
	}

	return worst, findings
}

// enumerateCiphers offers every candidate, records what the server picks,
// removes it, and repeats. The number of handshakes is the number of suites
// the server supports, not the number offered.
//
// The second return value says whether the list is finished. Every loop that
// can end two ways has to say which one happened, and this one used to treat
// any handshake error as "nothing left that both sides accept" — which is one
// specific answer from the server, not a description of a timeout, a reset, or
// a host that stopped answering halfway through twenty-two connections.
//
// Getting that wrong is optimistic, which is the direction that matters. The
// suites arrive strongest first, because that is the order a Go server
// prefers, so a truncated list drops the weak end and the verdict improves.
// A host can do it on purpose.
func (p *Prober) enumerateCiphers(ctx context.Context, host, port string, version uint16) (found []CipherResult, complete bool) {
	remaining := candidateSuites(version)
	found = make([]CipherResult, 0, len(remaining))

	for round := 0; len(remaining) > 0; round++ {
		if round >= maxEnumerationRounds {
			// Above anything Go can offer, so this is a server answering with
			// suites it was not offered, or something stranger. Either way the
			// list is not finished.
			return found, false
		}
		if ctx.Err() != nil {
			return found, false
		}

		state, _, err := p.handshake(ctx, host, port, version, remaining, nil)
		if err != nil {
			return found, isNoSharedSuite(err)
		}

		// A server that answers with a suite we did not offer is out of
		// spec. Removing nothing would loop forever, so stop — and say the
		// list is unfinished, because it is.
		idx := slices.Index(remaining, state.CipherSuite)
		if idx < 0 {
			return found, false
		}

		found = append(found, gradeCipher(state.CipherSuite))
		remaining = slices.Delete(remaining, idx, idx+1)
	}

	// Everything Go can offer was offered and accounted for.
	return found, true
}

// isNoSharedSuite reports whether the server answered and said no, as opposed
// to the conversation failing.
//
// This is the one ending that finishes an enumeration honestly: the server
// considered what was left and had nothing in common with it. A timeout, a
// reset, a refused connection or a closed socket all mean the question went
// unanswered, and the suites not yet reached stay unknown.
//
// Matched on the alert the server sends rather than on our own guess about
// what silence means. classifyHandshakeError already draws this line for the
// version probe; this is the same line drawn where it decides a verdict.
func isNoSharedSuite(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "handshake failure") ||
		strings.Contains(msg, "insufficient security") ||
		strings.Contains(msg, "no cipher suite supported") ||
		strings.Contains(msg, "protocol version not supported")
}

// detectServerPreference offers the same suites in reversed order. A server
// with its own preference returns the same suite regardless; one that follows
// the client returns whichever we listed first.
func (p *Prober) detectServerPreference(ctx context.Context, host, port string, v VersionResult) (known, prefers bool) {
	if len(v.Ciphers) < 2 {
		return false, false
	}

	forward := make([]uint16, len(v.Ciphers))
	for i, c := range v.Ciphers {
		forward[i] = c.ID
	}
	reversed := slices.Clone(forward)
	slices.Reverse(reversed)

	first, _, err := p.handshake(ctx, host, port, v.Version, forward, nil)
	if err != nil {
		return false, false
	}
	second, _, err := p.handshake(ctx, host, port, v.Version, reversed, nil)
	if err != nil {
		return false, false
	}

	return true, first.CipherSuite == second.CipherSuite
}

// postQuantum offers the hybrid group and nothing else, once.
//
// The classification is its own rather than classifyHandshakeError's, because
// the alerts mean something different here. That function answers "did the
// server refuse this version"; this one asks "did the server refuse this
// group", and a server with no group in common sends handshake_failure or
// illegal_parameter, while one that wants a different group sends a
// HelloRetryRequest naming a group this client did not offer. All three are
// the server answering. Anything else is the question going unanswered, and
// the two are not reported alike.
func (p *Prober) postQuantum(ctx context.Context, host, port string) PostQuantum {
	const group = "X25519MLKEM768"

	if _, _, err := p.handshake(ctx, host, port, tls.VersionTLS13, nil,
		[]tls.CurveID{tls.X25519MLKEM768}); err == nil {
		return PostQuantum{Measured: true, Offered: true, Group: group}
	} else if declinedGroup(err) {
		return PostQuantum{Measured: true, Group: group}
	} else {
		text, _ := classifyHandshakeError(err, tls.VersionTLS13)
		return PostQuantum{Group: group, Reason: text}
	}
}

// declinedGroup reports whether the server answered and said no.
func declinedGroup(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "handshake failure") ||
		strings.Contains(msg, "illegal parameter") ||
		strings.Contains(msg, "insufficient security") ||
		strings.Contains(msg, "server selected unsupported group")
}

// handshake performs one handshake at a fixed version with an optional suite
// list, returning the connection state and the address reached.
func (p *Prober) handshake(ctx context.Context, host, port string, version uint16, suites []uint16, groups []tls.CurveID) (*tls.ConnectionState, string, error) {
	ctx, cancel := context.WithTimeout(ctx, p.handshakeTimeout())
	defer cancel()

	conn, err := p.dial()(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()

	addr := ""
	if remote := conn.RemoteAddr(); remote != nil {
		addr = remote.String()
	}

	// Both settings gosec objects to here are the purpose of the tool rather
	// than an oversight.
	//
	// InsecureSkipVerify is on because the probe must describe expired,
	// self-signed, and mismatched certificates rather than fail on them.
	// Verification is performed separately in certinfo, on the chain
	// collected here, so an invalid certificate becomes a finding instead of
	// an absent result.
	//
	// MinVersion drops to TLS 1.0 because reporting that a server still
	// accepts an obsolete protocol version requires speaking it.
	//
	// #nosec G402 -- deliberate: this is a TLS scanner, not a TLS client
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	}
	if len(suites) > 0 {
		cfg.CipherSuites = suites
	}
	if len(groups) > 0 {
		// Offering one group and nothing else is how a question gets a plain
		// answer: the server either takes it or says no, with no third
		// outcome to interpret.
		cfg.CurvePreferences = groups
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, addr, err
	}

	state := tlsConn.ConnectionState()
	return &state, addr, nil
}

func (p *Prober) dial() DialFunc {
	if p.Dial != nil {
		return p.Dial
	}
	d := &safedial.Dialer{
		Timeout:      p.handshakeTimeout(),
		TotalTimeout: p.totalTimeout(),
	}
	return d.DialContext
}

func (p *Prober) handshakeTimeout() time.Duration {
	if p.HandshakeTimeout > 0 {
		return p.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

func (p *Prober) totalTimeout() time.Duration {
	if p.TotalTimeout > 0 {
		return p.TotalTimeout
	}
	return defaultTotalTimeout
}

// gradeCipher pairs a suite ID with the policy verdict for its IANA name.
func gradeCipher(id uint16) CipherResult {
	return CipherResult{
		ID:            id,
		CipherFinding: policy.GradeCipher(tls.CipherSuiteName(id)),
	}
}

// candidateSuites returns every suite Go can be told to offer at the given
// version, insecure ones included. Reporting that a server still accepts RC4
// is the point of the exercise.
//
// TLS 1.3 returns nothing: Go ignores Config.CipherSuites for that version,
// so there is no selection to make and nothing to enumerate.
func candidateSuites(version uint16) []uint16 {
	if version >= tls.VersionTLS13 {
		return nil
	}

	var out []uint16
	for _, cs := range tls.CipherSuites() {
		if slices.Contains(cs.SupportedVersions, version) {
			out = append(out, cs.ID)
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if slices.Contains(cs.SupportedVersions, version) {
			out = append(out, cs.ID)
		}
	}
	return out
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// classifyHandshakeError turns a failure into a phrase safe to publish.
//
// Two things have to be true of what comes back. It has to distinguish a
// refusal by the server from a refusal by our own client, because Go disables
// TLS 1.0 and 1.1 by default and reporting that as "the server does not
// support it" would be a false negative. And it has to carry nothing that
// describes this machine.
//
// The second requirement is the one that was missing. Go's network errors are
// written for an operator reading a terminal and name whatever helps there:
//
//	safedial: resolve "example.test": lookup example.test on 185.12.64.2:53: no such host
//	safedial: connect "example.test:443": dial tcp 203.0.113.7:443: i/o timeout
//
// The first repeats the address of the resolver this service uses, which
// belongs to whoever runs the machine and not in a public reply. The second
// repeats an address that is already reported deliberately in Report.Address,
// but here it arrives through a path nobody reviewed.
//
// So nothing is passed through. Every branch returns a fixed phrase, and the
// default is a phrase rather than the error. A caller who needs the detail can
// run the command line tool, where the operator and the reader are the same
// person.
// The second return value says whether the server itself declined the
// version. Only one branch below can answer yes; everything else is a
// description of something that went wrong on the way, and calling any of it
// a refusal credits the server with a decision it never made.
func classifyHandshakeError(err error, version uint16) (text string, refused bool) {
	if err == nil {
		return "", false
	}
	msg := err.Error()

	switch {
	// Our own client would not offer this version, which is not the same as
	// the server refusing it. Saying so keeps a false negative out of the
	// report.
	case strings.Contains(msg, "no supported versions"),
		strings.Contains(msg, "unsupported protocol version"),
		strings.Contains(msg, "no cipher suite supported"):
		return fmt.Sprintf("not tested: this build of Go declined to offer %s", versionName(version)), false

	// The server answered and said no.
	case strings.Contains(msg, "protocol version not supported"),
		strings.Contains(msg, "handshake failure"),
		strings.Contains(msg, "no application protocol"),
		strings.Contains(msg, "insufficient security"):
		return fmt.Sprintf("server refused %s", versionName(version)), true

	// Refused by policy before anything was dialled. The reason belongs in
	// the report; the address that triggered it does not.
	case errors.Is(err, safedial.ErrBlocked):
		return "not scanned: this is not a destination the service will connect to", false

	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "server misbehaving"),
		strings.Contains(msg, "no addresses"):
		return "the name did not resolve", false

	case errors.Is(err, context.DeadlineExceeded),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "context deadline exceeded"):
		return "the connection timed out", false

	case errors.Is(err, context.Canceled):
		return "the scan was cancelled before this version was reached", false

	case strings.Contains(msg, "connection refused"):
		return "the connection was refused", false

	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "EOF"):
		return "the connection closed during the handshake", false

	case strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "host is down"),
		strings.Contains(msg, "address family not supported"):
		// "Unreachable" and "unreachable from here" are different findings,
		// and the first was being reported for both.
		//
		// A name publishing only AAAA records is unreachable from a host with
		// no IPv6 route however healthy the server is, and the reply said the
		// host could not be reached — a statement about somebody else's
		// server, reached from a fact about this scanner. The family is a
		// property of the name, published in its own DNS and checkable in a
		// second, so naming it says what happened without describing this
		// machine. It is only said when it can be the explanation: a refusal
		// or a reset proves the path works, and neither reaches this branch.
		var family *safedial.SingleFamilyError
		if errors.As(err, &family) {
			return fmt.Sprintf("the host could not be reached, and every address published for this name is %s; "+
				"a scanner with no %s route reaches none of them", family.Family, family.Family), false
		}
		return "the host could not be reached", false

	case strings.Contains(msg, "first record does not look like a TLS handshake"):
		return "the server answered with something that is not TLS", false

	case strings.Contains(msg, "certificate"):
		// Reached only if a certificate problem stops the handshake despite
		// InsecureSkipVerify, which is unusual. The chain is described by
		// certinfo when one arrives; here there is nothing to describe.
		return "the handshake failed while the certificate was being processed", false

	default:
		// Deliberately not err.Error(). An unrecognised failure is the case
		// most likely to carry an address or a path, and it is exactly the
		// case nobody has reviewed.
		return fmt.Sprintf("%s could not be established", versionName(version)), false
	}
}

// handshakeLogIDs reads the log identifier out of each timestamp the
// handshake carried.
//
// Go has already split the list into its entries, so what arrives here is a
// bare SerializedSCT: a version byte, then a 32-byte identifier. Nothing else
// is read and no signature is checked; the identifier is wanted only so that a
// log appearing both here and inside the certificate is counted once.
//
// An entry too short to hold those fields, or announcing a version this has
// not seen, is skipped rather than guessed at, and counted so the caller can
// say so. It used to be skipped and not counted, on the reasoning that the
// total beside it would make the gap visible — which asks a reader to notice
// that two numbers disagree and work out why.
func handshakeLogIDs(scts [][]byte) (ids []string, unreadable int) {
	const (
		versionV1 = 0
		idLen     = 32
		minSCT    = 1 + idLen + 8 + 2
	)

	seen := make(map[string]struct{}, len(scts))

	for _, sct := range scts {
		if len(sct) < minSCT || sct[0] != versionV1 {
			unreadable++
			continue
		}
		id := hex.EncodeToString(sct[1 : 1+idLen])
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, unreadable
}

// observe, unsettled and standing add a note of each kind.
//
// They exist so that writing a note means choosing what kind of claim it is,
// at the point where that is known. A plain append would let a sentence reach
// the report with no kind at all, and a note with no kind is filed under
// whichever heading comes first — which is the defect these replaced.
func (r *Report) observe(text string) { r.Notes = append(r.Notes, policy.Observed(text)) }

func (r *Report) unsettled(text string) { r.Notes = append(r.Notes, policy.Unsettled(text)) }

// standing takes a limit rather than a sentence, so a standing note cannot
// be written here without being in policy.StandingLimits() — and therefore on
// the page that explains them.
func (r *Report) standing(l policy.StandingLimit) { r.Notes = append(r.Notes, l.Note()) }
