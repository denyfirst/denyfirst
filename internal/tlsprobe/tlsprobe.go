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

	// ServerPreference reports whether the server imposes its own cipher
	// ordering. False means it follows the client's order, which lets an
	// outdated client steer the connection towards a weaker suite.
	ServerPreference bool `json:"serverPreference"`

	// PreferenceKnown is false when the question could not be settled,
	// typically because fewer than two suites were available to compare.
	PreferenceKnown bool `json:"preferenceKnown"`

	ALPN        string `json:"alpn,omitempty"`
	OCSPStapled bool   `json:"ocspStapled"`
	SCTCount    int    `json:"sctCount"`

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
	Notes []string `json:"notes,omitempty"`
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

			state, addr, err := p.handshake(ctx, host, port, version, nil)
			result := VersionResult{Version: version, Name: versionName(version)}

			if err != nil {
				result.Error = classifyHandshakeError(err, version)
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
				// was negotiated instead of enumerating.
				result.Ciphers = []CipherResult{gradeCipher(state.CipherSuite)}
			} else {
				result.Ciphers = p.enumerateCiphers(ctx, host, port, version)
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
		report.Address = addrs[i]
		report.ALPN = state.NegotiatedProtocol
		report.OCSPStapled = len(state.OCSPResponse) > 0
		report.SCTCount = len(state.SignedCertificateTimestamps)
		report.SCTLogIDs = handshakeLogIDs(state.SignedCertificateTimestamps)
		break
	}

	report.Verdict, report.Findings = summarise(results)
	report.BlockedDestination = blockedDestination(results)

	if len(report.Certificates) == 0 {
		report.Notes = append(report.Notes,
			"No handshake completed, so no certificate chain was retrieved.")
	}

	// Preference detection needs a version where we control the ordering.
	if idx := slices.IndexFunc(results, func(v VersionResult) bool {
		return v.Supported && v.Version != tls.VersionTLS13 && len(v.Ciphers) >= 2
	}); idx >= 0 {
		known, prefers := p.detectServerPreference(ctx, host, port, results[idx])
		report.PreferenceKnown = known
		report.ServerPreference = prefers
	} else {
		report.Notes = append(report.Notes,
			"Cipher preference could not be determined: it requires a pre-1.3 version offering at least two suites.")
	}

	// The two notes below describe different gaps and both belong in a
	// report. The first bounds what was offered at all; the second explains
	// why one version shows a single suite. Dropping either leaves the reader
	// to assume the list is exhaustive.
	if slices.ContainsFunc(results, func(v VersionResult) bool { return v.Supported }) {
		report.Notes = append(report.Notes,
			"Only cipher suites implemented by Go's TLS stack were offered. Suites outside it, and SSLv2 or SSLv3, are not covered.")
	}

	if slices.ContainsFunc(results, func(v VersionResult) bool {
		return v.Supported && v.Version == tls.VersionTLS13
	}) {
		report.Notes = append(report.Notes,
			"For TLS 1.3 only the negotiated suite is listed. Go gives a client no way to choose among TLS 1.3 suites, so the rest could not be enumerated.")
	}

	report.Duration = time.Since(start)
	report.DurationMs = report.Duration.Milliseconds()
	return report, nil
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

	return policy.Worst(verdicts...), findings
}

// enumerateCiphers offers every candidate, records what the server picks,
// removes it, and repeats. The number of handshakes is the number of suites
// the server supports, not the number offered.
func (p *Prober) enumerateCiphers(ctx context.Context, host, port string, version uint16) []CipherResult {
	remaining := candidateSuites(version)
	found := make([]CipherResult, 0, len(remaining))

	for round := 0; len(remaining) > 0 && round < maxEnumerationRounds; round++ {
		if ctx.Err() != nil {
			break
		}

		state, _, err := p.handshake(ctx, host, port, version, remaining)
		if err != nil {
			// Nothing left that both sides accept.
			break
		}

		// A server that answers with a suite we did not offer is out of
		// spec. Removing nothing would loop forever, so stop.
		idx := slices.Index(remaining, state.CipherSuite)
		if idx < 0 {
			break
		}

		found = append(found, gradeCipher(state.CipherSuite))
		remaining = slices.Delete(remaining, idx, idx+1)
	}

	return found
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

	first, _, err := p.handshake(ctx, host, port, v.Version, forward)
	if err != nil {
		return false, false
	}
	second, _, err := p.handshake(ctx, host, port, v.Version, reversed)
	if err != nil {
		return false, false
	}

	return true, first.CipherSuite == second.CipherSuite
}

// handshake performs one handshake at a fixed version with an optional suite
// list, returning the connection state and the address reached.
func (p *Prober) handshake(ctx context.Context, host, port string, version uint16, suites []uint16) (*tls.ConnectionState, string, error) {
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
func classifyHandshakeError(err error, version uint16) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	switch {
	// Our own client would not offer this version, which is not the same as
	// the server refusing it. Saying so keeps a false negative out of the
	// report.
	case strings.Contains(msg, "no supported versions"),
		strings.Contains(msg, "unsupported protocol version"),
		strings.Contains(msg, "no cipher suite supported"):
		return fmt.Sprintf("not tested: this build of Go declined to offer %s", versionName(version))

	// The server answered and said no.
	case strings.Contains(msg, "protocol version not supported"),
		strings.Contains(msg, "handshake failure"),
		strings.Contains(msg, "no application protocol"),
		strings.Contains(msg, "insufficient security"):
		return fmt.Sprintf("server refused %s", versionName(version))

	// Refused by policy before anything was dialled. The reason belongs in
	// the report; the address that triggered it does not.
	case errors.Is(err, safedial.ErrBlocked):
		return "not scanned: this is not a destination the service will connect to"

	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "server misbehaving"),
		strings.Contains(msg, "no addresses"):
		return "the name did not resolve"

	case errors.Is(err, context.DeadlineExceeded),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "context deadline exceeded"):
		return "the connection timed out"

	case errors.Is(err, context.Canceled):
		return "the scan was cancelled before this version was reached"

	case strings.Contains(msg, "connection refused"):
		return "the connection was refused"

	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "EOF"):
		return "the connection closed during the handshake"

	case strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "host is down"):
		return "the host could not be reached"

	case strings.Contains(msg, "first record does not look like a TLS handshake"):
		return "the server answered with something that is not TLS"

	case strings.Contains(msg, "certificate"):
		// Reached only if a certificate problem stops the handshake despite
		// InsecureSkipVerify, which is unusual. The chain is described by
		// certinfo when one arrives; here there is nothing to describe.
		return "the handshake failed while the certificate was being processed"

	default:
		// Deliberately not err.Error(). An unrecognised failure is the case
		// most likely to carry an address or a path, and it is exactly the
		// case nobody has reviewed.
		return fmt.Sprintf("%s could not be established", versionName(version))
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
// not seen, is skipped rather than guessed at. The count beside this reports
// how many arrived, so a skipped entry shows up as a difference between the
// two rather than disappearing.
func handshakeLogIDs(scts [][]byte) []string {
	const (
		versionV1 = 0
		idLen     = 32
		minSCT    = 1 + idLen + 8 + 2
	)

	var out []string
	seen := make(map[string]struct{}, len(scts))

	for _, sct := range scts {
		if len(sct) < minSCT || sct[0] != versionV1 {
			continue
		}
		id := hex.EncodeToString(sct[1 : 1+idLen])
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
