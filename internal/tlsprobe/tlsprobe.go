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

	Duration time.Duration `json:"durationMs"`

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
		break
	}

	report.Verdict, report.Findings = summarise(results)

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

	if slices.ContainsFunc(results, func(v VersionResult) bool {
		return v.Supported && v.Version == tls.VersionTLS13
	}) {
		report.Notes = append(report.Notes,
			"For TLS 1.3 only the negotiated suite is listed. Go gives a client no way to choose among TLS 1.3 suites, so the rest could not be enumerated.")
	}

	report.Duration = time.Since(start)
	return report, nil
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

// classifyHandshakeError separates a refusal by the server from a refusal by
// our own client. Go disables TLS 1.0 and 1.1 by default and may drop them
// entirely in a later release; reporting that as "the server does not support
// it" would be a false negative.
func classifyHandshakeError(err error, version uint16) string {
	msg := err.Error()

	switch {
	case strings.Contains(msg, "no supported versions"),
		strings.Contains(msg, "unsupported protocol version"),
		strings.Contains(msg, "no cipher suite supported"):
		return fmt.Sprintf("not tested: this build of Go declined to offer %s (%v)", versionName(version), err)
	case strings.Contains(msg, "protocol version not supported"),
		strings.Contains(msg, "handshake failure"):
		return fmt.Sprintf("server refused %s", versionName(version))
	default:
		return err.Error()
	}
}
