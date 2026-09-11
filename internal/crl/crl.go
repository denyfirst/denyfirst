// Package crl reads a certificate revocation list and says whether a
// certificate is on it.
//
// It exists because the answer moved. Until the CA/Browser Forum made OCSP
// optional and revocation lists mandatory, a certificate that could be checked
// named a responder and a server could staple the answer — which asks nobody
// anything, because the bytes arrive in the handshake. Authorities have taken
// the option: Let's Encrypt, which issues for a large share of the web, stopped
// publishing OCSP entirely. A certificate from one of them names no responder,
// so nothing can be stapled, so a report that only reads stapled responses has
// nothing to say about revocation for most of the internet.
//
// # What this discloses, and to whom
//
// Fetching a list tells the authority that somebody downloaded a list. It does
// not say which certificate is being examined: one list covers thousands, and
// authorities serve them from content delivery networks to the whole internet.
// That is a materially smaller disclosure than the one the privacy page is
// written about — *enquiring whether a certificate is still valid* is OCSP,
// which names the serial in the question — and the difference is why this is
// worth doing where OCSP was not.
//
// It is still a request this project would not otherwise make, and the
// demonstration deployment promises on its privacy page that it makes none. So
// a demonstration build compiles the call out: demo.Enabled is a constant, so
// the branch that would reach this package is eliminated rather than switched
// off, and the promise stays true there by construction rather than by a
// default somebody could change.
//
// Everywhere else it simply runs. A revoked certificate is as serious a finding
// as this check has, and on a deployment that requires proof of control the
// certificate belongs to whoever asked — there is nothing to hide from
// themselves, and a switch they had to find first would be a gap in a report
// dressed as a choice. See docs/scope.md.
//
// # Everything here is untrusted input, in two directions
//
// The address fetched is named by the certificate the scanned server sent, so
// it is chosen by whoever is being scanned. A distribution point reading
// http://10.0.0.1/ is a request into the network this scanner runs in, which is
// why the dialler is the same one every other outbound connection uses and why
// the ports are the two a list is ever published on.
//
// The bytes that come back are chosen by whoever answered that address. They
// are parsed under a size cap and then verified against the issuing
// certificate before a single field is believed — without that, anyone able to
// answer a plaintext HTTP request could report a sound certificate as revoked,
// or a revoked one as sound.
package crl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/truststore"
)

const (
	// maxList bounds one download.
	//
	// A sharded list from a large authority runs to a few megabytes; this sits
	// above that and far below anything that would be worth serving to a
	// scanner. Exceeded, the answer is that revocation was not checked — never
	// a guess, because a truncated list is a list every serial is absent from
	// and "absent" is what "not revoked" is read from (R4).
	maxList = 8 << 20

	defaultTimeout = 10 * time.Second

	// maxPoints bounds how many distribution points are tried.
	//
	// A certificate may name several, and they are alternates rather than a
	// set to collect: the first that answers with a list this issuer signed has
	// answered the question. Two is enough for a failover and small enough that
	// a certificate naming forty addresses cannot turn one scan into forty
	// requests somebody else pays for.
	maxPoints = 2
)

// Ports a revocation list is published on. Fixed rather than configurable,
// because the address comes from the scanned server's certificate and a port
// taken from it would make this a port scanner aimed by the target.
var allowedPorts = []string{"80", "443"}

// Status is what was established about the certificate.
type Status int

const (
	// Unknown means nothing was established. It is not "good": a list that
	// could not be fetched, parsed, verified or trusted leaves the question
	// open, and Result.Reason says which (R4).
	Unknown Status = iota

	// Good means a list this issuer signed was current and did not name this
	// certificate.
	Good

	// Revoked means a list this issuer signed named this certificate.
	Revoked
)

// Result is what one check established.
type Result struct {
	Status Status

	// RevokedAt is when the authority says the certificate was revoked. Only
	// meaningful for Revoked.
	RevokedAt time.Time

	// ReasonCode is RFC 5280's revocation reason, or zero when the list did
	// not say. Zero is ambiguous by construction — the extension being absent
	// and the extension saying "unspecified" encode identically — so a caller
	// that renders it has to say "not stated" rather than "unspecified".
	ReasonCode int

	// ThisUpdate and NextUpdate are the window the list claims for itself, so
	// a report can say how old the answer is rather than presenting it as
	// current.
	ThisUpdate time.Time
	NextUpdate time.Time

	// Reason says why nothing was established, for Unknown.
	//
	// A fixed phrase from this package and never an error from the network or
	// the parser: those name resolvers, addresses and internal types, and this
	// string reaches a report a stranger reads (I6).
	Reason string
}

// Fetcher downloads and checks revocation lists. The zero value is usable and
// reaches the network through safedial.
type Fetcher struct {
	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations — which is the guard that
	// matters here, because the address being dialled was named by the
	// certificate the scanned server sent.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store for a distribution point served over HTTPS.
	// Nil means the system store; see internal/truststore for why that is not
	// the same as leaving it nil further down.
	Roots *x509.CertPool

	// Timeout bounds one download. Zero means ten seconds.
	Timeout time.Duration
}

// Check asks whether the leaf is on a list its issuer publishes.
//
// The issuer is required and is not optional politeness: a list is believed
// only after its signature verifies against the certificate that issued the
// leaf, so without the issuer there is nothing to verify against and the answer
// is Unknown.
func (f *Fetcher) Check(ctx context.Context, leaf, issuer *x509.Certificate, now time.Time) Result {
	switch {
	case leaf == nil || issuer == nil:
		return Result{Reason: "the issuing certificate was not sent, so a list could not be verified"}
	case len(leaf.CRLDistributionPoints) == 0:
		return Result{Reason: "the certificate names no revocation list"}
	}

	var last Result
	tried := 0

	for _, point := range leaf.CRLDistributionPoints {
		if tried >= maxPoints {
			break
		}

		address, ok := usable(point)
		if !ok {
			// Not counted against the budget: refusing to dial something cost
			// nothing, and a certificate whose first entry is an ldap:// URL
			// should not thereby lose its http one.
			last = Result{Reason: "the certificate names a revocation list at an address this does not fetch"}
			continue
		}
		tried++

		out := f.checkOne(ctx, address, leaf, issuer, now)
		if out.Status != Unknown {
			return out
		}
		last = out
	}

	if last.Reason == "" {
		last.Reason = "no revocation list could be read"
	}
	return last
}

// checkOne reads one distribution point.
func (f *Fetcher) checkOne(ctx context.Context, address string, leaf, issuer *x509.Certificate, now time.Time) Result {
	der, reason := f.download(ctx, address)
	if reason != "" {
		return Result{Reason: reason}
	}

	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return Result{Reason: "the revocation list could not be parsed"}
	}

	// Before anything in it is read. Whoever answered that address chose these
	// bytes, and a list nobody signed is a claim from a stranger about somebody
	// else's certificate — in either direction.
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return Result{Reason: "the revocation list was not signed by the issuing authority"}
	}

	out := Result{ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate}

	// A list outside its own window is not an answer. An authority states when
	// it will publish the next one; past that, absence from this one says
	// nothing about now.
	switch {
	case !list.ThisUpdate.IsZero() && now.Before(list.ThisUpdate):
		out.Reason = "the revocation list is not yet in effect"
		return out
	case !list.NextUpdate.IsZero() && now.After(list.NextUpdate):
		out.Reason = "the revocation list is older than the authority said it would be"
		return out
	}

	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil {
			continue
		}
		if serialsMatch(entry.SerialNumber, leaf.SerialNumber) {
			out.Status = Revoked
			out.RevokedAt = entry.RevocationTime
			out.ReasonCode = entry.ReasonCode
			return out
		}
	}

	out.Status = Good
	return out
}

// download fetches one address, or says why it did not.
func (f *Fetcher) download(ctx context.Context, address string) ([]byte, string) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, "the revocation list address could not be requested"
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := f.client().Do(req)
	if err != nil {
		// The underlying error names resolvers and addresses, so only the
		// shape of the failure is reported (I6).
		return nil, "the revocation list could not be fetched"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "the revocation list was not served"
	}

	// One byte past the cap, so a list exactly at the limit is readable and one
	// over it is recognisable as over rather than silently truncated.
	der, err := io.ReadAll(io.LimitReader(resp.Body, maxList+1))
	if err != nil {
		return nil, "the revocation list could not be read"
	}
	if len(der) > maxList {
		// Never truncated and then parsed. Every serial is absent from a
		// truncated list, and absence is exactly what "not revoked" is read
		// from, so a cut list answers "good" about a revoked certificate.
		return nil, "the revocation list is larger than this fetches"
	}
	return der, ""
}

// UserAgent is what this client says it is.
//
// The same identification the rest of the project sends, for the same reason:
// an authority reading its own access log can find out precisely what asked and
// why. A fetch that hides is a fetch nobody can make a decision about.
const UserAgent = "denyfirst/1 (+https://denyfirst.dev/tls/method)"

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout <= 0 {
		return defaultTimeout
	}
	return f.Timeout
}

func (f *Fetcher) client() *http.Client {
	dial := f.Dial
	if dial == nil {
		d := &safedial.Dialer{Timeout: f.timeout(), AllowedPorts: allowedPorts}
		dial = d.DialContext
	}

	// The store that decides "trusted" for a distribution point served over
	// HTTPS, loaded rather than left for the platform to choose (R7).
	//
	// A failure is not handled here. It leaves an empty pool, so an HTTPS
	// distribution point fails closed and the answer is that revocation was not
	// checked — which is what a machine with no readable store should say about
	// every question that needs one.
	roots, _ := truststore.Resolve(f.Roots)

	return &http.Client{
		// A redirect from a distribution point is an address chosen by
		// whoever answered an address chosen by the scanned server, which is
		// one hand-off further than anything else here follows. The hop is
		// recorded as a failure to fetch, which is the honest outcome: nothing
		// was established.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: dial,
			Proxy:       nil,
			// As in webprobe: RootCAs and nothing that would weaken a handshake.
			// No InsecureSkipVerify, no ServerName pinned across hosts, no shared
			// session cache, and no version named here.
			TLSClientConfig: &tls.Config{RootCAs: roots},

			MaxIdleConns:        2,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: f.timeout(),
		},
	}
}

// usable turns a distribution point into an address this will fetch, or reports
// that it will not.
//
// http and https only. A certificate may name ldap://, ftp:// or a scheme
// nobody has implemented since 2003, and following one would mean this program
// speaking a protocol chosen by the party it is measuring.
func usable(point string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(point))
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Hostname() == "" {
		return "", false
	}

	// Credentials would be sent by this program into the access log of
	// whatever answered, which is the same reason webprobe strips them from a
	// Location header.
	u.User = nil
	u.Fragment = ""
	return u.String(), true
}

// serialsMatch compares two serial numbers.
//
// By value rather than by encoding. A serial is an integer, and the same
// integer can be written with or without a leading zero byte depending on
// whether its top bit is set — so comparing bytes reports a revoked
// certificate as sound for every serial above 0x7f, which is most of them.
func serialsMatch(a, b *big.Int) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Cmp(b) == 0
}

// String renders a status for a log or a test failure. Not for a report: a
// report's wording is internal/policy's.
func (s Status) String() string {
	switch s {
	case Good:
		return "good"
	case Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}
