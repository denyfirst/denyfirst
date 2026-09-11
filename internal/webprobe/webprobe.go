// Package webprobe reads the response headers a web server sends to an
// ordinary client, over HTTPS and over plaintext HTTP, and records the
// redirects it is told to follow.
//
// It exists because several security properties of a website are visible only
// in an HTTP response and not in a TLS handshake. A host can negotiate TLS 1.3
// with a perfect certificate and still be trivially stripped: no
// Strict-Transport-Security, and port 80 serving content instead of sending
// the visitor to the secure address. The TLS check grades that host strong,
// correctly, and says nothing about the way it is actually reached.
//
// An HTTP request is not a TLS handshake, and the difference is the reason
// this is a separate package with its own rules rather than a few more fields
// on the TLS probe:
//
//   - A handshake stops at the transport. A request enters the application:
//     it appears in an access log with a path, it reaches whatever sits in
//     front of the origin, and on a badly built application a GET can change
//     state.
//
//   - Half the ports this project scans have no HTTP at all — 465, 636, 990,
//     993, 995 and 5061 among them. A header check folded into the TLS scan
//     would report a missing security header for a mail server, which is not
//     a finding but a category error.
//
// So the discipline is written into the code rather than left to the caller:
//
//   - One GET of "/", over HTTPS and over plaintext. Nothing else.
//
//   - No path is ever constructed here. After the first request the only
//     addresses fetched are the ones a Location header names. There is no
//     probing of /admin, no guessing under /.well-known, and no second guess
//     of any kind: this reads what the server volunteers to everybody.
//
//   - The body is never read. Headers are taken and the body is closed
//     unread, so a large or slow response costs a header's worth of traffic
//     and nothing more.
//
//   - Only headers this check grades are kept. A header outside the list in
//     recorded() is not merely ignored; it is never held, so it cannot reach
//     a report, a log or a JSON payload somebody pastes into a chat window.
//
//   - Cookie values are not recorded, and there is nowhere to put one. Cookie
//     carries the name and the attributes that decide whether a cookie is
//     safe; it has no value field at all, because a field that exists is a
//     field somebody fills in later.
//
//   - The client identifies itself truthfully, and the user agent names a
//     page explaining exactly what is sent. A scan that is recognisable is
//     one an administrator can decide about; an anonymous one is one they can
//     only be alarmed by.
package webprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/truststore"
)

// DialFunc matches net.Dialer.DialContext and safedial.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

const (
	defaultRequestTimeout = 10 * time.Second
	defaultTotalTimeout   = 40 * time.Second

	// defaultMaxRedirects bounds one chain.
	//
	// Browsers allow twenty. Five is enough to see the shape of any
	// arrangement worth reporting — plaintext to secure, apex to www, or the
	// loop between the two that some sites ship by accident — and it bounds
	// the number of servers one probe touches. A chain longer than this is
	// itself the finding, so stopping does not lose anything.
	defaultMaxRedirects = 5

	// maxLocationLength caps a Location before it is followed.
	//
	// A redirect target is attacker-controlled input from the point of view
	// of whoever runs this, and there is no legitimate address near this
	// length. Refusing to follow is safe: the hop that produced it is already
	// recorded, which is what a reader needs.
	maxLocationLength = 2048
)

// Ports are the two a website is reached on. They are fixed rather than
// configurable: this check is about how a site answers the addresses a person
// types, and a person types neither a port nor a scheme.
const (
	securePort = "443"
	plainPort  = "80"
)

// Prober fetches headers. The zero value is usable.
type Prober struct {
	// Dial opens the TCP connection. Nil selects safedial, which refuses
	// private, loopback, link-local and reserved destinations — including
	// ones reached by following a redirect, which is the case that matters
	// here: the first address is one the operator chose, and every address
	// after it was chosen by the server.
	Dial DialFunc

	// RequestTimeout bounds one hop. Zero means ten seconds.
	RequestTimeout time.Duration

	// TotalTimeout bounds both chains together. Zero means forty seconds. A
	// tighter deadline on the caller's context takes precedence.
	TotalTimeout time.Duration

	// MaxRedirects bounds one chain. Zero means five. Negative means none are
	// followed, which is what a test of the first response wants.
	MaxRedirects int

	// Roots is the trust store every certificate on a chain is judged against.
	//
	// Nil means the system store, loaded explicitly. It does not mean "let
	// crypto/tls decide": a nil RootCAs reaches x509.Verify as a nil Roots,
	// which on Windows and macOS hands the whole question to the platform
	// verifier — a different store from the one a service checked when it
	// started (R7).
	//
	// This check had no TLSClientConfig at all until 2026-09-11, so that was
	// the behaviour, and here it is worse than a wrong grade. A certificate the
	// deciding store cannot verify is a handshake that fails, and a failed
	// handshake is reported as a site that is not reachable over HTTPS. A fact
	// about the machine running the scan, printed as a finding about somebody
	// else's server.
	Roots *x509.CertPool

	// UserAgent identifies this client. Empty selects DefaultUserAgent.
	//
	// Whatever is set here is sent verbatim, so a caller embedding this
	// package is free to say who they are. What is not offered is a way to
	// send nothing: the transport sends this field or the default, never an
	// empty string, because a probe that hides is a probe an administrator
	// cannot make a decision about.
	UserAgent string
}

// DefaultUserAgent is what this client says it is when nothing else is set.
//
// The address is part of the identification rather than decoration. An
// administrator reading it in an access log at three in the morning can open
// one page and find out precisely what was sent and why, which is the
// difference between a request they can dismiss and one they must
// investigate.
const DefaultUserAgent = "denyfirst/1 (+https://denyfirst.dev/web/method)"

// ErrNotAHostname is returned for a target that is not a bare hostname.
var ErrNotAHostname = errors.New("webprobe: target must be a bare hostname")

// resolveRoots is truststore.Resolve, as a variable so that a test can make it
// fail.
//
// The branch it guards matters most on a machine whose certificate store cannot
// be read, which is the machine no test runs on — and a test that skips itself
// everywhere is the same silence A7 is about, arriving in a test file. The rule
// itself is truststore's, because the TLS check asks the same question of the
// same kind of nil (R7).
var resolveRoots = truststore.Resolve

// Reach answers whether this probe may connect to a host a redirect named.
//
// The first address in a chain is one the caller chose and has already
// authorised. Every address after it was chosen by the server that answered,
// and a probe that follows one without asking has been aimed by somebody
// other than the operator. safedial stops such a hop reaching a private
// address; nothing stopped it reaching a public host the deployment was never
// allowed to touch — an excluded name, a host outside what a demonstration
// build owns, or a domain nobody proved control of. So the caller's boundary
// is asked again, at the hop, which is where the connection is (N6, N10).
//
// It returns the reason to record when the answer is no, and an empty string
// when it is yes. A reason rather than an error, because this string is
// written into a report a stranger reads: an error from the caller's own
// boundary could carry a resolver's address or a name this program undertakes
// not to repeat, and a signature with nowhere to put one is stronger than a
// rule saying not to (I6).
//
// A nil Reach follows any host the rest of these limits allow, which is what
// the command line is: the scan leaves from the operator's own machine, and a
// browser would have followed the same redirect.
type Reach func(ctx context.Context, host string) string

// walk is what one Probe call carries across both of its chains: where it may
// go, and what it has already asked about.
//
// The answers are remembered because asking can cost a DNS lookup, and a
// redirect to the same host on the other scheme is the ordinary case rather
// than the exception. One question per distinct name per probe.
type walk struct {
	reach   Reach
	decided map[string]string
}

// may reports the reason a host is not to be reached, or an empty string.
func (w *walk) may(ctx context.Context, host string) string {
	if w.reach == nil {
		return ""
	}

	// Folded here rather than trusted to have been folded, for the reason N8
	// gives about its own comparison: EXAMPLE.COM, example.com and
	// example.com. are one server, and a memo keyed on the spelling a server
	// happened to send would ask again — or, worse, remember an answer under
	// a key nothing else matches.
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	if why, asked := w.decided[host]; asked {
		return why
	}

	why := w.reach(ctx, host)
	w.decided[host] = why
	return why
}

// Cookie is one Set-Cookie header, without its value.
//
// There is no Value field, and its absence is the point. The attributes below
// are everything a rule needs in order to say whether a cookie is safe; the
// value is a session identifier as often as not, and a report is a thing
// people paste into issue trackers and chat windows. A struct with nowhere to
// put a secret cannot leak one by a later change that looked harmless.
type Cookie struct {
	Name string `json:"name"`

	Secure   bool `json:"secure"`
	HTTPOnly bool `json:"httpOnly"`

	// SameSite is the attribute as sent, lowercased: "strict", "lax", "none",
	// or empty when the attribute was absent. Absent and "lax" are different
	// facts even where browsers now default to the second, because a default
	// is a property of the browser and this is a report about the server.
	SameSite string `json:"sameSite,omitempty"`

	// HostPrefix and SecurePrefix record the cookie name prefixes that browsers
	// enforce structurally, which is a stronger guarantee than the attributes
	// they imply.
	HostPrefix   bool `json:"hostPrefix,omitempty"`
	SecurePrefix bool `json:"securePrefix,omitempty"`

	// Path and Domain are the two attributes a __Host- prefix constrains, and
	// they are here so that the prefix can be checked in full rather than in
	// part.
	//
	// RFC 6265bis requires a __Host- cookie to carry Secure, to set Path=/,
	// and to carry no Domain at all. A browser that finds any of those wrong
	// rejects the cookie outright — so a site setting __Host-session without
	// Path=/ has a session cookie that silently does not exist, and every
	// symptom of that is somewhere other than the header. Reading two of the
	// three conditions would have reported a guarantee the browser is not
	// making.
	//
	// Neither is a secret. A path and a domain are scoping instructions the
	// server sends to every visitor, and Cookie still has nowhere to put a
	// value.
	Path string `json:"path,omitempty"`

	// DomainSet records that the attribute was present, which is the question
	// the prefix asks. The value is kept too because a Domain widens a cookie
	// beyond the host that set it, and a reader checking scope needs to see
	// how far.
	Domain    string `json:"domain,omitempty"`
	DomainSet bool   `json:"domainSet,omitempty"`
}

// Hop is one request and the response to it.
type Hop struct {
	// URL is the address requested. The first in a chain is built here; every
	// one after it came from a Location header.
	URL string `json:"url"`

	// TLS records whether this hop was made over TLS. Kept per hop because a
	// chain that starts secure and ends plaintext is exactly the arrangement
	// worth reporting.
	TLS bool `json:"tls"`

	Status int `json:"status,omitempty"`

	// Headers holds only the headers this check grades. See recorded().
	Headers map[string][]string `json:"headers,omitempty"`

	// Cookies are the Set-Cookie headers of this response, without values.
	Cookies []Cookie `json:"cookies,omitempty"`

	// Err is why this hop produced no response. Non-empty means Status and
	// Headers are unset, which is different from a response with no headers.
	//
	// Every value is a phrase written in classifyProbeError. Nothing from the
	// standard library reaches it, because Go words network failures for an
	// operator reading a terminal and names the resolver's address while
	// doing so (I6).
	Err string `json:"error,omitempty"`

	// blocked records that this hop was refused by safedial rather than by
	// anything on the network.
	//
	// Unexported, so it cannot be serialised: a caller is told the
	// destination was refused through Report.BlockedDestination, which is the
	// question they can act on. Kept per hop only because that is where the
	// fact is known.
	blocked bool
}

// Chain is one starting address and the hops that followed from it.
type Chain struct {
	Hops []Hop `json:"hops"`

	// Truncated is set when the redirect limit was reached with another
	// Location still waiting. The chain is then incomplete, and a reader must
	// not conclude anything from where it stops.
	Truncated bool `json:"truncated,omitempty"`

	// Stopped explains why the chain ended before an answer, where that was a
	// decision rather than a failure — a Location this probe will not follow,
	// for instance.
	Stopped string `json:"stopped,omitempty"`
}

// Final returns the last hop, or nil for an empty chain.
func (c *Chain) Final() *Hop {
	if c == nil || len(c.Hops) == 0 {
		return nil
	}
	return &c.Hops[len(c.Hops)-1]
}

// Report is what one probe observed about one host.
type Report struct {
	Host string `json:"host"`

	// Secure is the chain that began at https://host/.
	Secure *Chain `json:"secure,omitempty"`

	// Plain is the chain that began at http://host/. A host that answers
	// nothing on port 80 produces a chain holding one hop with an error,
	// which is a different fact from a host that answers with content.
	Plain *Chain `json:"plain,omitempty"`

	// UserAgent is what was sent, recorded so that a report says how it was
	// obtained rather than requiring the reader to trust a document.
	UserAgent string `json:"userAgent"`

	// BlockedDestination reports that every hop was refused by safedial
	// before anything was dialled: the name resolves only to private,
	// loopback, link-local or reserved addresses.
	//
	// The same field the TLS report carries, for the same reason. A caller
	// has to be able to count this — "attempts at private addresses rose
	// from two a day to eight thousand" is the sentence that says somebody
	// is using this as a way into the network it runs in — and a count built
	// by matching prose breaks silently the first time the prose is
	// improved (A7).
	//
	// Not serialised: it is a fact about why this service declined, not a
	// measurement of the host, and the caller turns it into a refusal with
	// its own status code rather than passing it through.
	BlockedDestination bool `json:"-"`

	// TrustStoreUnreadable reports that this machine's certificate store could
	// not be read, so nothing on either chain was verified against anything.
	//
	// Serialised, unlike the field above, because a reader has to see it. Every
	// HTTPS hop fails when it is set — truststore answers a failure with an
	// empty pool, which is the safe answer and not a usable one — and a chain of
	// failed handshakes reads as a site that is not served over HTTPS. That
	// would be a fact about the machine running the scan printed as a finding
	// about somebody else's server, which is the failure R4 is about.
	//
	// A field rather than prose, for the reason A7 gives about
	// BlockedDestination: the sentence lives in internal/policy and is written
	// from this, so a count or a renderer built on it does not break the first
	// time the sentence is improved.
	TrustStoreUnreadable bool `json:"trustStoreUnreadable,omitempty"`
}

// Probe fetches the headers of one host over both schemes.
//
// The two chains are independent: a host with a certificate that does not
// verify produces a failed secure chain and a plaintext chain that is still
// worth reading, and the reverse holds for a host with nothing on port 80.
// Neither failure is returned as an error, because neither is a failure of
// this program. An error here means the target was refused or nothing could
// be attempted at all.
// reach is asked for every host a redirect names other than this one, and a
// nil reach follows them all. It is a parameter rather than a field on Prober
// deliberately. Dial is a field because leaving it unset selects the safe
// answer; this one has no safe default — the command line must follow a
// redirect anywhere and a service must not — so it is the caller's decision
// every time, spelled at every call site, where a review can see a nil.
// A guard a constructor has to remember to set is a guard somebody forgets,
// and this project has already been caught by exactly that (N9).
func (p *Prober) Probe(ctx context.Context, host string, reach Reach) (*Report, error) {
	if err := CheckHostname(host); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, p.totalTimeout())
	defer cancel()

	report := &Report{Host: host, UserAgent: p.userAgent()}

	// Resolved here rather than inside the client, so that a store which could
	// not be read reaches the report instead of being spent as a chain of
	// failed handshakes nobody can explain.
	roots, rootsErr := resolveRoots(p.Roots)
	report.TrustStoreUnreadable = rootsErr != nil

	client := p.clientWith(roots)

	// The host asked about is authorised already — the caller said so by
	// asking — so it is seeded rather than looked up again. A redirect from
	// https to http on the same name, which is the commonest redirect there
	// is, then costs nothing.
	w := &walk{
		reach:   reach,
		decided: map[string]string{strings.ToLower(strings.TrimSuffix(host, ".")): ""},
	}

	// Secure first. If the deadline runs out it should run out on the chain
	// that matters most, rather than on the one that exists to catch a
	// stripping arrangement.
	report.Secure = p.chain(ctx, client, "https://"+net.JoinHostPort(host, securePort)+"/", w)
	report.Plain = p.chain(ctx, client, "http://"+net.JoinHostPort(host, plainPort)+"/", w)

	// Asked of both chains together. One port refused and the other reached
	// is a name that was measured; only a name where every attempt was
	// declined is a destination this service will not go to.
	report.BlockedDestination = blockedDestination(report.Secure, report.Plain)

	return report, nil
}

// chain follows one starting address as far as the limits allow.
func (p *Prober) chain(ctx context.Context, client *http.Client, start string, w *walk) *Chain {
	out := &Chain{}
	next := start

	for i := 0; ; i++ {
		if i > p.maxRedirects() {
			out.Truncated = true
			return out
		}

		hop := p.fetch(ctx, client, next)
		out.Hops = append(out.Hops, hop)
		if hop.Err != "" {
			return out
		}

		loc, why := nextURL(hop, next)
		if why != "" {
			out.Stopped = why
			return out
		}
		if loc == "" {
			return out
		}

		// Asked before the address is dialled rather than after it is
		// recorded, so that a hop the deployment may not make leaves nothing
		// in anybody's access log. The hop that produced the Location is
		// already in the chain, and the Location header itself is one of the
		// headers this probe keeps, so a reader can see where it pointed
		// without this sentence naming it (I3).
		if why := w.may(ctx, hostOf(loc)); why != "" {
			out.Stopped = why
			return out
		}

		next = loc
	}
}

// hostOf is the name in an address nextURL has already parsed and accepted.
//
// An address that will not parse here cannot have come from nextURL, which
// returns nothing it could not parse. It is answered as the empty name rather
// than as an address to be dialled, so that an unreadable target reaches the
// boundary as something to refuse instead of skipping it.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// fetch performs one request and records what came back.
func (p *Prober) fetch(ctx context.Context, client *http.Client, target string) Hop {
	hop := Hop{URL: target, TLS: strings.HasPrefix(target, "https://")}

	ctx, cancel := context.WithTimeout(ctx, p.requestTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		hop.Err, hop.blocked = classifyProbeError(err)
		return hop
	}
	req.Header.Set("User-Agent", p.userAgent())

	resp, err := client.Do(req)
	if err != nil {
		hop.Err, hop.blocked = classifyProbeError(err)
		return hop
	}

	// Closed without being read. A response body is the largest thing a
	// server can make this program carry, it is the part that costs the
	// server bandwidth, and nothing here grades it. Closing an unread body
	// tells the transport to drop the connection rather than drain it.
	defer resp.Body.Close()

	hop.Status = resp.StatusCode
	hop.Headers = recorded(resp.Header)
	hop.Cookies = cookies(resp.Header.Values("Set-Cookie"))
	return hop
}

// nextURL decides where a chain goes after one hop.
//
// It returns the next address, or an empty string when the chain has ended,
// or a reason when this probe declines to follow. Declining is recorded
// rather than silent: a reader who cannot tell "it stopped here" from "it was
// not followed" cannot interpret the chain at all.
func nextURL(hop Hop, from string) (next, stopped string) {
	if hop.Status < 300 || hop.Status > 399 {
		return "", ""
	}

	raw := ""
	if v := hop.Headers["Location"]; len(v) > 0 {
		raw = v[0]
	}
	if raw == "" {
		return "", ""
	}
	if len(raw) > maxLocationLength {
		return "", "the Location header was too long to follow"
	}

	base, err := url.Parse(from)
	if err != nil {
		return "", "this address could not be parsed"
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", "the Location header was not a valid address"
	}

	// Resolved against the address that produced it, which is what a browser
	// does with a relative Location. Constructing it any other way would mean
	// this probe choosing a path, which is the one thing it does not do.
	u := base.ResolveReference(ref)

	switch u.Scheme {
	case "http", "https":
	default:
		return "", fmt.Sprintf("the Location header named a %q address, which is not followed", u.Scheme)
	}

	// Credentials in a redirect target are stripped rather than sent. They
	// would go into a request this program makes, and from there into
	// whatever records that request.
	u.User = nil

	// A fragment is never sent on the wire. Dropping it here keeps the
	// recorded address the same as the one requested.
	u.Fragment = ""

	if u.Hostname() == "" {
		return "", "the Location header named no host"
	}

	return u.String(), ""
}

// recorded keeps the headers this check grades and drops everything else.
//
// An allow list rather than a deny list, and the difference is not stylistic.
// A response carries whatever the server chose to send, including headers
// that name internal hosts, software versions, request identifiers and
// occasionally a value somebody will regret publishing. A report built from a
// deny list holds all of it until somebody thinks of the next entry.
//
// Adding a rule that reads a new header means adding the header here, which
// is a line in a diff a reviewer can see.
func recorded(h http.Header) map[string][]string {
	keep := []string{
		"Location",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
	}

	var out map[string][]string
	for _, name := range keep {
		v := h.Values(name)
		if len(v) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string][]string, len(keep))
		}
		// Copied. Values returns the slice the header map holds, and a caller
		// mutating a report would otherwise reach into the response.
		out[name] = append([]string(nil), v...)
	}
	return out
}

// cookies reads the attributes of each Set-Cookie header and discards the
// value with the name it belongs to.
//
// The value is dropped where it is parsed rather than where it is rendered.
// Dropping it later would mean it existed in memory, in a struct, in
// whatever a caller serialised in between — and the one property worth having
// here is that it was never carried at all.
func cookies(headers []string) []Cookie {
	var out []Cookie
	for _, raw := range headers {
		parts := strings.Split(raw, ";")
		if len(parts) == 0 {
			continue
		}

		name, _, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}

		c := Cookie{
			Name: name,
			// The prefixes are case-sensitive in the specification, and a
			// browser enforces them exactly. Matching case-insensitively here
			// would report a guarantee the browser is not making.
			HostPrefix:   strings.HasPrefix(name, "__Host-"),
			SecurePrefix: strings.HasPrefix(name, "__Secure-"),
		}

		for _, attr := range parts[1:] {
			key, value, _ := strings.Cut(strings.TrimSpace(attr), "=")
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "secure":
				c.Secure = true
			case "httponly":
				c.HTTPOnly = true
			case "samesite":
				c.SameSite = strings.ToLower(strings.TrimSpace(value))
			case "path":
				c.Path = strings.TrimSpace(value)
			case "domain":
				// Presence is recorded separately from the value, because
				// "Domain=" with nothing after it is still the attribute
				// being present and a __Host- cookie carrying it is still
				// rejected by a browser.
				c.DomainSet = true
				c.Domain = strings.TrimSpace(value)
			}
		}
		out = append(out, c)
	}
	return out
}

// client builds the HTTP client.
//
// Redirects are not followed by the client. Every hop is made by chain()
// above, so that each one is recorded, each one is counted against the limit,
// and the decision to follow is taken here rather than by the standard
// library's own rules.
func (p *Prober) client() *http.Client {
	roots, _ := resolveRoots(p.Roots)
	return p.clientWith(roots)
}

// clientWith builds the client around a store that has already been resolved.
//
// Split from client() so that Probe can see whether resolving failed. The
// reason has to reach a report: truststore answers a failure with an empty pool,
// which fails every handshake closed, and a chain of failed handshakes reads as
// a site that is not reachable over HTTPS unless something says otherwise (R4).
func (p *Prober) clientWith(roots *x509.CertPool) *http.Client {
	dial := p.Dial
	if dial == nil {
		d := &safedial.Dialer{
			Timeout: p.requestTimeout(),
			// Ports as well as addresses. A redirect can name any port on any
			// host, and a probe that follows one has been aimed by the server
			// rather than by the operator.
			AllowedPorts: []string{securePort, plainPort},
		}
		dial = d.DialContext
	}

	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: dial,

			// Everything this config does not say is deliberate.
			//
			// No InsecureSkipVerify, obviously, and no MinVersion either: the
			// package default is what a browser does, and naming a version here
			// would move a measurement rather than a setting — a host reachable
			// only over an old protocol would start being reported as not
			// reachable at all.
			//
			// No ServerName. One config serves every hop of both chains, and a
			// name set here would be checked against the certificate of a host
			// the redirect moved on from, so every redirect off the first name
			// would fail verification and be reported as a broken site.
			//
			// No ClientSessionCache. A cache shared across hosts is a cache
			// that can resume somebody else's session, and a resumed handshake
			// is not the handshake this check means to measure.
			TLSClientConfig: &tls.Config{RootCAs: roots},

			// What a browser negotiates. Headers are the same either way, but
			// a probe that speaks a protocol no visitor speaks is measuring
			// something no visitor sees.
			ForceAttemptHTTP2: true,

			// Nothing is reused between chains for long. Idle connections
			// held open are connections the scanned server is paying to keep.
			MaxIdleConns:        2,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: p.requestTimeout(),

			// No proxy, ever. A proxy from the environment would put a third
			// party between this program and the host being measured, and the
			// measurement would then describe the proxy.
			Proxy: nil,
		},
	}
}

// CheckHostname refuses anything that is not a bare name.
//
// Exported because a caller has to be able to ask before it acts. A scanner
// deciding whether a deployment may reach a host wants a valid host first:
// asking the deployment about "not a hostname" and answering "this deployment
// does not demonstrate that" tells the reader the wrong thing about their own
// mistake.
//
// No scheme, no path, no port, no address. The check is deliberately narrow:
// this reads how a website answers the thing a person types into a browser,
// and a person types neither a scheme nor a port. A caller wanting something
// else is asking for a different measurement, which should have a different
// name rather than a flag on this one.
func CheckHostname(host string) error {
	switch {
	case host == "":
		return fmt.Errorf("%w: it is empty", ErrNotAHostname)
	case strings.Contains(host, "/"):
		return fmt.Errorf("%w: give the name alone, with no scheme or path", ErrNotAHostname)
	case strings.ContainsAny(host, ": "):
		return fmt.Errorf("%w: give the name alone, with no port", ErrNotAHostname)
	case net.ParseIP(host) != nil:
		return fmt.Errorf("%w: an address carries no name for a certificate or a cookie to be scoped to", ErrNotAHostname)
	case !strings.Contains(strings.TrimSuffix(host, "."), "."):
		return fmt.Errorf("%w: the host needs a full name with a domain, such as example.com", ErrNotAHostname)
	}
	return nil
}

func (p *Prober) requestTimeout() time.Duration {
	if p.RequestTimeout > 0 {
		return p.RequestTimeout
	}
	return defaultRequestTimeout
}

func (p *Prober) totalTimeout() time.Duration {
	if p.TotalTimeout > 0 {
		return p.TotalTimeout
	}
	return defaultTotalTimeout
}

func (p *Prober) maxRedirects() int {
	if p.MaxRedirects != 0 {
		if p.MaxRedirects < 0 {
			return 0
		}
		return p.MaxRedirects
	}
	return defaultMaxRedirects
}

func (p *Prober) userAgent() string {
	if p.UserAgent != "" {
		return p.UserAgent
	}
	return DefaultUserAgent
}
