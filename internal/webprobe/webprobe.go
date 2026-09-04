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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
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
	Err string `json:"error,omitempty"`
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
}

// Probe fetches the headers of one host over both schemes.
//
// The two chains are independent: a host with a certificate that does not
// verify produces a failed secure chain and a plaintext chain that is still
// worth reading, and the reverse holds for a host with nothing on port 80.
// Neither failure is returned as an error, because neither is a failure of
// this program. An error here means the target was refused or nothing could
// be attempted at all.
func (p *Prober) Probe(ctx context.Context, host string) (*Report, error) {
	if err := checkHostname(host); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, p.totalTimeout())
	defer cancel()

	report := &Report{Host: host, UserAgent: p.userAgent()}

	client := p.client()

	// Secure first. If the deadline runs out it should run out on the chain
	// that matters most, rather than on the one that exists to catch a
	// stripping arrangement.
	report.Secure = p.chain(ctx, client, "https://"+net.JoinHostPort(host, securePort)+"/")
	report.Plain = p.chain(ctx, client, "http://"+net.JoinHostPort(host, plainPort)+"/")

	return report, nil
}

// chain follows one starting address as far as the limits allow.
func (p *Prober) chain(ctx context.Context, client *http.Client, start string) *Chain {
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
		next = loc
	}
}

// fetch performs one request and records what came back.
func (p *Prober) fetch(ctx context.Context, client *http.Client, target string) Hop {
	hop := Hop{URL: target, TLS: strings.HasPrefix(target, "https://")}

	ctx, cancel := context.WithTimeout(ctx, p.requestTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		hop.Err = err.Error()
		return hop
	}
	req.Header.Set("User-Agent", p.userAgent())

	resp, err := client.Do(req)
	if err != nil {
		hop.Err = unwrapURLError(err)
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

// checkHostname refuses anything that is not a bare name.
//
// No scheme, no path, no port, no address. The check is deliberately narrow:
// this reads how a website answers the thing a person types into a browser,
// and a person types neither a scheme nor a port. A caller wanting something
// else is asking for a different measurement, which should have a different
// name rather than a flag on this one.
func checkHostname(host string) error {
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

// unwrapURLError removes the wrapper the http client adds.
//
// url.Error prints the method and the whole address in front of every
// failure, and the address is already the URL field of the hop this error
// belongs to. Printed as it comes, a report says the same address twice and
// the reason is at the end of a long line.
func unwrapURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
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
