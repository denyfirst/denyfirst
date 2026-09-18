// Package mtasts reads the MTA-STS policy a domain publishes.
//
// The DNS record at _mta-sts.<domain> announces that a policy exists. It does
// not say what the policy is: RFC 8461 puts that in a file served over HTTPS at
// mta-sts.<domain>, and until this package existed a report could say a policy
// was announced and nothing else.
//
// That gap was the whole of the finding. A policy in testing mode tells a
// sending server to carry on delivering when TLS fails and to send a report
// about it — which is a rehearsal, not a protection — and it looks identical
// from DNS to one in enforce mode. An operator who set it to testing during a
// rollout two years ago and forgot has no protection and every appearance of
// it, and nothing they can run tells them so.
//
// # This is a connection, and that is the change
//
// The mail check reads DNS and nothing else, and this breaks that. It is one
// GET of one address RFC 8461 fixes, to a host derived from the target, for a
// file the operator deliberately published so that every sending server on the
// internet would read it. No path is invented: the address is
// https://mta-sts.<domain>/.well-known/mta-sts.txt and there is no other.
//
// It runs where control of the domain has been proven, and nowhere else. That
// is the same condition the web check reads a page under, for the same reason:
// the request is to a host in an estate the person asking has shown is theirs.
//
// # What is kept
//
// The mode, the maximum age, and the exchangers the policy names. Nothing else
// — the file is small and public, and there is still no reason to hold bytes a
// rule does not read.
package mtasts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

const (
	// Host is the name a policy is served from, beneath the domain.
	Host = "mta-sts."

	// Path is where RFC 8461 puts the file. The one path this check builds,
	// and it is fixed by the specification rather than guessed at.
	Path = "/.well-known/mta-sts.txt"

	// securePort is the only port a policy is fetched from. RFC 8461 requires
	// HTTPS, and a policy served in the clear is one anybody on the path can
	// rewrite — which is the attack the policy exists to stop.
	securePort = "443"

	// maxBody bounds what a host can make this carry. A policy is a few lines;
	// anything near this is not one.
	maxBody = 64 << 10

	// maxNames bounds how many exchangers a policy can put in a report.
	maxNames = 32

	// UserAgent identifies the request the way every other one this project
	// makes is identified.
	UserAgent = "porch/1 (+https://denyfirst.dev/tls/method; mta-sts)"

	defaultTimeout = 10 * time.Second
)

// Mode is what the policy tells a sending server to do when TLS fails.
type Mode string

const (
	// Enforce: a sender must not deliver. The protection.
	Enforce Mode = "enforce"

	// Testing: a sender delivers anyway and reports. A rehearsal.
	Testing Mode = "testing"

	// None: the domain is switching MTA-STS off, and says so deliberately so
	// that senders holding a cached policy stop applying it.
	None Mode = "none"
)

// Policy is what the file said.
type Policy struct {
	// Fetched is whether the file was read at all. Without it every field
	// below is silence rather than a policy that said nothing (R4).
	Fetched bool `json:"fetched"`

	// Reason says why it could not be read. A failure to fetch is not a
	// domain without a policy.
	Reason string `json:"reason,omitempty"`

	// Mode is what the policy says, or empty when the file carried no mode —
	// which RFC 8461 makes it invalid, since a policy without one tells a
	// sender nothing.
	Mode Mode `json:"mode,omitempty"`

	// MaxAge is how long a sender may cache it, in seconds.
	MaxAge int `json:"maxAge,omitempty"`

	// MX are the patterns the policy permits, lowercased. A leading "*." is
	// kept: it is a wildcard the specification defines and dropping it would
	// turn one pattern into a different one.
	MX []string `json:"mx,omitempty"`

	// Invalid says why a fetched file is not a policy a sending server would
	// apply, and is empty when it is one. Mode, MaxAge and MX are empty when it
	// is set: nothing in an invalid policy is acted on.
	Invalid string `json:"invalid,omitempty"`

	// MXTruncated is true when the policy named more patterns than are kept.
	// Which exchangers it covers is then not established: a pattern past the
	// bound might be the one that covers a host.
	MXTruncated bool `json:"mxTruncated,omitempty"`
}

// Fetcher reads a policy. The zero value is usable.
type Fetcher struct {
	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations — the same guard a scan
	// uses, because this is a connection to a host somebody named.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store the connection is judged against. Nil means the
	// store internal/truststore resolves to.
	//
	// What it may not be is off. RFC 8461 requires the policy be fetched over
	// a connection whose certificate validates for the policy host, and a
	// policy read over one this program would not trust is a policy anybody on
	// the path could have written — which is precisely what MTA-STS exists to
	// prevent.
	Roots *x509.CertPool

	// Timeout bounds the fetch. Zero means ten seconds.
	Timeout time.Duration
}

// Fetch reads the policy for one domain.
//
// Never returns an error. A policy that could not be read is a Policy carrying
// the reason, because a caller that had to tell a failed fetch from an absent
// policy by inspecting an error would eventually stop doing it (R4).
func (f *Fetcher) Fetch(ctx context.Context, domain string) Policy {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	target := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(Host+domain, securePort),
		Path:   Path,
	}).String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Policy{Reason: "the address could not be built"}
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := f.client().Do(req)
	if err != nil {
		// The shape of the failure only. Go words network errors for somebody
		// reading a terminal and names addresses doing it, and this reaches a
		// report (I6).
		//
		// One phrase for every cause, deliberately: a certificate that did not
		// validate, a host that does not exist and a connection refused are
		// all "the policy could not be read", because the operator's next step
		// is the same in each case and a report guessing between them would be
		// guessing.
		return Policy{Reason: "the policy file could not be fetched over TLS"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Policy{Reason: "the policy file is not served at " + Path}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Policy{Reason: "the policy file could not be read"}
	}

	policy, invalid := parse(string(body))
	if invalid != "" {
		// A file that is not a valid policy is, to a sending server, no
		// policy: RFC 8461 has it carry on as though MTA-STS were not
		// published. It was fetched, and nothing in it is kept but what is
		// wrong with it. Before the 2026-09-16 audit (A18) a file with no
		// version line was read as enforcing.
		//
		// Built afresh rather than from what parse returned. parse returns an
		// empty Policy with a reason too, so a sabotage of either one alone
		// escapes the tests (2026-09-17): the two guard one property, that
		// nothing parse saw before finding the fault reaches a report.
		return Policy{Fetched: true, Invalid: invalid}
	}
	policy.Fetched = true
	return policy
}

// parse reads the key-value lines RFC 8461 §3.2 defines, and says what makes the
// file not a policy where something does.
//
// Unknown keys are ignored rather than refused: the specification says a parser
// must, so that it can be extended. What is required is required: a version of
// STSv1, one of the three modes, a max_age, and for a policy that enforces or
// tests, at least one mx. version, mode and max_age appear once; a file that
// says two things about one of them says nothing a sender can act on.
func parse(body string) (Policy, string) {
	var out Policy

	if len(body) > maxBody {
		// Refused rather than read in part: a policy cut at the bound could
		// lose the pattern that covers an exchanger and report it uncovered.
		return Policy{}, "it is larger than a policy may be"
	}

	seen := map[string]bool{}
	version := ""
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(strings.TrimSuffix(value, "\r"))

		switch key {
		case "version", "mode", "max_age":
			if seen[key] {
				return Policy{}, "it gives " + key + " more than once"
			}
			seen[key] = true
		}

		switch key {
		case "version":
			version = value

		case "mode":
			switch strings.ToLower(value) {
			case "enforce":
				out.Mode = Enforce
			case "testing":
				out.Mode = Testing
			case "none":
				out.Mode = None
			default:
				return Policy{}, "its mode is not one RFC 8461 defines"
			}

		case "max_age":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return Policy{}, "its max_age is not a number of seconds"
			}
			out.MaxAge = n

		case "mx":
			if len(out.MX) >= maxNames {
				out.MXTruncated = true
				continue
			}
			if name := cleanName(value); name != "" {
				out.MX = append(out.MX, name)
			}
		}
	}

	switch {
	case version != "STSv1":
		return Policy{}, "it does not declare version STSv1"
	case out.Mode == "":
		return Policy{}, "it declares no mode"
	case !seen["max_age"]:
		return Policy{}, "it declares no max_age"
	case out.Mode != None && len(out.MX) == 0 && !out.MXTruncated:
		return Policy{}, "it names no mx for a mode that needs them"
	}
	return out, ""
}

// Covers reports whether a policy permits delivery to one exchanger.
//
// RFC 8461 §4.1: a pattern is either an exact name or one leading "*." label,
// and the wildcard matches exactly one label rather than any number. A sender
// in enforce mode that finds no match must not deliver, so this is the question
// that decides whether an enforcing policy breaks the domain's own mail.
func (p Policy) Covers(host string) bool {
	host = cleanName(host)
	if host == "" {
		return false
	}

	for _, pattern := range p.MX {
		if pattern == host {
			return true
		}
		rest, ok := strings.CutPrefix(pattern, "*.")
		if !ok {
			continue
		}
		// One label, and it must be a label rather than part of one.
		_, under, found := strings.Cut(host, ".")
		if found && under == rest {
			return true
		}
	}
	return false
}

// cleanName folds a name and strips what a report may not carry.
//
// The file comes from a host the scanned party controls, so a name in it is
// chosen by whoever is being measured (I5).
func cleanName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		name = name[:253]
	}

	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_' || r == '*':
			return r
		}
		return -1
	}, name)
}

func (f *Fetcher) dialFunc() func(context.Context, string, string) (net.Conn, error) {
	if f.Dial != nil {
		return f.Dial
	}
	d := &safedial.Dialer{AllowedPorts: []string{securePort}}
	return d.DialContext
}

func (f *Fetcher) client() *http.Client {
	// Resolved rather than passed through. A nil pool, and on Windows and macOS
	// the system pool as well, hands verification to the platform, which then
	// fetches whatever the presented certificate names (see internal/truststore).
	// A store that cannot be read leaves an empty pool, so the fetch fails
	// closed.
	roots, _ := truststore.Resolve(f.Roots)

	return &http.Client{
		Transport: &http.Transport{
			DialContext: f.dialFunc(),

			// One request per client, and the client is not kept. A kept-alive
			// connection on a transport nobody holds stays open until the peer
			// closes it — one more for every policy fetched (audit A28).
			DisableKeepAlives: true,

			// No proxy. One would put a third party between this and a policy
			// whose whole purpose is that nobody in the middle can rewrite it.
			Proxy: nil,

			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
			},
		},

		// Nothing is followed. RFC 8461 §3.3 says a sender must not follow a
		// redirect when fetching a policy, and for the reason every other
		// refusal here has: a redirect is the host choosing where this looks
		// next, and the policy is a file at one address.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},

		Timeout: f.timeout(),
	}
}

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return defaultTimeout
}
