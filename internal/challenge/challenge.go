// Package challenge fetches the file half of a verification challenge.
//
// It is one request for a file an operator deliberately placed, made before a
// host is scanned and only when the DNS proof was not found. It is not a
// check: nothing it reads becomes a measurement, nothing it returns reaches a
// report, and if the file is absent the host is refused rather than described.
//
// It lives here rather than in internal/verify because that package decides
// who may be scanned and imports nothing of this project's own — the same
// property internal/policy has, and for the same reason: a rule about who may
// be reached should be readable without reading an HTTP client.
//
// # The connection is the dangerous part
//
// A fetch is a connection this deployment opens to a host somebody named, and
// it happens before the boundary has decided anything. That is the shape of an
// SSRF into the scanner, which is one of the three things verification exists
// to survive. So it dials through safedial exactly as a scan does, refuses
// every port but the secure one, follows nothing, and reads a bounded body.
package challenge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/verify"
)

const (
	// securePort is the only port a challenge is fetched from.
	//
	// A file served in the clear proves control of what an attacker on the
	// path can rewrite, which is not control of anything. HTTPS or nothing.
	securePort = "443"

	// maxBody bounds what a host can make this deployment carry.
	//
	// A token is forty characters. Anything approaching this is not one, and
	// the response is read into memory before it is compared.
	maxBody = 4 << 10

	defaultTimeout = 10 * time.Second
)

// Fetcher reads the challenge file over HTTPS. The zero value is usable.
type Fetcher struct {
	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations.
	//
	// A deployment scanning its own internal estate will need to reach those,
	// and that is a switch it has to set deliberately — the same one the scan
	// itself needs. Until it does, the file method reaches public hosts only
	// and the DNS method reaches everything, which is the safe way round.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store the challenge connection is judged against.
	//
	// Nil means the system pool. An internal estate signs its own
	// certificates, and a deployment scanning one has an authority the
	// machine may not carry — so the caller can say which store decides,
	// exactly as it does for the chains a scan reads.
	//
	// What it may not be is off. A challenge fetched over a connection this
	// program would not trust proves control of nothing: whoever can answer
	// for the name can serve any file, which is the whole of what is being
	// asked.
	Roots *x509.CertPool

	// Timeout bounds the fetch. Zero means ten seconds.
	Timeout time.Duration
}

// FetchChallenge returns the body served at verify.Path, or ErrNoChallenge.
//
// The certificate is verified. A challenge fetched over a connection this
// program would not trust proves control of nothing: an attacker who can
// answer for the name can serve any file they like, which is the whole of what
// is being asked.
func (f *Fetcher) FetchChallenge(ctx context.Context, host string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	target := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, securePort),
		Path:   verify.Path,
	}).String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", errors.New("challenge: the address could not be built")
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := f.client().Do(req)
	if err != nil {
		// The reason is not passed through. Go writes network errors for an
		// operator reading a terminal and names the resolver's address doing
		// it, and this error reaches a caller that may put it in front of
		// somebody (I6).
		return "", errors.New("challenge: the host could not be reached over TLS")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Not an error. A host that serves no such file has published no
		// proof, which is a fact about the domain and the one the operator
		// needs to act on.
		return "", verify.ErrNoChallenge
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", errors.New("challenge: the response could not be read")
	}
	if len(body) == 0 {
		return "", verify.ErrNoChallenge
	}

	return strings.TrimSpace(string(body)), nil
}

// UserAgent identifies the request the way every other one this project makes
// is identified. An operator finding it in their own access log should be able
// to tell it from a scan.
const UserAgent = "porch/1 (+https://denyfirst.dev/web/method; verification)"

// dialFunc is the connection this fetcher opens with.
//
// A function rather than three lines inside client(), so that a test can ask
// what a nil Dial actually selects. Asking through FetchChallenge cannot: the
// error is deliberately the same phrase whether a destination was refused by
// policy or simply had nothing listening (I6), so the two are indistinguishable
// from outside — which is right for a caller and useless for a test.
func (f *Fetcher) dialFunc() func(context.Context, string, string) (net.Conn, error) {
	if f.Dial != nil {
		return f.Dial
	}
	d := &safedial.Dialer{AllowedPorts: []string{securePort}}
	return d.DialContext
}

func (f *Fetcher) client() *http.Client {
	dial := f.dialFunc()

	return &http.Client{
		Transport: &http.Transport{
			DialContext: dial,

			// No proxy. One would put a third party between this deployment
			// and the proof, and the proof is the whole boundary.
			Proxy: nil,

			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    f.Roots,
			},
		},

		// Nothing is followed. A redirect is the host choosing where this
		// deployment looks next, and a challenge is a file at one address —
		// following one would let a host prove control of itself by pointing
		// at somewhere the file already is.
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

// Compile-time assurance that this satisfies the boundary's needs.
var _ verify.Fetcher = (*Fetcher)(nil)
