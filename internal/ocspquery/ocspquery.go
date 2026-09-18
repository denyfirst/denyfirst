// Package ocspquery asks a certificate's own responder whether it has been
// revoked, and believes the answer only once it verifies.
//
// # Why this is separate, and switched off
//
// internal/ocsp reads a response the server stapled, and nothing there fetches
// anything: a stapled response is the authority's statement handed over by the
// server, so the authority never learns who is looking. Asking the responder
// directly is the opposite. The question carries the certificate's serial and
// its issuer, so the authority learns which certificate somebody is examining,
// from which address, and when.
//
// That is why R3a says no responder is ever asked, and why this package exists
// anyway: on the command line an operator examining their own certificate may
// decide the authority learning that is no disclosure at all. So it runs only
// where a caller sets it, the command line sets it only behind a flag, the
// service never does, and the demonstration build cannot. See R3a.
//
// # What is guarded
//
// The address comes from the certificate the scanned server sent, so it is
// chosen by the party being measured — the argument N11 makes for revocation
// lists, and the same guards follow: safedial, ports 80 and 443, http and https
// only, credentials stripped, no redirect, no proxy, two responders at most, and
// a size cap that refuses rather than truncates. What comes back is believed
// only after internal/ocsp verifies it against the issuer and finds it current.
package ocspquery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/porch/internal/crl"
	"github.com/denyfirst/porch/internal/ocsp"
	"github.com/denyfirst/porch/internal/safedial"
	"github.com/denyfirst/porch/internal/truststore"
)

const (
	// maxResponders bounds how many addresses one certificate can make this ask.
	maxResponders = 2

	// maxResponse is the largest answer read. A real one is a few hundred bytes.
	maxResponse = 64 << 10

	defaultTimeout = 10 * time.Second
)

var allowedPorts = []string{"80", "443"}

// Result is what asking established.
type Result struct {
	// Status is "good", "revoked" or "unknown" from a verified, current answer,
	// and empty when no answer established anything.
	Status string

	RevokedAt  time.Time
	ThisUpdate time.Time
	NextUpdate time.Time

	// Reason says why nothing was established, in this project's own words.
	Reason string
}

// Fetcher asks responders. The zero value is usable and reaches the network
// through safedial.
type Fetcher struct {
	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store for a responder served over HTTPS. Nil means the
	// system store, resolved explicitly (R7).
	Roots *x509.CertPool

	// Timeout bounds one question. Zero means ten seconds.
	Timeout time.Duration
}

// Check asks the responders leaf names about it.
//
// The issuer is required: the answer is believed only once it verifies against
// the certificate that issued the leaf, and without it nothing is even asked.
func (f *Fetcher) Check(ctx context.Context, leaf, issuer *x509.Certificate, now time.Time) Result {
	switch {
	case leaf == nil || issuer == nil:
		return Result{Reason: "the issuing certificate was not sent, so a responder's answer could not be verified"}
	case len(leaf.OCSPServer) == 0:
		return Result{Reason: "the certificate names no responder"}
	}

	question, err := ocsp.Request(leaf, issuer)
	if err != nil {
		return Result{Reason: "the question could not be written for this certificate"}
	}

	var last Result
	tried := 0
	for _, server := range leaf.OCSPServer {
		if tried >= maxResponders {
			break
		}
		address, ok := usable(server)
		if !ok {
			last = Result{Reason: "the certificate names a responder at an address this does not ask"}
			continue
		}
		tried++

		out := f.askOne(ctx, address, question, leaf, issuer, now)
		if out.Status != "" {
			return out
		}
		last = out
	}

	if last.Reason == "" {
		last.Reason = "no responder could be asked"
	}
	return last
}

// askOne asks one responder and reads what it says.
func (f *Fetcher) askOne(ctx context.Context, address string, question []byte, leaf, issuer *x509.Certificate, now time.Time) Result {
	der, reason := f.post(ctx, address, question)
	if reason != "" {
		return Result{Reason: reason}
	}

	response, err := ocsp.Check(der, leaf, issuer, now)
	if err != nil {
		// internal/ocsp writes its own sentences and passes nothing through from
		// elsewhere, so what it says names no machine (I6).
		return Result{Reason: "the responder's answer established nothing: " + strings.TrimPrefix(err.Error(), "ocsp: ")}
	}
	return Result{
		Status:     string(response.Status),
		RevokedAt:  response.RevokedAt,
		ThisUpdate: response.ThisUpdate,
		NextUpdate: response.NextUpdate,
	}
}

// post sends the question, or says why it could not.
func (f *Fetcher) post(ctx context.Context, address string, question []byte) ([]byte, string) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(question))
	if err != nil {
		return nil, "the responder's address could not be asked"
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	req.Header.Set("User-Agent", crl.UserAgent)

	resp, err := f.client().Do(req)
	if err != nil {
		return nil, "the responder could not be reached"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "the responder did not answer the question"
	}

	// One byte past the cap, so an answer over it is recognised as over rather
	// than silently cut and then misread.
	der, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, "the responder's answer could not be read"
	}
	if len(der) > maxResponse {
		return nil, "the responder's answer is larger than this reads"
	}
	return der, ""
}

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
	roots, _ := truststore.Resolve(f.Roots)

	return &http.Client{
		// A redirect is an address chosen by whoever answered an address chosen
		// by the scanned server; for the reason internal/crl gives, it is not
		// followed and nothing is established.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:         dial,
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: roots},
			MaxIdleConns:        2,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: f.timeout(),
		},
	}
}

// usable turns a responder address into one this asks, or refuses it: http and
// https only, a host, and no credentials.
func usable(server string) (string, bool) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	u.User = nil
	return u.String(), true
}
