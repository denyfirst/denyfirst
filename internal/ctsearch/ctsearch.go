// Package ctsearch finds the certificates a public log has recorded for a name.
//
// Every publicly trusted certificate is submitted to append-only logs before a
// browser will accept it. That is what makes this possible: a certificate
// somebody obtained for your name, from any authority, is in those logs whether
// or not you know about it. Finding one you did not order is the earliest
// warning available that a name has been issued for behind your back — and it
// is a warning nothing in a handshake can give, because the certificate you are
// looking for is on somebody else's server.
//
// # This asks a third party a question that names you
//
// A log is an append-only structure of billions of entries with no index by
// name, so "which certificates exist for example.com" cannot be asked of a log
// directly. It is asked of a monitor, and the question contains the domain.
//
// That is a larger disclosure than reading a revocation list, where one list
// covers thousands and the question names nothing, and it is the same shape as
// the OCSP query this project refuses. What makes it acceptable is not the
// monitor's reputation — a certificate authority is not automatically a safe
// recipient of query data, and several of them sell monitoring — but that
// certificate transparency is public by design. The certificates for a name are
// already published to anyone who looks. Nothing new about the domain is
// disclosed; what is disclosed is that somebody is looking.
//
// So: never on the demonstration, which promises it queries no log. On a
// deployment that required proof of control, the name belongs to whoever asked
// and there is nothing to hide from themselves. On the command line it is the
// operator's explicit choice, because there the name may be somebody else's.
//
// # The monitor is replaceable
//
// Searcher is an interface and the shipped implementation is one field. A
// monitor that goes away, changes its interface, or that an operator would
// rather not use is a substitution rather than a rewrite — which is the honest
// answer to depending on a service this project does not run.
package ctsearch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/truststore"
)

const (
	// maxBody bounds one answer. A name with a long issuance history produces
	// a large document, and this is a scanner rather than an archive.
	maxBody = 4 << 20

	// maxEntries bounds what is kept after parsing. A report listing hundreds
	// of certificates is a report nobody reads; the count is still reported in
	// full, and Result.Truncated says the list is not.
	maxEntries = 50

	defaultTimeout = 15 * time.Second

	// maxField bounds one string taken from an answer. Issuer names and subject
	// names come from certificates anybody may log, so they are chosen by
	// whoever obtained them rather than by the operator being scanned.
	maxField = 256

	// maxNames bounds the names kept from one entry.
	maxNames = 20
)

// Entry is one certificate a log recorded.
type Entry struct {
	// Serial is the certificate's serial number as the monitor reported it,
	// lowercase hexadecimal.
	//
	// It is what deduplication is done on, and that is not a detail. Every
	// certificate is logged twice — once as a precertificate and once as
	// itself — so a name with one certificate comes back as two entries with
	// one serial. Reporting the raw count would tell an operator they have
	// twice as many certificates as they do, which on this scanner's own
	// domain was the first thing the real answer showed.
	Serial string `json:"serial"`

	// Issuer is the authority that signed it, as the monitor reported it,
	// truncated and stripped of anything unprintable.
	Issuer string `json:"issuer"`

	// Names are the names the certificate covers.
	Names []string `json:"names,omitempty"`

	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

// Result is what one search established.
type Result struct {
	// Entries are the distinct certificates found, newest first.
	Entries []Entry `json:"entries,omitempty"`

	// Distinct is how many distinct certificates the monitor reported, which
	// is not len(Entries) when the list was truncated.
	Distinct int `json:"distinct"`

	// Truncated is true when more certificates exist than are listed.
	Truncated bool `json:"truncated,omitempty"`

	// Reason says why nothing was established. Empty on success.
	//
	// This project's own sentence, never an error from the network or the
	// decoder: those name resolvers, addresses and internal types, and this
	// string reaches a report a stranger reads (I6).
	Reason string `json:"reason,omitempty"`
}

// Searcher answers which certificates a log has recorded for a name.
//
// An interface so the monitor can be replaced without touching anything that
// reads a result. See the package comment.
type Searcher interface {
	Search(ctx context.Context, name string) Result
}

// CRTSh searches crt.sh, which indexes the public logs.
type CRTSh struct {
	// Endpoint is the address to query, with %s for the name. Empty means the
	// default. A monitor with a compatible answer can be substituted here.
	Endpoint string

	// Dial opens the connection. Nil selects safedial, which refuses private,
	// loopback, link-local and reserved destinations.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Roots is the trust store the monitor's certificate is judged against.
	// Nil means the system store, loaded explicitly (R7).
	Roots *x509.CertPool

	// Timeout bounds one search. Zero means fifteen seconds.
	//
	// A monitor that is slow is a monitor that spends a scan's budget. This
	// check is worth having and is not worth waiting on: a search that does
	// not finish is reported as not established, which is the same answer a
	// deployment that does not search gives.
	Timeout time.Duration
}

// defaultEndpoint is the address queried when none is configured.
//
// Identity rather than q, and output=json rather than a parsed page. Written
// from what the service actually answers rather than from memory: q with
// output=json is a 404, and /json is a 502. A check built on a remembered
// address would have shipped asking for a page that does not exist and
// reporting every name as having no certificates — which is the failure shape
// that matters here, since "none found" is the reassuring answer.
const defaultEndpoint = "https://crt.sh/?Identity=%s&output=json"

// entry is one record as the monitor writes it.
type entry struct {
	IssuerName   string `json:"issuer_name"`
	NameValue    string `json:"name_value"`
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

// Search asks the monitor what it has for one name.
//
// Exact name only. A certificate obtained for a subdomain is a real risk and is
// not covered here, so a report has to say so rather than leave a reader taking
// a clean answer for a clean estate (R4). Widening the query multiplies the
// answer for any domain of size, which is a decision to make deliberately
// rather than as a default.
func (c *CRTSh) Search(ctx context.Context, name string) Result {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return Result{Reason: "no name was given to search for"}
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	address := fmt.Sprintf(c.endpoint(), url.QueryEscape(name))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return Result{Reason: "the monitor's address could not be requested"}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return Result{Reason: "the certificate transparency monitor could not be reached"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{Reason: "the certificate transparency monitor did not answer the search"}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Result{Reason: "the monitor's answer could not be read"}
	}
	if len(body) > maxBody {
		// Not truncated and then parsed. A cut answer is an answer with
		// certificates missing from it, and "none found" is the reassuring
		// half of this check (R4).
		return Result{Reason: "the monitor's answer is larger than this reads"}
	}

	var raw []entry
	if err := json.Unmarshal(body, &raw); err != nil {
		return Result{Reason: "the monitor's answer was not in the form this reads"}
	}

	return summarise(raw)
}

// UserAgent identifies this client to the monitor, as everything else here
// identifies itself. A search that hides is one nobody can ask about.
const UserAgent = "denyfirst/1 (+https://denyfirst.dev/tls/method)"

// summarise turns what the monitor said into what a report may show.
//
// Deduplicated by serial, because every certificate is logged twice: once as a
// precertificate, once as itself. The first real answer this was run against —
// this project's own domain, one certificate — came back as two entries sharing
// one serial.
func summarise(raw []entry) Result {
	var out Result
	seen := map[string]bool{}

	for _, e := range raw {
		serial := strings.ToLower(strings.TrimSpace(e.SerialNumber))
		if serial == "" || seen[serial] {
			continue
		}
		seen[serial] = true
		out.Distinct++

		if len(out.Entries) >= maxEntries {
			out.Truncated = true
			continue
		}

		out.Entries = append(out.Entries, Entry{
			Serial:    clean(serial),
			Issuer:    clean(e.IssuerName),
			Names:     names(e.NameValue),
			NotBefore: stamp(e.NotBefore),
			NotAfter:  stamp(e.NotAfter),
		})
	}
	return out
}

// names splits the name list one entry carries.
//
// A multi-name certificate arrives with its names separated by newlines, which
// is also the reason they are split rather than shown: a newline reaching a
// report unbroken is a line a reader cannot attribute to the field it came
// from.
func names(value string) []string {
	var out []string
	for _, n := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		if len(out) >= maxNames {
			break
		}
		if n = clean(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// clean bounds one string from the monitor and strips what should not travel.
//
// These come from certificates anybody may obtain and log, so the values are
// chosen by whoever obtained them. A report is rendered in a browser and pasted
// into chat windows, and a control character in a subject is an old trick for
// making one line look like another.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxField {
		s = s[:maxField]
	}

	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// stamp reads the monitor's timestamps, which carry no zone and are UTC.
func stamp(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func (c *CRTSh) timeout() time.Duration {
	if c.Timeout <= 0 {
		return defaultTimeout
	}
	return c.Timeout
}

func (c *CRTSh) endpoint() string {
	if c.Endpoint == "" {
		return defaultEndpoint
	}
	return c.Endpoint
}

func (c *CRTSh) client() *http.Client {
	dial := c.Dial
	if dial == nil {
		d := &safedial.Dialer{Timeout: c.timeout(), AllowedPorts: []string{"443", "80"}}
		dial = d.DialContext
	}

	roots, _ := truststore.Resolve(c.Roots)

	return &http.Client{
		// A redirect from a monitor is an address that monitor chose. The hop
		// is not followed and the search is reported as not established, which
		// is the honest outcome.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: dial,
			Proxy:       nil,

			// As everywhere: RootCAs and nothing that would weaken a
			// handshake. No InsecureSkipVerify, no pinned ServerName, no
			// shared session cache, no version named here.
			TLSClientConfig: &tls.Config{RootCAs: roots},

			MaxIdleConns:        2,
			IdleConnTimeout:     5 * time.Second,
			TLSHandshakeTimeout: c.timeout(),
		},
	}
}

var _ Searcher = (*CRTSh)(nil)
