// Package rootstores holds the root certificates four clients trust, and says
// which of them would accept a chain.
//
// # Why this exists
//
// A report said a chain was trusted, meaning trusted by the store of the
// machine that ran the scan. That is one store among several: Mozilla, Chrome,
// Microsoft and Apple each ship their own, and remove authorities on their own
// timetables. A chain this machine trusts can fail in a browser, and a chain it
// does not can be accepted by all four. The report now says, for each of them,
// what the carried copy of its store says.
//
// # Where the stores come from, and what is not claimed about them
//
// From the Common CA Database, which Mozilla, Microsoft, Google and Apple use
// to publish their inclusion decisions, and for Chrome from the root store file
// in the Chromium source. See refresh/.
//
// Unlike Google's transparency log list, none of these is signed by its
// publisher. What protects the carried file is that it is fetched over HTTPS,
// that refresh/ refuses it unless every certificate's hash matches the
// fingerprint its publisher lists beside it, that a person reads the diff and
// signs the commit (S6), and that a test checks every carried certificate
// against its recorded hash on every build. That is less than a signature, and
// the documentation says so rather than borrowing the stronger word.
//
// # What is not modelled
//
// Membership, and the one condition that can be checked exactly from here:
// Mozilla's "distrust for TLS after" date, compared with when the certificate
// was issued. Chrome's constraints depend on the Chrome version and on
// transparency receipt dates, and Microsoft's "NotBefore" roots carry a date its
// published report does not include, so both are reported as conditional —
// accepted under terms this report does not evaluate — rather than guessed.
//
// A root whose certificate Go cannot parse is not carried. Microsoft includes
// EC-ACC, whose serial number is negative, and Go refuses such a certificate —
// so its verifier could never use the root, and a chain reaching it is reported
// as not trusted by the stores that include it. refresh/ names every root it
// leaves out this way.
//
// Nothing here is graded. Which store a deployment's verdict rests on is still
// the deployment's own (R7); these are said beside it.
package rootstores

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed roots.json
var rootsJSON []byte

// Store names one client's root store.
type Store string

const (
	Mozilla   Store = "mozilla"
	Chrome    Store = "chrome"
	Microsoft Store = "microsoft"
	Apple     Store = "apple"
)

// All is every store, in the order a report names them.
var All = []Store{Mozilla, Chrome, Microsoft, Apple}

// Name is how a report writes a store.
func (s Store) Name() string {
	switch s {
	case Mozilla:
		return "Mozilla"
	case Chrome:
		return "Chrome"
	case Microsoft:
		return "Microsoft"
	case Apple:
		return "Apple"
	}
	return string(s)
}

// Statuses a root can have in a store, as the carried file writes them.
const (
	statusTrusted     = "trusted"
	statusConditional = "conditional"
	distrustPrefix    = "distrust-after:"
)

// maxRoots bounds what a carried file can make this hold.
const maxRoots = 4096

var (
	// ErrCorrupt means the carried file does not match itself: a certificate
	// whose bytes do not hash to the fingerprint recorded beside it.
	ErrCorrupt = errors.New("rootstores: a carried root does not match its recorded fingerprint")

	errUnreadable = errors.New("rootstores: the carried root stores could not be read")
)

// File is the carried file's shape, shared with refresh/.
type File struct {
	Retrieved string            `json:"retrieved"`
	Sources   map[string]string `json:"sources"`
	Roots     []Root            `json:"roots"`
}

// Root is one certificate and what each store says of it.
type Root struct {
	SHA256 string            `json:"sha256"`
	Name   string            `json:"name"`
	DER    string            `json:"der"`
	Stores map[string]string `json:"stores"`
}

// Set is the carried stores, read and checked.
type Set struct {
	Retrieved string
	pools     map[Store]*x509.CertPool
	status    map[Store]map[[32]byte]string
}

var (
	carriedOnce sync.Once
	carried     *Set
	carriedErr  error
)

// Carried is the stores this build carries, read once.
func Carried() (*Set, error) {
	carriedOnce.Do(func() {
		carried, carriedErr = Parse(rootsJSON)
	})
	return carried, carriedErr
}

// Parse reads a stores file, refusing it if any certificate does not hash to
// the fingerprint recorded beside it.
func Parse(raw []byte) (*Set, error) {
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, errUnreadable
	}
	if len(f.Roots) > maxRoots {
		return nil, errUnreadable
	}

	out := &Set{
		Retrieved: f.Retrieved,
		pools:     map[Store]*x509.CertPool{},
		status:    map[Store]map[[32]byte]string{},
	}
	for _, s := range All {
		out.pools[s] = x509.NewCertPool()
		out.status[s] = map[[32]byte]string{}
	}

	for _, r := range f.Roots {
		der, err := base64.StdEncoding.DecodeString(r.DER)
		if err != nil {
			return nil, errUnreadable
		}
		sum := sha256.Sum256(der)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), r.SHA256) {
			return nil, ErrCorrupt
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errUnreadable
		}
		for name, status := range r.Stores {
			store := Store(name)
			pool, known := out.pools[store]
			if !known || !validStatus(status) {
				return nil, errUnreadable
			}
			pool.AddCert(cert)
			out.status[store][sum] = status
		}
	}
	return out, nil
}

func validStatus(s string) bool {
	if s == statusTrusted || s == statusConditional {
		return true
	}
	date, ok := strings.CutPrefix(s, distrustPrefix)
	if !ok {
		return false
	}
	_, err := time.Parse(time.DateOnly, date)
	return err == nil
}

// Verdict is what one store makes of a chain.
type Verdict string

const (
	// Trusted: the chain reaches a root the store includes for TLS without
	// conditions this report cannot evaluate.
	Trusted Verdict = "trusted"

	// Conditional: the chain reaches a root the store includes under terms —
	// a client version, a date not published with the store — this report does
	// not evaluate.
	Conditional Verdict = "conditional"

	// Distrusted: the chain reaches a root the store stopped trusting for
	// certificates issued after a date, and this one was issued after it.
	Distrusted Verdict = "distrusted"

	// NotTrusted: the chain reaches no root the store includes.
	NotTrusted Verdict = "not-trusted"
)

// Judgement is one store's answer.
type Judgement struct {
	Store   Store
	Verdict Verdict

	// Root names the root the chain reached, where it reached one.
	Root string

	// After is the distrust date, for Distrusted.
	After string
}

// Judge asks each store whether it would accept the chain at the given time.
//
// The time is the caller's, for the reason certinfo asks its own trust question
// at a chosen moment: an expired certificate fails every store on its dates, and
// whether the stores include its root is a separate question (R4b).
func (s *Set) Judge(chain []*x509.Certificate, at time.Time) []Judgement {
	out := make([]Judgement, 0, len(All))
	if s == nil || len(chain) == 0 {
		return out
	}

	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	for _, store := range All {
		j := Judgement{Store: store, Verdict: NotTrusted}

		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots:         s.pools[store],
			Intermediates: intermediates,
			CurrentTime:   at,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err == nil {
			j = s.best(store, leaf, chains)
		}
		out = append(out, j)
	}
	return out
}

// best is the most favourable answer across every path to a root the store
// includes: a client accepts a chain if any path works.
func (s *Set) best(store Store, leaf *x509.Certificate, chains [][]*x509.Certificate) Judgement {
	rank := map[Verdict]int{Trusted: 3, Conditional: 2, Distrusted: 1, NotTrusted: 0}
	best := Judgement{Store: store, Verdict: NotTrusted}

	for _, chain := range chains {
		root := chain[len(chain)-1]
		status := s.status[store][sha256.Sum256(root.Raw)]

		j := Judgement{Store: store, Root: root.Subject.CommonName}
		switch {
		case status == statusTrusted:
			j.Verdict = Trusted
		case status == statusConditional:
			j.Verdict = Conditional
		case strings.HasPrefix(status, distrustPrefix):
			after := strings.TrimPrefix(status, distrustPrefix)
			cutoff, _ := time.Parse(time.DateOnly, after)
			// The date is the last day certificates were still trusted, so a
			// certificate issued on it is trusted and one issued the day after
			// is not.
			if leaf.NotBefore.Before(cutoff.AddDate(0, 0, 1)) {
				j.Verdict = Trusted
			} else {
				j.Verdict, j.After = Distrusted, after
			}
		default:
			// Unreachable today, and a sabotage turning it into a NotTrusted
			// path escaped every test on 2026-09-14 for that reason rather
			// than for want of one: a pool holds only roots the file gave a
			// status, so every path Verify returns ends at one, and a
			// NotTrusted path could never outrank the NotTrusted best it
			// starts from. Kept so that a status added to the file and not
			// to this switch is skipped rather than read as trust.
			continue
		}
		if rank[j.Verdict] > rank[best.Verdict] {
			best = j
		}
	}
	return best
}

// Summary is one line per root and store, sorted, for comparing two files by
// what they say rather than by when they were fetched.
func Summary(f File) []string {
	var out []string
	for _, r := range f.Roots {
		for store, status := range r.Stores {
			out = append(out, strings.ToLower(r.SHA256)+" "+store+" "+status)
		}
	}
	sort.Strings(out)
	return out
}
