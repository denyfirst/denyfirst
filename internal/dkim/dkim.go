// Package dkim reads the signing keys a domain publishes, at selectors it is
// told to look under.
//
// # Why a selector has to be named
//
// A DKIM key lives at <selector>._domainkey.<domain>, and DNS offers no way to
// list what is under a name. There is no query for "every selector this domain
// has": the only way to find one is to know it already, or to try names and see
// which answer.
//
// Every other tool tries names, and the reason is that every other tool is a
// web form — a stranger types a domain and there is nobody to ask. That is not
// this tool's position. An installation somebody runs themselves is being run
// by the person who set the records up, and asking them is available here in a
// way it is not to a form.
//
// So selectors come from two places, and the report always says which:
//
//   - **Named by the operator.** Exact, and the only authoritative source.
//   - **Documented by a provider.** Google Workspace documents "google";
//     Microsoft 365 documents "selector1" and "selector2". These are not a
//     list this project invented and then graded people against — each is
//     published by the provider whose service uses it, and each entry here
//     carries the provider it belongs to so a reader can go and check.
//
// The second is a convenience and never a claim. A domain where none of them
// answer has not been shown to lack DKIM; it has been shown that these
// particular names hold nothing, and the report says exactly that (R4).
//
// # Why looking is not the guessing this project refuses
//
// Everywhere else, "no guessing" means no constructing paths on somebody's
// server: no /admin, no probing under /.well-known. That rule is about requests
// that reach the scanned party, appear in their access log, and look like an
// attack.
//
// A DNS lookup reaches the target's zone, not the target. A name that does not
// exist costs a resolver one answer and the domain nothing at all, and a key
// that does exist is published for every receiving mail server on the internet
// to read. The two are different acts and this package does the second.
package dkim

import (
	"context"
	"strconv"
	"strings"
)

const (
	// keyPrefix is where a key lives, beneath the selector.
	keyPrefix = "._domainkey."

	// maxSelectors bounds how many names one scan will look under.
	//
	// The operator supplies these, so this is not a defence against them. It
	// bounds what one scan costs a resolver when somebody pastes a list, and it
	// keeps a report a report.
	maxSelectors = 16

	// maxTagLength bounds one value read out of a record.
	maxTagLength = 512

	// weakKeyBits is the size below which RFC 8301 says a verifier may treat a
	// signature as insecure.
	//
	// Not a threshold this project chose. RFC 8301 raised the floor to 1024
	// explicitly, and says signers SHOULD use at least 1024 and verifiers MAY
	// treat shorter keys as insecure — so a key under it is one a receiver is
	// entitled to ignore, which is a fact about the key rather than an opinion
	// about it.
	weakKeyBits = 1024
)

// Resolver is the lookup this package needs.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) (values []string, existed bool, err error)
}

// Source says where a selector came from, because it changes what an absence
// means.
type Source string

const (
	// FromOperator is a selector somebody named on the command line. An
	// absence here is a fact worth reporting: they said it should be there.
	FromOperator Source = "named"

	// FromProvider is a selector a mail provider documents. An absence means
	// only that this name holds nothing.
	FromProvider Source = "documented"
)

// Key is what one selector held.
type Key struct {
	Selector string `json:"selector"`
	Source   Source `json:"source"`

	// Found is whether a DKIM record was there at all.
	Found bool `json:"found"`

	// Reason says why the lookup could not be made. A failure to look is not
	// an absence (R4).
	Reason string `json:"reason,omitempty"`

	// Algorithm is what k= said: "rsa", "ed25519", or empty for the default,
	// which RFC 6376 makes rsa.
	Algorithm string `json:"algorithm,omitempty"`

	// Bits is the size of an RSA key, or 0 where it could not be read or the
	// algorithm is not RSA.
	Bits int `json:"bits,omitempty"`

	// Revoked is true when p= is present and empty, which RFC 6376 defines as
	// a revoked key rather than a broken record. A signature made with it
	// cannot verify, deliberately.
	Revoked bool `json:"revoked,omitempty"`

	// Testing is true when t=y. RFC 6376: a verifier must not treat a failure
	// under a testing key as a reason to reject, so a domain that left this on
	// after a rollout has a signature nobody acts on.
	Testing bool `json:"testing,omitempty"`
}

// Facts is what looking under a set of selectors established.
type Facts struct {
	// Looked is true when any selector was asked about at all. Without it an
	// empty Keys is silence rather than absence.
	Looked bool `json:"looked"`

	// Keys is one entry per selector asked about, in the order asked.
	Keys []Key `json:"keys,omitempty"`
}

// Selector is a name to look under, and where it came from.
type Selector struct {
	Name   string
	Source Source
}

// Check reads the key at each selector.
func Check(ctx context.Context, r Resolver, domain string, selectors []Selector) Facts {
	if len(selectors) == 0 {
		return Facts{}
	}
	if len(selectors) > maxSelectors {
		selectors = selectors[:maxSelectors]
	}

	facts := Facts{Looked: true}
	seen := map[string]bool{}

	for _, s := range selectors {
		name := fold(s.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true

		facts.Keys = append(facts.Keys, read(ctx, r, name, s.Source, domain))
	}

	return facts
}

// read looks under one selector.
func read(ctx context.Context, r Resolver, selector string, source Source, domain string) Key {
	key := Key{Selector: selector, Source: source}

	values, _, err := r.LookupTXT(ctx, selector+keyPrefix+domain)
	if err != nil {
		// The shape of the failure only: the underlying error names resolvers
		// and addresses (I6).
		key.Reason = "the record could not be read"
		return key
	}

	// A record is DKIM only if it announces itself. RFC 6376 makes v= optional
	// for a key record, so a record carrying p= counts too — but something that
	// merely mentions the name does not.
	for _, v := range values {
		tags := parseTags(v)
		if !isKey(tags) {
			continue
		}

		key.Found = true
		key.Algorithm = tags["k"]

		if p, ok := tags["p"]; ok && strings.TrimSpace(p) == "" {
			// RFC 6376 §3.6.1: an empty p= is a revoked key, not a broken
			// record. The distinction matters — one is a decision and the
			// other is a mistake.
			key.Revoked = true
		} else if ok {
			key.Bits = rsaBits(p, tags["k"])
		}

		key.Testing = hasFlag(tags["t"], "y")
		return key
	}

	return key
}

// isKey reports whether a TXT value is a DKIM key record.
func isKey(tags map[string]string) bool {
	if v, ok := tags["v"]; ok {
		return strings.EqualFold(strings.TrimSpace(v), "DKIM1")
	}
	// No v= at all. RFC 6376 permits it, so a record carrying a public key is
	// one; anything else at this name is somebody else's note.
	_, hasKey := tags["p"]
	return hasKey
}

// hasFlag reports whether a colon-separated flag list carries one.
func hasFlag(list, want string) bool {
	for _, f := range strings.Split(list, ":") {
		if strings.EqualFold(strings.TrimSpace(f), want) {
			return true
		}
	}
	return false
}

// parseTags reads a record into its tag=value pairs.
//
// Values come from a zone the scanned party controls, so each is bounded before
// it is kept.
func parseTags(record string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if _, taken := out[name]; taken {
			continue
		}
		out[name] = bound(strings.TrimSpace(value))
	}
	return out
}

func bound(s string) string {
	if len(s) > maxTagLength {
		return s[:maxTagLength]
	}
	return s
}

func fold(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Weak reports whether a key is one RFC 8301 says a verifier may treat as
// insecure.
func (k Key) Weak() bool {
	return k.Found && !k.Revoked && k.Bits > 0 && k.Bits < weakKeyBits
}

// Describe renders a key's size the way a report says it.
//
// Empty for a selector that held nothing. A key that was not found has no
// description, and returning one made the JSON say describes:"published" beside
// found:false — two fields disagreeing about the same record.
func (k Key) Describe() string {
	if !k.Found {
		return ""
	}
	switch {
	case k.Revoked:
		return "revoked"
	case k.Algorithm == "ed25519":
		return "Ed25519"
	case k.Bits > 0:
		return "RSA " + strconv.Itoa(k.Bits)
	case k.Algorithm != "":
		return k.Algorithm
	default:
		return "published"
	}
}
