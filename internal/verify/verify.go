// Package verify decides whether a deployment has been shown control of a
// domain before it will scan it.
//
// It is the sibling of internal/exclusion and internal/demo: the same
// boundary, asked in the same place, from a third source of authority. The
// exclusion list is what this project will not touch, whoever asks. The
// demonstration list is compiled into a binary. This one is established at run
// time, by the operator, about their own estate — and it is the one that makes
// a self-hosted service safe to put on a network.
//
// Without it, a denyfirstd anyone can reach is the arrangement N6 dismantled,
// rebuilt inside somebody's intranet: a colleague types a hostname, a
// compromised CI job types a different one, an SSRF into the scanner types
// whatever it likes, and it is the operator's address in a stranger's logs.
// docs/scope.md is the design and the reasoning; this is the code.
//
// # What proof is
//
// A TXT record at _denyfirst-challenge.<domain> carrying the token this
// deployment expects for that domain. Publishing it requires control of the
// zone, which is the thing being proven.
//
// # The token is per domain
//
// Not one secret published everywhere. A single value readable in public DNS
// would let anyone who looked at one domain's record publish the same string
// on a name they control — including a name pointed at somebody else's
// address — and have this deployment scan it. So the token is derived from a
// deployment secret and the domain together, and reading one tells nobody
// anything about another.
//
// # Nothing is remembered
//
// A verification that is checked once and stored is a standing authorisation
// outliving the relationship it came from: a domain changes hands, a supplier
// contract ends, a subsidiary is sold. Re-reading also means revocation works
// by deleting the record, which is the only revocation an operator will
// actually find. A lookup is one round trip.
package verify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
)

// Label is the name a challenge is published under, beneath the domain.
const Label = "_denyfirst-challenge"

// ErrNotVerified is returned for a domain this deployment has not been shown
// control of.
//
// The message states the rule and names no host (I3). Which domain was refused
// is something the caller already knows and the operator can see; putting it
// here would put it in every error string that error travels through.
var ErrNotVerified = errors.New("this deployment scans only domains it has been shown control of")

// Resolver is the lookup this package needs. internal/dnsclient satisfies it.
//
// An interface so that a test can answer without a network, and so that this
// package does not decide how DNS is spoken. It is the narrowest shape that
// does the job: one name, the values found, and whether the name exists.
type Resolver interface {
	LookupChallenge(ctx context.Context, name string) (values []string, existed bool, err error)
}

// Token is what a domain has to publish to be scannable by this deployment.
//
// Derived from the deployment's secret and the domain, so that one domain's
// record proves nothing about another. Base32 without padding because a TXT
// value is read and retyped by people, and an alphabet without case or
// punctuation survives that.
func Token(secret []byte, domain string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(fold(domain)))

	return "denyfirst-verification=" +
		strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil)[:20]))
}

// Scope decides which names a proof covers.
type Scope struct {
	// Secret is what tokens are derived from. A deployment with none verifies
	// nothing, which is the safe reading of an incomplete configuration: the
	// alternative is a scanner that accepts any record it finds.
	Secret []byte

	// Resolver reads the challenge. Nil means nothing can be proven.
	Resolver Resolver
}

// Covers reports whether this deployment has been shown control of the host,
// or of a domain above it.
//
// A record at example.com covers www.example.com, and that is deliberate: a
// zone is what a TXT record proves control of, and requiring one record per
// hostname would mean an operator publishing a record for every name they
// intend to look at, which nobody would do. What it does not do is cover a
// name delegated away — that cannot be seen from a TXT lookup, and
// docs/scope.md says why the honest answer is to say what is being reached
// rather than to invent a rule about it.
//
// The walk is bounded and starts at the host itself, so the most specific
// proof wins and a deployment that has been shown control of one subdomain
// does not thereby reach its parent.
func (s Scope) Covers(ctx context.Context, host string) error {
	if len(s.Secret) == 0 || s.Resolver == nil {
		// Not an error about the host. A deployment configured to require
		// proof and given no way to check it must refuse rather than admit,
		// but the reason is local and the message says which it is.
		return errors.New("this deployment requires proof of control and has no way to check it")
	}

	host = fold(host)
	if host == "" {
		return ErrNotVerified
	}

	labels := strings.Split(host, ".")

	// Two labels is the shortest thing a challenge can be published under, so
	// the walk stops there rather than asking about a public suffix. It would
	// find nothing, and asking is a query somebody else's resolver serves.
	for i := 0; i+1 < len(labels); i++ {
		domain := strings.Join(labels[i:], ".")

		values, _, err := s.Resolver.LookupChallenge(ctx, Label+"."+domain)
		if err != nil {
			// A lookup that failed is not a domain that is unverified, and
			// the difference matters: reporting the second would tell an
			// operator to publish a record they have already published.
			return err
		}

		want := Token(s.Secret, domain)
		for _, v := range values {
			// Constant time, because the comparison is against a value an
			// outsider supplies and a token is the whole of the proof.
			if hmac.Equal([]byte(strings.TrimSpace(strings.ToLower(v))), []byte(want)) {
				return nil
			}
		}
	}

	return ErrNotVerified
}

// fold reduces a name the way every other comparison in this project does.
//
// DNS is case-insensitive and a trailing dot names the same zone, so a token
// derived from one spelling has to match a record published under another
// (I7). Done here as well as wherever a caller folded, because a guard that
// depends on its caller having folded is a guard that fails on the first
// caller who did not.
func fold(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
