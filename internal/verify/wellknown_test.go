package verify

import (
	"context"
	"errors"
	"testing"
)

// serves answers the file challenge from a table.
type serves map[string]string

func (s serves) FetchChallenge(_ context.Context, host string) (string, error) {
	body, ok := s[host]
	if !ok {
		return "", ErrNoChallenge
	}
	return body, nil
}

// failingFetch answers every fetch with an error.
type failingFetch struct{ err error }

func (f failingFetch) FetchChallenge(context.Context, string) (string, error) {
	return "", f.err
}

func fileScope(f Fetcher) Scope {
	return Scope{Secret: secret, Resolver: published{}, Fetcher: f}
}

// A host serving the file is scannable by a check that reads it over HTTP.
//
// The method exists for teams without access to their own DNS, which is a
// common enough arrangement that refusing them would mean refusing the estates
// this tool is for.
func TestAServedFileProvesTheHost(t *testing.T) {
	f := serves{"www.example.com": Token(secret, "www.example.com")}

	if err := fileScope(f).Covers(context.Background(), "www.example.com", HTTPOnly); err != nil {
		t.Errorf("a host serving its own challenge was refused: %v", err)
	}
}

// And it proves that host and nothing else.
//
// A record in a zone is a statement about the zone. A file on a host is a
// statement about the host, and reading it as the first would let one file
// open every name under a domain — including the ones delegated to somebody
// else, which is the failure docs/scope.md is written about.
func TestAServedFileProvesNoOtherName(t *testing.T) {
	f := serves{"www.example.com": Token(secret, "www.example.com")}

	for _, host := range []string{
		"example.com",          // the parent
		"deep.www.example.com", // a name beneath it
		"other.example.com",    // a sibling
	} {
		if err := fileScope(f).Covers(context.Background(), host, HTTPOnly); !errors.Is(err, ErrNotVerified) {
			t.Errorf("Covers(%q) = %v; a file on one host proved another name", host, err)
		}
	}
}

// And it does not prove a check that reaches a port a browser never touches.
//
// This is the distinction the surface exists for. A file served over HTTPS
// proves control of what one hostname answers on 443. It proves nothing about
// port 993 on the same name: a content network serves the file while the mail
// service answers from an origin the person who placed it may not administer.
func TestAServedFileDoesNotProveACheckThatLeavesTheBrowsersPorts(t *testing.T) {
	f := serves{"www.example.com": Token(secret, "www.example.com")}

	if err := fileScope(f).Covers(context.Background(), "www.example.com", AnyPort); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Covers(AnyPort) = %v; a file proved a check that may open port 993", err)
	}
}

// The zone proof covers every surface, which is the difference between them.
func TestTheZoneProofCoversEverySurface(t *testing.T) {
	p := published{Label + ".example.com": {Token(secret, "example.com")}}

	for _, surface := range []Surface{HTTPOnly, AnyPort} {
		if err := (Scope{Secret: secret, Resolver: p}).Covers(context.Background(), "www.example.com", surface); err != nil {
			t.Errorf("the zone proof did not cover surface %v: %v", surface, err)
		}
	}
}

// A file carrying the wrong token proves nothing.
//
// The direction a fetcher that returned anything at all would satisfy.
func TestAFileWithTheWrongTokenIsRefused(t *testing.T) {
	for _, body := range []string{
		"",
		"anything",
		Token(secret, "example.com"), // the parent's token
		Token([]byte("other"), "www.example.com"), // another deployment's
	} {
		f := serves{"www.example.com": body}
		if err := fileScope(f).Covers(context.Background(), "www.example.com", HTTPOnly); !errors.Is(err, ErrNotVerified) {
			t.Errorf("a file containing %q was accepted", body)
		}
	}
}

// A fetch that failed is not a host that published nothing.
//
// The same distinction the DNS half makes, and it matters more here: a host
// that is down fails the fetch, and telling its operator to publish a file
// they have already published sends them to the wrong place entirely.
func TestAFailedFetchIsNotAHostThatPublishedNothing(t *testing.T) {
	boom := errors.New("the host could not be reached over TLS")

	err := Scope{Secret: secret, Resolver: published{}, Fetcher: failingFetch{boom}}.
		Covers(context.Background(), "www.example.com", HTTPOnly)

	if errors.Is(err, ErrNotVerified) {
		t.Error("a host that could not be reached was reported as one that published nothing")
	}
	if !errors.Is(err, boom) {
		t.Errorf("the fetch failure was replaced with %v", err)
	}
}

// A host serving no file falls through to the refusal rather than to an error.
//
// ErrNoChallenge is the fetcher saying the host answered and had nothing,
// which is the fact the operator acts on.
func TestAHostServingNoFileIsRefusedRatherThanErrored(t *testing.T) {
	err := fileScope(serves{}).Covers(context.Background(), "www.example.com", HTTPOnly)

	if !errors.Is(err, ErrNotVerified) {
		t.Errorf("Covers = %v, want the verification refusal", err)
	}
}

// No fetcher means the file method is not offered, which is the stricter
// arrangement and therefore the right thing for nil to mean.
func TestNoFetcherMeansOnlyTheZoneProofWorks(t *testing.T) {
	err := Scope{Secret: secret, Resolver: published{}}.
		Covers(context.Background(), "www.example.com", HTTPOnly)

	if !errors.Is(err, ErrNotVerified) {
		t.Errorf("Covers = %v, want the verification refusal", err)
	}
}

// The zone proof is asked first, and a host with one is never fetched from.
//
// DNS is cheaper, covers more, and costs the scanned host nothing — where a
// fetch is a request this deployment makes to their server on every scan.
func TestAHostWithAZoneProofIsNeverFetchedFrom(t *testing.T) {
	var fetched bool
	watching := watchingFetcher{fetched: &fetched}

	p := published{Label + ".example.com": {Token(secret, "example.com")}}
	if err := (Scope{Secret: secret, Resolver: p, Fetcher: watching}).
		Covers(context.Background(), "www.example.com", HTTPOnly); err != nil {
		t.Fatalf("a name under a proven zone was refused: %v", err)
	}

	if fetched {
		t.Error("a host whose zone was proven was asked for a file as well, which is a request " +
			"this deployment makes to their server for nothing")
	}
}

type watchingFetcher struct{ fetched *bool }

func (w watchingFetcher) FetchChallenge(context.Context, string) (string, error) {
	*w.fetched = true
	return "", ErrNoChallenge
}
