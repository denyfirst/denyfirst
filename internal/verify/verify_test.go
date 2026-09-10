package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// published answers from a table, so a test needs no network.
type published map[string][]string

func (p published) LookupChallenge(_ context.Context, name string) ([]string, bool, error) {
	values, ok := p[name]
	return values, ok, nil
}

// failing answers every lookup with an error.
type failing struct{ err error }

func (f failing) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, false, f.err
}

var secret = []byte("a deployment secret")

func scope(p Resolver) Scope { return Scope{Secret: secret, Resolver: p} }

// A domain that published the token is scannable, and so is a name beneath it.
//
// The zone is what a TXT record proves control of. Requiring one record per
// hostname would mean publishing a record for every name an operator intends
// to look at, which nobody would do, and an estate checked by nobody is worth
// less than one checked with a broader proof.
func TestAPublishedTokenCoversTheZone(t *testing.T) {
	p := published{
		Label + ".example.com": {Token(secret, "example.com")},
	}

	for _, host := range []string{
		"example.com",
		"www.example.com",
		"deep.nested.example.com",
		"EXAMPLE.COM",
		"www.example.com.",
	} {
		if err := scope(p).Covers(context.Background(), host); err != nil {
			t.Errorf("Covers(%q) = %v, want nil", host, err)
		}
	}
}

// And a domain that published nothing is refused.
//
// The other direction, and the one a scope that returned nil on every path
// would satisfy silently. This is the whole boundary: without it a service
// anyone on a network can reach is a scanner for that network.
func TestADomainThatProvedNothingIsRefused(t *testing.T) {
	p := published{
		Label + ".example.com": {Token(secret, "example.com")},
	}

	for _, host := range []string{
		"example.org",
		"www.example.org",
		"notexample.com",
		"example.com.attacker.test",
	} {
		if err := scope(p).Covers(context.Background(), host); !errors.Is(err, ErrNotVerified) {
			t.Errorf("Covers(%q) = %v, want ErrNotVerified", host, err)
		}
	}
}

// One domain's token proves nothing about another.
//
// This is why the token is derived per domain rather than being one secret
// published everywhere. A single value readable in public DNS would let
// anybody who looked at one record publish the same string on a name they
// control — including a name pointed at somebody else's address — and have
// this deployment scan it.
func TestATokenFromOneDomainDoesNotProveAnother(t *testing.T) {
	mine := Token(secret, "example.com")
	theirs := Token(secret, "attacker.test")

	if mine == theirs {
		t.Fatal("two domains derive the same token, so publishing one record proves control of every domain")
	}

	// The attacker publishes what they read from example.com's DNS.
	p := published{
		Label + ".attacker.test": {mine},
	}
	if err := scope(p).Covers(context.Background(), "attacker.test"); !errors.Is(err, ErrNotVerified) {
		t.Error("a token copied from another domain was accepted")
	}
}

// A token depends on the secret, so one deployment's proof is not another's.
func TestATokenFromAnotherDeploymentIsNotAccepted(t *testing.T) {
	other := Token([]byte("a different deployment"), "example.com")

	p := published{Label + ".example.com": {other}}
	if err := scope(p).Covers(context.Background(), "example.com"); !errors.Is(err, ErrNotVerified) {
		t.Error("a token derived from another deployment's secret was accepted")
	}
}

// A record among others is found.
//
// A name carries TXT records for several unrelated purposes — SPF, a site
// verification for somebody else's product — and a scope that only read the
// first would refuse a domain that had done everything asked of it.
func TestTheTokenIsFoundAmongOtherRecords(t *testing.T) {
	p := published{
		Label + ".example.com": {
			"v=spf1 -all",
			"some-other-product-verification=abc123",
			Token(secret, "example.com"),
		},
	}

	if err := scope(p).Covers(context.Background(), "example.com"); err != nil {
		t.Errorf("a token published beside other records was not found: %v", err)
	}
}

// A deployment that requires proof and cannot check it refuses.
//
// The safe reading of an incomplete configuration, and the same argument
// safedial and AllowAnyPort already make: a protection that fails open is one
// that is eventually off without anybody noticing.
func TestAScopeThatCannotCheckRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope Scope
	}{
		{"no secret", Scope{Resolver: published{}}},
		{"no resolver", Scope{Secret: secret}},
		{"neither", Scope{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.scope.Covers(context.Background(), "example.com"); err == nil {
				t.Error("a scope that cannot check anything admitted a host")
			}
		})
	}
}

// A lookup that failed is not a domain that is unverified.
//
// Reporting the second would tell an operator to publish a record they have
// already published, and send them looking at their DNS instead of at the
// resolver that would not answer.
func TestALookupFailureIsNotAnUnverifiedDomain(t *testing.T) {
	boom := errors.New("the resolver did not answer")

	err := Scope{Secret: secret, Resolver: failing{boom}}.Covers(context.Background(), "example.com")
	if errors.Is(err, ErrNotVerified) {
		t.Error("a resolver that would not answer was reported as a domain that proved nothing")
	}
	if !errors.Is(err, boom) {
		t.Errorf("the lookup failure was replaced with %v", err)
	}
}

// The refusal states the rule and names no host (I3).
func TestTheRefusalNamesNoHost(t *testing.T) {
	err := scope(published{}).Covers(context.Background(), "secret-internal-name.example.com")
	if err == nil {
		t.Fatal("an unverified host was admitted")
	}
	if strings.Contains(err.Error(), "secret-internal-name") {
		t.Errorf("the refusal repeats the host back: %v", err)
	}
}

// The walk stops before a public suffix.
//
// Asking about a challenge under "com" would find nothing and would be a query
// somebody else's resolver serves. It also could not succeed: nobody publishes
// a record there, and if anybody could, one record would open every domain
// beneath it.
func TestTheWalkDoesNotReachForAPublicSuffix(t *testing.T) {
	var asked []string
	p := recorder{asked: &asked, values: published{}}

	_ = Scope{Secret: secret, Resolver: p}.Covers(context.Background(), "www.example.com")

	for _, name := range asked {
		if name == Label+".com" {
			t.Error("the walk asked about a challenge under a public suffix")
		}
	}
	if len(asked) == 0 {
		t.Fatal("no lookup was made at all")
	}
}

// The most specific proof is asked for first, so a subdomain can be verified
// without its parent being.
func TestTheMostSpecificNameIsAskedFirst(t *testing.T) {
	var asked []string
	p := recorder{asked: &asked, values: published{}}

	_ = Scope{Secret: secret, Resolver: p}.Covers(context.Background(), "a.b.example.com")

	want := []string{
		Label + ".a.b.example.com",
		Label + ".b.example.com",
		Label + ".example.com",
	}
	for i, name := range want {
		if i >= len(asked) || asked[i] != name {
			t.Fatalf("lookups were %v, want them to begin %v", asked, want)
		}
	}
}

// A token is stable, and it is what an operator is told to publish.
func TestATokenIsStableAndSpellable(t *testing.T) {
	first := Token(secret, "example.com")
	if first != Token(secret, "example.com") {
		t.Error("two calls produced different tokens, so a published record would stop matching")
	}
	if first != Token(secret, "EXAMPLE.COM.") {
		t.Error("a token depends on the spelling of the name, so a record published under one " +
			"form would not match a scan of another")
	}
	if !strings.HasPrefix(first, "denyfirst-verification=") {
		t.Errorf("a token does not say what it is: %q", first)
	}

	value := strings.TrimPrefix(first, "denyfirst-verification=")
	if strings.ContainsAny(value, "=+/ ") {
		t.Errorf("a token carries characters that do not survive being retyped: %q", value)
	}
}

// recorder notes what was asked, so the shape of the walk can be checked.
type recorder struct {
	asked  *[]string
	values published
}

func (r recorder) LookupChallenge(ctx context.Context, name string) ([]string, bool, error) {
	*r.asked = append(*r.asked, name)
	return r.values.LookupChallenge(ctx, name)
}
