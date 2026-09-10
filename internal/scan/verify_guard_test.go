package scan

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
	"github.com/denyfirst/denyfirst/internal/verify"
)

type nothingPublished struct{}

func (nothingPublished) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, false, nil
}

type oneDomain struct {
	secret []byte
	name   string
}

func (o oneDomain) LookupChallenge(_ context.Context, name string) ([]string, bool, error) {
	if name == verify.Label+"."+o.name {
		return []string{verify.Token(o.secret, o.name)}, true, nil
	}
	return nil, false, nil
}

// A deployment that requires proof scans only what it has been shown, and the
// refusal comes before anything is dialled.
func TestTheTLSScannerRefusesAnUnverifiedNameBeforeDialling(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name for its own reason")
	}

	var dialed bool
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("nothing is listening")
			},
		},
		Verify: &verify.Scope{Secret: []byte("s"), Resolver: nothingPublished{}},
	}

	_, err := s.Scan(context.Background(), "example.test")
	if !errors.Is(err, verify.ErrNotVerified) {
		t.Errorf("Scan returned %v, want the verification refusal", err)
	}
	if dialed {
		t.Error("an unverified name was refused and a connection was opened anyway")
	}
}

// And a name that was proven is scanned. A guard that refused everything would
// satisfy the test above while making the tool useless.
func TestTheTLSScannerScansAVerifiedName(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name for its own reason")
	}

	secret := []byte("s")
	var dialed bool

	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("nothing is listening")
			},
		},
		Verify: &verify.Scope{Secret: secret, Resolver: oneDomain{secret: secret, name: "example.test"}},
	}

	if _, err := s.Scan(context.Background(), "www.example.test"); err != nil {
		t.Fatalf("a name under a proven domain was refused: %v", err)
	}
	if !dialed {
		t.Error("a verified name was accepted and nothing was ever dialled")
	}
}

// Nil means no proof is required, which is what the command line wants.
func TestTheTLSScannerNeedsNoProofByDefault(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name for its own reason")
	}

	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("nothing is listening")
			},
		},
	}

	if _, err := s.Scan(context.Background(), "example.test"); err != nil {
		t.Errorf("a scanner with no scope refused a name: %v", err)
	}
}

// An excluded name is refused as excluded, whether or not control of it was
// proven, and the order that produces that is the point.
//
// Proving control does not put an excluded name back in reach: the list says
// which names this project will not touch, whoever asks and whatever they have
// shown (N8). Asked the other way round, an operator is told to publish a TXT
// record for a name that will be refused after they publish it — work that
// changes nothing, prompted by this program.
func TestAnExcludedNameIsRefusedAsExcludedRatherThanAsUnproven(t *testing.T) {
	secret := []byte("s")

	for _, tc := range []struct {
		name     string
		resolver verify.Resolver
	}{
		// The case that distinguishes the two orders: nothing is published,
		// so a scope asked first would answer before the list is reached.
		{"nothing proven", nothingPublished{}},
		{"control proven", oneDomain{secret: secret, name: "army.mil"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Scanner{Verify: &verify.Scope{Secret: secret, Resolver: tc.resolver}}

			_, err := s.Scan(context.Background(), "army.mil")
			if err == nil {
				t.Fatal("an excluded name was scanned")
			}
			if errors.Is(err, verify.ErrNotVerified) {
				t.Fatalf("the excluded name was refused for want of proof (%v); the list is asked "+
					"after the scope, so an operator is sent to publish a record that changes nothing", err)
			}
		})
	}
}
