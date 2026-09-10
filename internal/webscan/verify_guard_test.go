package webscan

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/verify"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// nothingPublished proves no domain.
type nothingPublished struct{}

func (nothingPublished) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, false, nil
}

// oneDomain proves exactly the domain it was built for.
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
//
// The guard is in Scan rather than in whatever calls it, so it holds for the
// command line and for entry points not written yet — the same argument N6
// makes about the demonstration list, and the one that decides whether a
// service anyone on a network can reach is a scanner for that network.
func TestAnUnverifiedNameIsRefusedBeforeAnythingIsDialled(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name before the scope is reached")
	}

	// atomic because the prober opens several connections at once: tlsprobe
	// probes every version in parallel, and a plain bool written from those
	// goroutines and read here is a race the -race build finds. It only finds
	// it on Linux, because -race needs cgo and a Go installation on Windows
	// brings no C toolchain, so CI is the first place this shows.
	var dialed atomic.Bool
	s := &Scanner{
		Prober: &webprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, errors.New("nothing is listening")
			},
			RequestTimeout: time.Second,
			TotalTimeout:   2 * time.Second,
		},
		Verify: &verify.Scope{Secret: []byte("s"), Resolver: nothingPublished{}},
	}

	_, err := s.Scan(context.Background(), "example.test")
	if !errors.Is(err, verify.ErrNotVerified) {
		t.Errorf("Scan returned %v, want the verification refusal", err)
	}
	if dialed.Load() {
		t.Error("an unverified name was refused and a connection was opened anyway")
	}
}

// And a name that was proven is scanned.
//
// The other direction. A guard that refused everything would satisfy the test
// above while making the tool useless, and that failure is quieter than it
// sounds: an operator who has published the record and still cannot scan reads
// it as a bug in their DNS.
func TestAVerifiedNameIsScanned(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name before the scope is reached")
	}

	secret := []byte("s")
	// atomic because the prober opens several connections at once: tlsprobe
	// probes every version in parallel, and a plain bool written from those
	// goroutines and read here is a race the -race build finds. It only finds
	// it on Linux, because -race needs cgo and a Go installation on Windows
	// brings no C toolchain, so CI is the first place this shows.
	var dialed atomic.Bool

	s := &Scanner{
		Prober: &webprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, errors.New("nothing is listening")
			},
			RequestTimeout: time.Second,
			TotalTimeout:   2 * time.Second,
		},
		Verify: &verify.Scope{Secret: secret, Resolver: oneDomain{secret: secret, name: "example.test"}},
	}

	if _, err := s.Scan(context.Background(), "www.example.test"); err != nil {
		t.Fatalf("a name under a proven domain was refused: %v", err)
	}
	if !dialed.Load() {
		t.Error("a verified name was accepted and nothing was ever dialled")
	}
}

// Nil means no proof is required, which is what the command line wants.
//
// Whoever runs it already has the machine and the scan leaves from their own
// address. A default that required proof there would stop somebody scanning
// their own network, which is what the tool is for.
func TestNoScopeMeansNoProofIsRequired(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name for its own reason")
	}

	s := &Scanner{
		Prober: &webprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("nothing is listening")
			},
			RequestTimeout: time.Second,
			TotalTimeout:   2 * time.Second,
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

// servesFile proves one host through the file method and nothing through DNS.
type servesFile struct {
	secret []byte
	host   string
}

func (s servesFile) FetchChallenge(_ context.Context, host string) (string, error) {
	if host == s.host {
		return verify.Token(s.secret, s.host), nil
	}
	return "", verify.ErrNoChallenge
}

// A file proof does open the web check.
//
// The other side of the surface, and the half that makes the method worth
// having: it exists for teams without access to their own DNS, and a file that
// proved nothing anywhere would be a method nobody can use. What it proves is
// what a web check reads — one hostname, the way a browser reaches it.
func TestAFileProofOpensTheWebCheck(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name before the scope is reached")
	}

	secret := []byte("s")
	var dialed atomic.Bool

	s := &Scanner{
		Prober: &webprobe.Prober{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, errors.New("nothing is listening")
			},
			RequestTimeout: time.Second,
			TotalTimeout:   2 * time.Second,
		},
		Verify: &verify.Scope{
			Secret:   secret,
			Resolver: nothingPublished{},
			Fetcher:  servesFile{secret: secret, host: "example.test"},
		},
	}

	if _, err := s.Scan(context.Background(), "example.test"); err != nil {
		t.Fatalf("a host serving its own challenge was refused: %v", err)
	}
	if !dialed.Load() {
		t.Error("a proven host was accepted and nothing was ever dialled")
	}
}

// And it opens that host only.
//
// A file on one host says nothing about a name beneath it. Reading it as a
// zone proof would let one file open every name under a domain, including the
// ones delegated to somebody else.
func TestAFileProofDoesNotOpenAnotherName(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name before the scope is reached")
	}

	secret := []byte("s")
	s := &Scanner{
		Verify: &verify.Scope{
			Secret:   secret,
			Resolver: nothingPublished{},
			Fetcher:  servesFile{secret: secret, host: "example.test"},
		},
	}

	if _, err := s.Scan(context.Background(), "www.example.test"); !errors.Is(err, verify.ErrNotVerified) {
		t.Errorf("Scan returned %v; a file on one host opened another name", err)
	}
}
