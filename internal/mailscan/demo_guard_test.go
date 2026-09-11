//go:build demo

package mailscan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
)

// A demonstration build refuses a domain this project does not own, whatever
// asks it.
//
// Written because the last two checks to arrive here — the revocation list and
// the transparency log search — each shipped a promise about what the
// demonstration does with nothing guarding it, and both were caught by a
// sabotage rather than by a test. The guard is in Scan rather than in a caller,
// so an entry point written later inherits it instead of having to remember it.
func TestTheMailScannerRefusesADomainThisProjectDoesNotOwn(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	_, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if !errors.Is(err, demo.ErrNotATarget) {
		t.Fatalf("Scan(example.com) = %v, want demo.ErrNotATarget", err)
	}
}

// A refused domain is never asked about.
//
// The whole reason the guard sits where it does, and the version of this that
// matters most for a check made of lookups: the refusal is not about opening a
// socket, it is about the query leaving at all. A guard below the lookups would
// return the same error and would already have told a resolver which domain
// somebody was curious about.
func TestARefusedDomainIsNeverLookedUp(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	if _, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com"); !errors.Is(err, demo.ErrNotATarget) {
		t.Fatalf("Scan = %v, want demo.ErrNotATarget", err)
	}
	if len(z.asked) != 0 {
		t.Errorf("%d lookup(s) were made for a domain this deployment refuses: %v", len(z.asked), z.asked)
	}
}

// The refusal names no domain (I6).
func TestTheMailRefusalNamesNoDomain(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	_, err := (&Scanner{Resolver: z}).Scan(context.Background(), "secret-internal-name.example")
	if err == nil {
		t.Fatal("a domain outside the list was accepted")
	}
	if strings.Contains(err.Error(), "secret-internal-name") {
		t.Errorf("the refusal names the domain back: %v", err)
	}
}

// A mistyped target is told it is mistyped.
//
// Asked the other way round, a demonstration build answers "this deployment
// does not demonstrate that" to somebody who typed a scheme or a port, which
// tells them the wrong thing about their own mistake.
func TestAMistypedDomainIsToldItIsMistyped(t *testing.T) {
	z := &zone{records: map[string][]string{}}

	for _, bad := range []string{"example.com:25", "https://example.com", "localhost", ""} {
		_, err := (&Scanner{Resolver: z}).Scan(context.Background(), bad)
		if errors.Is(err, demo.ErrNotATarget) {
			t.Errorf("Scan(%q) was refused as undemonstrated rather than as invalid", bad)
		}
		if !errors.Is(err, errNotADomain) {
			t.Errorf("Scan(%q) = %v, want errNotADomain", bad, err)
		}
	}
}

func TestTheTagSwitchesTheMailScannerToo(t *testing.T) {
	if !demo.Enabled {
		t.Fatal("built with the demo tag and demo.Enabled is false")
	}
}
