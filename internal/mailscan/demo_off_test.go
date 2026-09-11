//go:build !demo

package mailscan

import (
	"context"
	"errors"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
)

// The ordinary build has no list to be outside of.
//
// Asserted rather than assumed, for the reason the web check asserts it: a
// guard that fired here would be the demonstration's restriction leaking into
// every copy anybody runs, and the person it would stop is an operator reading
// their own domain's mail policy on their own machine.
func TestTheOrdinaryMailScannerIsNotADemonstration(t *testing.T) {
	if demo.Enabled {
		t.Fatal("built without the demo tag and demo.Enabled is true")
	}

	z := &zone{records: map[string][]string{}}
	if _, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com"); errors.Is(err, demo.ErrNotATarget) {
		t.Fatal("the ordinary build refused a domain as undemonstrated")
	}
}
