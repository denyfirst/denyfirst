//go:build !demo

package webscan

import (
	"context"
	"errors"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// The ordinary build has no list to be outside of.
//
// Under the demo tag, because without it there is nothing to assert: this is
// the tool, and the tool scans whatever it is pointed at. A guard that fired
// here would be the deployment restriction leaking into every copy anybody
// runs, which is the opposite of what this project decided.
func TestTheOrdinaryWebScannerIsNotADemonstration(t *testing.T) {
	if demo.Enabled {
		t.Fatal("built without the demo tag and demo.Enabled is true")
	}

	s := &Scanner{Prober: &webprobe.Prober{Dial: refuseToDial}}
	_, err := s.Scan(context.Background(), "example.com")
	if errors.Is(err, demo.ErrNotATarget) {
		t.Fatal("the ordinary build refused a host as undemonstrated")
	}
}
