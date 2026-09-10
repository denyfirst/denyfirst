//go:build demo

package webscan

import (
	"context"
	"errors"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/exclusion"
)

// The exclusion list is asked before the deployment's own list, and no
// authority overrides it.
//
// Both refuse, so on the ordinary build the order decides nothing and no test
// without this tag can see it — a sabotage that swapped them escaped every
// one. What the order encodes is that the exclusion list is not a permission
// question. A deployment list says which hosts this installation is *for*;
// the exclusion list says which names this project will not touch whoever is
// asking and whatever they have proven. A source of authority added later —
// a verified domain, on a deployment that establishes its scope at run time —
// must not be able to buy a scan of a name on this list, and the way that
// stays true is that the list is asked first.
//
// Under this tag army.mil is outside the demonstration list as well, so the
// two refusals compete and the right one has to win.
func TestTheExclusionListIsNotOverriddenByTheDeploymentList(t *testing.T) {
	_, err := (&Scanner{}).Scan(context.Background(), "army.mil")

	if errors.Is(err, demo.ErrNotATarget) {
		t.Fatal("an excluded name was refused as one this deployment does not demonstrate; " +
			"the exclusion list has to be asked before any source of authority, or an " +
			"authority added later could buy a scan of a name on it")
	}
	if !errors.Is(err, exclusion.ErrRefused) {
		t.Fatalf("Scan returned %v, want the exclusion refusal", err)
	}
}
