//go:build demo

package webscan

import (
	"context"
	"testing"
)

// A demonstration build does not follow a redirect off the hosts it owns.
//
// This is the deployment the whole restriction was written for: until the
// boundary was asked at the hop, one Location header on a host this project
// owns would have had this project's own server connecting to a stranger —
// the exact arrangement N6 dismantled, arriving through a door nobody was
// watching. It needs no compromise to happen either. A marketing redirect to
// somebody else's platform is enough.
//
// Only the demonstration build can see this. The ordinary build has no list
// for a host to be outside of, so the ordinary tests exercise the exclusion
// list and the verified zone instead, and this one is what CI runs under the
// tag.
func TestARedirectOffTheDemonstrationIsNotFollowed(t *testing.T) {
	d := &redirector{from: "denyfirst.dev", to: "http://example.com/"}
	s := &Scanner{Prober: d.start(t)}

	result, err := s.Scan(context.Background(), "denyfirst.dev")
	if err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if d.reached("example.com") {
		t.Error("a demonstration build followed a redirect to a host this project does not " +
			"own. The compiled-in list is the whole of what makes this deployment safe to " +
			"run, and a server that answers a redirect is choosing the next address")
	}
	if len(stopped(result)) == 0 {
		t.Error("the chain declined to follow and recorded no reason")
	}
}

// And it still follows one within what it owns.
func TestARedirectInsideTheDemonstrationIsFollowed(t *testing.T) {
	d := &redirector{from: "denyfirst.dev", to: "http://www.denyfirst.dev/"}
	s := &Scanner{Prober: d.start(t)}

	if _, err := s.Scan(context.Background(), "denyfirst.dev"); err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if !d.reached("www.denyfirst.dev") {
		t.Error("a demonstration build refused a redirect within the hosts it owns; the " +
			"list covers everything beneath each entry, and a report that stops at the " +
			"first redirect is a demonstration of nothing")
	}
}
