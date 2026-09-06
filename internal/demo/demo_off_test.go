//go:build !demo

package demo

import "testing"

// The tool is not a demonstration.
//
// Without the build tag there is no list and nothing is refused for being
// outside it: this is the thing people run, and it goes where they point it.
// A default that restricted anything would be a default that quietly limits
// somebody scanning their own network.
func TestTheOrdinaryBuildIsNotADemonstration(t *testing.T) {
	if Enabled {
		t.Fatal("the ordinary build thinks it is a demonstration")
	}
	for _, host := range []string{"example.test", "denyfirst.dev", "192.0.2.1", ""} {
		if Refusal(host) {
			t.Errorf("the ordinary build refuses %q for not being a demonstration target", host)
		}
	}
	if got := Targets(); len(got) != 0 {
		t.Errorf("the ordinary build carries a demonstration list: %v", got)
	}
}
