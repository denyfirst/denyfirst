//go:build demo

package demo

import "testing"

// The list itself, asked about through the matcher that decides it.
//
// Under the demo tag, because without it there is no list: the ordinary build
// has nothing to demonstrate on and an empty list is what it should have.
func TestTheDemonstrationListIsNotEmpty(t *testing.T) {
	if len(Targets()) == 0 {
		t.Fatal("the demonstration build has no hosts to demonstrate on")
	}
	for _, host := range Targets() {
		if !isTarget(host) {
			t.Errorf("%q is on the list and the list does not match it", host)
		}
		if !isTarget("under." + host) {
			t.Errorf("%q is on the list and does not cover what is beneath it", host)
		}
	}
}
