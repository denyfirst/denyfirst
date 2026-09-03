//go:build demo

package scan

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// What the build on denyfirst.dev will and will not do.
//
// These run only under the tag, because that is the only build in which the
// question exists. The ordinary suite covers the tool; this covers the list.

// A host this project does not own is not scanned, whoever asks.
//
// Checked at Scanner.Scan rather than at the HTTP handler, so it holds for
// the command line built with the same tag and for anything written later. A
// guard in one entry point disappears the moment a second one is added.
func TestTheDemonstrationBuildRefusesAHostItDoesNotOwn(t *testing.T) {
	s := &Scanner{}

	for _, host := range []string{
		"example.com",
		"example.test",
		"denyfirst.dev.example.com",
		"notdenyfirst.dev",
	} {
		_, err := s.Scan(context.Background(), host)
		if !errors.Is(err, ErrNotADemoTarget) {
			t.Errorf("scanning %q gave %v, want the demonstration refusal", host, err)
		}
	}
}

// The refusal does not repeat the host back.
//
// The message is printed, and a message that echoes what it was given is a
// place where somebody else's text reaches a reader of ours.
func TestTheDemonstrationRefusalNamesNoHost(t *testing.T) {
	if strings.Contains(ErrNotADemoTarget.Error(), "%") {
		t.Error("the refusal is a format string, so it is meant to carry something back")
	}
}

// The list is not empty.
//
// An empty list refuses everything, which fails in the safe direction and is
// still broken: the demonstration would demonstrate nothing. This is the test
// that notices.
func TestTheDemonstrationListIsNotEmpty(t *testing.T) {
	if len(DemoTargets()) == 0 {
		t.Fatal("the demonstration build has no hosts to demonstrate on")
	}
	for _, host := range DemoTargets() {
		if !isDemoTarget(host) {
			t.Errorf("%q is on the list and the list does not match it", host)
		}
		if !isDemoTarget("under." + host) {
			t.Errorf("%q is on the list and does not cover what is beneath it", host)
		}
	}
}

// It really is a demonstration build.
func TestTheTagIsWhatSwitchesIt(t *testing.T) {
	if !Demo {
		t.Fatal("built with the demo tag and Demo is false")
	}
	if !DemoRefusal("example.com") {
		t.Error("a demonstration build does not refuse a host it does not own")
	}
	if DemoRefusal("denyfirst.dev") {
		t.Error("a demonstration build refuses a host it does own")
	}
}
