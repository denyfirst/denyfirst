package main

import (
	"testing"
	"time"
)

// What each switch reaches.
//
// A flag parsed into a variable nobody reads compiles, runs, prints itself in
// the usage text, and does nothing. -resolver was exactly that for the length
// of one sabotage: declared, documented, never assigned. Nothing here scans
// anything; it asks what the scanner was built with.

// The command line lifts two restrictions the service keeps, by default.
func TestTheCommandLineLiftsWhatOnlyAServiceNeeds(t *testing.T) {
	s := tlsScanner(time.Second, false, "", false)

	if !s.AllowAnyPort {
		t.Error("the port allow list is enforced on the command line; a local operator " +
			"scanning their own service on 8444 is not the abuse that list guards against")
	}
	if !s.AllowIPTargets {
		t.Error("an address is refused on the command line; an operator checking their own " +
			"server before its name resolves is the case this one exists for")
	}
}

// A named resolver reaches the scanner.
func TestTheResolverFlagReachesTheScanner(t *testing.T) {
	s := tlsScanner(time.Second, false, "192.0.2.9:53", false)

	if s.Resolver == nil {
		t.Fatal("-resolver was given and the scanner has none, so the CAA lookup will read " +
			"this machine's configuration instead of the address the operator named")
	}
	if s.Resolver.Server != "192.0.2.9:53" {
		t.Errorf("the scanner asks %q, want the address that was named", s.Resolver.Server)
	}
}

// And no resolver leaves the machine's own configuration to be read.
//
// The other direction, and it is the one that matters most: a default that
// quietly pointed every scan at some fixed resolver would move who learns what
// is being scanned, which is not a decision to make on an operator's behalf.
func TestNoResolverFlagLeavesTheMachinesOwnConfiguration(t *testing.T) {
	s := tlsScanner(time.Second, false, "", false)

	if s.Resolver != nil {
		t.Errorf("no -resolver was given and the scanner was built with %+v; the machine's "+
			"own configuration is what an empty flag means", s.Resolver)
	}
}

// The private-address guard is off until it is asked for, and then it is off.
func TestPrivateAddressesAreReachedOnlyWhenAsked(t *testing.T) {
	if s := tlsScanner(time.Second, false, "", false); s.Prober.Dial != nil {
		t.Error("the prober was given a dialler without -allow-private; the default has to be " +
			"safedial, or a mistyped name can be aimed at an internal host")
	}
	if s := tlsScanner(time.Second, true, "", false); s.Prober.Dial == nil {
		t.Error("-allow-private was given and the prober still dials through safedial, so the " +
			"switch does nothing and an operator scanning their own network cannot")
	}
}

// The log search is off unless it is asked for.
//
// The only check here that is. Everything else this command does reaches a
// server the operator named or reads something already in hand; this sends the
// name to a monitor this project does not run, and the question contains the
// name. On a service that required proof of control the name belongs to whoever
// asked, so it runs there with no switch — here the name may be somebody
// else's, and telling a third party which domain you are looking at is a
// disclosure to make rather than one to inherit (N12).
func TestTheLogSearchIsOffUntilItIsAskedFor(t *testing.T) {
	if s := tlsScanner(time.Second, false, "", false); s.Logs != nil {
		t.Error("a scan would query a public monitor without -check-logs, so the name of " +
			"whatever somebody scans is sent to a third party they did not choose")
	}
	if s := tlsScanner(time.Second, false, "", true); s.Logs == nil {
		t.Error("-check-logs was given and no searcher was configured, so the flag is " +
			"documented in the usage text and does nothing")
	}
}
