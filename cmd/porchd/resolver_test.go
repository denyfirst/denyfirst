package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
)

// -resolver reaches every lookup the service makes itself: the scanner's, which
// httpapi hands to the mail check, and the proof-of-control challenge's.
//
// Asserted on what run() builds from, because a flag parsed and never assigned
// compiles, runs and does nothing — porch-scan's -resolver did exactly that.
func TestTheResolverFlagReachesEveryLookup(t *testing.T) {
	const named = "192.0.2.53:53"

	scanner := serviceScanner(nil, nil, named)
	if scanner.Resolver == nil || scanner.Resolver.Server != named {
		t.Errorf("the scanner asks %+v; -resolver named %s", scanner.Resolver, named)
	}

	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	scope, err := verificationScope(secret, named)
	if err != nil {
		t.Fatalf("reading the scope: %v", err)
	}
	client, ok := scope.Resolver.(*dnsclient.Client)
	if !ok || client.Server != named {
		t.Errorf("the challenge is read through %+v; -resolver named %s", scope.Resolver, named)
	}

	// And run() passes the flag to both, rather than the empty string.
	source := repoFile(t, "cmd/porchd/main.go")
	for _, call := range []string{"serviceScanner(roots, scope, *resolver)", "verificationScope(*verifySecretFile, *resolver)"} {
		if !strings.Contains(source, call) {
			t.Errorf("run() does not call %s, so -resolver may not reach it", call)
		}
	}
}

// Without the flag nothing is set, so the mail check builds its own default
// rather than receiving a nil pointer inside an interface.
func TestNoResolverFlagLeavesTheScannerUnset(t *testing.T) {
	if r := serviceScanner(nil, nil, "").Resolver; r != nil {
		t.Errorf("with no -resolver the scanner holds %+v", r)
	}
}

// The service never asks a certificate's responder, with or without proof of
// control: the question names the certificate to its authority, and only an
// operator on the command line makes that choice (R3a).
func TestTheServiceNeverAsksAResponder(t *testing.T) {
	for _, resolver := range []string{"", "192.0.2.53:53"} {
		if r := serviceScanner(nil, nil, resolver).Responder; r != nil {
			t.Errorf("the service's scanner holds a responder fetcher %+v; it must never ask one", r)
		}
	}
}

// A resolver must be an address and a port. A name would be looked up through
// the machine's resolver, which is the one the flag exists to step around.
func TestAResolverThatIsNotAnAddressAndPortIsRefused(t *testing.T) {
	for _, bad := range []string{"1.1.1.1", "dns.example:53", "1.1.1.1:0", "[fe80::1%eth0]:53", "1.1.1.1:99999", ":5353"} {
		if err := resolverAddress(bad); err == nil {
			t.Errorf("-resolver %q was accepted", bad)
		} else if strings.Contains(err.Error(), bad) {
			t.Errorf("the refusal repeats the value back: %v", err)
		}
	}
	for _, good := range []string{"", "1.1.1.1:53", "[2606:4700:4700::1111]:53", "192.168.1.1:5353"} {
		if err := resolverAddress(good); err != nil {
			t.Errorf("-resolver %q was refused: %v", good, err)
		}
	}

	// And run() asks before the flag reaches anything. A check nothing calls
	// passes every assertion above and refuses nothing.
	source := repoFile(t, "cmd/porchd/main.go")
	check := strings.Index(source, "resolverAddress(*resolver)")
	use := strings.Index(source, "verificationScope(*verifySecretFile, *resolver)")
	if check < 0 || use < 0 || check > use {
		t.Error("run() does not check -resolver before the first thing that uses it")
	}
}
