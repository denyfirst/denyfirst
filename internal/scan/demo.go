package scan

import (
	"errors"
	"strings"
)

// The public deployment of this project is a demonstration, not a service.
//
// Until 2026-09-03 anybody could point denyfirst.dev at any host on the
// internet and this server would open the connections. That arrangement put
// the project in the worst position available to it: ours was the address in
// the scanned party's logs, and we had deliberately made ourselves unable to
// say who had asked, because recording that is the one thing this project
// undertakes not to do. Being the visible party and the unattributable one at
// the same time is not a position to argue from — it is one to leave.
//
// There are two ways out. Start keeping records, which is not available: the
// promise is the point. Or stop connecting to third parties at all, which is
// this.
//
// So the tool is run by the person who wants the answer, on their own
// machine, from their own address, under their own responsibility — and the
// public deployment scans only hosts this project owns, as a demonstration
// that the instrument works and that its verdicts can be reproduced.
//
// The restriction is compiled in rather than configured. A configuration
// difference is a security boundary, and those are the boundaries that rot: a
// flag can be omitted, a file can be edited, an environment variable can be
// missing and nothing looks wrong. Under the "demo" build tag the list is in
// the binary and there is no way to widen it without building a different
// binary. Without the tag there is no restriction at all, which is what the
// tool is for.

// ErrNotADemoTarget is returned by a demonstration build for any host outside
// its list. It names no host back.
var ErrNotADemoTarget = errors.New("this deployment demonstrates the tool on hosts it owns; run it yourself to scan anything else")

// isDemoTarget reports whether a host is one the demonstration list covers.
//
// Matching is at label boundaries and not by string suffix, for the same
// reason the exclusion list matches that way and in the same direction of
// caution: here a sloppy match would let a host in rather than keep one out.
// "denyfirst.dev" must cover tls10-only.denyfirst.dev and must not cover
// denyfirst.dev.example.com — which a plain HasSuffix gets wrong, and which is
// precisely how somebody would arrange to be scanned by us.
func isDemoTarget(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	for _, allowed := range demoTargets {
		allowed = strings.ToLower(strings.TrimSuffix(allowed, "."))
		if allowed == "" {
			continue
		}
		if host == allowed {
			return true
		}
		if strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

// DemoRefusal reports whether a demonstration build refuses this host, so the
// HTTP layer can answer with its own words before a scan is attempted.
//
// It answers false in an ordinary build, where there is nothing to refuse.
func DemoRefusal(host string) bool {
	return Demo && !isDemoTarget(host)
}

// DemoTargets returns the hosts a demonstration build will scan.
//
// Published rather than kept quiet: a visitor who is refused should be able to
// see the whole list, and a reader who wants to check that the list is what we
// say it is can read it here and in the binary.
func DemoTargets() []string {
	out := make([]string, len(demoTargets))
	copy(out, demoTargets)
	return out
}

// DemoHost is one entry on the demonstration menu.
//
// The menu and the boundary are different things and are kept apart. The
// boundary is a list of domains and it decides what may be connected to; the
// menu is a list of particular hosts with a sentence each, and it decides what
// a visitor is offered. A menu entry outside the boundary would be an offer
// the scanner refuses, which a test prevents.
type DemoHost struct {
	// Host is scanned as written.
	Host string

	// Shows is what this host is here to demonstrate, in a few words.
	Shows string
}

// DemoHosts returns the menu a demonstration build offers.
//
// Empty in the ordinary build, where the person running the tool chooses.
func DemoHosts() []DemoHost {
	out := make([]DemoHost, len(demoHosts))
	copy(out, demoHosts)
	return out
}
