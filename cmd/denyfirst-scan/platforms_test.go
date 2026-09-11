package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	buildTargets = regexp.MustCompile(`(?m)^targets="([^"]+)"`)
	vetLoop      = regexp.MustCompile(`for os in ([a-z ]+); do`)
)

// Every platform the release ships is type-checked by CI.
//
// `go vet ./...` on the Linux runner does not read a file behind `//go:build
// windows`. It is not merely unvetted, it is never compiled — so a syntax error
// in one passes every gate in this repository and fails in scripts/build.sh on
// a release evening, at the step the procedure assumes is already known to
// work. That stopped being hypothetical the day internal/dnsclient grew a
// per-platform resolver so the CAA check would run on Windows (R7).
//
// The platform list is read out of the build script rather than written here,
// because adding a release target and forgetting the gate is the same omission
// one file further along.
func TestEveryReleasedPlatformIsVetted(t *testing.T) {
	script, err := os.ReadFile("../../scripts/build.sh")
	if err != nil {
		t.Fatalf("reading the build script: %v", err)
	}
	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("reading the CI workflow: %v", err)
	}

	targets := buildTargets.FindSubmatch(script)
	if targets == nil {
		t.Fatal("scripts/build.sh no longer declares targets=\"...\"; this test is reading " +
			"nothing and would pass for a workflow that vets one platform")
	}

	shipped := map[string]bool{}
	for _, target := range strings.Fields(string(targets[1])) {
		shipped[strings.SplitN(target, "/", 2)[0]] = true
	}
	if len(shipped) < 2 {
		t.Fatalf("found only %v in the build targets, which cannot be right", keys(shipped))
	}

	loop := vetLoop.FindSubmatch(workflow)
	if loop == nil {
		t.Fatal("the CI workflow has no `for os in ...` vet loop, so a file behind another " +
			"platform's build tag is compiled nowhere before a release")
	}

	vetted := map[string]bool{}
	for _, os := range strings.Fields(string(loop[1])) {
		vetted[os] = true
	}

	for os := range shipped {
		if !vetted[os] {
			t.Errorf("the release builds for %s and CI vets %v; a file behind //go:build %s "+
				"is never compiled until somebody tags a release", os, keys(vetted), os)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
