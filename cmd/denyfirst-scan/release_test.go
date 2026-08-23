package main

import (
	"os"
	"strings"
	"testing"
)

// The procedure that decides what people download has to be in the
// repository.
//
// Until 2026-08-22 it was in a chat window: three workflow files and a
// PowerShell script each held a piece, and the order, the dry run and the two
// repository settings it rests on were written nowhere. For a project whose
// argument is that everything here can be checked, that was the one thing a
// reader could not check — and a maintainer who lost the window would have
// had to reconstruct it.
func TestTheReleaseProcedureIsWrittenDown(t *testing.T) {
	body, err := os.ReadFile("../../docs/releasing.md")
	if err != nil {
		t.Fatalf("reading docs/releasing.md: %v", err)
	}
	page := string(body)

	// Each of these is a step that cannot be inferred from the workflows, and
	// each has already gone wrong once.
	for _, required := range []struct {
		text string
		why  string
	}{
		{"dry run", "the dry run is the step that keeps a first mistake off a release evening"},
		{"release.ps1", "the signing step"},
		{"build-release.yml", "how to restart the build when the tag did not trigger it"},
		{"--draft=false", "publishing, which is what starts the reproduction"},
		{"docs/policy-changes.md", "what an upgrader has to be told"},
		{"cannot be deleted or moved", "the tag ruleset the signature's meaning depends on"},
		{"Squash and rebase merging are disabled", "the merge setting S6 records"},
	} {
		if !strings.Contains(page, required.text) {
			t.Errorf("docs/releasing.md no longer covers %q — %s", required.text, required.why)
		}
	}
}

// A procedure's first instruction has to work.
//
// `.\scripts\release.ps1 -Tag v0.1.0` was the documented invocation in the
// script's own help and in the workflow's closing message, and on a default
// Windows installation PowerShell refuses to run a script file at all. So the
// release procedure's entry point failed before the script started, on the
// single kind of machine it exists to run on — the same class of defect as
// the build recipe in docs/verify.md that named a linker symbol this program
// did not define.
//
// Every place that spells out how to invoke it has to spell out one that
// runs. Prose mentioning the bare path is fine and is how the failure is
// explained; a line handing it a tag is an instruction.
func TestTheDocumentedInvocationIsTheOneThatWorks(t *testing.T) {
	for _, path := range []string{
		"../../docs/releasing.md",
		"../../scripts/release.ps1",
		"../../.github/workflows/build-release.yml",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		for n, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, "release.ps1 -Tag") {
				continue
			}
			if !strings.Contains(line, "-ExecutionPolicy Bypass") {
				t.Errorf("%s:%d hands release.ps1 a tag without a way to run it:\n  %s",
					path, n+1, strings.TrimSpace(line))
			}
		}
	}
}
