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

		// Each of the four below is a mistake that has been made, in order.
		{"gh pr list --state open", "a release must not begin while a green pull request is unmerged: that is how v0.3.1 shipped, signed and reproduced, without the one fix it existed to carry"},
		{"--json databaseId", "a run has to be named, or gh opens a picker and the wrong run is watched"},
		{"git status --short", "reading the index before staging and again after is what keeps unrelated files out of a commit"},
		{"gh pr merge --merge", "auto-merge is off here, so merging is a step somebody has to take and four pull requests were left green and unmerged in one day"},
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

// A command in a procedure is an instruction, and an instruction that opens a
// menu is one somebody answers wrongly at two in the morning.
//
// `gh run watch` and `gh run view --log` with no run named list every recent
// run and wait for a choice. On 2026-08-23 the CI run was chosen instead of
// the build, the draft release was taken to exist, and the next command
// answered `release not found` on the one procedure that must never be
// guessed at.
//
// Only lines that are commands are checked. Prose naming the bare form is how
// the failure gets explained, and this test would otherwise forbid explaining
// it.
func TestEveryRunCommandNamesItsRun(t *testing.T) {
	for _, path := range []string{
		"../../docs/releasing.md",
		"../../docs/verify.md",
		"../../README.md",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		for n, line := range strings.Split(string(body), "\n") {
			command := strings.TrimSpace(line)
			rest, isWatch := strings.CutPrefix(command, "gh run watch")
			if !isWatch {
				var isView bool
				rest, isView = strings.CutPrefix(command, "gh run view")
				if !isView || !strings.Contains(rest, "--log") {
					continue
				}
			}

			// What has to be there is a run to act on: an id, a variable
			// holding one, or the query that produces one. A flag is not one.
			named := false
			for _, field := range strings.Fields(rest) {
				if strings.HasPrefix(field, "-") {
					break
				}
				named = true
				break
			}
			if !named {
				t.Errorf("%s:%d names no run, so it opens a picker:\n  %s", path, n+1, command)
			}
		}
	}
}
