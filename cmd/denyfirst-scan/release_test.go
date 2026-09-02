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
		{"name the tag about to be cut", "a rule set's section is written before the tag exists, so it reads Unreleased until somebody comes back for it — denyfirst-v4 said so on the page five releases after v0.4.0 shipped it"},
		{"STOP: not on the branch, nothing applied", "the branch check has to be the condition the patch is applied under: printed on its own line it went past twice, and both times the commit landed on main"},
		{"STOP: not on the branch, nothing committed", "a patch applied by hand after a failed switch reaches the same place, so the commit is guarded too"},
		{"carries the reason for the change, and nothing else", "a commit message is published and permanent, and an identifier in one cannot be taken back without rewriting main"},
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

// A release is bytes anybody can verify. A deploy is the separate claim that
// those bytes are what answers on port 443, and it is made by a person typing
// commands into a server a few times a year.
//
// Until 2026-09-01 that sequence was written nowhere. The release page said
// "then deploy" and gave one command, which does not exist on the machine it
// was written for — so the whole of S1 to S14 ended at the point where its
// conclusion had to be carried to production by memory.
//
// Each entry below is a step whose absence is not visible from the result. A
// deploy that skipped every one of them still leaves a service answering
// correctly, which is why they are written down rather than noticed.
func TestTheDeployProcedureIsWrittenDown(t *testing.T) {
	body, err := os.ReadFile("../../docs/releasing.md")
	if err != nil {
		t.Fatalf("reading docs/releasing.md: %v", err)
	}
	page := string(body)

	for _, required := range []struct {
		text string
		why  string
	}{
		{"--workflow=reproduce.yml --limit 1",
			"a build that was signed but not reproduced is one a single laptop vouches for"},
		{"ssh-keygen -Y verify",
			"the signature is checked on the machine that will run the file, not only on the one that downloaded it"},
		{"raw.githubusercontent.com/denyfirst/denyfirst/main/.allowed_signers",
			"the key comes from the repository; a key shipped beside the file it vouches for establishes nothing"},
		{"install -o root -g root -m 0755",
			"owner and mode are set as the file is written, so there is no interval with the wrong ownership on the live path"},
		{"denyfirstd.rollback-",
			"a rollback carries the version it holds; denyfirstd.bak from 2026-08-18 is what the alternative looks like"},
		{"getcap /opt/denyfirst/denyfirstd",
			"the binary must carry no file capability — the unit grants the port to one process instead"},
		{"AmbientCapabilities",
			"where the capability actually comes from"},
		{"MainPID",
			"the running process is identified through /proc/<pid>/exe: a failed restart leaves the old inode serving while the new file looks correct"},
		{"set -euo pipefail",
			"the deploy block stops at the first failure: pasted as loose lines, three 404s let it carry on and copy the running binary over itself as a rollback of the version already running"},
		{`git rev-parse "v0.2.0^{commit}"`,
			"the tag has to be on the commit just read, and quoted, or PowerShell hands git the tag's first parent — which on a merge commit is the previous tip and looks exactly like the failure this check is for"},
		{"An existing tag means either that",
			"an existing tag is a stop: on 2026-09-01 the release carried on past `fatal: tag already exists` and shipped, signed and deployed the commit before the change it was for"},
		{"noexec",
			"why the download goes under the deploying user's home rather than /tmp"},
	} {
		if !strings.Contains(page, required.text) {
			t.Errorf("docs/releasing.md no longer covers %q — %s", required.text, required.why)
		}
	}
}

// The service is named by the path it is at.
//
// `denyfirstd` is not on PATH on the server, and on 2026-09-01 the one deploy
// instruction this repository contained was `denyfirstd -version`. It answered
// `denyfirstd: command not found` the first time anybody followed it.
//
// This is the same defect as the release script's own example failing on
// Windows: a document naming a command nobody had run. Prose mentioning the
// bare name is how the failure gets explained; a line handing it a flag is an
// instruction, and an instruction has to work.
func TestTheServiceIsNamedByThePathItIsAt(t *testing.T) {
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
			command = strings.TrimPrefix(command, "sudo ")
			rest, bare := strings.CutPrefix(command, "denyfirstd")
			if !bare || !strings.HasPrefix(rest, " -") {
				continue
			}
			t.Errorf("%s:%d invokes the service by a name that is not on PATH there:\n  %s",
				path, n+1, strings.TrimSpace(line))
		}
	}
}
