# Working on denyfirst

This file is read at the start of every session. It is the rules that are not
visible from the code, and the reasons behind them are in
[`docs/invariants.md`](docs/invariants.md) — three thousand lines of *why*,
each entry written the day something went wrong. Read the invariant before
changing what it guards.

Everything here is public. It carries no personal preference, no account, no
session identifier, and nothing about who is working on it.

---

## What this is

A scanner that measures how a host is reached and grades what it finds. Two
checks so far: the TLS handshake and the certificate behind it
(`denyfirst-tls-v6`), and how a website is reached over HTTP
(`denyfirst-web-v2`).

**The tool is what you run. The site is a demonstration of it.** The public
deployment at denyfirst.dev connects only to hosts this project owns, and that
restriction is compiled in — see N6. Anyone who wants to scan anything else
runs the tool themselves.

**No third-party dependencies.** `go.mod` has no `require` block and it is to
stay that way. Nothing is fetched beyond the standard library, so there is no
supply chain under a program whose whole argument is that it can be checked.

---

## The three priorities, in order

Security, privacy, anonymity — of this project and of whatever it scans. A
change that improves one at the cost of another is a change to argue about
before writing, not after.

Concretely, and each of these has an invariant:

- **Record nothing that is not needed.** Not the hostname, not the client
  address, not a timestamp beyond a date. `/api/v1/stats` is publishable
  precisely because nobody, including whoever seizes the machine, can learn
  from it who used the service or what they looked at.
- **Never echo the input back in an error.** A message says what the rule is
  (I6).
- **A guard goes where the connection is made**, not in the handler that
  happens to call it today. A guard in one place is a guard somebody walks
  around by adding an entry point (N6).
- **Say what was measured, never what it implies** (R17), and **nothing
  measured is not the same as passing** (R4).

---

## Rules for a change

**Sabotage what you wrote, in both directions.** Break the new behaviour and
check a test fails; then break it the opposite way and check a test fails.
Count them and say so in the commit message. A sabotage that escapes gets a
new test — or, if investigation shows it is not a defect, a comment saying why
the code is the way it is. Neither outcome is silent.

**A verdict change is a rule-set version change.** A user who scans an
unchanged server twice and gets two grades has been given a reason to distrust
both. Bump the rule set, add a section to `docs/policy-changes.md` marked
`Unreleased`, and let the release procedure force it to name its tag.

**Where no document sets a threshold, report rather than grade** (R21). A
threshold this project invented is one nobody can argue with, which means
nobody can correct it either, and it survives into a report telling somebody
their correct decision is a fault.

**Every invariant cites tests that exist.** CI fails otherwise. Rename a test
and the citation goes with it.

**Error strings are lowercase, one line, no trailing punctuation.**
staticcheck ST1005 is a required check.

---

## Rules for git

**Commit messages carry the reason for the change and nothing else.** No
attribution trailers, no session, tool or account identifiers, no link a
reader of this repository cannot follow. One reached `main` before this rule
existed; it stays, and it is not repeated.

**The branch is a condition, not a line to read.** `git switch -c` fails if
the branch exists, and a failed switch leaves you on `main` — where the commit
then lands. Twice. Do the work inside the check:

```sh
git switch -c topic/thing-2026-01-01 main
[ "$(git branch --show-current)" = topic/thing-2026-01-01 ] || exit 1
```

**Stage by name. Never `git add -A`.** It has swept two CI logs and a
downloaded patch file into commits that reached `main`.

**Read the index before staging and again after.**

**Merge commits only.** Squash and rebase merging are disabled: a rebase
cannot preserve a commit signature, and GitHub does not re-sign.

**Never `gh pr merge --admin`,** and never `--auto`. The first bypasses the
required checks, which is the whole apparatus. The second lands a change with
nobody looking at the result, which is why it is switched off.

`gh pr checks --watch` run immediately after `gh pr create` reports "no checks
reported" and exits, because none has registered yet. Wait a few seconds.

---

## Running the gates

```sh
gofmt -l internal cmd
go vet ./...
go test ./...
```

Two things about `go test ./...`:

- **On Windows and macOS, two `internal/certinfo` tests fail** and have since
  they were written. They build a private authority and point `SSL_CERT_FILE`
  and `SSL_CERT_DIR` at it; only Go's unix root loader reads those variables,
  so the platform verifier never sees the test root. It is a real defect —
  `certinfo` verifies with a nil `Roots`, which means a different trust store
  from the one `denyfirstd` checks at startup — and it has its own change
  waiting. Until then, exclude that package on those platforms.
- **`-race` needs cgo**, which needs a C toolchain a Go installation on
  Windows does not bring. CI runs it on Linux.

**The other build.** The demonstration deployment is a build tag, and nothing
above exercises it:

```sh
go build -tags demo ./...
go test -tags demo ./internal/demo/ ./internal/scan/ ./internal/webscan/ ./internal/web/
```

Nine `internal/httpapi` tests fail under that tag on every commit: they scan
`example.test`, which a demonstration build refuses. CI runs only the
demonstration's own test there, deliberately. Do not bend forty tests to a
deployment restriction.

**The text gates**, which need no Go and catch what Go cannot:

```sh
# every invariant cites a test that exists
grep -ohE '`(Test|Fuzz)[A-Za-z0-9_]+`' docs/invariants.md | tr -d '`' | sort -u > /tmp/cited
grep -rhoE '^func (Test|Fuzz)[A-Za-z0-9_]+' --include='*_test.go' . | sed -E 's/^func //' | sort -u > /tmp/defined
comm -23 /tmp/cited /tmp/defined     # must be empty
```

---

## What is not automated, and stays that way

**Signing a release.** A workflow builds from the tagged source on a machine
the maintainer does not control and cannot sign; the maintainer signs on their
own machine and does not build. Compromising either alone yields nothing, and
that is the only reason the split exists. Do not collapse it because it is
inconvenient.

**Publishing and deploying.** `docs/releasing.md` is the procedure. Every step
in it is there because it has already gone wrong once.

**Merging.** A person looks at the result.

---

## Where things are

| | |
|---|---|
| `internal/tlsprobe`, `internal/certinfo` | the TLS measurement |
| `internal/webprobe` | the HTTP measurement: one `GET` of `/`, headers only (N7) |
| `internal/policy` | every rule, versioned, each citing the document it rests on |
| `internal/scan`, `internal/webscan` | a check: measure, then grade |
| `internal/demo` | which hosts this deployment may reach, compiled in |
| `internal/safedial` | refuses private, loopback and reserved destinations |
| `internal/httpapi` | the service; the only package that sees untrusted input |
| `internal/web` | the pages |
| `docs/invariants.md` | why all of the above is the way it is |
| `docs/roadmap.md` | where this is going, and what is known to be wrong |
