# Cutting a release

This is the maintainer's procedure. It lived in a chat window and in nobody's
repository, which for a project whose argument is that everything here can be
checked is the wrong place for the one procedure that decides what people
download.

Two parties make a release and neither can do it alone. A workflow builds from
the tagged source on a machine the maintainer does not control, in a log
anyone can read, and cannot sign. The maintainer signs on their own machine
and does not build. Compromising either alone yields nothing, which is the
reason the steps are split and the reason not to collapse them when one of
them is inconvenient.

---

## Landing a change

Most days there is no release, only a change. These are here because each one
has already gone wrong, and each costs less to do than the mistake cost to
find.

**Confirm the branch before applying a patch.** `git switch -c` fails if the
branch already exists, and a failed switch leaves you where you were — which
on 2026-08-23 was `main`, where the commit then landed.

```powershell
git switch -c topic/thing-2026-01-01 main
git branch --show-current
```

**Read the index before staging, and again after.** `git add -A` takes
everything in the directory, including whatever was left there while working
out what was wrong. On 2026-08-31 it took two saved workflow logs into a
commit that reached `main`. Nothing in those was sensitive; that was luck
rather than a property, and the second look is what turns it into one.

```powershell
git status --short
git add -A
git status --short
```

**Write diagnostic output somewhere other than the repository.** `gh run view
--log` writes into the current directory, and the current directory is usually
this one. `*.log` is ignored now, which catches that shape and not the next
file with a different extension.

```powershell
gh run view $id --log | Out-File -Encoding utf8 "$env:TEMP\run.log"
```

**Merge as soon as the checks are green.** Auto-merge is disabled here and
that is the right setting: it lands a change without anybody looking at the
result. The cost is that merging is a step somebody has to take, and on
2026-08-23 four pull requests were left green and unmerged, each discovered
only when the next patch failed to apply on top of it. One of them was the
only reason v0.3.1 existed.

```powershell
gh pr checks --watch
gh pr merge --merge
```

---

## Before the first time

**A signing key**, separate from the key that pushes to GitHub, at
`%USERPROFILE%\.ssh\id_ed25519_denyfirst_release` or wherever `-SigningKey`
points. Its public half is in `.allowed_signers`. If it lived in GitHub's
secrets, whoever took the account could sign a release, and the signature
would confirm only that they had access.

**`gh`**, authenticated as somebody who can edit releases.

**`bash`**, for `-Compare`. Git for Windows ships one and puts only its `cmd\`
directory on the path, so the script also looks in `C:\Program Files\Git\bin\`.

**A way to run the script at all.** On a default Windows installation
PowerShell refuses to run any script file, and `.\scripts\release.ps1` fails
before it starts:

```
File ...\release.ps1 cannot be loaded because running scripts is disabled
on this system.
```

Run it in a child process that is allowed to, which changes nothing outside
that one process:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0 -Compare
```

Do not change the machine's policy to make this go away. The execution policy
is not a security boundary — Microsoft says so, and `-ExecutionPolicy Bypass`
is a documented flag rather than a trick — so relaxing it permanently buys no
safety and loses the accident it does prevent. What protects this step is that
the script is in this repository and has been read.

---

## The dry run

Do this once, on a tag you are not releasing, before the first real release
and after any change to `release.ps1` or `build.sh`. Signing is the one place
where a mistake is expensive and, until 2026-08-22, the one place that had
never been exercised end to end.

```powershell
git checkout main
git pull
git tag -s v0.2.0-rc1 -m "Dry run of the release procedure. Not a release."
git push origin v0.2.0-rc1
gh run watch (gh run list --workflow=build-release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Then the maintainer's half, without publishing anything:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0-rc1 -Compare
```

Stop there. Do not upload the signature and do not publish: `reproduce.yml`
runs on publication, and a release candidate is not the thing to point it at.

**The tag stays.** Tags here cannot be deleted or moved, which is what makes a
signature over one mean anything, so a dry run leaves a signed tag behind for
ever. That is the correct trade, and the reason to name release candidates as
such rather than reusing the real number.

Delete the draft release when you are finished with it. Do not pass
`--cleanup-tag`: it will fail on the tag, which is the rule working.

```powershell
gh release delete v0.2.0-rc1 --yes
```

---

## The release

```powershell
git checkout main
git pull

# Nothing may be waiting. A green pull request that was never merged is not in
# this tag, and on 2026-08-23 that produced v0.3.1: released, signed,
# reproduced and deployed without the one fix it existed to carry.
gh pr list --state open

git log --oneline -1              # the commit this will release

git tag -s v0.2.0 -m "denyfirst v0.2.0"
git push origin v0.2.0
gh run watch (gh run list --workflow=build-release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

`gh run watch` with no argument lists every recent run and waits for one to be
chosen. On 2026-08-23 the CI run was picked instead of the build, the draft
was assumed to exist, and the next command answered `release not found`. A
procedure is a set of instructions; an instruction that opens a menu is one
somebody answers wrongly at two in the morning.

The workflow builds every artifact, runs `go vet`, `go test` and `govulncheck`
against the tagged source, writes `SHA256SUMS` and `BUILD`, and leaves a
**draft** release. A draft is invisible to anyone but you, so the binaries
wait there unsigned without being downloadable.

If it did not start, or you are rebuilding after a failure:

```powershell
gh workflow run build-release.yml -f tag=v0.2.0
```

Check the log before going further. Both gate steps have to have run: a
release built from source that does not pass its own tests is a release nobody
gated.

```powershell
$id = gh run list --workflow=build-release.yml --limit 1 --json databaseId --jq '.[0].databaseId'
gh run view $id --log | Select-String "Refuse to stage"
```

### Sign

`-Compare` needs the tag checked out. Otherwise it compares the release
against whatever is in the working tree and reports a difference count for the
wrong source.

```powershell
git checkout v0.2.0
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0 -Compare
```

**Expect every artifact to match, on Windows too.** This page used to say the
opposite — that a cross-compile from Windows puts a different `GOROOT` into
the runtime package and the comparison could only mean something on Linux.
Measured on 2026-08-23 against v0.3.0: ten artifacts, ten identical, from
Windows. The toolchain came from the module cache rather than from an
installed `GOROOT`, and `-trimpath` does normalise module cache paths.

That holds whenever the `go` directive in `go.mod` names a version other than
the Go on your PATH, which is the ordinary case here. If they happen to be the
same version, the build uses the installed `GOROOT` and the bytes will differ
by that path — so read the `goroot` line in `BUILD` before treating a
difference as anything else.

A mismatch is now worth stopping for. Telling a verifier that mismatches are
normal on their platform is the one lesson this check must never teach, and it
was being taught in four places.

Anything the script refuses to sign, it says why and signs nothing. Do not
work around it.

### Publish

```powershell
gh release upload v0.2.0 dist\SHA256SUMS.sig --clobber
gh release edit v0.2.0 --draft=false
```

Publication starts `reproduce.yml`, which verifies the signature, checks that
the tag and the default branch trust the same keys, rebuilds every artifact on
a runner and compares. Watch it:

```powershell
gh run watch (gh run list --workflow=reproduce.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

A red mark there is public, which is the point. It is also the only thing that
demonstrates the property this whole arrangement exists for, so it is worth
watching rather than assuming.

### Afterwards

Write the release notes so somebody upgrading knows what moved.
`docs/policy-changes.md` records what a new rule set grades differently, and a
verdict from one policy version is not comparable with a verdict from another
— link it rather than restating it.

Then deploy, and confirm the running service is the build you just made:

```sh
denyfirstd -version
```

---

## What each step is for

| Step | What it establishes |
|---|---|
| Signed tag | Which commit is being released, and by whom |
| Public build | The binaries correspond to that commit, in a log anyone can read |
| Gates in the workflow | That commit passes its own tests and carries no known reachable vulnerability |
| `release.ps1` checks | The build record names this tag, this commit, and a build script that exists in this history |
| The signature | The list of hashes came from the key in `.allowed_signers` |
| `reproduce.yml` | Someone other than the maintainer can rebuild the same bytes, and the release is signed |

No single one of those is the answer. The signature without the public build
says a compromised laptop signed something; the public build without the
signature says anyone who takes the account can ship; the reproduction without
either says only that the bytes are self-consistent.

---

## Repository settings this depends on

Neither can be asserted by a test from inside a checkout, which is why they
are written down.

**Merge commits only.** Squash and rebase merging are disabled. A rebase merge
cannot preserve a commit signature — the signature covers the parent hash —
and GitHub does not re-sign, so rebase-merged commits arrive on `main`
unsigned, after every check has already gone green. S6 has the history.

**Tags cannot be deleted or moved.** A tag that can be moved is a tag whose
signature says nothing about what was released: the bytes people verified
against would stay valid while the tag pointed somewhere else. Both
restrictions belong on, and the cost is that a dry run's tag is permanent.
