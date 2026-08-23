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
gh run watch
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
git log --oneline -1              # the commit this will release

git tag -s v0.2.0 -m "denyfirst v0.2.0"
git push origin v0.2.0
gh run watch
```

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
gh run view --log | Select-String "Refuse to stage"
```

### Sign

`-Compare` needs the tag checked out. Otherwise it compares the release
against whatever is in the working tree and reports a difference count for the
wrong source.

```powershell
git checkout v0.2.0
powershell.exe -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Tag v0.2.0 -Compare
```

On Windows the comparison reports differences, and that is expected: a
cross-compile from Windows puts a different `GOROOT` into the runtime package
and `-trimpath` does not reach it. What matters on Windows is everything the
script does before that — the commit matches the tag, the build script matches
the hash recorded in `BUILD`, and every file matches the checksum list. Run
the comparison on Linux if you want it to mean something; `reproduce.yml` does
it there anyway, after publication, in public.

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
gh run watch
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
