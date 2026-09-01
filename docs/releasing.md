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

Stage the paths the change touches, by name. `git add -A` was in this place
until 2026-09-01, when it swept a downloaded patch file into the commit that
applied it — the same shape as the logs, in the procedure written to prevent
them. Reading the index afterwards showed the extra file and did not stop it,
because nothing was asked to.

```powershell
git status --short
git add docs/releasing.md internal/policy/note.go
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

# The tag has to be new, and it has to be on the commit just read.
#
# On 2026-09-01 `git tag -s` answered `fatal: tag already exists` and the
# release went on regardless: the tag had been cut before the last pull
# request merged, so v0.6.0 was built, signed, reproduced and deployed from
# the commit before the change it was for. An existing tag means either that
# this version is already released or that something older than you think is
# about to be published. Both are a stop.
#
# Quote the argument. Unquoted, PowerShell takes {commit} for a script block
# and git is handed `v0.7.0^` — the tag's first parent, which on a merge
# commit is the previous tip and looks exactly like the failure this check is
# for.
git rev-parse "v0.2.0^{commit}"
git rev-parse main

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

The notes are edited with `gh release edit vX.Y.Z --notes-file NOTES.md`, and
`--notes-file` is read relative to the current directory. On 2026-09-01 it was
not, the command failed, and the published release kept a draft sentence
saying it had no signature yet — an actively false statement on a release that
was signed. Check what the page says after editing it, not that the command
was typed.

Then deploy, which is the section below.

---

## Deploying

A release is a set of bytes anybody can verify. A deploy is the separate claim
that those exact bytes are what now answers on port 443, and nothing above
establishes it.

Until 2026-09-01 this page said *then deploy* and gave one command,
`denyfirstd -version`. It is not on `PATH` on the machine it was written for,
so the only instruction that existed failed on the evening it was first
followed.

### Nothing is deployed that was not reproduced

Publication is not the last gate. `reproduce.yml` is the only step showing
these bytes come from this source on a machine that is not the maintainer's,
so a build that was signed but not reproduced is one that a single laptop
vouches for.

```sh
gh run list --workflow=reproduce.yml --limit 1
```

### The signature is checked again, on the machine that will run it

Verifying on the laptop that did the download establishes something about the
laptop. The bytes that matter are the ones on the server, so the server checks
them — with the same commands `docs/verify.md` gives a stranger, which is the
point of publishing them.

The whole block runs inside a subshell with `set -euo pipefail`, so the first
failure stops it. Pasted as loose lines it does not: on 2026-09-01 the release
had not been published yet, three `curl` calls answered 404, and the block
carried on to copy the running binary over itself as a rollback of the version
that was already running. Nothing was damaged and nothing was checked either,
which is the shape of the accident worth preventing. A subshell rather than a
bare `set -e`, so a failure ends the block and not the login session.

```sh
(
set -euo pipefail

V=v0.4.0
base=https://github.com/denyfirst/denyfirst/releases/download/${V}

mkdir -p ~/deploy && cd ~/deploy
curl -fsSLO "${base}/denyfirstd_${V}_linux_amd64"
curl -fsSLO "${base}/SHA256SUMS"
curl -fsSLO "${base}/SHA256SUMS.sig"
curl -fsSLO https://raw.githubusercontent.com/denyfirst/denyfirst/main/.allowed_signers

ssh-keygen -Y verify \
  -f .allowed_signers \
  -I releases@denyfirst.dev \
  -n file \
  -s SHA256SUMS.sig \
  < SHA256SUMS

sha256sum --check --ignore-missing SHA256SUMS
```

The key comes from the repository and not from the release, because a
signature verifies against whatever key it is handed: a key shipped beside the
file it vouches for establishes nothing. The fingerprint `ssh-keygen` prints
is the one in `docs/verify.md`, and it is the same fingerprint whether a
stranger checks it or this server does.

Nothing here needs a credential for the repository. The production machine
holds no token, no deploy key and no write access to anything — it fetches
public files and checks a signature, which is all a deploy requires.

`/tmp` is mounted `noexec` on this server. The download directory is under the
deploying user's home for that reason, and the binary is never executed from
where it lands.

### Install

```sh
/opt/denyfirst/denyfirstd -version

sudo install -o root -g root -m 0755 \
  ~/deploy/denyfirstd_${V}_linux_amd64 /opt/denyfirst/denyfirstd.new
sudo cp -a /opt/denyfirst/denyfirstd /opt/denyfirst/denyfirstd.rollback-v0.3.2
sudo mv /opt/denyfirst/denyfirstd.new /opt/denyfirst/denyfirstd
sudo systemctl restart denyfirstd
)
```

The first line is read, not run for form's sake: the rollback below is named
for the version it printed. Better still, name it from the binary itself —
`prev="$(/opt/denyfirst/denyfirstd -version | head -1 | awk '{print $2}')"` —
because a version typed by hand is a version that can be typed wrongly.

`install` sets owner and mode as it writes. `cp` followed by `chmod` leaves a
window in which the file is in place with the wrong ownership, and that window
is on the live path.

`mv` inside one filesystem is a rename, so the path never exists half-written.
Copying onto the live path does, and the moment it is half-written is a moment
the service might restart.

The file is `root:root`; the service runs as `denyfirst`. The account the
service runs as cannot rewrite the file it executes, which is the entire
reason the two are different.

The rollback carries the version in its name. A file called `denyfirstd.bak`
is one nobody can reason about a week later — there was one on this server
from 2026-08-18, and nothing recorded what it held. Keep one, named.

### The binary carries no capability

Port 443 is reached through the unit:

```
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

which grants the capability to this one process as it starts. A file
capability would grant it to anybody on the machine who runs the file, which
is a much larger claim than the one that needs making.

```sh
getcap /opt/denyfirst/denyfirstd
```

must print nothing. `install` does not carry capabilities across, so this
holds unless somebody sets one by hand — which is exactly why it is checked
rather than assumed.

### Confirm the service, not the file

```sh
/opt/denyfirst/denyfirstd -version
sudo readlink /proc/$(systemctl show -p MainPID --value denyfirstd)/exe
curl -s https://denyfirst.dev/healthz
```

The first runs the file on disk and says what was installed. It does not say
what is serving: a restart that failed leaves the previous process alive on
the previous inode, still answering, while the new file sits in place looking
correct. The second line is what separates them — it must print
`/opt/denyfirst/denyfirstd`, and must not end in `(deleted)`.

The third is the running process answering over the network, and it is the
only one of the three that is evidence about what people actually reach.

Every command here names the service by its path. `denyfirstd` alone is not on
`PATH`.

### Afterwards

```sh
rm -rf ~/deploy
```

The downloaded files are public and are not secret. They are removed because a
stale binary beside a live one is the copy somebody installs by mistake next
time.

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
