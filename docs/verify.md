# Verifying a release

Two questions are worth asking about a binary you are about to run, and they
are different questions.

**Did this come from the maintainer?** Answered by the signature.

**Does it correspond to the source you can read?** Answered by rebuilding it,
or by trusting the workflow in this repository that rebuilds every release on
a machine the maintainer does not control.

Neither question is answered by downloading over HTTPS. TLS tells you the file
came from GitHub, and GitHub is not the party you need to trust.

---

## Check the signature

Every release carries `SHA256SUMS`, listing the SHA-256 of each binary, and
`SHA256SUMS.sig`, an OpenSSH signature over that list. Only the list is
signed: one verification then covers every file, and the list itself is the
record of what was released.

`ssh-keygen` ships with OpenSSH, so nothing needs installing.

```sh
# The public key that signs releases, from this repository.
curl -fsSLO https://raw.githubusercontent.com/denyfirst/denyfirst/main/.allowed_signers

# The list and its signature, from the release.
curl -fsSLO https://github.com/denyfirst/denyfirst/releases/download/v0.1.0/SHA256SUMS
curl -fsSLO https://github.com/denyfirst/denyfirst/releases/download/v0.1.0/SHA256SUMS.sig

ssh-keygen -Y verify \
  -f .allowed_signers \
  -I releases@denyfirst.dev \
  -n file \
  -s SHA256SUMS.sig \
  < SHA256SUMS
```

A pass prints:

```
Good "file" signature for releases@denyfirst.dev with ED25519 key SHA256:ut6bginhZ4lZINMSXNDv3vJ6fyvmDHhtnoBJH0/Nr9Y
```

Anything else means stop. A missing signature, a key that does not match, or a
modified list are all the same answer.

### About the key

The signing key is not the key used to push to GitHub. They are separate so
that losing one does not cost the other, and so that compromising the GitHub
account does not yield the ability to sign a release.

That separation is the reason this signature is worth checking. If the key
lived in GitHub's secrets, anyone who took the account could sign whatever
they liked, and the signature would confirm only that the attacker had access.

---

## Check the binary against the list

```sh
curl -fsSLO https://github.com/denyfirst/denyfirst/releases/download/v0.1.0/denyfirst-scan_v0.1.0_linux_amd64

sha256sum --ignore-missing -c SHA256SUMS
```

On macOS, `shasum -a 256 --ignore-missing -c SHA256SUMS`.

On Windows:

```powershell
(Get-FileHash -Algorithm SHA256 .\denyfirst-scan_v0.1.0_windows_amd64.exe).Hash.ToLower()
```

and compare that line against `SHA256SUMS` by eye.

---

## Rebuild it yourself

The signature says the maintainer produced the file. Rebuilding says the file
is what the source produces, which is the question that matters if you are
worried about the maintainer's account rather than about a download being
tampered with in transit.

Builds are reproducible. `-trimpath` removes local paths, `CGO_ENABLED=0`
removes the host C toolchain, and `-buildvcs=false` keeps the embedded version
stamp from varying with how the tree was fetched.

**Run the release's own build script rather than a command copied off this
page.** The flags are part of what the hash covers, and a second copy of them
in a document is free to drift away from the one that made the release. This
page carried such a copy until 2026-08-20, and it had drifted: it named
`-X main.version=v0.1.0`, a symbol this program does not define. Go accepts the
flag silently, folds the whole link command into the build ID, and writes that
into the binary — so the recipe printed here produced a different hash from the
release, on the correct source, with the correct compiler, for everyone who
followed it. A verification step that fails for honest reasons does not fail
safe. It teaches the reader that mismatches here are normal, which is the one
lesson that must never be taught about this check.

There is now one copy of the build command, in `scripts/build.sh`, used by the
release workflow, by the reproduction workflow, by the signing script and by
the instructions below. CI fails if a second one appears.

```sh
git clone https://github.com/denyfirst/denyfirst
cd denyfirst
git checkout v0.1.0

# BUILD, from the release, records what produced it: the Go version and the
# SHA-256 of the build script that ran. A different compiler produces
# different bytes from identical source, and so does a different script.
# Check both before concluding anything from a mismatch.
cat /path/to/downloaded/BUILD

go version                      # must match the toolchain line
sha256sum scripts/build.sh      # must match the buildscript line

# Through bash rather than as a program: the file is committed without an
# execute bit and the workflow sets one at build time.
# Builds every artifact in the release, which is what the workflow does.
bash scripts/build.sh v0.1.0 dist

sha256sum dist/denyfirst-scan_v0.1.0_linux_amd64
```

The hash should match the line in `SHA256SUMS`. If it does not, and both the
toolchain and the script hash match, that is worth reporting through the
process in `SECURITY.md`.

On Windows, use the bash that ships with Git for Windows. Do not translate the
script into PowerShell: a translation is a second copy of the command, which is
the thing that just went wrong.

### If the tag has no `scripts/build.sh`

v0.1.0 was cut before that script existed, so a checkout of that tag does not
contain one and the `sha256sum` line above will say so. The release workflow
has the same problem and answers it the same way: it takes the script from the
default branch and records the hash of what it took. That recorded hash, not
the branch, is the thing to check.

```sh
git fetch origin main
git checkout origin/main -- scripts/build.sh

sha256sum scripts/build.sh      # must equal the buildscript line in BUILD
```

If those disagree, stop. It means the binary was built by a script neither this
tag nor the current default branch contains, and until that hash can be found
somewhere in the history, what produced the release is unknown — which is the
one thing the `buildscript` line exists to make visible. Every tag from here on
carries its own copy and needs none of this.

`BUILD` is itself listed inside `SHA256SUMS`, so the signature checked above
covers it. That ordering is deliberate. While the provenance record sat outside
the signed list, anyone able to replace a release asset could also write the
explanation for why it no longer matched.

The `Reproduce` workflow in this repository does this automatically after every
release, on a GitHub runner. Its result is public, so the check exists whether
or not anyone runs it by hand.

---

## Build from source and skip releases entirely

The most direct option, and the one that needs the least trust.

```sh
git clone https://github.com/denyfirst/denyfirst
cd denyfirst
go build ./cmd/denyfirst-scan
```

There are no third-party dependencies. `go.mod` has no `require` block, so
`go build` fetches nothing beyond the standard library, and there is no
supply chain here to audit beyond Go itself.

---

## What none of this covers

Verification confirms the file matches the source. It does not confirm the
source is correct: a signed, reproducible build of subtly wrong grading rules
is still wrong. The rules are in `internal/policy`, each with the document it
rests on, and `docs/invariants.md` states what the project guarantees and
which test protects each guarantee. Those are the parts worth reading if you
intend to rely on the output.