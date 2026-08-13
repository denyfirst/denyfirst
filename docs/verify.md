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

```sh
git clone https://github.com/denyfirst/denyfirst
cd denyfirst
git checkout v0.1.0

# The BUILD file in the release records the Go version used. A different
# compiler can produce different bytes from identical source, so match it.
cat /path/to/downloaded/BUILD

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=v0.1.0" \
    -o denyfirst-scan_v0.1.0_linux_amd64 ./cmd/denyfirst-scan

sha256sum denyfirst-scan_v0.1.0_linux_amd64
```

The hash should match the line in `SHA256SUMS`. If it does not and the Go
version matches, that is worth reporting through the process in `SECURITY.md`.

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