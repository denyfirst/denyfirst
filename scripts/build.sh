#!/bin/bash
#
# Builds every release artifact into a directory.
#
# One copy, called by both build-release.yml and reproduce.yml. Two copies of
# a build command drift, and when they do, every hash disagrees and the
# failure is indistinguishable from a tampered release. A reproduction check
# is only worth running if a mismatch means something.
#
# The toolchain is not arranged here either: the go directive in go.mod names
# the version and Go's own mechanism fetches it. Installing one elsewhere
# gives a different GOROOT, which -trimpath does not reach.
#
# Usage:
#   scripts/build.sh v0.1.0 dist

set -euo pipefail

tag=${1:?usage: build.sh TAG OUTPUT_DIR}
out=${2:?usage: build.sh TAG OUTPUT_DIR}

mkdir -p "$out"

# The targets. Adding one here adds it to the release and to every
# reproduction of it, which is the point of the file.
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"
commands="denyfirst-scan denyfirstd"

# -trimpath removes the local module path, CGO_ENABLED=0 removes the host C
# toolchain, -buildvcs=false keeps the embedded VCS stamp from varying with
# how the tree was fetched, and -s -w drop the symbol and DWARF tables.
#
# -X main.version stamps the tag into the binary. Without it a program could
# not say which release it was: -buildvcs=false is deliberate, and the tag in
# the filename is lost the moment somebody renames or packages the file, so an
# operator holding a binary had no way to check whether it was the one that
# fixed anything. The value comes from the tag argument, which both callers
# pass identically, so two builds of one tag still produce identical bytes and
# a reproduction still compares like with like.
#
# Together they make the output depend on the source, the compiler and the tag
# and nothing else. Any flag added here has to be added for both callers at
# once, which is now automatic.
for target in $targets; do
    os="${target%/*}"
    arch="${target#*/}"

    for command in $commands; do
        name="${command}_${tag}_${os}_${arch}"
        [ "$os" = "windows" ] && name="${name}.exe"

        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build -trimpath -buildvcs=false \
                -ldflags "-s -w -X main.version=${tag}" \
                -o "${out}/${name}" "./cmd/${command}"
    done
done

# The build that runs on denyfirst.dev.
#
# It is the same program with one list compiled in: it connects only to hosts
# this project owns, so that the public deployment stops opening connections
# to third parties on a stranger's behalf. The property is worth nothing until
# the binary carrying it is the binary that runs, and a binary that runs is one
# that was released — signed, listed in SHA256SUMS, and rebuilt by the
# reproduction workflow like every other artifact here.
#
# Linux and amd64 only, deliberately. This is not a thing to download and use;
# it is a thing one server runs, and offering it for five platforms would
# invite somebody to install a crippled scanner by mistake. The name says what
# it is for the same reason.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -buildvcs=false -tags demo \
        -ldflags "-s -w -X main.version=${tag}" \
        -o "${out}/denyfirstd-demonstration_${tag}_linux_amd64" "./cmd/denyfirstd"

ls -la "$out"