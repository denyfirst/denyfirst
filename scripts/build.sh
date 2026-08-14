#!/bin/bash
#
# Builds every release artifact into a directory.
#
# This exists because the same command lived in two workflows and drifted
# twice in one afternoon: once when one of them installed a toolchain to a
# different GOROOT, and once when one carried -X main.version and the other
# did not. Both times ten hashes disagreed, and both times the failure looked
# exactly like a tampered binary.
#
# A reproduction check is only worth running if a mismatch means something.
# Two copies of a build command guarantee that a mismatch eventually means
# nothing, and then nobody looks at it. So there is one copy, here, and both
# build-release.yml and reproduce.yml call it.
#
# Nothing about the toolchain is arranged here either. The go directive in
# go.mod names the version and Go's own mechanism fetches it into the module
# cache; installing one somewhere else gives a different GOROOT, and -trimpath
# does not reach GOROOT.
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
# Together they make the output depend on the source and the compiler and
# nothing else. Any flag added here has to be added for both callers at once,
# which is now automatic.
for target in $targets; do
    os="${target%/*}"
    arch="${target#*/}"

    for command in $commands; do
        name="${command}_${tag}_${os}_${arch}"
        [ "$os" = "windows" ] && name="${name}.exe"

        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build -trimpath -buildvcs=false \
                -ldflags "-s -w" \
                -o "${out}/${name}" "./cmd/${command}"
    done
done

ls -la "$out"