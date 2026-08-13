<#
.SYNOPSIS
    Builds and signs a release.

.DESCRIPTION
    Runs on the maintainer's machine rather than in CI, and that is the whole
    point. A signing key held as a GitHub secret would let anyone who
    compromised the account sign a malicious release, which is the attack this
    signature exists to prevent. The key never leaves this machine.

    Builds are reproducible: -trimpath removes local paths, CGO_ENABLED=0
    removes the host C toolchain, and -buildvcs=false keeps the embedded VCS
    stamp from varying with how the tree was fetched. Anyone can rebuild from
    the same tag and get byte-identical files, and a workflow in this
    repository does exactly that after every release is published.

.PARAMETER Tag
    The version being released, such as v0.1.0.

.PARAMETER SigningKey
    Path to the private key used for the signature. Separate from the GitHub
    key on purpose: one being lost must not cost the other.

.EXAMPLE
    .\scripts\release.ps1 -Tag v0.1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
    [string]$Tag,

    [string]$SigningKey = "$env:USERPROFILE\.ssh\id_ed25519_denyfirst_release",

    [string]$Identity = 'releases@denyfirst.dev'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    # ── Refuse to build anything that is not exactly the tagged source ──────
    #
    # A binary built from a dirty tree cannot be reproduced by anyone else,
    # which makes the signature a claim nobody can check.

    $status = git status --porcelain
    if ($status) {
        throw "The working tree has uncommitted changes. A release is built from committed source only:`n$status"
    }

    $head = (git rev-parse HEAD).Trim()
    $tagged = (git rev-list -n 1 $Tag 2>$null)
    if (-not $tagged) {
        throw "Tag $Tag does not exist. Create it first:`n  git tag -s $Tag -m 'notes'`n  git push origin $Tag"
    }
    if ($head -ne $tagged.Trim()) {
        throw "HEAD is $head but $Tag points at $($tagged.Trim()). Check out the tag before building."
    }

    if (-not (Test-Path $SigningKey)) {
        throw "No signing key at $SigningKey."
    }

    # ── Report the toolchain, because it is part of the result ─────────────
    #
    # Two Go versions can produce different bytes from identical source, so the
    # version is recorded alongside the checksums. Without it, a reproduction
    # that fails tells nobody whether the source or the compiler differed.

    $goVersion = (go version).Trim()
    Write-Host "Building $Tag with $goVersion" -ForegroundColor Cyan

    $dist = Join-Path $repoRoot 'dist'
    if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
    New-Item -ItemType Directory -Path $dist | Out-Null

    $targets = @(
        @{ OS = 'linux';   Arch = 'amd64' },
        @{ OS = 'linux';   Arch = 'arm64' },
        @{ OS = 'darwin';  Arch = 'amd64' },
        @{ OS = 'darwin';  Arch = 'arm64' },
        @{ OS = 'windows'; Arch = 'amd64' }
    )

    $commands = @('denyfirst-scan', 'denyfirstd')

    foreach ($target in $targets) {
        foreach ($command in $commands) {
            $name = "${command}_${Tag}_$($target.OS)_$($target.Arch)"
            if ($target.OS -eq 'windows') { $name += '.exe' }

            $output = Join-Path $dist $name

            $env:GOOS = $target.OS
            $env:GOARCH = $target.Arch
            $env:CGO_ENABLED = '0'

            # -s -w drop the symbol and DWARF tables: smaller files, and one
            # fewer thing that can differ between builds.
            go build -trimpath -buildvcs=false -ldflags "-s -w" -o $output "./cmd/$command"

            if ($LASTEXITCODE -ne 0) { throw "Build failed for $name" }
            Write-Host "  $name" -ForegroundColor DarkGray
        }
    }

    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue

    # ── Checksums ──────────────────────────────────────────────────────────
    #
    # In the format sha256sum -c expects, so a reader on any Unix can check
    # them without installing anything.

    Push-Location $dist
    try {
        $lines = Get-ChildItem -File | Sort-Object Name | ForEach-Object {
            $hash = (Get-FileHash -Algorithm SHA256 $_.Name).Hash.ToLower()
            "$hash  $($_.Name)"
        }

        # LF, no BOM. A CRLF file fails sha256sum -c on Linux and a BOM makes
        # the first line unparseable, either of which turns a verification step
        # into a support question.
        $utf8 = New-Object System.Text.UTF8Encoding $false
        $checksums = Join-Path $dist 'SHA256SUMS'
        [System.IO.File]::WriteAllText($checksums, ($lines -join "`n") + "`n", $utf8)

        $info = @(
            "tag $Tag",
            "commit $head",
            "toolchain $goVersion",
            "flags -trimpath -buildvcs=false -ldflags '-s -w'",
            "cgo disabled"
        )
        [System.IO.File]::WriteAllText((Join-Path $dist 'BUILD'), ($info -join "`n") + "`n", $utf8)

        # ── Signature ──────────────────────────────────────────────────────
        #
        # Only SHA256SUMS is signed. Signing every file would produce a
        # signature nobody checks in full; signing the list means one
        # verification covers every artifact, and the list itself names what
        # was released.

        Write-Host "`nSigning SHA256SUMS" -ForegroundColor Cyan
        ssh-keygen -Y sign -f $SigningKey -n file $checksums
        if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }

        # Verify what was just produced, against the same file a user would
        # use. A signature only the signer can check is not a signature.
        $allowed = Join-Path $repoRoot '.allowed_signers'
        if (Test-Path $allowed) {
            Write-Host 'Verifying the signature as a user would' -ForegroundColor Cyan

            # cmd's redirection rather than a PowerShell pipeline. Get-Content
            # decodes the file and re-encodes it on the way out, which turns
            # the LF endings written above into CRLF and changes the bytes the
            # signature covers. The verification then fails on a file that is
            # perfectly good, which is a worse outcome than not checking at
            # all: it teaches whoever sees it to ignore the check.
            cmd /c "ssh-keygen -Y verify -f `"$allowed`" -I $Identity -n file -s `"$checksums.sig`" < `"$checksums`""
            if ($LASTEXITCODE -ne 0) {
                throw 'The signature did not verify against .allowed_signers. Check that the public key there matches the signing key.'
            }
        }
        else {
            Write-Warning ".allowed_signers is missing, so the signature was not checked the way a user would check it."
        }
    }
    finally {
        Pop-Location
    }

    Write-Host "`nReady in dist\" -ForegroundColor Green
    Write-Host "Publish with:" -ForegroundColor Green
    Write-Host "  gh release create $Tag dist\* --title $Tag --notes 'First release.'" -ForegroundColor DarkGray
}
finally {
    Pop-Location
}