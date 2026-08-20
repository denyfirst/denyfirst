<#
.SYNOPSIS
    Signs a release that was built in public, and publishes it.

.DESCRIPTION
    The binaries are not built here. A workflow builds them from the tagged
    source on a machine nobody controls, in a log anyone can read, and this
    downloads that result, checks it, signs the checksums and publishes.

    The reason is the one that matters most about a release. A signature says
    the artifacts came from whoever holds the key; it says nothing about
    whether they correspond to the source. Building on the same machine that
    signs means one compromise produces both a malicious binary and a valid
    signature for it, and nothing in the chain notices.

    Splitting it means two separate parties are involved: a workflow that
    builds but cannot sign, and this machine, which signs but does not build.
    Compromising either alone yields nothing, and the build is visible to
    everyone while it happens.

    Optionally rebuilds locally and compares. That check is off by default
    because it only holds on Linux — cross-compiling from Windows puts a
    different GOROOT in the runtime package, which -trimpath does not reach —
    and a check that fails on every honest release teaches people to ignore
    it.

.PARAMETER Tag
    The version being released, such as v0.1.0.

.PARAMETER SigningKey
    Path to the private key used for the signature. Separate from the GitHub
    key on purpose: one being lost must not cost the other.

.PARAMETER Compare
    Rebuild locally and compare against what the workflow produced. Meaningful
    on Linux; on Windows the difference is the host, not the source.

.EXAMPLE
    .\scripts\release.ps1 -Tag v0.1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
    [string]$Tag,

    [string]$SigningKey = "$env:USERPROFILE\.ssh\id_ed25519_denyfirst_release",

    [string]$Identity = 'releases@denyfirst.dev',

    [switch]$Compare
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    if (-not (Test-Path $SigningKey)) {
        throw "No signing key at $SigningKey."
    }

    $tagged = (git rev-list -n 1 $Tag 2>$null)
    if (-not $tagged) {
        throw "Tag $Tag does not exist locally. Create and push it first:`n  git tag -s $Tag -m 'notes'`n  git push origin $Tag"
    }

    $dist = Join-Path $repoRoot 'dist'
    if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }

    # ── Fetch what the workflow built ──────────────────────────────────────
    #
    # The workflow leaves a draft release. A draft is invisible to anyone but
    # the maintainer, so the binaries sit there unsigned without anybody being
    # able to download them, which is the property that makes this safe to do
    # in two steps.

    Write-Host "Downloading the draft release for $Tag" -ForegroundColor Cyan

    New-Item -ItemType Directory -Path $dist | Out-Null
    gh release download $Tag --dir $dist --clobber
    if ($LASTEXITCODE -ne 0) {
        throw "No release found for $Tag. Push the tag and wait for build-release.yml, or start it with:`n  gh workflow run build-release.yml -f tag=$Tag"
    }

    if (Test-Path (Join-Path $dist 'SHA256SUMS.sig')) {
        Write-Warning "This release already carries a signature. Signing again replaces it."
    }

    $checksums = Join-Path $dist 'SHA256SUMS'
    $buildInfo = Join-Path $dist 'BUILD'
    if (-not (Test-Path $checksums)) { throw "The artifact has no SHA256SUMS." }
    if (-not (Test-Path $buildInfo)) { throw "The artifact has no BUILD record." }

    # ── Check what is about to be signed ───────────────────────────────────
    #
    # A signature over a file nobody read is a signature over whatever was in
    # it. The commit is checked against the tag, and every listed file has to
    # be present with the hash the list claims.

    Write-Host "`nBuild record" -ForegroundColor Cyan
    Get-Content $buildInfo | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    function Read-BuildField([string]$name) {
        # Matched explicitly rather than by chaining onto Select-String's
        # result, which under StrictMode throws a message about a null
        # property when what actually happened is that the record is missing
        # a field. Failing closed is right; failing closed with an
        # unreadable reason is how a check gets skipped next time.
        $match = Select-String -Path $buildInfo -Pattern "^$name\s+(\S+)"
        if (-not $match) {
            throw "The build record has no '$name' field. Nothing was signed."
        }
        return $match.Matches.Groups[1].Value
    }

    $recordedCommit = Read-BuildField 'commit'
    if ($recordedCommit -ne $tagged.Trim()) {
        throw "The build records commit $recordedCommit but $Tag points at $($tagged.Trim())."
    }

    $recordedTag = Read-BuildField 'tag'
    if ($recordedTag -ne $Tag) {
        throw "The build records tag $recordedTag rather than $Tag."
    }

    # ── The procedure, not only the source ─────────────────────────────────
    #
    # The commit check above says the workflow built the right source. It says
    # nothing about how, and the how is a file: scripts/build.sh decides the
    # flags, and therefore the bytes. It used to be fetched from the default
    # branch at build time, so somebody able to move that branch could change
    # what a tagged, honest commit compiled into — and reproduce.yml read the
    # same mutable file, so the reproduction agreed.
    #
    # This is the half of that fix which lives on the machine holding the key.
    # A signature is a statement about bytes; this is what lets the statement
    # mean "built by the procedure in this repository" rather than "built
    # somehow".
    $recordedScript = Read-BuildField 'buildscript'

    function Get-BlobSha256([string]$rev) {
        # Through a file rather than a pipeline: PowerShell decodes and
        # re-encodes text, which would change the bytes being hashed. The same
        # reason the signature check at the bottom uses cmd's redirection.
        $temporary = [System.IO.Path]::GetTempFileName()
        try {
            cmd /c "git show `"$rev`" > `"$temporary`" 2>nul" | Out-Null
            if ($LASTEXITCODE -ne 0) { return $null }
            if ((Get-Item $temporary).Length -eq 0) { return $null }
            return (Get-FileHash -Algorithm SHA256 $temporary).Hash.ToLower()
        }
        finally {
            Remove-Item $temporary -ErrorAction SilentlyContinue
        }
    }

    $scriptSources = [ordered]@{
        "the tag $Tag" = Get-BlobSha256 "${Tag}:scripts/build.sh"
        'origin/main'  = Get-BlobSha256 'origin/main:scripts/build.sh'
    }

    $scriptSource = $null
    foreach ($candidate in $scriptSources.GetEnumerator()) {
        if ($candidate.Value -and $candidate.Value -eq $recordedScript) {
            $scriptSource = $candidate.Key
            break
        }
    }

    if (-not $scriptSource) {
        $seen = ($scriptSources.GetEnumerator() |
            ForEach-Object { "    $($_.Key): $(if ($_.Value) { $_.Value } else { 'absent' })" }) -join "`n"
        throw @"
The release was built by a script this repository does not contain.

  recorded in BUILD: $recordedScript
$seen

scripts/build.sh decides the build flags and therefore the bytes, so a
procedure nobody can point at is a binary nobody can account for. Fetch
origin, read the diff, and only sign once the hash above is one you can
find in the history. Nothing was signed.
"@
    }
    Write-Host "  build script matches $scriptSource" -ForegroundColor DarkGray

    Write-Host "`nVerifying every hash in the list" -ForegroundColor Cyan
    $bad = 0
    foreach ($line in Get-Content $checksums) {
        if ($line -notmatch '^([0-9a-f]{64})\s+(.+)$') { continue }
        $want = $Matches[1]
        $name = $Matches[2].Trim()

        $file = Join-Path $dist $name
        if (-not (Test-Path $file)) {
            Write-Host "  missing: $name" -ForegroundColor Red
            $bad++
            continue
        }
        $have = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
        if ($have -ne $want) {
            Write-Host "  mismatch: $name" -ForegroundColor Red
            $bad++
        }
    }
    if ($bad -gt 0) { throw "$bad file(s) do not match the checksum list. Nothing was signed." }
    Write-Host "  every file matches" -ForegroundColor DarkGray

    # ── Optionally rebuild and compare ─────────────────────────────────────

    if ($Compare) {
        Write-Host "`nRebuilding locally to compare" -ForegroundColor Cyan
        Write-Host "  (meaningful on Linux; on Windows a difference is the host, not the source)" -ForegroundColor DarkGray

        $local = Join-Path $repoRoot 'dist-local'
        if (Test-Path $local) { Remove-Item -Recurse -Force $local }
        New-Item -ItemType Directory -Path $local | Out-Null

        $head = (git rev-parse HEAD).Trim()
        if ($head -ne $tagged.Trim()) {
            # Was a warning, which meant the comparison ran against whatever
            # was checked out and reported a difference count for the wrong
            # source. A check whose result cannot be interpreted is worse than
            # no check: the number looks like evidence.
            throw "HEAD is $head but $Tag points at $($tagged.Trim()). Check out the tag before comparing:`n  git checkout $Tag"
        }

        foreach ($target in @(
            @{ OS = 'linux'; Arch = 'amd64' }, @{ OS = 'linux'; Arch = 'arm64' },
            @{ OS = 'darwin'; Arch = 'amd64' }, @{ OS = 'darwin'; Arch = 'arm64' },
            @{ OS = 'windows'; Arch = 'amd64' })) {

            foreach ($command in @('denyfirst-scan', 'denyfirstd')) {
                $name = "${command}_${Tag}_$($target.OS)_$($target.Arch)"
                if ($target.OS -eq 'windows') { $name += '.exe' }

                $env:GOOS = $target.OS
                $env:GOARCH = $target.Arch
                $env:CGO_ENABLED = '0'
                go build -trimpath -buildvcs=false -ldflags "-s -w" -o (Join-Path $local $name) "./cmd/$command"
            }
        }
        Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue

        $same = 0; $diff = 0
        Get-ChildItem $local -File | ForEach-Object {
            $mine = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
            $theirs = (Get-FileHash -Algorithm SHA256 (Join-Path $dist $_.Name)).Hash.ToLower()
            if ($mine -eq $theirs) { $same++ } else { $diff++ }
        }
        Write-Host "  $same identical, $diff different" -ForegroundColor DarkGray
        Remove-Item -Recurse -Force $local
    }

    # ── Sign ───────────────────────────────────────────────────────────────
    #
    # Only SHA256SUMS is signed. Signing every file would produce a signature
    # nobody checks in full; signing the list means one verification covers
    # every artifact, and the list itself is the record of what was released.

    Write-Host "`nSigning SHA256SUMS" -ForegroundColor Cyan
    ssh-keygen -Y sign -f $SigningKey -n file $checksums
    if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }

    $allowed = Join-Path $repoRoot '.allowed_signers'
    if (Test-Path $allowed) {
        Write-Host 'Verifying the signature as a user would' -ForegroundColor Cyan

        # cmd's redirection rather than a PowerShell pipeline: Get-Content
        # decodes and re-encodes, which turns the LF endings into CRLF and
        # changes the bytes the signature covers. The check would then fail on
        # a perfectly good file, which is worse than not checking — it teaches
        # whoever sees it to ignore the result.
        # Every interpolated value is quoted. $Tag is constrained by
        # ValidatePattern and $Identity is not, so an identity containing a
        # quote would otherwise end the argument and hand the rest to cmd as
        # commands. It is an operator-supplied parameter rather than anything
        # a stranger sends, which makes this cheap rather than urgent — and
        # cheap is not a reason to leave it.
        cmd /c "ssh-keygen -Y verify -f `"$allowed`" -I `"$Identity`" -n file -s `"$checksums.sig`" < `"$checksums`""
        if ($LASTEXITCODE -ne 0) {
            throw 'The signature did not verify against .allowed_signers.'
        }
    }
    else {
        Write-Warning ".allowed_signers is missing, so the signature was not checked the way a user would."
    }

    Write-Host "`nSigned." -ForegroundColor Green
    Write-Host "Upload the signature and publish:" -ForegroundColor Green
    Write-Host "  gh release upload $Tag dist\SHA256SUMS.sig --clobber" -ForegroundColor DarkGray
    Write-Host "  gh release edit $Tag --draft=false" -ForegroundColor DarkGray
}
finally {
    Pop-Location
}