Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-SynapsenUtf8NoBom {
    param([string]$Path,[string]$Text)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path,$Text,$enc)
}

function New-SynapsenReleaseManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][string]$ReleaseId,
        [Parameter(Mandatory=$true)][string]$ArtifactPath,
        [Parameter(Mandatory=$true)][string]$ArtifactSha256,
        [Parameter(Mandatory=$true)][Int64]$ArtifactSizeBytes,
        [Parameter(Mandatory=$true)][string]$M1SealSha256,
        [Parameter(Mandatory=$true)][string]$ProvenanceSha256,
        [string]$SbomPath,
        [string]$SbomSha256,
        [string]$SbomSchemaVersion,
        [bool]$SbomCanonical = $false,
        [string]$SigningFingerprint = 'UNBOUND_PRE_SIGNING',
        [string]$SigningSubkeyFingerprint,
        [switch]$Signed
    )

    foreach ($h in @($ArtifactSha256,$M1SealSha256,$ProvenanceSha256)) {
        if ($h -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid SHA256.' }
    }
    if ($SbomSha256 -and $SbomSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Invalid SBOM SHA256.'
    }
    if ($SbomSha256) {
        if (-not $SbomPath) { throw 'Bound SBOM path is required.' }
        if ($SbomSchemaVersion -cne 'SPDX-3.0.1') { throw 'Bound SBOM must use SPDX-3.0.1.' }
        if (-not $SbomCanonical) { throw 'Bound SPDX 3.0.1 SBOM must be canonical.' }
    }
    elseif ($SbomPath -or $SbomSchemaVersion -or $SbomCanonical) {
        throw 'Partial SBOM binding is forbidden.'
    }
    if ($Signed) {
        if ($SigningFingerprint -cnotmatch '^[0-9A-F]{40}$' -or $SigningSubkeyFingerprint -cnotmatch '^[0-9A-F]{40}$') {
            throw 'Signed manifest requires full uppercase primary and signing-subkey fingerprints.'
        }
    }

    $obj = [ordered]@{
        schema = 'synapsen.release.manifest.v1'
        release_id = $ReleaseId
        artifact = [ordered]@{
            path = $ArtifactPath
            sha256 = $ArtifactSha256.ToLowerInvariant()
            size_bytes = $ArtifactSizeBytes
        }
        evidence = [ordered]@{
            m1_seal_sha256 = $M1SealSha256.ToLowerInvariant()
            provenance_sha256 = $ProvenanceSha256.ToLowerInvariant()
            sbom = [ordered]@{
                required = $true
                path = $(if ($SbomPath) { $SbomPath } else { $null })
                sha256 = $(if ($SbomSha256) { $SbomSha256.ToLowerInvariant() } else { $null })
                schema_version = $(if ($SbomSha256) { $SbomSchemaVersion } else { $null })
                canonical = $(if ($SbomSha256) { $true } else { $false })
                state = $(if ($SbomSha256) { 'BOUND' } else { 'PENDING_BLOCKING' })
            }
        }
        trust = [ordered]@{
            signing_fingerprint = $SigningFingerprint
            signing_subkey_fingerprint = $(if ($Signed) { $SigningSubkeyFingerprint } else { $null })
            signature_profile = $(if ($Signed) { 'OpenPGP Ed25519 detached armored' } else { $null })
            signing_state = $(if ($Signed) { 'SIGNED_RELEASE' } else { 'NOT_SIGNED_BY_IMPLEMENTATION_FOUNDATION' })
        }
    }

    $json = $obj | ConvertTo-Json -Depth 8
    Write-SynapsenUtf8NoBom -Path $OutputPath -Text ($json + "`n")
    [pscustomobject]@{
        path = $OutputPath
        sha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
        schema = $obj.schema
        sbom_state = $obj.evidence.sbom.state
    }
}

function New-SynapsenSha256Sums {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][object[]]$Items
    )

    $lines = @()
    foreach ($item in $Items | Sort-Object -Property name) {
        if ([string]$item.sha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw "Invalid SHA256SUMS item: $($item.name)"
        }
        $lines += "$(([string]$item.sha256).ToLowerInvariant())  $([string]$item.name)"
    }

    Write-SynapsenUtf8NoBom -Path $OutputPath -Text (($lines -join "`n") + "`n")
    [pscustomobject]@{
        path = $OutputPath
        item_count = $lines.Count
        sha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

Export-ModuleMember -Function New-SynapsenReleaseManifest,New-SynapsenSha256Sums
