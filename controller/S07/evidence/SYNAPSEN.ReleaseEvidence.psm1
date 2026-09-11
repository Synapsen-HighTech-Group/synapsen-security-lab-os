Set-StrictMode -Version Latest
function New-SynapsenReleaseEvidenceSeal {
    param(
        [Parameter(Mandatory=$true)][string]$OutputDirectory,
        [Parameter(Mandatory=$true)][object[]]$Files,
        [string]$State='IMPLEMENTATION_EVIDENCE_ONLY'
    )
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    }
    $entries = @()
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "Evidence file missing: $f" }
        $entries += [pscustomobject]@{
            path=[string]$f
            sha256=(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant()
            size_bytes=(Get-Item -LiteralPath $f).Length
        }
    }
    [pscustomobject]@{
        schema='synapsen.s07.release-evidence-seal.v1'
        timestamp=(Get-Date).ToString('o')
        state=$State
        file_count=$entries.Count
        files=$entries
        release_signing_authorized=$false
        signing_keys_mutated=$false
        candidate_mutated=$false
        recoverable=$true
    }
}
Export-ModuleMember -Function New-SynapsenReleaseEvidenceSeal
