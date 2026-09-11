#requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$Artifact,
    [string]$Signature,
    [string]$TrustedKeyring,
    [switch]$RequireSignature,
    [string]$ExpectedReleaseId = 'SYNAPSEN-SECURITY-LAB-OS-2026.3-S07',
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\SYNAPSEN.ReleaseVerifier.psm1'
Import-Module $module -Force

try {
    $r = Invoke-SynapsenReleaseVerification -ManifestPath $Manifest -ArtifactPath $Artifact -SignaturePath $Signature -TrustedKeyring $TrustedKeyring -RequireSignature:$RequireSignature -ExpectedReleaseId $ExpectedReleaseId
    if ($Json) {
        $r | ConvertTo-Json -Depth 8
    }
    else {
        Write-Host "SYNAPSEN_RELEASE_VERIFY=$($r.pass)"
        Write-Host "ARTIFACT_HASH=$($r.artifact_hash.reason)"
        Write-Host "SIGNATURE=$($r.signature.reason)"
        Write-Host "PROVENANCE=$($r.provenance.reason)"
        Write-Host "SBOM=$($r.sbom.reason)"
        Write-Host "M1_SEAL=$($r.m1_seal.reason)"
        Write-Host "FAIL_CLOSED=$($r.fail_closed)"
    }
    if ($r.pass) { exit 0 }
    exit 2
}
catch {
    Write-Host 'SYNAPSEN_RELEASE_VERIFY=False'
    Write-Host 'FAIL_CLOSED=True'
    Write-Host "ERROR=$($_.Exception.Message)"
    exit 3
}
