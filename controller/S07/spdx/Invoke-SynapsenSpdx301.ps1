[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackagesPath,
    [Parameter(Mandatory)][string]$ArtifactPath,
    [Parameter(Mandatory)][string]$ArtifactSha256,
    [Parameter(Mandatory)][string]$ReleaseId,
    [Parameter(Mandatory)][string]$Created,
    [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = $PSScriptRoot
$Generator = Join-Path $Root 'New-SynapsenSpdx301Sbom.py'
$Validator = Join-Path $Root 'Test-SynapsenSpdx301Sbom.py'
$Official = Join-Path $Root 'official\3.0.1'
$Schema = Join-Path $Official 'spdx-json-schema.json'
$Context = Join-Path $Official 'spdx-context.jsonld'
$Model = Join-Path $Official 'spdx-model.ttl'
$Vendor = Join-Path $Root 'vendor\3.0.1'
$ExpectedAssets = [ordered]@{
    $Schema = '582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1'
    $Context = 'c72b0928f094c83e5c127784edb1ebca2af74a104fcacc007c332b23cbc788bd'
    $Model = '30ebb4af2d70a9809044ef46f44cc3dc5125226d70f818a50ed2e1d5f404c593'
}

function Sha([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Ok([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "Assertion failed: $Label" }
}
function Invoke-Python([string[]]$Arguments) {
    $Output = @(& $Python.Source @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Python subprocess failed:`n$($Output -join "`n")" }
    $Output -join "`n"
}

$Python = Get-Command python -ErrorAction Stop | Select-Object -First 1
foreach ($Path in @($PackagesPath,$ArtifactPath,$Generator,$Validator,$Vendor)) {
    Ok (Test-Path -LiteralPath $Path) "required path $Path"
}
foreach ($Entry in $ExpectedAssets.GetEnumerator()) {
    Ok (Test-Path -LiteralPath $Entry.Key -PathType Leaf) "official SPDX asset $($Entry.Key)"
    Ok ((Sha $Entry.Key) -ceq $Entry.Value) "official SPDX asset SHA $($Entry.Key)"
}
Ok ($ArtifactSha256 -match '^[0-9a-fA-F]{64}$') 'artifact SHA256 syntax'
Ok (-not (Test-Path -LiteralPath $OutputPath)) 'fresh SBOM output'
$ReproPath = "$OutputPath.reprocheck"
Ok (-not (Test-Path -LiteralPath $ReproPath)) 'fresh reproducibility output'

$PreviousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = $(if ($PreviousPythonPath) { "$Vendor$([IO.Path]::PathSeparator)$PreviousPythonPath" } else { $Vendor })
    $GeneratorArguments = @(
        $Generator,
        '--packages',$PackagesPath,
        '--artifact',$ArtifactPath,
        '--artifact-sha256',$ArtifactSha256.ToLowerInvariant(),
        '--release-id',$ReleaseId,
        '--created',$Created,
        '--output',$OutputPath
    )
    $Generation = Invoke-Python $GeneratorArguments
    Ok ($Generation.Contains('CANONICAL_JSON=PASS')) 'canonical generation'
    $ReproArguments = [string[]]$GeneratorArguments.Clone()
    $ReproArguments[$ReproArguments.Count - 1] = $ReproPath
    $Reproduction = Invoke-Python $ReproArguments
    Ok ((Sha $OutputPath) -ceq (Sha $ReproPath)) 'byte-for-byte reproducibility'

    $Validation = Invoke-Python @(
        $Validator,
        '--sbom',$OutputPath,
        '--packages',$PackagesPath,
        '--artifact',$ArtifactPath,
        '--artifact-sha256',$ArtifactSha256.ToLowerInvariant(),
        '--release-id',$ReleaseId,
        '--schema',$Schema,
        '--context',$Context,
        '--model',$Model
    )
    foreach ($Needle in @('SPDX_VERSION=3.0.1','CANONICAL_JSON=PASS','JSON_SCHEMA=PASS','SHACL=PASS','SYNAPSEN_CONTRACT=PASS')) {
        Ok ($Validation.Contains($Needle)) "validator result $Needle"
    }
}
finally {
    $env:PYTHONPATH = $PreviousPythonPath
    if (Test-Path -LiteralPath $ReproPath -PathType Leaf) { [IO.File]::Delete([IO.Path]::GetFullPath($ReproPath)) }
}

Write-Host $Generation
Write-Host 'REPRODUCIBILITY=PASS'
Write-Host $Validation
Write-Host "OFFICIAL_SCHEMA_SHA256=$($ExpectedAssets[$Schema])"
Write-Host "OFFICIAL_CONTEXT_SHA256=$($ExpectedAssets[$Context])"
Write-Host "OFFICIAL_MODEL_SHA256=$($ExpectedAssets[$Model])"
Write-Host 'OFFLINE_AFTER_SETUP=True'
