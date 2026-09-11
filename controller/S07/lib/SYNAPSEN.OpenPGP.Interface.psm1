Set-StrictMode -Version Latest

function Get-SynapsenOpenPgpCapability {
    $gpg = Get-Command gpg -ErrorAction SilentlyContinue | Select-Object -First 1
    $gpgv = Get-Command gpgv -ErrorAction SilentlyContinue | Select-Object -First 1
    [pscustomobject]@{
        gpg_present = ($null -ne $gpg)
        gpg_path = $(if ($gpg) { $gpg.Source } else { $null })
        gpgv_present = ($null -ne $gpgv)
        gpgv_path = $(if ($gpgv) { $gpgv.Source } else { $null })
        release_signing_completed = $true
        verification_enforced = $true
        trusted_primary_fingerprint = '67328AC71B4D6D77365E71AE304228C84D338F8E'
        trusted_signing_subkey_fingerprint = '6D47D3B77836B1E51A2B218B5AAFBE7F7212CFF7'
        signing_execution_authorized = $false
        key_mutation_authorized = $false
    }
}

function New-SynapsenSigningPlan {
    param(
        [Parameter(Mandatory=$true)][string]$ManifestPath,
        [Parameter(Mandatory=$true)][string]$SignaturePath,
        [string]$ExpectedFingerprint
    )
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw 'Manifest missing.'
    }
    [pscustomobject]@{
        operation = 'OPENPGP_DETACHED_ARMORED_SIGNATURE'
        manifest_path = $ManifestPath
        signature_path = $SignaturePath
        expected_fingerprint = $ExpectedFingerprint
        execution_authorized = $false
        key_generation_authorized = $false
        key_import_authorized = $false
        key_export_authorized = $false
        note = 'Initial release signing is closed. Additional signing requires a separately authorized offline custody session.'
    }
}

Export-ModuleMember -Function Get-SynapsenOpenPgpCapability,New-SynapsenSigningPlan
