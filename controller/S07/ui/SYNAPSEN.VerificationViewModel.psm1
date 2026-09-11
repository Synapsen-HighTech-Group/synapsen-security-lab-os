Set-StrictMode -Version Latest
function ConvertTo-SynapsenVerificationViewModel {
    param([Parameter(Mandatory=$true)]$VerificationResult)
    $overall = if ([bool]$VerificationResult.pass) { 'PASS' } else { 'FAIL' }
    [pscustomobject]@{
        overall_state = $overall
        title = 'Release-Verifizierung'
        summary = $(if ($overall -eq 'PASS') { 'Vertrauenspfad bestaetigt.' } else { 'Freigabe blockiert. Pflichtpruefung fehlgeschlagen.' })
        cards = @(
            [pscustomobject]@{id='artifact';title='ISO-Integritaet';state=$(if($VerificationResult.artifact_hash.pass){'PASS'}else{'FAIL'});detail=[string]$VerificationResult.artifact_hash.reason},
            [pscustomobject]@{id='signature';title='Release-Signatur';state=$(if($VerificationResult.signature.pass){'PASS'}else{'FAIL'});detail=[string]$VerificationResult.signature.reason},
            [pscustomobject]@{id='provenance';title='Build-Herkunft';state=$(if($VerificationResult.provenance.pass){'PASS'}else{'FAIL'});detail=[string]$VerificationResult.provenance.reason},
            [pscustomobject]@{id='sbom';title='SPDX 3.0.1';state=$(if($VerificationResult.sbom.pass){'PASS'}else{'FAIL'});detail=[string]$VerificationResult.sbom.reason},
            [pscustomobject]@{id='m1';title='M1-Abnahmesiegel';state=$(if($VerificationResult.m1_seal.pass){'PASS'}else{'FAIL'});detail=[string]$VerificationResult.m1_seal.reason}
        )
        fail_closed = $true
        trust_override_allowed = $false
    }
}
Export-ModuleMember -Function ConvertTo-SynapsenVerificationViewModel
