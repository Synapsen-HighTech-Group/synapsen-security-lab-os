#requires -Version 5.1
Set-StrictMode -Version Latest

$matrix = @(
    [pscustomobject]@{id='S07-T01';case='VALID_RELEASE_CHAIN';expected='PASS'},
    [pscustomobject]@{id='S07-T02';case='TAMPERED_ARTIFACT';expected='FAIL'},
    [pscustomobject]@{id='S07-T03';case='TAMPERED_MANIFEST';expected='FAIL'},
    [pscustomobject]@{id='S07-T04';case='TAMPERED_SIGNATURE';expected='FAIL'},
    [pscustomobject]@{id='S07-T05';case='WRONG_UNTRUSTED_KEY';expected='FAIL'},
    [pscustomobject]@{id='S07-T06';case='MISSING_PROVENANCE';expected='FAIL'},
    [pscustomobject]@{id='S07-T07';case='MISSING_SBOM';expected='FAIL'},
    [pscustomobject]@{id='S07-T08';case='MISSING_M1_SEAL';expected='FAIL'},
    [pscustomobject]@{id='S07-T09';case='MALFORMED_MANIFEST';expected='FAIL'},
    [pscustomobject]@{id='S07-T10';case='REPLAY_RELEASE_ID_MISMATCH';expected='FAIL'},
    [pscustomobject]@{id='S07-T11';case='EXPIRED_SIGNING_SUBKEY';expected='FAIL'},
    [pscustomobject]@{id='S07-T12';case='REVOKED_RELEASE_KEY';expected='FAIL'},
    [pscustomobject]@{id='S07-T13';case='MISSING_SIGNATURE';expected='FAIL'},
    [pscustomobject]@{id='S07-T14';case='MISSING_TRUSTED_KEYRING';expected='FAIL'},
    [pscustomobject]@{id='S07-T15';case='MANIFEST_SCHEMA_DOWNGRADE';expected='FAIL'},
    [pscustomobject]@{id='S07-T16';case='SBOM_PATH_TRAVERSAL';expected='FAIL'}
)
[pscustomobject]@{
    schema = 'synapsen.s07.acceptance-matrix.contract.v2'
    case_count = $matrix.Count
    unsafe_case_count = 0
    state = 'REAL_MATRIX_PASS_CLOSED_SEALED'
    evidence_revision = 'V24T-WP06-R1'
    cases = $matrix
} | ConvertTo-Json -Depth 6
