Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-SynapsenReleaseManifest {
    param([Parameter(Mandatory=$true)][string]$ManifestPath,[string]$ExpectedReleaseId)
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw 'Manifest missing.' }
    try { $obj = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json }
    catch { throw "Malformed manifest: $($_.Exception.Message)" }
    if ([string]$obj.schema -cne 'synapsen.release.manifest.v1') { throw "Unsupported schema: $($obj.schema)" }
    if (-not ([string]$obj.release_id -cmatch '^SYNAPSEN-SECURITY-LAB-OS-[0-9]{4}\.[0-9]+-S[0-9]{2}$')) { throw 'Malformed release id.' }
    if ($ExpectedReleaseId -and [string]$obj.release_id -cne $ExpectedReleaseId) { throw 'Release id mismatch / replay blocked.' }
    if ([string]$obj.trust.signing_state -cne 'SIGNED_RELEASE') { throw 'Manifest is not in signed release state.' }
    if ([string]$obj.trust.signature_profile -cne 'OpenPGP Ed25519 detached armored') { throw 'Unsupported signature profile.' }
    foreach ($fingerprint in @([string]$obj.trust.signing_fingerprint,[string]$obj.trust.signing_subkey_fingerprint)) {
        if ($fingerprint -cnotmatch '^[0-9A-F]{40}$') { throw 'Malformed signing fingerprint.' }
    }
    $obj
}

function Resolve-SynapsenBoundPath {
    param([Parameter(Mandatory=$true)][string]$ManifestPath,[Parameter(Mandatory=$true)][string]$RelativePath)
    if ([IO.Path]::IsPathRooted($RelativePath)) { throw 'Absolute bound path is forbidden.' }
    $base = [IO.Path]::GetFullPath((Split-Path -Parent $ManifestPath)).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath((Join-Path $base $RelativePath))
    if (-not $resolved.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'Bound path escapes release directory.' }
    $resolved
}

function Test-SynapsenArtifactHash {
    param([string]$ArtifactPath,[string]$ExpectedSha256,[Nullable[Int64]]$ExpectedSizeBytes)
    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) { return [pscustomobject]@{pass=$false;reason='ARTIFACT_MISSING';actual_sha256=$null;actual_size_bytes=$null} }
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') { return [pscustomobject]@{pass=$false;reason='ARTIFACT_BINDING_MALFORMED';actual_sha256=$null;actual_size_bytes=$null} }
    $item = Get-Item -LiteralPath $ArtifactPath
    $actual = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashPass = $actual -ceq $ExpectedSha256
    $sizePass = ($null -eq $ExpectedSizeBytes) -or $item.Length -eq [Int64]$ExpectedSizeBytes
    [pscustomobject]@{pass=($hashPass-and$sizePass);reason=$(if(-not$hashPass){'HASH_MISMATCH'}elseif(-not$sizePass){'SIZE_MISMATCH'}else{'PASS'});actual_sha256=$actual;actual_size_bytes=$item.Length}
}

function Get-SynapsenTrustedKeyState {
    param([string]$TrustedKeyring,[string]$ExpectedPrimaryFingerprint,[string]$ExpectedSigningFingerprint,[datetime]$VerificationTimeUtc)
    if (-not (Test-Path -LiteralPath $TrustedKeyring -PathType Leaf)) { return [pscustomobject]@{pass=$false;reason='TRUSTED_KEYRING_MISSING'} }
    $gpg = Get-Command gpg -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $gpg) { return [pscustomobject]@{pass=$false;reason='OPENPGP_KEY_INSPECTOR_MISSING'} }
    $output = @(& $gpg.Source --batch --no-options --with-colons --with-fingerprint --with-subkey-fingerprint --show-keys $TrustedKeyring 2>&1)
    if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{pass=$false;reason='TRUSTED_KEY_PARSE_FAIL';output=(($output|ForEach-Object{[string]$_})-join"`n")} }
    $lines = @(($output|ForEach-Object{[string]$_}) | Where-Object { $_ -match '^(pub|sub|fpr):' })
    $primary=$null; $sub=$null; $mode=''
    foreach($line in $lines){
        $f=$line-split':'
        if($f[0]-eq'pub'){$primary=[ordered]@{validity=$f[1];algorithm=$f[3];created=[int64]$f[5];expires=[int64]$f[6];capabilities=$f[11];fingerprint=$null};$mode='pub';continue}
        if($f[0]-eq'sub'){$sub=[ordered]@{validity=$f[1];algorithm=$f[3];created=[int64]$f[5];expires=[int64]$f[6];capabilities=$f[11];fingerprint=$null};$mode='sub';continue}
        if($f[0]-eq'fpr' -and $mode-eq'pub' -and -not$primary.fingerprint){$primary.fingerprint=$f[9];continue}
        if($f[0]-eq'fpr' -and $mode-eq'sub' -and -not$sub.fingerprint){$sub.fingerprint=$f[9];continue}
    }
    if(-not$primary-or-not$sub){return [pscustomobject]@{pass=$false;reason='REQUIRED_KEY_OR_SUBKEY_MISSING'}}
    $now=[DateTimeOffset]$VerificationTimeUtc; $epoch=$now.ToUnixTimeSeconds()
    $revoked=(@('r','d')-contains[string]$primary.validity)-or(@('r','d')-contains[string]$sub.validity)
    $expired=($primary.expires-gt0-and$epoch-ge$primary.expires)-or($sub.expires-gt0-and$epoch-ge$sub.expires)
    $identity=([string]$primary.fingerprint-ceq$ExpectedPrimaryFingerprint)-and([string]$sub.fingerprint-ceq$ExpectedSigningFingerprint)
    $algorithms=([string]$primary.algorithm-ceq'22')-and([string]$sub.algorithm-ceq'22')-and([string]$primary.capabilities-cmatch'c')-and([string]$sub.capabilities-cmatch's')
    [pscustomobject]@{pass=($identity-and$algorithms-and-not$revoked-and-not$expired);reason=$(if(-not$identity){'KEY_FINGERPRINT_MISMATCH'}elseif(-not$algorithms){'KEY_PROFILE_MISMATCH'}elseif($revoked){'KEY_REVOKED'}elseif($expired){'KEY_EXPIRED'}else{'PASS'});primary_fingerprint=$primary.fingerprint;signing_fingerprint=$sub.fingerprint;primary_expires=$primary.expires;signing_expires=$sub.expires;verification_epoch=$epoch}
}

function Test-SynapsenDetachedSignature {
    param([string]$ManifestPath,[string]$SignaturePath,[string]$TrustedKeyring,[string]$ExpectedPrimaryFingerprint,[string]$ExpectedSigningFingerprint,[datetime]$VerificationTimeUtc=(Get-Date).ToUniversalTime())
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return [pscustomobject]@{pass=$false;reason='MANIFEST_MISSING';exit_code=$null} }
    if (-not (Test-Path -LiteralPath $SignaturePath -PathType Leaf)) { return [pscustomobject]@{pass=$false;reason='SIGNATURE_MISSING';exit_code=$null} }
    $keyState=Get-SynapsenTrustedKeyState -TrustedKeyring $TrustedKeyring -ExpectedPrimaryFingerprint $ExpectedPrimaryFingerprint -ExpectedSigningFingerprint $ExpectedSigningFingerprint -VerificationTimeUtc $VerificationTimeUtc
    if(-not$keyState.pass){return [pscustomobject]@{pass=$false;reason=$keyState.reason;exit_code=$null;key_state=$keyState}}
    $gpgv=Get-Command gpgv -ErrorAction SilentlyContinue|Select-Object -First 1
    if(-not$gpgv){return [pscustomobject]@{pass=$false;reason='OPENPGP_VERIFIER_MISSING';exit_code=$null}}
    $output=@(& $gpgv.Source --status-fd 1 --keyring $TrustedKeyring $SignaturePath $ManifestPath 2>&1);$exit=$LASTEXITCODE
    $text=($output|ForEach-Object{[string]$_})-join"`n"
    $statusPass=$text-cmatch("(?m)^\[GNUPG:\] VALIDSIG "+[regex]::Escape($ExpectedSigningFingerprint)+" ")-and$text-cmatch[regex]::Escape($ExpectedPrimaryFingerprint)
    [pscustomobject]@{pass=($exit-eq0-and$statusPass);reason=$(if($exit-ne0){'SIGNATURE_VERIFY_FAIL'}elseif(-not$statusPass){'SIGNER_FINGERPRINT_MISMATCH'}else{'PASS'});exit_code=$exit;key_state=$keyState;output=$text}
}

function Test-SynapsenSbomBinding {
    param([Parameter(Mandatory=$true)]$Manifest,[Parameter(Mandatory=$true)][string]$ManifestPath)
    $b=$Manifest.evidence.sbom
    if(-not$b-or[string]$b.state-cne'BOUND'){return [pscustomobject]@{pass=$false;reason='SBOM_REQUIRED'}}
    if([string]$b.schema_version-cne'SPDX-3.0.1'-or-not[bool]$b.canonical){return [pscustomobject]@{pass=$false;reason='SBOM_SCHEMA_OR_CANONICAL_MISMATCH'}}
    if([string]$b.sha256-cnotmatch'^[0-9a-f]{64}$'-or-not[string]$b.path){return [pscustomobject]@{pass=$false;reason='SBOM_BINDING_MALFORMED'}}
    try{$resolved=Resolve-SynapsenBoundPath -ManifestPath $ManifestPath -RelativePath ([string]$b.path)}catch{return [pscustomobject]@{pass=$false;reason='SBOM_PATH_UNSAFE'}}
    if(-not(Test-Path -LiteralPath $resolved -PathType Leaf)){return [pscustomobject]@{pass=$false;reason='SBOM_MISSING';resolved_path=$resolved}}
    $actual=(Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant();$expected=[string]$b.sha256
    [pscustomobject]@{pass=($actual-ceq$expected);reason=$(if($actual-ceq$expected){'PASS'}else{'SBOM_HASH_MISMATCH'});actual_sha256=$actual;resolved_path=$resolved;schema_version=[string]$b.schema_version;canonical=[bool]$b.canonical}
}

function Test-SynapsenProvenanceBinding {
    param($Manifest,[string]$ManifestPath)
    $expected=[string]$Manifest.evidence.provenance_sha256
    if($expected-cnotmatch'^[0-9a-f]{64}$'){return [pscustomobject]@{pass=$false;reason='PROVENANCE_BINDING_MALFORMED'}}
    $path=Resolve-SynapsenBoundPath -ManifestPath $ManifestPath -RelativePath ("$($Manifest.release_id).provenance.json")
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){return [pscustomobject]@{pass=$false;reason='PROVENANCE_MISSING';resolved_path=$path}}
    $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    [pscustomobject]@{pass=($actual-ceq$expected);reason=$(if($actual-ceq$expected){'PASS'}else{'PROVENANCE_HASH_MISMATCH'});actual_sha256=$actual;resolved_path=$path}
}

function Test-SynapsenM1SealBinding {
    param($Manifest,[string]$ManifestPath)
    $expected=[string]$Manifest.evidence.m1_seal_sha256
    if($expected-cnotmatch'^[0-9a-f]{64}$'){return [pscustomobject]@{pass=$false;reason='M1_BINDING_MALFORMED'}}
    $path=Resolve-SynapsenBoundPath -ManifestPath $ManifestPath -RelativePath ("$($Manifest.release_id).M1.acceptance-seal.json")
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){return [pscustomobject]@{pass=$false;reason='M1_SEAL_MISSING';resolved_path=$path}}
    $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    [pscustomobject]@{pass=($actual-ceq$expected);reason=$(if($actual-ceq$expected){'PASS'}else{'M1_SEAL_HASH_MISMATCH'});actual_sha256=$actual;resolved_path=$path}
}

function Invoke-SynapsenReleaseVerification {
    param([string]$ManifestPath,[string]$ArtifactPath,[string]$SignaturePath,[string]$TrustedKeyring,[switch]$RequireSignature,[string]$ExpectedReleaseId,[datetime]$VerificationTimeUtc=(Get-Date).ToUniversalTime())
    try{$manifest=Read-SynapsenReleaseManifest -ManifestPath $ManifestPath -ExpectedReleaseId $ExpectedReleaseId}catch{return [pscustomobject]@{pass=$false;reason='MANIFEST_REJECTED';detail=$_.Exception.Message;fail_closed=$true}}
    $artifact=Test-SynapsenArtifactHash -ArtifactPath $ArtifactPath -ExpectedSha256 ([string]$manifest.artifact.sha256) -ExpectedSizeBytes ([Nullable[Int64]][Int64]$manifest.artifact.size_bytes)
    $signature=if($RequireSignature){Test-SynapsenDetachedSignature -ManifestPath $ManifestPath -SignaturePath $SignaturePath -TrustedKeyring $TrustedKeyring -ExpectedPrimaryFingerprint ([string]$manifest.trust.signing_fingerprint) -ExpectedSigningFingerprint ([string]$manifest.trust.signing_subkey_fingerprint) -VerificationTimeUtc $VerificationTimeUtc}else{[pscustomobject]@{pass=$true;reason='NOT_REQUIRED'}}
    $sbom=Test-SynapsenSbomBinding -Manifest $manifest -ManifestPath $ManifestPath
    $provenance=Test-SynapsenProvenanceBinding -Manifest $manifest -ManifestPath $ManifestPath
    $m1=Test-SynapsenM1SealBinding -Manifest $manifest -ManifestPath $ManifestPath
    $all=$artifact.pass-and$signature.pass-and$sbom.pass-and$provenance.pass-and$m1.pass
    [pscustomobject]@{pass=$all;reason=$(if($all){'PASS'}else{'RELEASE_CHAIN_FAIL'});release_id=[string]$manifest.release_id;artifact_hash=$artifact;signature=$signature;sbom=$sbom;provenance=$provenance;m1_seal=$m1;fail_closed=$true}
}

Export-ModuleMember -Function Read-SynapsenReleaseManifest,Resolve-SynapsenBoundPath,Test-SynapsenArtifactHash,Get-SynapsenTrustedKeyState,Test-SynapsenDetachedSignature,Test-SynapsenSbomBinding,Test-SynapsenProvenanceBinding,Test-SynapsenM1SealBinding,Invoke-SynapsenReleaseVerification
