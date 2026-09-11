#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release-metadata" / "S07"
EVIDENCE = ROOT / "evidence" / "public"

EXPECTED_ISO_SHA = "92bd8a7cf26d011ff45e7430b741b912a32e175b132a3eee559fa4fb4a4bfc96"
EXPECTED_ISO_BYTES = 5652692992
EXPECTED_RELEASE_SHA = "5570d6ee5e3217038a6d649a17bb1d68ccb58aed6fee82bc4f5881a4666ec805"
EXPECTED_SIGNATURE_SHA = "972230fd01eb3fa6773dd77a2b259ea804b3f1950138b5e5ab373bb6f0446933"
EXPECTED_PROVENANCE_SHA = "021d0fa088ece4a2b99f50ce8aa4caff31ea09e48f19786eeaa410da74252e55"
EXPECTED_SBOM_SHA = "6dfdb4f97a6fdb72a03d868ba77abc4a8f8617484de192fd88fe0cdadb0cae9c"
EXPECTED_PACKAGES_SHA = "11549f523cfd7435b0461ca406056edaeb98615c79ca11e90bed6133fa87f379"

def sha(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def check(cond: bool, label: str) -> None:
    if not cond:
        raise AssertionError(label)
    print(f"[PASS] {label}")

def main() -> int:
    release_path = RELEASE / "SYNAPSEN-SECURITY-LAB-OS-2026.3-S07.release.json"
    sig_path = RELEASE / "SYNAPSEN-SECURITY-LAB-OS-2026.3-S07.release.json.asc"
    prov_path = RELEASE / "SYNAPSEN-SECURITY-LAB-OS-2026.3-S07.provenance.json"
    sbom_path = RELEASE / "SYNAPSEN-SECURITY-LAB-OS-2026.3-S07.spdx.json"
    pkg_path = RELEASE / "live-image-amd64.packages"
    matrix_path = EVIDENCE / "S07_WP06_FULL_ACCEPTANCE_MATRIX.json"
    wp05_path = EVIDENCE / "S07_WP05_STATUS.json"
    public_ev_path = EVIDENCE / "S07_PUBLIC_RELEASE_EVIDENCE.json"

    for p in [release_path, sig_path, prov_path, sbom_path, pkg_path, matrix_path, wp05_path, public_ev_path]:
        check(p.is_file(), f"required file present: {p.relative_to(ROOT)}")

    check(sha(release_path) == EXPECTED_RELEASE_SHA, "release manifest SHA-256")
    check(sha(sig_path) == EXPECTED_SIGNATURE_SHA, "detached signature SHA-256")
    check(sha(prov_path) == EXPECTED_PROVENANCE_SHA, "provenance SHA-256")
    check(sha(sbom_path) == EXPECTED_SBOM_SHA, "SPDX SBOM SHA-256")
    check(sha(pkg_path) == EXPECTED_PACKAGES_SHA, "package inventory SHA-256")

    release = json.loads(release_path.read_text(encoding="utf-8"))
    check(release["release_id"] == "SYNAPSEN-SECURITY-LAB-OS-2026.3-S07", "release ID")
    check(release["artifact"]["sha256"] == EXPECTED_ISO_SHA, "ISO hash binding")
    check(release["artifact"]["size_bytes"] == EXPECTED_ISO_BYTES, "ISO size binding")
    check(release["evidence"]["provenance_sha256"] == EXPECTED_PROVENANCE_SHA, "provenance binding")
    check(release["evidence"]["sbom"]["sha256"] == EXPECTED_SBOM_SHA, "SBOM binding")
    check(release["evidence"]["sbom"]["schema_version"] == "SPDX-3.0.1", "SPDX schema version")
    check(release["evidence"]["sbom"]["canonical"] is True, "SPDX canonical flag")

    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    check(matrix["case_count"] == 16, "16 acceptance cases")
    check(matrix["all_expectations_met"] is True, "all acceptance expectations met")
    check(all(c["actual"] == c["expected"] for c in matrix["cases"]), "acceptance actual == expected")
    check(all(c["fail_closed"] is True for c in matrix["cases"]), "acceptance cases fail closed")

    wp05 = json.loads(wp05_path.read_text(encoding="utf-8"))
    check(wp05["spdx_version"] == "3.0.1", "WP05 SPDX version")
    check(wp05["package_count"] == 2953, "WP05 package count")
    check(wp05["sbom_sha256"] == EXPECTED_SBOM_SHA, "WP05 SBOM hash")
    check(wp05["reproducibility"] == "PASS", "WP05 reproducibility evidence")
    check(wp05["json_schema"] == "PASS", "WP05 JSON Schema evidence")
    check(wp05["shacl"] == "PASS", "WP05 SHACL evidence")

    public_ev = json.loads(public_ev_path.read_text(encoding="utf-8"))
    check(public_ev["source_provenance"]["rar_v24t_files_compared"] == 13, "13 RAR/V24T files compared")
    check(public_ev["source_provenance"]["rar_v24t_exact_sha256_matches"] == 13, "13/13 RAR/V24T exact hashes")

    # Public privacy guard for text-like repository files.
    patterns = {
        "private GitHub identity": re.compile("Blazz" + "cantara", re.I),
        "legacy/private email": re.compile(r"sven\.cartarius@" + r"(gmx|web)\.de", re.I),
        "private Windows user path": re.compile(re.escape("C:\\Users\\" + "sve" + "nc"), re.I),
        "private street marker": re.compile("Kland" + r"orfer\s+Stra", re.I),
        "GitHub token literal": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        "private key block": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    }
    text_ext = {".md",".txt",".json",".yml",".yaml",".toml",".ini",".cfg",".ps1",".psm1",".sh",".py",".js",".ts",".html",".css",".bat",".sha256",".csv"}
    findings = []
    for p in ROOT.rglob("*"):
        if p.is_file() and p.suffix.lower() in text_ext:
            try:
                text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for name, rx in patterns.items():
                if rx.search(text):
                    findings.append((name, p.relative_to(ROOT).as_posix()))
    check(not findings, "public privacy/secret text scan")

    # No intentionally forbidden large/private artifact classes.
    forbidden_suffixes = {".iso",".vdi",".vmdk",".qcow2",".ova",".ovf",".rar",".7z",".pfx",".p12",".key",".pem"}
    forbidden = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file() and p.suffix.lower() in forbidden_suffixes]
    check(not forbidden, "no ISO/VM/archive/private-key file classes")

    print("SSLOS_PUBLIC_REPO_VERIFY=PASS")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SSLOS_PUBLIC_REPO_VERIFY=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(2)
