#!/usr/bin/env python3
"""Generate a deterministic SPDX 3.0.1 canonical JSON SBOM for SYNAPSEN."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys


CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPEC_VERSION = "3.0.1"
BASE = "urn:synapsen:spdx:3.0.1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_created(value: str) -> str:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        fail("--created must include an explicit UTC offset")
    utc = parsed.astimezone(dt.timezone.utc).replace(microsecond=0)
    return utc.isoformat().replace("+00:00", "Z")


def read_packages(path: pathlib.Path) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            continue
        fields = raw.split("\t")
        if len(fields) != 2 or not all(fields):
            fail(f"Malformed package record at line {number}")
        name, version = fields
        if any(ord(char) < 0x20 for char in name + version):
            fail(f"Control character in package record at line {number}")
        item = (name, version)
        if item in seen:
            fail(f"Duplicate package record at line {number}: {name} {version}")
        seen.add(item)
        packages.append(item)
    if not packages:
        fail("Package inventory is empty")
    return sorted(packages, key=lambda item: (item[0].encode("utf-8"), item[1].encode("utf-8")))


def package_id(name: str, version: str) -> str:
    identity = hashlib.sha256((name + "\0" + version).encode("utf-8")).hexdigest()
    return f"{BASE}:package:{identity}"


def build_document(
    packages: list[tuple[str, str]],
    release_id: str,
    artifact_sha256: str,
    created: str,
) -> dict:
    release_token = hashlib.sha256(release_id.encode("utf-8")).hexdigest()
    creation_id = "_:synapsen-creation-info"
    tool_id = f"{BASE}:tool:canonical-generator"
    supplier_id = f"{BASE}:organization:synapsen-hightech-group"
    document_id = f"{BASE}:document:{release_token}"
    sbom_id = f"{BASE}:sbom:{release_token}"
    product_id = f"{BASE}:product:{release_token}"
    relationship_id = f"{BASE}:relationship:{release_token}:contains"

    package_elements = []
    package_ids = []
    for name, version in packages:
        spdx_id = package_id(name, version)
        package_ids.append(spdx_id)
        package_elements.append(
            {
                "creationInfo": creation_id,
                "name": name,
                "software_copyrightText": "NOASSERTION",
                "software_packageVersion": version,
                "spdxId": spdx_id,
                "type": "software_Package",
            }
        )

    creation_info = {
        "@id": creation_id,
        "created": created,
        "createdBy": [supplier_id],
        "createdUsing": [tool_id],
        "specVersion": SPEC_VERSION,
        "type": "CreationInfo",
    }
    tool = {
        "creationInfo": creation_id,
        "name": "SYNAPSEN SPDX 3.0.1 Canonical Generator",
        "spdxId": tool_id,
        "type": "Tool",
    }
    supplier = {
        "creationInfo": creation_id,
        "name": "SYNAPSEN HIGHTECH GROUP",
        "spdxId": supplier_id,
        "type": "Organization",
    }
    product = {
        "creationInfo": creation_id,
        "name": "SYNAPSEN SECURITY LAB OS",
        "software_copyrightText": "NOASSERTION",
        "software_packageVersion": release_id,
        "software_primaryPurpose": "operatingSystem",
        "spdxId": product_id,
        "suppliedBy": supplier_id,
        "type": "software_Package",
        "verifiedUsing": [
            {"algorithm": "sha256", "hashValue": artifact_sha256, "type": "Hash"}
        ],
    }
    relationship = {
        "completeness": "complete",
        "creationInfo": creation_id,
        "from": product_id,
        "relationshipType": "contains",
        "spdxId": relationship_id,
        "to": package_ids,
        "type": "Relationship",
    }
    sbom = {
        "creationInfo": creation_id,
        "element": [product_id, relationship_id, *package_ids],
        "name": f"{release_id} runtime package SBOM",
        "profileConformance": ["core", "software"],
        "rootElement": [product_id],
        "software_sbomType": ["build", "runtime"],
        "spdxId": sbom_id,
        "type": "software_Sbom",
    }
    document = {
        "creationInfo": creation_id,
        "element": [sbom_id, tool_id, supplier_id, product_id, relationship_id, *package_ids],
        "name": f"{release_id} SPDX 3.0.1 document",
        "profileConformance": ["core", "software"],
        "rootElement": [sbom_id],
        "spdxId": document_id,
        "type": "SpdxDocument",
    }

    return {
        "@context": CONTEXT,
        "@graph": [
            creation_info,
            document,
            supplier,
            tool,
            sbom,
            product,
            relationship,
            *package_elements,
        ],
    }


def canonical_bytes(document: dict) -> bytes:
    text = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    encoded = text.encode("utf-8")
    if b"\n" in encoded or b"\r" in encoded or encoded.startswith(b"\xef\xbb\xbf"):
        fail("Canonical serialization invariant failed")
    return encoded


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packages", required=True, type=pathlib.Path)
    parser.add_argument("--artifact", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    expected_hash = args.artifact_sha256.lower()
    if not SHA256_RE.fullmatch(expected_hash):
        fail("Invalid --artifact-sha256")
    if not args.artifact.is_file() or not args.packages.is_file():
        fail("Artifact or package inventory missing")
    if args.output.exists():
        fail("Output already exists; overwrite forbidden")
    actual_hash = sha256_file(args.artifact)
    if actual_hash != expected_hash:
        fail(f"Artifact hash mismatch: {actual_hash}")

    packages = read_packages(args.packages)
    document = build_document(
        packages=packages,
        release_id=args.release_id,
        artifact_sha256=expected_hash,
        created=normalize_created(args.created),
    )
    payload = canonical_bytes(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print("SPDX_VERSION=3.0.1")
    print("CANONICAL_JSON=PASS")
    print(f"PACKAGE_COUNT={len(packages)}")
    print(f"SBOM_SHA256={hashlib.sha256(payload).hexdigest()}")
    print(f"SBOM_BYTES={len(payload)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
