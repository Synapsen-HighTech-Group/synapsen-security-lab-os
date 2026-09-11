#!/usr/bin/env python3
"""Fail-closed local validator for SYNAPSEN SPDX 3.0.1 canonical JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys


CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPEC_VERSION = "3.0.1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def read_packages(path: pathlib.Path) -> list[tuple[str, str]]:
    records = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            continue
        fields = raw.split("\t")
        if len(fields) != 2 or not all(fields):
            fail(f"Malformed package record at line {number}")
        records.append((fields[0], fields[1]))
    if len(records) != len(set(records)):
        fail("Package inventory contains duplicates")
    return sorted(records, key=lambda item: (item[0].encode("utf-8"), item[1].encode("utf-8")))


def validate_schema(document: object, schema_path: pathlib.Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        fail(f"Official SPDX JSON Schema validation failed at {location}: {first.message}")


def validate_semantics(
    document: dict,
    context_path: pathlib.Path,
    model_path: pathlib.Path,
) -> str:
    from pyshacl import validate
    from rdflib import Graph

    local_context = json.loads(context_path.read_text(encoding="utf-8"))
    if "@context" not in local_context:
        fail("Vendored SPDX JSON-LD context is malformed")
    semantic_document = json.loads(json.dumps(document))
    semantic_document["@context"] = local_context["@context"]
    data_graph = Graph().parse(
        data=json.dumps(semantic_document, ensure_ascii=False), format="json-ld"
    )
    model_graph = Graph().parse(model_path.as_posix(), format="turtle")
    conforms, _, report = validate(
        data_graph,
        shacl_graph=model_graph,
        ont_graph=model_graph,
        abort_on_first=False,
        allow_infos=False,
        allow_warnings=False,
        advanced=False,
        inference="none",
        meta_shacl=False,
    )
    if not conforms:
        fail(f"Official SPDX SHACL validation failed: {str(report)[:4000]}")
    return str(report)


def validate_synapsen_contract(
    document: dict,
    packages_path: pathlib.Path,
    artifact_path: pathlib.Path,
    artifact_sha256: str,
    release_id: str,
) -> int:
    if document.get("@context") != CONTEXT:
        fail("SPDX 3.0.1 context mismatch")
    graph = document.get("@graph")
    if not isinstance(graph, list):
        fail("@graph missing")
    documents = [item for item in graph if item.get("type") == "SpdxDocument"]
    sboms = [item for item in graph if item.get("type") == "software_Sbom"]
    creation_infos = [item for item in graph if item.get("type") == "CreationInfo"]
    if len(documents) != 1 or len(sboms) != 1 or len(creation_infos) != 1:
        fail("Exactly one SpdxDocument, software_Sbom and CreationInfo are required")
    if creation_infos[0].get("specVersion") != SPEC_VERSION:
        fail("CreationInfo does not bind SPDX 3.0.1")

    elements = [item for item in graph if isinstance(item.get("spdxId"), str)]
    by_id = {item["spdxId"]: item for item in elements}
    if len(by_id) != len(elements):
        fail("Duplicate spdxId")
    for collection in (documents[0], sboms[0]):
        if collection.get("profileConformance") != ["core", "software"]:
            fail("Core/software profile binding mismatch")
        for key in ("element", "rootElement"):
            refs = collection.get(key)
            if not isinstance(refs, list) or not refs:
                fail(f"{collection['type']} {key} is empty")
            missing = [ref for ref in refs if ref not in by_id]
            if missing:
                fail(f"Unresolved {collection['type']} {key} reference: {missing[0]}")
    if documents[0]["rootElement"] != [sboms[0]["spdxId"]]:
        fail("SpdxDocument root is not the SBOM")

    product_ids = sboms[0].get("rootElement", [])
    if len(product_ids) != 1:
        fail("SBOM must have one product root")
    product = by_id[product_ids[0]]
    if product.get("type") != "software_Package":
        fail("SBOM root is not a software package")
    if product.get("name") != "SYNAPSEN SECURITY LAB OS":
        fail("Product name mismatch")
    if product.get("software_packageVersion") != release_id:
        fail("Product release ID mismatch")
    hashes = product.get("verifiedUsing")
    if hashes != [{"algorithm": "sha256", "hashValue": artifact_sha256, "type": "Hash"}]:
        fail("Product artifact hash binding mismatch")

    relationships = [item for item in graph if item.get("type") == "Relationship"]
    if len(relationships) != 1:
        fail("Exactly one package-containment relationship is required")
    relationship = relationships[0]
    if relationship.get("from") != product["spdxId"] or relationship.get("relationshipType") != "contains":
        fail("Package-containment relationship mismatch")
    if relationship.get("completeness") != "complete":
        fail("Package-containment completeness mismatch")

    expected_packages = read_packages(packages_path)
    actual_packages = sorted(
        (
            item.get("name"),
            item.get("software_packageVersion"),
        )
        for item in graph
        if item.get("type") == "software_Package" and item["spdxId"] != product["spdxId"]
    )
    if actual_packages != expected_packages:
        fail("SBOM package inventory does not exactly match the sealed package list")
    package_ids = {
        item["spdxId"]
        for item in graph
        if item.get("type") == "software_Package" and item["spdxId"] != product["spdxId"]
    }
    if set(relationship.get("to", [])) != package_ids or len(relationship.get("to", [])) != len(package_ids):
        fail("Containment relationship does not cover every package exactly once")
    if sha256_file(artifact_path) != artifact_sha256:
        fail("Artifact SHA256 changed during validation")
    return len(expected_packages)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", required=True, type=pathlib.Path)
    parser.add_argument("--packages", required=True, type=pathlib.Path)
    parser.add_argument("--artifact", required=True, type=pathlib.Path)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--schema", required=True, type=pathlib.Path)
    parser.add_argument("--context", required=True, type=pathlib.Path)
    parser.add_argument("--model", required=True, type=pathlib.Path)
    args = parser.parse_args()

    expected_hash = args.artifact_sha256.lower()
    if not SHA256_RE.fullmatch(expected_hash):
        fail("Invalid --artifact-sha256")
    for path in (args.sbom, args.packages, args.artifact, args.schema, args.context, args.model):
        if not path.is_file():
            fail(f"Required file missing: {path}")

    payload = args.sbom.read_bytes()
    if payload.startswith(b"\xef\xbb\xbf") or b"\n" in payload or b"\r" in payload:
        fail("SBOM is not UTF-8 no-BOM, single-line canonical JSON")
    document = json.loads(payload.decode("utf-8"))
    if canonical_bytes(document) != payload:
        fail("SBOM bytes are not canonical deterministic JSON")
    validate_schema(document, args.schema)
    package_count = validate_synapsen_contract(
        document,
        packages_path=args.packages,
        artifact_path=args.artifact,
        artifact_sha256=expected_hash,
        release_id=args.release_id,
    )
    report = validate_semantics(document, args.context, args.model)
    report_hash = hashlib.sha256(report.encode("utf-8")).hexdigest()
    print("SPDX_VERSION=3.0.1")
    print("CANONICAL_JSON=PASS")
    print("JSON_SCHEMA=PASS")
    print("SHACL=PASS")
    print("SYNAPSEN_CONTRACT=PASS")
    print(f"PACKAGE_COUNT={package_count}")
    print(f"SBOM_SHA256={hashlib.sha256(payload).hexdigest()}")
    print(f"SHACL_REPORT_SHA256={report_hash}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
