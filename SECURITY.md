# Security Policy

This repository contains reviewable security-lab engineering code and release
integrity evidence.

## Publication safety

The public tree must not contain:

- private keys or recovery material;
- passwords, tokens or credentials;
- private device serial numbers;
- private Windows user paths;
- VM disks or raw disk images;
- unreviewed personal logs;
- an ISO unless a separate release decision explicitly approves it.

## Release trust

A checksum by itself is not a trust decision. The original S07 design binds the
artifact hash to a signed release manifest, trusted signing identity, provenance,
SBOM and acceptance seal.

This public snapshot does not include all artifacts required to rerun that full
private release chain. The included verifier source is for engineering review.

## Responsible use

SSLOS is intended for authorized security labs, defensive learning and system
engineering. Users are responsible for complying with applicable law and
authorization boundaries.
