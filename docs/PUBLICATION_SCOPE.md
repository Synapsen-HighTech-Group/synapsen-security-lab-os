# Publication Scope

## Included

- first-party S07 release verification source;
- first-party release manifest/evidence helpers;
- first-party SPDX generator and validator source;
- acceptance-matrix contract and public-safe result;
- UI verification contract/view-model;
- safe release metadata;
- generated SPDX SBOM and package inventory;
- provenance ledger and public evidence summaries.

## Deliberately excluded

- private path-bearing evidence originals;
- drive labels, storage serial numbers and custody-device metadata;
- key-recovery files;
- private key or encrypted secret-key copies;
- VM images and snapshots;
- ISO image;
- large archives;
- vendored third-party Python wheels;
- third-party specification assets pending redistribution review;
- generated caches.

The excluded data remains relevant to the private evidence chain, but it is not
necessary for a recruiter-facing public repository.
