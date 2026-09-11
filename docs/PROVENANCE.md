# Provenance

The local Foundation 010E source audit resolved three distinct roles:

- **Controller/evidence root:** current S07 controller and release evidence;
- **V24T artifact mirror:** final S07 release-artifact metadata;
- **Acceptance VM:** validation environment, not source-of-truth.

The compact canonical sample used to assemble this public repository has:

- SHA-256: `524b71012e01c1ed8384bba088bcbea8e0ea69fbef687e158a3833cf1a59fe57`
- size: `6214613` bytes
- collected source/evidence files reported by the local extractor: `86`
- hard secret findings: `0`
- RAR ↔ V24T comparisons: `13/13` exact SHA-256 matches

## Revision naming caveat

The final release-seal/promotion evidence identifies the released artifact as
`V24T-BRANDING-R1`.

The unchanged release provenance JSON contains:

- `candidate_revision`: `V24P-BRANDING-R1`
- source candidate: `V24N-XFCE-R2`
- branding contract: `V24O-R4`

This repository preserves that original metadata and documents the naming
difference instead of silently rewriting historical evidence.
