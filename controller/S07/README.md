# SYNAPSEN S07 Implementation Foundation

State: PROJECT_FULLY_FINALIZED_PASS_CLOSED_SEALED

Implemented and sealed:
- WP-01 deterministic release manifest + SHA256SUMS
- WP-02 OpenPGP Ed25519 detached-signature implementation and trust policy
- WP-03 offline verifier core + CLI
- WP-04 German-first Control Center verification contract/view model
- WP-05 SPDX 3.0.1 canonical JSON capability, local schema/SHACL validation and deterministic release binding
- WP-06 full positive/negative acceptance matrix (16/16 expected outcomes)
- WP-08 release evidence/recovery framework

Closed:
- WP-07 networkless key ceremony; encrypted custody copies on two owner-approved offline media
- real release signing and public trust metadata
- WP-06 tamper, trust, expiry, revocation, downgrade and missing-evidence acceptance
- WP-08 final release evidence/recovery seal

Still pending:
- None

WP-05 implementation:
- `spdx/Invoke-SynapsenSpdx301.ps1` generates and validates the release SBOM repeatably.
- Official SPDX 3.0.1 JSON Schema, JSON-LD context and SHACL/OWL model are pinned locally by SHA-256.
- The verifier fails closed on missing, mismatched, downgraded or noncanonical SBOM bindings.
