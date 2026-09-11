# Architecture Snapshot

The public S07 source shows a release-verification architecture with five bound
trust checks:

1. release-manifest parsing and release-ID validation;
2. artifact SHA-256 and size verification;
3. detached OpenPGP verification and trusted-key state checking;
4. SPDX 3.0.1 SBOM binding;
5. provenance and M1 acceptance-seal binding.

The verifier returns a fail-closed result if any required branch fails.

The UI layer consumes the same verification result through a German-first
view-model. The public contract disallows silent trust overrides and requires
offline verification and keyboard access.

This snapshot focuses on release integrity. It is not a complete diagram of all
desktop, installer, tool-catalog, theme or operating-system subsystems.
