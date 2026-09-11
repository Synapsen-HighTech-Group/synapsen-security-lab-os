# Dependencies and Reproducibility

The original private/offline S07 validation environment pinned official SPDX
3.0.1 assets and a local Python dependency set.

This public snapshot intentionally includes the **first-party generator and
validator source** but not:

- vendored Python wheels;
- the copied SPDX JSON-LD context;
- copied JSON Schema;
- copied SHACL/OWL model.

The original `Invoke-SynapsenSpdx301.ps1` retains the expected asset hashes so
the sealed implementation can be reviewed.

Because those dependencies, the ISO and the complete distribution build
workspace are not published here, this snapshot does **not** claim a complete
public source-to-ISO reproducible build.
