# Known Limitations

1. **Public source scope is partial.** The captured canonical sample did not
   include the complete distribution build workspace.
2. **No public ISO in this candidate.** The verified artifact hash is documented,
   but the multi-gigabyte image is not staged for GitHub.
3. **Full release verification is not independently rerunnable from this repo
   alone.** The public signing key/trusted keyring and path-bearing M1 seal are
   not embedded in this preview.
4. **Provenance revision naming is historically inconsistent.** The final sealed
   artifact is V24T-BRANDING-R1 while the unchanged provenance JSON retains
   `candidate_revision: V24P-BRANDING-R1`.
5. **Broader project maturity remains IN DEVELOPMENT.** S07 release-chain closure
   must not be generalized into a claim that every planned SSLOS subsystem is
   finished.
