# scripts/

Stdlib-only helpers that CI runs and tests import. Nothing here ships in the package — the
installable surface is `src/ens_evidence/` only.

A helper lives here instead of inline in a workflow YAML so it can be unit-tested and run
locally before pushing. An inline `python -c` gate cannot be either, which is how the previous
`scan.yml` stub survived unverified.
