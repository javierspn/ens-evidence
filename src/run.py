"""Orchestration + CLI: five finding-path verbs (scan, baseline update, bundle, report,
explain) plus the `rules` bootstrap group (fetch, status).

`rules fetch` clones semgrep-rules at a required --sha into the operator's own environment. It
refuses without an explicit licence acknowledgement (--accept-rules-license /
ENS_EVIDENCE_ACCEPT_RULES_LICENSE / accept_rules_license in config), exiting 2 after printing
the terms — never a prompt. Rule files are never modified, mirrored, bundled or published:
Semgrep Rules License v1.0 forbids redistribution. run.json records mode, repo URL, SHA and
per-language rule counts — plus engine versions, Trivy's vulnerability-DB and checks-bundle
versions (absent from SARIF; read from Trivy's cache metadata), mapping version+hash, baseline
hash and config hash. Every drifting input is disclosed; see DESIGN.md "Drift".

Owns the run store under ``out/<date>_<git-short-sha>/`` (immutable, append-only), the skip
key (git SHA + engine versions + mapping hash + baseline hash + config hash), and config
resolution: flags -> ENS_EVIDENCE_* env -> .ens-evidence.yml -> defaults. Never interactive.

Engines are subprocess calls to pinned binaries, never Python imports; a missing binary
exits 2 with a message naming it. Exit 0 = no new findings at/above --fail-on, 1 = there
are, 2 = tool error.

Stub — see DESIGN.md for the contract and specs/001-core-pipeline for the slice.
"""

SCHEMA = "ens-evidence/1"


def main() -> int:
    raise NotImplementedError("spec 001-core-pipeline")


if __name__ == "__main__":
    raise SystemExit(main())
