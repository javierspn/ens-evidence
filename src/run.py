"""Orchestration + CLI: the five verbs (scan, baseline update, bundle, report, explain).

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
