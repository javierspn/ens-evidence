# 001-core-pipeline

**Owns:** CLI contract, run store, engines → SARIF → JSONL → baseline.

**Acceptance:** fixture in, identical JSONL twice; green in a bare ubuntu runner from a
3-line workflow; `--fail-on high` gates a fixture with one new high finding.

**Implemented 2026-07-26** — 38/38 tasks, acceptance criteria verified by
`tests/test_normalise.py` (engine-free, from captured SARIF fixtures),
`tests/test_run_store.py` and `tests/test_cli.py` (real-engine scenarios marked
`engines`). Spec artifacts: `spec.md` → `plan.md` (+ `research.md`, `data-model.md`,
`contracts/`, `quickstart.md`) → `tasks.md`.
