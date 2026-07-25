# 001-core-pipeline

**Owns:** CLI contract, run store, engines → SARIF → JSONL → baseline.

**Acceptance:** fixture in, identical JSONL twice; green in a bare ubuntu runner from a
3-line workflow; `--fail-on high` gates a fixture with one new high finding.

`spec.md` generated 2026-07-25 (`/speckit.specify`); `plan.md` and `tasks.md` pending
(`/speckit.plan` → `/speckit.tasks`). Spec the hard parts (normaliser, fingerprints);
point at [DESIGN.md](../../DESIGN.md) rather than restating the measure list.
