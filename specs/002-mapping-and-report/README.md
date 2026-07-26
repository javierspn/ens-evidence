# 002-mapping-and-report

**Owns:** mapping semantics, the Spanish evidence report, top-10 triage, `explain`.

**Acceptance:** JSONL in, Spanish PDF out; the mapping table authored from real scanner
output, not imagination.

**Implemented 2026-07-26** — 33/33 tasks. Spec written from spec 001's real output;
acceptance verified by `tests/test_mapper.py`, `tests/test_render.py` and the report
cases in `tests/test_cli.py`, all engine-free against the committed run in
`tests/fixtures/run/`. See [DESIGN.md](../../DESIGN.md).
