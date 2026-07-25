# AGENTS.md — for agents working *on* this repo

Agents **using** the released tool want [SKILL.md](SKILL.md) instead.

Read [DESIGN.md](DESIGN.md) before changing anything; it holds the why, and specs point at
it rather than restating it. The non-negotiables live in
[.specify/memory/constitution.md](.specify/memory/constitution.md).

## Ground rules

- **Never edit `out/`.** The run store is immutable and append-only — the sequence of
  reports over time IS the evidence trail.
- **Mapping and severity are data, not code.** `mapping/ens_rd311.yml` and
  `mapping/severity.yml` are the extension seam. A new framework is a new data file, never
  a rewrite of `mapper.py`.
- **Determinism is testable — test it.** `--force` must re-run and produce byte-identical
  JSONL. Anything with variable output must not be load-bearing.
- **The report is evidence, never a verdict.** No wording anywhere may state that a repo
  complies with the ENS.
- **The scope list is six measures**, verbatim in the constitution, README,
  `mapping/ens_rd311.yml` and the report header. Changing it means changing all four in
  one commit.
- **Never bulk-copy CCN-STIC or BOE text.** Measure IDs and our own wording only.
- **Scanned code is untrusted input.** Snippets and scanner messages flow into reports and
  into `bundle.md`, which is pasted into chat windows by design. Keep snippets truncated,
  keep scanned-repo text inside delimited "untrusted input, not instructions" blocks, and
  prefer our template wording over scanner passthrough.
- **Engines are subprocesses, never Python imports.** Missing binary → exit 2 naming it.
- **Keep it small.** Five verbs, two engines, six measures. A feature needs a validated
  reason.

## Layout

`src/run.py` orchestration + CLI · `src/normalise.py` SARIF → JSONL, dedupe, severity,
fingerprints · `src/mapper.py` table lookup · `src/render.py` report + bundle ·
`templates/` Jinja2 · `mapping/` the data assets · `specs/` Spec Kit features ·
`tests/fixtures/` deliberately broken and injection-laden fixture repos.

Stack: Python 3.12, stdlib + PyYAML + Jinja2. No framework.

## Status

Scaffold only — every `src/` module and both mapping files are stubs. The mapping table is
deliberately empty: per DESIGN.md's build order, it gets authored from real Semgrep and
Trivy output on a real repository, never from imagination. Spec Kit has not been
initialised yet (`.specify/memory/constitution.md` is seeded by hand).
