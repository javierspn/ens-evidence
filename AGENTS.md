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

Scaffold plus data files — every `src/` module is still a stub.

Spec Kit is initialised (`/speckit-specify`, `/speckit-plan`, `/speckit-tasks`,
`/speckit-implement`; note the dash, not the dot DESIGN.md uses) and the constitution is
ratified at 1.1.0.

`mapping/ens_rd311.yml` and `mapping/severity.yml` are authored from real scans of ten
repositories — 939 findings, 339 rule ids: five private (three app/GitOps, two with
lockfiles for CVE and SBOM coverage) and five public vulnerable apps spanning
Python/Django/Flask, Express/TypeScript, Java/Spring and Go. See
[docs/scan-baseline.md](docs/scan-baseline.md), which also
records what closed and what is still open. All original gaps are closed; what remains is
that **neither engine is hermetic** — Trivy resolves Maven POMs over the network, Semgrep
fetches a versionless ruleset — which Principle I cannot survive. Spec 001 owns it. Read the
note before extending either data file.

`tests/mapping-cases.yml` is the mapping contract — 30 observed cases plus 3 ids that must
fall through to `unmapped` (two earlier probes were proven wrong by real scans, so treat the
list as assumptions). Changing a mapping rule without updating it should break the
suite; that is the point.

Scope is six measures: `mp.sw.1 · mp.sw.2 · mp.s.2 · op.exp.2 · op.exp.3 · op.exp.4`,
verified against the BOE text. `op.acc.5` was dropped in constitution 1.1.0 — do not
reintroduce it without a scanner that can actually evidence an authentication mechanism.
