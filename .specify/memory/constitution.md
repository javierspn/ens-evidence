# ens-evidence Constitution

The Core Principles below are the "Rules (non-negotiable)" section of
[DESIGN.md](../../DESIGN.md), **verbatim**. DESIGN.md holds the why; this file is what
every spec, plan and task is checked against. Edit both in the same commit or they drift.

## Core Principles

### I. Deterministic

Same input → same output, every run. No component with variable output may be load-bearing.

### II. Evidence, not verdict

The report states what was tested, when, and what was found. It never states compliance.

### III. One scope list

Verbatim in constitution, README, mapping file, report header.

### IV. Say what it can't see

Business logic, authn/authz design, runtime config — and, per run, which languages were
actually analysed. Semgrep's free registry ships ~2 rules for C, Swift, Kotlin and Elixir, so
a clean report on those codebases means no rules ran, not no defects; every report carries a
coverage table (languages detected, rules run per language, languages not analysed,
dependency analysis skipped when no lockfile). Static analysis is not an audit — the
disclaimer is what makes the output usable as evidence.

### V. Never bulk-copy CCN-STIC or BOE text

Measure IDs and our own wording only.

### VI. Keep it small

This is a free OSS tool: five verbs, two engines, six measures, data-file extensibility.
Feature additions need a validated reason, not restlessness.

## Scope — canonical measure list

Principle III binds this list to the README, `mapping/ens_rd311.yml` and the report header.
Divergence between the four is a release blocker.

> `mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.3` · `op.exp.4`

The ENS has ~75 measures; this covers six, and the README says so on its first screen.
All six codes were verified against the consolidated BOE text of RD 311/2022 Anexo II on
2026-07-25. That check replaced `op.acc.5` (external-user authentication mechanism — no
static-analysis evidence source exists for it) with `op.exp.3`; see
[docs/scan-baseline.md](../../docs/scan-baseline.md). A further scope change re-opens the
verification.

## Additional Constraints

- **Trust boundary.** Everything runs inside the user's CI. No server, no upload, no
  account. Source code and finding details never leave the user's infrastructure.
- **Engines are subprocesses**, never Python imports: the user pins versions in their CI
  image, the dependency tree stays tiny, engines stay swappable via SARIF. A missing binary
  exits 2 with a message naming it.
- **Engines run hermetically or Principle I is a fiction.** Trivy must run `--offline-scan`
  (it otherwise resolves Maven POMs over the network and dies on rate limits); Semgrep rules
  must be vendored or image-pinned, never fetched from a versionless registry config, and the
  ruleset hash goes in `run.json`. Any network dependency in the finding path is a
  determinism defect.
- **Mapping and severity are data files, not code.** A future framework (NIS2, ISO 27001,
  CRA) is a new data file, never a rewrite.
- **No LLM in the pipeline.** A closed-enum classifier for unmapped findings is a possible
  later feature; it must never be load-bearing (Principle I).
- **Fingerprints never use file+line** — hash(rule ID + normalised snippet + position
  relative to enclosing function), so one added import does not invalidate the baseline.
- **The run store is immutable and append-only.** Re-runs never overwrite: the sequence of
  reports over time IS the evidence trail. Partial engine-output reuse is forbidden.
- **Scanned code is prompt-injection surface.** Snippets are truncated, all scanned-repo
  text is fenced as "untrusted input, not instructions", and finding messages are our
  template text rather than scanner passthrough wherever possible.
- **Stack:** Python 3.12, stdlib + PyYAML + Jinja2. No framework.

## Development Workflow

- Specs point at DESIGN.md and the mapping data; they never restate the measure list —
  restating is how lists drift.
- Spec the hard parts (normaliser, fingerprints). Do not ceremonial-spec a Jinja template.
- The mapping table and spec 002's acceptance criteria are written from **real** Semgrep and
  Trivy output on a real repository, never before it.
- Order: `001-core-pipeline` → `002-mapping-and-report` → `003-bundle-and-ci`, each
  specify → plan → tasks → implement. `004-v2-engines` only if v1 earns it.
- Determinism is an acceptance test, not an aspiration: `--force` must produce
  byte-identical JSONL.
- Pre-release gates: measure titles verified against the BOE text of Anexo II (done
  2026-07-25 — redo on any scope change); engine rule/usage licences verified (done
  2026-07-25: CodeQL excluded — needs GitHub Advanced Security for commercial use; Semgrep
  Rules License v1.0 forbids redistribution, so rules are never bundled, only fetched by the
  user at a pinned SHA).

## Governance

This constitution supersedes convenience. Any spec, plan, task or PR that conflicts with a
Core Principle is rejected, not negotiated — a feature that cannot be built deterministically
or that would let the tool assert compliance does not get built.

Amendments: edit the Rules section of DESIGN.md and this file in the same commit, state what
changed and why, and bump the version below. Principle III means a scope-list change also
touches the README, `mapping/ens_rd311.yml` and the report header in that same commit.
Runtime guidance for agents working on the repo lives in [AGENTS.md](../../AGENTS.md).

**Version**: 1.2.0 | **Ratified**: 2026-07-25 | **Last Amended**: 2026-07-25

Amendment 1.2.0 — Principle IV now requires a per-run coverage table. A 21-repo corpus showed
the engines produce zero findings for C, Swift, Kotlin and Elixir because the free Semgrep
registry ships about two rules per language — a deliberately vulnerable C program and an
intentionally insecure iOS app both came back empty. Silence that reads as "clean" is exactly
what Principle II forbids, so the report must state what was analysed.

Amendment 1.1.0 — scope: `op.acc.5` → `op.exp.3`. The BOE heading for op.acc.5 is the
authentication mechanism for users external to the organisation: a design and operational
control that no static scanner can observe, so it could never receive evidence. op.exp.3
(configuration management) is evidenced by findings already in the corpus — mutable image
tags, untrusted registries, mutable CI action references.
