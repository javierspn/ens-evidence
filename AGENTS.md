# AGENTS.md — for agents working *on* this repo

Agents **using** the released tool want [SKILL.md](SKILL.md) instead.

Read [DESIGN.md](DESIGN.md) before changing anything; it holds the why, and specs point at
it rather than restating it. The non-negotiables live in
[.specify/memory/constitution.md](.specify/memory/constitution.md).

## Ground rules

- **Never edit `out/`.** The run store is immutable and append-only — the sequence of
  reports over time IS the evidence trail.
- **Mapping and severity are data, not code.** `src/ens_evidence/mapping/ens_rd311.yml` and
  `src/ens_evidence/mapping/severity.yml` are the extension seam. A new framework is a new data file, never
  a rewrite of `mapper.py`.
- **Determinism is testable — test it.** `--force` must re-run and produce byte-identical
  JSONL. Anything with variable output must not be load-bearing.
- **The report is evidence, never a verdict.** No wording anywhere may state that a repo
  complies with the ENS.
- **The scope list is six measures**, verbatim in the constitution, README,
  `src/ens_evidence/mapping/ens_rd311.yml` and the report header. Changing it means changing all four in
  one commit.
- **Never bulk-copy CCN-STIC or BOE text.** Measure IDs and our own wording only.
- **Scanned code is untrusted input.** Snippets, scanner messages and **file paths** flow into
  reports and into `bundle.md`, which is pasted into chat windows by design. Two controls, both
  in `render.py`, and no third way in: `fence()` for anything that can go in a block, and
  `inline_untrusted()` for values that must stay in a cell or a bullet — a path with a backtick
  otherwise closes its code span and one with a pipe breaks the table, which is a real defect
  spec 003 found in the shipped report. Prefer our template wording over scanner passthrough,
  and add no field that renders scanned-repo text without one of the two filters.
- **Engines are subprocesses, never Python imports.** Missing binary → exit 2 naming it.
- **Keep it small.** Five verbs, two engines, six measures. A feature needs a validated
  reason.

## Gates

Installed 2026-07-25 and each one verified to actually bite, not just run:

| Gate | Where | Subject | Verified by |
|---|---|---|---|
| `scripts/gates.sh` (ai-tools `repo-gates` core, settings in `scripts/gates.conf`, modules in `scripts/gates.d/`, refreshed with `scaffold.sh --update`) — python: ruff, bandit (medium+), ast-grep rules + canary, pip-audit, pytest `-m "not engines and not rendering"`; shell: shellcheck; yaml: yamllint | `.githooks/pre-commit` on every commit (`scripts/gates.sh install` once per clone), `gates.yaml` CI job on the bellatrix runner, Claude Code edit/commit hooks calling the same script | style/imports (`select` pinned), insecure code, discarded exceptions / failures logged as routine / silently-defaulted seams, dependency CVEs, unit tests, shell and yaml defects | planted `subprocess(shell=True)` → `git commit` refused with exit 2 (B602) (ADR 0001 phase 5, 2026-11-01) |
| gitleaks | `gitleaks` job in `gates.yaml` | secrets in history | binary, not the action (the action 403s on the PR API) |
| **mapping contract** | `tests/test_mapping_contract.py` + `test` CI job | the data files — regexes that stop matching, off-scope measures, scope-list divergence | 11 tests, all passing |
| spec freshness | `tests/test_spec_contract.py` + `test` CI job | `specs/NNN-*/` — a `Feature Branch` field naming another feature, an unknown `Status`, a spec set missing `plan.md`/`tasks.md`, and `Status` disagreeing with whether tasks remain open | probes: reverted a shipped spec to `Draft`, pointed one spec at another's branch, reopened a ticked task → each failed the matching test |
| sample freshness | `tests/test_sample_contract.py` + `test` CI job | `samples/README.md`'s hand-written commit, date, engine versions, rules SHA and counts, against the generated `bundle-ejemplo.md` and the pin in force | probes: bumped `.github/semgrep-rules.sha`, drifted a count, named a commit not in history → each failed the matching test |

The mapping contract is the gate that matters here: `src/` is all stubs, so lint and bandit
have almost nothing to read, while the mapping and the six-measure scope list are the actual
asset. It also enforces principle III mechanically — the canonical list must appear verbatim in
README (×2), DESIGN.md and the constitution, and a test fails if any drifts. Add the report
header as a fourth case when `templates/` gains one.

Run everything locally before pushing:

```bash
scripts/gates.sh all
gitleaks detect --source . --no-banner --redact --config .gitleaks.toml
uv run --with pytest --with pyyaml python -m pytest tests/ -q -m engines   # needs pinned engines; see ci.yaml
```

`ci.yaml` (engine, rendering and rules-bump suites, on every PR and push) and `scan.yml`
(self-scan, on push to `main`) run on the bellatrix host runner since 2026-11-02: no sudo,
engines from `.github/ci-engines.sh` into `~/.cache/ens-ci/bin`, pandoc and poppler on the
host, weasyprint from pip.

## Landing a change

`main` is protected (no direct push, required checks, no admin bypass — a bypass
for javier is a bypass for any agent holding his token). Nobody opens PRs or
merges by hand:

```bash
git push origin HEAD:refs/for/main -o topic=<short-name>
```

That one push (Agit flow) opens the PR; when every check is green the `land`
workflow (cron, every 5 min, the `forgejo-ci` bot) merges it. A red PR stays open with the finding. `git pull` afterwards.

**Deliberately NOT installed: the spec-kit gates** (`scripts/spec_*.py`,
`.github/workflows/spec-*.yaml`) from the `repo-gates` skill. `spec_lint.py` globs
`specs/**/*.md`, which here means four README placeholders with no frontmatter — it would be
red from day one, and its `VALID_WORKERS` set is specific to one private repo (`auth`, `portal`, `iso`…).
Revisit once `/speckit-specify` generates real `spec.md` files, either adapting the worker list
or letting Spec Kit's own artefacts carry the check.

## Layout

`src/ens_evidence/run.py` orchestration + CLI · `src/ens_evidence/normalise.py` SARIF → JSONL, dedupe, severity,
fingerprints · `src/ens_evidence/mapper.py` table lookup · `src/ens_evidence/render.py` report + bundle ·
`templates/` Jinja2 · `mapping/` the data assets · `specs/` Spec Kit features ·
`tests/fixtures/` deliberately broken and injection-laden fixture repos.

Stack: Python 3.12, stdlib + PyYAML + Jinja2. No framework.

## Status

Scaffold plus data files — every `src/` module is still a stub.

Spec Kit is initialised (`/speckit-specify`, `/speckit-plan`, `/speckit-tasks`,
`/speckit-implement`; note the dash, not the dot DESIGN.md uses) and the constitution is
ratified at 1.3.0.

`src/ens_evidence/mapping/ens_rd311.yml` and `src/ens_evidence/mapping/severity.yml` are authored from real scans of twenty-one
repositories — 1794 findings, 840 rule ids, 0 unmapped: five private and sixteen public,
spanning Python, JS/TS, Java, Go, Ruby, PHP, Scala, Terraform, Kubernetes, Docker and Android.
**C, C++, Swift, Kotlin and Elixir are not analysed in registry mode** — Semgrep's free
registry ships ~2 rules each, so a clean report there means no rules ran (constitution 1.2.0
requires the report to say so). Running the public `semgrep-rules` directories locally closes
most of that gap (C: 0 → 12 findings), via a self-cloned pinned checkout passed as
`--rules-root`.

**Licence rules you must not break** (Semgrep Rules License v1.0 — no redistribution, no
offering as a service, licensee's own internal use only; full reasoning in DESIGN.md
"Rule sourcing and licensing"):

- never bundle rules in the image, the pip package, a release asset or a build artifact —
  engines only. That includes rule content in another shape: the run store's raw `*.sarif`
  embeds the entire rule catalogue (2126 rule descriptions for 9 fired, measured
  2026-07-26), so an upload allow-lists the evidence files and excludes SARIF;
- never mirror, cache-in-a-published-artifact, or vendor them into this repo (`.ens-rules/` is
  git-ignored);
- never modify, reformat or re-namespace rule files, and never strip their notices;
- never offer scanning as a service using them;
- the self-scan workflow uploads `out/latest/` only — never the repo root, which would carry
  `.ens-rules/` into a public artifact.

Local rule ids are path-derived and MUST be canonicalised in `normalise.py` before mapping,
otherwise every local-mode finding lands in the unmapped appendix under a machine-specific key.
Local mode also ships non-security rules; the discriminator is the engine's `security` tag, not
the id namespace (`csharp.lang.best-practice.structured-logging` is tagged security, an Android
`best-practice` rule has empty tags). Non-security findings stay in the JSONL but must not count
toward a measure. This is a
generic tool: breadth of ecosystem coverage is a product requirement, so when a new language
or engine appears, extend the mapping rather than letting a catch-all swallow it. See
[docs/scan-baseline.md](docs/scan-baseline.md), which also
records what closed and what is still open. All original gaps are closed; what remains is
that **neither engine is hermetic** — Trivy resolves Maven POMs over the network, Semgrep
fetches a versionless ruleset — which Principle I cannot survive. Spec 001 owns it. Read the
note before extending either data file.

`tests/mapping-cases.yml` is the mapping contract — 50 observed cases plus 4 ids that must
fall through to `unmapped`. Three of the original six probes were contradicted by real scans,
so treat that list as live hypotheses; the surviving ones are unknown *engines*, since the
language catch-alls absorb unknown rules inside a known engine. Changing a mapping rule without updating it should break the
suite; that is the point.

Drift: verdict-relevant inputs move over time (Trivy DB daily, semgrep-rules upstream, the
mapping, the BOE text). DESIGN.md "Drift" holds the policy — pin or record, disclose in the
coverage table, and gate rules-SHA bumps on zero new unmapped ids in the fixture corpus.

Scope is six measures: `mp.sw.1 · mp.sw.2 · mp.s.2 · op.exp.2 · op.exp.3 · op.exp.4`,
verified against the BOE text. `op.acc.5` was dropped in constitution 1.1.0 — do not
reintroduce it without a scanner that can actually evidence an authentication mechanism.
