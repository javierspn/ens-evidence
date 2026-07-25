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

## Gates

Installed 2026-07-25 and each one verified to actually bite, not just run:

| Gate | Where | Subject | Verified by |
|---|---|---|---|
| `ast-grep` structural | `.claude/hooks/ast-grep-commit.sh` + `structural` CI job | discarded exceptions, failures logged as routine, silently-defaulted seams | staged a known-bad probe → hook exited **2** with both rules firing |
| bandit + pip-audit + gitleaks | `.claude/hooks/sec-scan-commit.sh` + `security` CI job | insecure code, dependency CVEs, secrets in history | staged `subprocess(shell=True)` → hook exited **2** (B602) |
| ruff | `lint` CI job | style/imports, `select` pinned to `["E","F","I","N","W"]` | `ruff check src/ tests/` clean |
| **mapping contract** | `tests/test_mapping_contract.py` + `test` CI job | the data files — regexes that stop matching, off-scope measures, scope-list divergence | 11 tests, all passing |

The mapping contract is the gate that matters here: `src/` is all stubs, so lint and bandit
have almost nothing to read, while the mapping and the six-measure scope list are the actual
asset. It also enforces principle III mechanically — the canonical list must appear verbatim in
README (×2), DESIGN.md and the constitution, and a test fails if any drifts. Add the report
header as a fourth case when `templates/` gains one.

Run everything locally before pushing:

```bash
uv run --with pytest --with pyyaml python -m pytest tests/ -q
uv run --with ruff ruff check src/ tests/
uv run --with bandit bandit -ll -r src/
uv run --with pip-audit pip-audit -r requirements-dev.txt
gitleaks detect --source . --no-banner --redact --config .gitleaks.toml
```

**Deliberately NOT installed: the spec-kit gates** (`scripts/spec_*.py`,
`.github/workflows/spec-*.yaml`) from the `repo-gates` skill. `spec_lint.py` globs
`specs/**/*.md`, which here means four README placeholders with no frontmatter — it would be
red from day one, and its `VALID_WORKERS` set is repo-a-specific (`auth`, `portal`, `iso`…).
Revisit once `/speckit-specify` generates real `spec.md` files, either adapting the worker list
or letting Spec Kit's own artefacts carry the check.

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
ratified at 1.3.0.

`mapping/ens_rd311.yml` and `mapping/severity.yml` are authored from real scans of twenty-one
repositories — 1794 findings, 840 rule ids, 0 unmapped: five private and sixteen public,
spanning Python, JS/TS, Java, Go, Ruby, PHP, Scala, Terraform, Kubernetes, Docker and Android.
**C, C++, Swift, Kotlin and Elixir are not analysed in registry mode** — Semgrep's free
registry ships ~2 rules each, so a clean report there means no rules ran (constitution 1.2.0
requires the report to say so). Running the public `semgrep-rules` directories locally closes
most of that gap (C: 0 → 12 findings), via `ens-evidence rules fetch --sha <commit>
--accept-rules-license`.

**Licence rules you must not break** (Semgrep Rules License v1.0 — no redistribution, no
offering as a service, licensee's own internal use only; full reasoning in DESIGN.md
"Rule sourcing and licensing"):

- never bundle rules in the image, the pip package or a release asset — engines only;
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
