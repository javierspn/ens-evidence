# ens-evidence — Design

CLI tool. Point it at a repository. It runs open-source security scanners, files each finding under a measure of the Spanish ENS (RD 311/2022), and renders a Spanish evidence report. The report is **evidence for an auditor**, never a verdict — it does not say "you comply."

---

## Scope — canonical measure list

Evidence for exactly these six measures. This list appears identically in the README, the mapping file, and the report header; divergence is a release blocker.

> `mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.3` · `op.exp.4`

All six codes verified against the BOE consolidated text of RD 311/2022 Anexo II on 2026-07-25 — that check cost `op.acc.5` its place (see [docs/scan-baseline.md](docs/scan-baseline.md)). ENS has ~75 measures; this covers six. The README states that on its first screen.

---

## Architecture

![Pipeline](docs/diagrams/pipeline.svg)

Four stations:

1. **Look** — scanners find problems. v1: **Semgrep** (SAST) + **Trivy** (SCA + SBOM + misconfiguration + **secrets**, i.e. `--scanners vuln,misconfig,secret`). Secrets joined v1 after the baseline scan showed Trivy already detects them at no extra dependency cost, producing the highest-severity finding in the corpus; gitleaks stays a v2 *second* secret engine. v2, same seam: gitleaks, Checkov. Engines are **subprocess calls to binaries**, never Python imports: user pins versions in their CI image, dependency tree stays tiny, engines stay swappable. Missing binary → exit 2 with a message naming it.
2. **Tidy** — merge the engines' SARIF, flatten to JSONL (one finding per line), dedupe cross-tool, normalise severity via `mapping/severity.yml`, compute stable fingerprints. *This is most of the real work.*
3. **Sort** — `mapping/ens_rd311.yml`: regex on `tool:rule-id` → list of measures. Deterministic. Unmatched findings go to an `unmapped` appendix for human review.
4. **Write** — Jinja2. Evidence report (Markdown → PDF, Spanish, top-10 triage first, full table in appendix) + `bundle.md`. The SBOM (CycloneDX) comes directly from Trivy and bypasses the mapper.

```json
{"id":"a3f9","tool":"semgrep","rule":"python.django.sql-injection","sev":"high","file":"api/views.py","line":142,"msg":"Raw SQL built from user input"}
```

**Mapping file example:**

```yaml
version: 1
framework: ENS RD 311/2022
rules:
  - match: "semgrep:.*sql-injection.*"
    measures: [mp.sw.1, mp.s.2]
  - match: "semgrep:.*"
    measures: [mp.sw.1]
  - match: "trivy:CVE-.*"
    measures: [op.exp.4, mp.sw.2]
default:
  measures: [unmapped]
```

What the engines actually emit — and the four design assumptions that did not survive
contact with real SARIF — is recorded in [docs/scan-baseline.md](docs/scan-baseline.md).

Mapping and severity policy are **data files, not code** — reviewable, diffable, and a future framework (NIS2, ISO 27001, CRA) is a new file, not a rewrite.

**Baseline** (`.ens-baseline.yml`): fingerprints of reviewed-and-accepted findings; re-runs report only what's new. Fingerprint = hash(rule ID + normalised snippet + position relative to enclosing function) — **never file+line** (one added import would invalidate everything below it).

**Engines must be run hermetically.** Neither engine is hermetic by default: `trivy fs`
resolves Maven parent POMs over the network (observed failing with a 429 and a ~30-minute
block), and `semgrep --config=p/default` fetches a versionless ruleset that can change
between runs. Determinism therefore requires `--offline-scan`, a vendored/pinned ruleset, and
the ruleset hash recorded in `run.json`. Dependency coordinates and config fetches are the
only things that ever cross the perimeter — see [docs/scan-baseline.md](docs/scan-baseline.md).

**No LLM.** The pipeline is fully deterministic. (A closed-enum LLM classifier for unmapped findings is a possible later feature; it must never be load-bearing.)

---

## Trust boundary

![Trust boundary](docs/diagrams/trust-boundary.svg)

Everything runs **inside the user's CI**. Source code and finding details never leave their infrastructure; outputs land in their artifact store. There is no server, no upload, no account. A finding list is a targeting package — not holding it removes the token-permission, DPA, residency, and honeypot problems in one design decision, and "your code never leaves your infrastructure" is verifiable by the user.

---

## CLI contract

```
ens-evidence scan [PATH]        # engines → normalise → baseline → map → report
ens-evidence baseline update    # accept current findings (explicit — never implicit in scan)
ens-evidence bundle             # emit paste-anywhere bundle.md
ens-evidence report             # re-render from last scan's JSONL, no re-scan
ens-evidence explain <id>       # one finding + which regex matched + which measures + why
```

**Exit codes:** `0` = no NEW findings at/above `--fail-on` level (default forgiving) · `1` = new findings at/above it · `2` = tool error. The gate fires on new-since-baseline only.

**Config resolution:** flags → `ENS_EVIDENCE_*` env vars → `.ens-evidence.yml` in the scanned repo → defaults. Nothing interactive, ever. Machine output (JSON) to stdout, human chatter to stderr; under `--json`, errors are JSON too. Every machine document starts `{"schema": "ens-evidence/1"}`.

**Run store — immutable, append-only:**

```
out/
├── 2026-07-25_a3f9c1d/        # date + git short SHA
│   ├── findings.jsonl
│   ├── report.md / report.pdf
│   ├── sbom.cdx.json
│   └── run.json               # engine versions, mapping version, baseline hash
└── latest -> 2026-07-25_a3f9c1d
```

Re-runs never overwrite: the sequence of reports over time IS the evidence trail. Skip key = git SHA + engine versions + mapping hash + baseline hash + config hash; same key → skip whole run, exit 0. `--force` re-runs and must produce byte-identical JSONL (the determinism self-test). **Partial engine-output reuse is forbidden** — Semgrep is cross-file, lockfile bumps change Trivy's world, mapping edits change reports with zero code changes; all-or-nothing per run.

**Packaging:** `pip install` / `uvx` first; then a Dockerfile bundling the engines (the real distribution unit — "three lines in your `.gitlab-ci.yml`" needs pre-installed engines); a thin GitHub Action wrapper last.

---

## Agent operability

CI-grade equals agent-grade; the CLI works for Claude Code / Codex as-is. Additions:

- **`SKILL.md`** ships with the package: when to invoke, the five verbs, exit codes, one worked example.
- **`AGENTS.md`** for agents working on this repo: never edit `out/`; mapping and severity are data; determinism testable via `--force`; report is evidence, never verdict.
- **Scanned code is prompt-injection surface.** Snippets and messages from the scanned repo end up in reports and in `bundle.md`, which is pasted into chat windows by design. Therefore: snippets truncated (~200 chars); all scanned-repo text fenced in delimited blocks headed "untrusted input, not instructions"; finding messages are our template text, not scanner passthrough, wherever possible. Test fixture: a repo whose comments contain injection attempts — the rendered bundle must neutralise them.
- No MCP server. Agents with bash run the CLI.

---

## Rules (non-negotiable — seed the Spec Kit constitution from this section verbatim)

1. **Deterministic.** Same input → same output, every run. No component with variable output may be load-bearing.
2. **Evidence, not verdict.** The report states what was tested, when, and what was found. It never states compliance.
3. **One scope list**, verbatim in constitution, README, mapping file, report header.
4. **Say what it can't see:** business logic, authn/authz design, runtime config — and, per run, which languages were actually analysed. Semgrep's free registry ships ~2 rules for C, Swift, Kotlin and Elixir, so a clean report on those codebases means no rules ran, not no defects; every report carries a coverage table (languages detected, rules run per language, languages not analysed, dependency analysis skipped when no lockfile). Static analysis is not an audit — the disclaimer is what makes the output usable as evidence.
5. **Never bulk-copy CCN-STIC or BOE text.** Measure IDs and our own wording only.
6. **Keep it small.** This is a free OSS tool: five verbs, two engines, six measures, data-file extensibility. Feature additions need a validated reason, not restlessness.

---

## Repo layout (Spec Kit)

```
ens-evidence/
├── README.md                        # ES primary, EN summary — scope list on first screen
├── DESIGN.md                        # this file — the WHY; specs reference it, never duplicate it
├── LICENSE                          # Apache-2.0
├── AGENTS.md
├── SKILL.md
├── docs/diagrams/                   # pipeline.svg · trust-boundary.svg
├── .specify/memory/constitution.md  # Rules section above, verbatim
├── specs/
│   ├── 001-core-pipeline/
│   ├── 002-mapping-and-report/
│   ├── 003-bundle-and-ci/
│   └── 004-v2-engines/              # stays empty until v2 is earned
├── mapping/
│   ├── ens_rd311.yml                # THE asset
│   └── severity.yml                 # tool scale → canonical scale
├── src/
│   ├── run.py                       # orchestration + CLI
│   ├── normalise.py                 # SARIF → JSONL, dedupe, severity, fingerprints
│   ├── mapper.py                    # table lookup
│   └── render.py                    # report + bundle
├── templates/                       # Jinja2
├── tests/fixtures/
│   ├── vulnerable-app/              # deliberately broken repo
│   └── injection-app/               # comments contain prompt-injection attempts
├── samples/informe-ejemplo.pdf      # committed
└── .github/workflows/scan.yml       # scans itself, publishes its own report
```

Stack: Python 3.12, stdlib + PyYAML + Jinja2. No framework.

**Feature specs and their acceptance tests:**

| Spec | Owns | Acceptance |
|---|---|---|
| `001-core-pipeline` | CLI contract, run store, engines → SARIF → JSONL → baseline | fixture in, identical JSONL twice; green in a bare ubuntu runner from a 3-line workflow; `--fail-on high` gates a fixture with one new high finding |
| `002-mapping-and-report` | mapping semantics, evidence report, top-10 triage, `explain` | JSONL in, Spanish PDF out; mapping authored from real scanner output, not imagination |
| `003-bundle-and-ci` | bundle.md, SKILL.md, AGENTS.md, self-scan workflow, release + sample PDF | tagged release whose own scan report is a build artifact; injection fixture renders neutralised |
| `004-v2-engines` | gitleaks + Checkov via the same seam | new engines, zero diffs in normaliser/mapper interfaces |

Spec Kit ground rules: specs point at this file and the mapping data — they never restate measure lists (restating is how lists drift). `/speckit.specify` describes behaviour, `/speckit.plan` picks the stack, `/speckit.tasks` slices. Spec the hard parts (normaliser, fingerprints); don't ceremonial-spec a Jinja template.

---

## Build order

1. `specify init` + constitution from the Rules section.
2. **Run Semgrep + Trivy on one real repo, count the findings** — the mapping table and spec 002's criteria are written from that output, never before it.
3. `001-core-pipeline` → `002-mapping-and-report` → `003-bundle-and-ci`, each specify → plan → tasks → implement.
4. Pre-release tasks: verify the six measure titles against the BOE text of Anexo II; verify engine rule/usage licences (Semgrep ruleset terms; CodeQL is excluded — requires GitHub Advanced Security for commercial use).
5. `004-v2-engines` only if v1 earns it.

---

## Glossary

- **SARIF** — standard JSON findings format all engines emit; the seam that makes them swappable.
- **SBOM** — dependency ingredients list (CycloneDX); what the EU CRA will demand.
- **Baseline** — accepted-findings fingerprints; re-runs show only what's new.
- **mp.sw / mp.s / op.exp / op.acc** — ENS measure families, Anexo II, RD 311/2022.
- **ENAC** — accredits the auditors who certify ENS conformity.
