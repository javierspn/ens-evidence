# Data Model — 001 Core Pipeline

Phase 1. Serialisation rules in [research.md R6](research.md); schemas rendered as
contracts in [contracts/artifacts.md](contracts/artifacts.md).

## Finding (one JSONL line)

| Field | Type | Rules |
|---|---|---|
| `id` | str | fingerprint prefix — unique within a run |
| `tool` | `semgrep` \| `trivy` | surviving representative after dedupe |
| `rule` | str | **canonical** rule id (R3) — never a path-derived local id |
| `class` | str | defect class from `src/ens_evidence/mapping/defect_classes.yml`, else `tool:rule` self-class (R4) |
| `sev` | `critical`\|`high`\|`medium`\|`low`\|`info` | via `src/ens_evidence/mapping/severity.yml`; uncovered input severity → the file's declared `default`, hard error only if none declared (FR-006) |
| `security` | bool | engine `security` tag verbatim (FR-004); `false` ⇒ excluded from measure counts downstream |
| `file` | str | repo-relative POSIX path (R4) — never absolute, never `%SRCROOT%`/`ROOTPATH` |
| `line` | int | display only — MUST NOT feed fingerprint or dedupe |
| `msg` | str | engine message, raw (fencing is render-time, spec 002) |
| `snippet` | str | normalised snippet used by the fingerprint |
| `fingerprint` | str | R5 hash — the baseline key |
| `merged_from` | list[[tool, rule]] | present when dedupe collapsed >1 engine finding |
| `new` | bool | fingerprint ∉ baseline at scan time |

Invariants: findings sorted by `(file, class, rule, fingerprint)`; file starts with the
schema line `{"schema":"ens-evidence/1"}`; non-security findings present but flagged.

## Run record (`run.json`)

| Field | Content |
|---|---|
| `schema` | `ens-evidence/1` |
| `run` | date, git HEAD SHA + short SHA, target path (repo-relative root), argv-resolved verb |
| `engines` | semgrep version · trivy version · trivy vulnerability-DB version+UpdatedAt · checks-bundle version (R2) |
| `rules` | mode (`local`\|`registry`) · repo URL · SHA · rules root · per-language rule counts (local) |
| `mapping` | `severity.yml` + `defect_classes.yml` version + content sha256 |
| `baseline` | `.ens-baseline.yml` sha256 (or `null` when absent) |
| `config` | resolved-config sha256 |
| `skip_key` | sha256 of R7 tuple — equality ⇒ next run skips |
| `coverage` | see Coverage record |
| `counts` | total · security · non-security · new · deduped-away |

## Coverage record (`run.json.coverage`)

| Field | Content |
|---|---|
| `languages_detected` | ext-census result: language → file count (R8) |
| `rules_per_language` | language → count (local mode) \| `"registry-uncounted"` |
| `languages_not_analysed` | detected languages with zero rules run |
| `dependency_analysis` | `done` \| `skipped-no-lockfile` |

## Baseline (`.ens-baseline.yml`)

| Field | Content |
|---|---|
| `schema` | `ens-evidence/1` |
| `updated` | ISO date of last `baseline update` |
| `fingerprints` | sorted list of accepted fingerprint strings |

State transitions: written **only** by `baseline update` (FR-009); `scan` reads. A
fingerprint's lifecycle: new → (operator review) → accepted (in baseline) → stale
(no longer found; kept until next `baseline update` prunes it).

## Defect classes (`src/ens_evidence/mapping/defect_classes.yml`)

| Field | Content |
|---|---|
| `version` | int |
| `classes` | list of `{match: "<regex on tool:rule-id>", class: "<name>"}`, first match wins |

Seeded from the baseline's proven duplicate pairs: `container-runs-as-root`
(`semgrep:dockerfile.security.missing-user` ∪ `trivy:DS-0002`), `pod-runs-as-root`
(`semgrep:yaml.kubernetes.security.run-as-non-root` ∪ `trivy:KSV-0012`). Unlisted ids
self-class — the file merges, never splits.
