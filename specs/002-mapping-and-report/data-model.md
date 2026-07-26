# Data Model — 002 Mapping and Report

Phase 1. Inputs are spec 001's stored artifacts
([001 contracts](../001-core-pipeline/contracts/artifacts.md)); this spec adds one data
file and one document. Decisions behind these shapes: [research.md](research.md).

## Inputs (read-only, from spec 001)

| Artifact | Used for |
|---|---|
| `out/<run>/findings.jsonl` | the findings themselves: `tool`, `rule`, `class`, `sev`, `security`, `file`, `line`, `msg`, `snippet`, `fingerprint`, `id`, `new`, `merged_from` |
| `out/<run>/run.json` | header + coverage table + staleness disclosures: engine versions, Trivy DB version/date, rules mode/SHA, mapping hashes, `coverage`, `counts` |

Neither is ever modified by this spec (immutable run store).

## `src/ens_evidence/mapping/measures_es.yml` (NEW)

| Field | Content |
|---|---|
| `version` | int |
| `verified` | ISO date the titles were checked against the BOE consolidated text of Anexo II |
| `measures` | map: measure id → `{title, gloss}` |

`title` and `gloss` are **our own Spanish wording**, never copied from BOE or CCN-STIC
(Principle V). Covers exactly the in-scope measures plus `unmapped`; a measure present in
the scope list but absent here is a release blocker, mirroring how the mapping file is
already gated.

## Mapped finding (in-memory, renderer input)

The 001 finding dict plus:

| Field | Type | Rules |
|---|---|---|
| `measures` | list[str] | from `mapper.measures_for`; `["unmapped"]` when nothing matched |
| `matched_rule` | str \| None | the mapping pattern that matched — drives `explain`, `None` when unmapped |
| `counts_toward_measures` | bool | `security and measures != ["unmapped"]`; a `False` finding is rendered but never counted (FR-003) |

## Report model (renderer context)

| Entity | Content |
|---|---|
| **Header** | scope list verbatim, run date, target, git SHA, mapping version, measure-list verification date |
| **Disclaimer** | what static analysis cannot see (business logic, authn/authz design, runtime config) + "not an audit" |
| **Coverage table** | `run.json.coverage`: languages detected, rules run per language (or `registry-uncounted`), languages not analysed, dependency-analysis status |
| **Staleness block** | rules mode + SHA, vulnerability-DB version + date, checks-bundle, engine versions, mapping version |
| **Triage** | ≤10 findings, ranked per [research.md R5](research.md) |
| **Measure sections** | one per in-scope measure, in scope-list order: title, gloss, its findings — or an explicit "no evidence gathered" line when it has none |
| **Full table** | every finding, sorted as 001 sorts them |
| **Unmapped appendix** | findings no rule matched, awaiting a mapping decision |
| **Non-security note** | findings the engines did not tag `security`: present, excluded from every measure |

Invariant (SC-002): each finding appears exactly once across measure sections, the
unmapped appendix, and the non-security note — sums reconcile with no residue.

## Explanation (the `explain` verb's output)

| Field | Content |
|---|---|
| `id` | the finding id queried |
| `finding` | tool, canonical rule, severity, file, fenced+truncated message |
| `matched_rule` | the mapping pattern that matched, or `null` |
| `measures` | measures produced, or `["unmapped"]` |
| `why` | the reasoning: which pattern, why it precedes any later match, whether the finding counts toward a measure |

## Report metadata (added to the run directory)

Rendering writes `report.md` (always) and `report.pdf` (when the converter is available)
**inside the run directory**. It never rewrites `findings.jsonl` or `run.json`; the
Markdown records its own render inputs (mapping version + hash, measures-file version,
template identity) in the document so two renders of one run are distinguishable.
