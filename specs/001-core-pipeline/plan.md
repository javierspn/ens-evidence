# Implementation Plan: Core Pipeline

**Branch**: `001-core-pipeline` | **Date**: 2026-07-25 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-core-pipeline/spec.md`

## Summary

Build the `scan` / `baseline update` finding path: invoke Semgrep + Trivy hermetically as
subprocesses, merge their SARIF into one sorted, deduplicated, canonically-identified
`findings.jsonl`, fingerprint findings baseline-stably, and land every run in an immutable
run store whose `run.json` records every drifting input plus per-run coverage data.
Acceptance is DESIGN.md's: byte-identical JSONL twice, green in a bare runner, `--fail-on
high` gates one new high finding.

## Technical Context

**Language/Version**: Python 3.12 (constitution-fixed)

**Primary Dependencies**: stdlib + PyYAML (Jinja2 reserved for spec 002; not used here).
Engines: Semgrep ≥1.171, Trivy ≥0.72 as external binaries, never imports.

**Storage**: files only — `out/<date>_<git-short-sha>/` run store, `.ens-baseline.yml`,
`mapping/*.yml` data files

**Testing**: pytest (already used by `tests/test_mapping_contract.py`)

**Target Platform**: Linux CI runner + macOS dev; no network on the finding path

**Project Type**: single CLI tool, flat `src/` (constitution: keep it small)

**Performance Goals**: none binding — engine runtime dominates; pipeline overhead
irrelevant at corpus scale (179 findings / 28 rule ids)

**Constraints**: determinism (byte-identical re-runs), hermetic engines
(`--offline-scan`, pinned rules), immutable append-only run store, nothing interactive

**Scale/Scope**: 2 engines, ~10³ findings per run, single repo per invocation

## Constitution Check

*GATE: constitution 1.4.0, checked pre-Phase 0 and re-checked post-Phase 1 — PASS (both).*

| Principle / constraint | Status | How the plan complies |
|---|---|---|
| I. Deterministic | ✅ | sorted findings, canonical JSON serialisation, hermetic engines, `--force` byte-identity is the acceptance test |
| II. Evidence, not verdict | ✅ | this spec emits findings + run record only; no compliance wording anywhere |
| III. One scope list | ✅ | measure list not restated in any 001 artifact; mapper is spec 002 |
| IV. Say what it can't see | ✅ | FR-011 coverage record per run; empty scans still write full run record |
| V. No CCN-STIC/BOE text | ✅ | no legal text touched |
| VI. Keep it small | ✅ | two verbs of the five (`scan`, `baseline update`), flat `src/`, no new abstractions; dedupe classes are a data file, not an engine |
| Engines are subprocesses | ✅ | `subprocess.run` on pinned binaries; missing binary → exit 2 naming it |
| Rules never distributed | ✅ | `scan` only consumes an existing rules root; `rules fetch` out of scope here |
| Drift pinned/recorded | ✅ | `run.json` records engine versions, Trivy DB + checks-bundle versions, rules mode+SHA, mapping hash, baseline hash, config hash |
| Hermetic or fiction | ✅ | `trivy --offline-scan`, `--skip-db-update` after explicit cache prime; Semgrep local rules root; any finding-path network use is a defect |
| Mapping/severity are data | ✅ | severity via `src/ens_evidence/mapping/severity.yml`; dedupe equivalence via `src/ens_evidence/mapping/defect_classes.yml` (new data file, same pattern) |
| No LLM | ✅ | none |
| Fingerprints never file+line | ✅ | hash(canonical rule id + normalised snippet + occurrence ordinal) — see research.md R5 |
| Run store immutable | ✅ | new dir per run, `latest` symlink swap is the only mutation; partial reuse forbidden by design (skip is all-or-nothing) |
| Injection surface | ✅ | 001 stores raw messages/snippets in JSONL only; fencing/truncation is render-time (spec 002/003) — JSONL is machine-read, never pasted |
| Stack | ✅ | Python 3.12, stdlib + PyYAML |

## Project Structure

### Documentation (this feature)

```text
specs/001-core-pipeline/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/
│   ├── cli.md           # verbs, exit codes, config resolution
│   └── artifacts.md     # findings.jsonl line schema, run.json schema, baseline schema
└── tasks.md             # /speckit-tasks output (not this command)
```

### Source Code (repository root)

```text
src/
├── run.py               # CLI, config resolution, engine subprocesses, run store, skip key, exit codes
├── normalise.py         # SARIF → JSONL: canonical ids, security split, dedupe, severity, fingerprints, sort
├── mapper.py            # untouched stub (spec 002)
└── render.py            # untouched stub (spec 002/003)

mapping/
├── severity.yml         # exists — engine scale → canonical scale
├── defect_classes.yml   # NEW — rule-id regex → defect class (cross-engine dedupe equivalences)
└── ens_rd311.yml        # untouched (spec 002)

tests/
├── fixtures/vulnerable-app/     # exists — extend with lockfile-less + shuffled-SARIF cases
├── fixtures/sarif/              # NEW — captured engine SARIF pairs for offline normaliser tests
├── test_normalise.py            # NEW — canonical ids, split, dedupe, fingerprints, sort, byte-identity
├── test_run_store.py            # NEW — skip key, immutability, run.json completeness, coverage record
└── test_cli.py                  # NEW — exit codes, --fail-on gate, baseline update, config resolution
```

**Structure Decision**: keep the existing flat four-module `src/` from DESIGN.md's repo
layout. 001 touches `run.py` and `normalise.py` only. No packages, no services — a
models/services split would violate Principle VI for a two-module change.

## Complexity Tracking

No violations — table intentionally empty.

One judgement call recorded: `src/ens_evidence/mapping/defect_classes.yml` is a new data file not named in
DESIGN.md's layout. It is the (path, defect class) dedupe key's data half; encoding
cross-engine equivalences in code would violate "mapping … are data files, not code".
Unlisted rule ids self-class (class = canonical rule id), so the file only ever *merges*
known duplicates and absence of an entry is safe.
