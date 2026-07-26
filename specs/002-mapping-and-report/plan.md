# Implementation Plan: Mapping and Report

**Branch**: `002-mapping-and-report` | **Date**: 2026-07-26 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-mapping-and-report/spec.md`

## Summary

Consume spec 001's stored run (`findings.jsonl` + `run.json`), file each finding under
ENS measures via the existing `src/ens_evidence/mapping/ens_rd311.yml` (first-match-wins over
`<tool>:<rule-id>`), and render a Spanish evidence report — scope list verbatim in the
header, coverage table from the run record, top-10 triage first, full table and unmapped
appendix after. Plus `explain <id>` for one finding's classification and `report` for
re-rendering without re-scanning. The report states what was tested and found; it never
states compliance.

## Technical Context

**Language/Version**: Python 3.12 (constitution-fixed)

**Primary Dependencies**: stdlib + PyYAML + **Jinja2** (first use of Jinja2 in the repo).
PDF via an external binary (`pandoc`), never a Python PDF library — same subprocess seam
as the engines, so the dependency tree stays tiny.

**Storage**: reads `out/<run>/findings.jsonl` + `run.json`; writes `report.md` /
`report.pdf` into that same run directory

**Testing**: pytest; rendering tests are engine-free and run from a committed fixture run
(no scanning, and no PDF binary needed for the Markdown assertions)

**Target Platform**: same as 001 — Linux CI + macOS dev

**Project Type**: single CLI tool, flat `src/`

**Performance Goals**: none binding — 28–453 findings render instantly

**Constraints**: deterministic rendering (same run + mapping + template → same bytes),
no compliance assertions anywhere, all scanned-repo text truncated and fenced, Spanish
output in our own wording only

**Scale/Scope**: 6 measures, ~10³ findings, one report document per run

## Constitution Check

*GATE: constitution 1.4.0, checked pre-Phase 0 and re-checked post-Phase 1 — PASS (both).*

| Principle / constraint | Status | How the plan complies |
|---|---|---|
| I. Deterministic | ✅ | render reads only stored run data; no clock, no engine, sorted iteration; byte-identical re-render is a test (SC-005) |
| II. Evidence, not verdict | ✅ | per-measure sections state evidence or its absence; a forbidden-phrase test scans the rendered text (SC-003) |
| III. One scope list | ✅ | scope list literal in the template → `SCOPE_DOCS` gains its fourth entry; a second test asserts the *rendered* report carries it too |
| IV. Say what it can't see | ✅ | coverage table + disclaimer + staleness disclosures rendered from `run.json` (FR-005, FR-007) |
| V. Never bulk-copy BOE/CCN-STIC | ✅ | `src/ens_evidence/mapping/measures_es.yml` holds **our own** Spanish wording — verified against Anexo II, never copied from it |
| VI. Keep it small | ✅ | completes the five finding-path verbs (`report`, `explain` added); no new abstraction — mapper is a table lookup, renderer is a template binding |
| Mapping/severity are data | ✅ | mapper holds zero mapping knowledge; measure titles are a data file too |
| No LLM | ✅ | none |
| Injection surface | ✅ | truncation + untrusted-input fencing enforced in the renderer and asserted over the rendered text (SC-006) |
| Run store immutable | ✅ | the report lands **inside** its own run dir; re-render replaces only that run's own report, never `findings.jsonl` or `run.json` |
| Engines are subprocesses | ✅ | extended to the PDF converter: external binary, absence disclosed rather than silent |
| Stack | ✅ | Python 3.12, stdlib + PyYAML + Jinja2 |

## Project Structure

### Documentation (this feature)

```text
specs/002-mapping-and-report/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/
│   ├── cli.md           # report + explain verbs, exit codes
│   └── report.md        # document structure contract (section order, required blocks)
└── tasks.md             # /speckit-tasks output (not this command)
```

### Source Code (repository root)

```text
src/
├── mapper.py            # table lookup: compile once, first-match-wins  (this spec)
├── render.py            # report assembly + untrusted-input fencing     (this spec)
├── run.py               # + `report` and `explain` verbs                (this spec)
└── normalise.py         # untouched (spec 001)

mapping/
├── ens_rd311.yml        # exists, authored from real output — consumed, not rewritten
├── measures_es.yml      # NEW — measure id -> our own Spanish title + one-line gloss
├── severity.yml         # untouched
└── defect_classes.yml   # untouched

templates/
└── report.md.j2         # NEW — Spanish evidence report; carries the scope list verbatim

tests/
├── test_mapping_contract.py   # + report template as SCOPE_DOCS' fourth site
├── test_mapper.py             # NEW — first-match-wins, unmapped fall-through, non-security
├── test_render.py             # NEW — structure, determinism, fencing, no-verdict, accounting
└── fixtures/run/              # NEW — a committed stored run (findings.jsonl + run.json)
                               #       so rendering tests need neither engines nor a scan
```

**Structure Decision**: unchanged flat `src/` — this spec fills in the two remaining
stubs (`mapper.py`, `render.py`) and adds two verbs to `run.py`. No packages, no service
layer: the mapper is a table lookup and the renderer is a template binding.

## Complexity Tracking

No constitution violations. Three judgement calls recorded, since each adds a file
DESIGN.md's layout does not name:

| Decision | Why needed | Simpler alternative rejected because |
|---|---|---|
| `src/ens_evidence/mapping/measures_es.yml` | The report must label each measure in Spanish. Principle V forbids copying BOE text, so the wording must be ours — versioned, diffable, reviewable | Rendering bare ids (`mp.sw.1`): an auditor-facing document listing only codes is poor evidence. Hardcoding titles in the template makes "our own wording" unreviewable and undiffable |
| PDF via external binary | Keeps the dependency tree at PyYAML + Jinja2 and reuses the subprocess seam the constitution already blesses | A Python PDF library (weasyprint/reportlab) — a framework-sized dependency the constitution's stack line excludes |
| `tests/fixtures/run/` | Rendering tests must run in CI with no engines installed and no scan; a committed stored run is the only engine-free input | Re-scanning inside the test — reintroduces the engine dependency the 001 CI gate deliberately removed |
