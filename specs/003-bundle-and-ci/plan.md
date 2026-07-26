# Implementation Plan: bundle, rules bootstrap and CI

**Branch**: `003-bundle-and-ci` | **Date**: 2026-07-26 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/003-bundle-and-ci/spec.md`

## Summary

Four deliverables, in dependency order: (1) the `bundle` verb — a second Jinja template over
the model `report` already builds, so scanned-repo text keeps travelling through the single
`render.fence()` path, plus an injection fixture and a stored run of it so the proof runs
without engines; (2) the `rules` bootstrap group — `fetch` (pinned `git fetch --depth 1 <sha>`
into `.ens-rules/`, gated on an explicit licence acknowledgement) and `status` (the existing
`rules_info()` as machine output); (3) CI — replace the `scan.yml` stub with a real self-scan
that fetches rules at run time and uploads `out/latest/` only, plus a rules-bump job that fails
on any new unmapped rule id; (4) a tagged release carrying `samples/informe-ejemplo.pdf`.

No new dependency, no new module layout: `run.py` gains subcommands, `render.py` gains one
render function, `templates/` gains one template.

## Technical Context

**Language/Version**: Python 3.12 (constitution: stdlib + PyYAML + Jinja2, no framework)

**Primary Dependencies**: PyYAML, Jinja2. New external binary dependency: `git` (already used
by `run.py:_git`) for the rules fetch. `pandoc` + `weasyprint` for the sample PDF, maintainer-side
only.

**Storage**: the existing immutable run store under `out/<run>/`; `bundle.md` is written into
the run directory beside `report.md`

**Testing**: pytest, `-m "not engines"` must stay green on a machine with neither Semgrep nor
Trivy — hence the stored-run fixture for the injection proof

**Target Platform**: developer machines (macOS/Linux) and GitHub Actions `ubuntu-latest`

**Project Type**: single CLI package, src-layout (`src/ens_evidence/`)

**Performance Goals**: not a factor — `bundle` renders one stored run; the rules fetch is a
depth-1 clone

**Constraints**: no network in the finding path (Principle I); rule files never leave the
runner (Semgrep Rules License v1.0); byte-identical output on re-render; no absolute host path
in any emitted document

**Scale/Scope**: one verb group + one verb + two workflows + one fixture + one sample

## Constitution Check

*GATE: passed before Phase 0; re-checked after Phase 1 design — no violation, no Complexity
Tracking entry needed.*

| Principle / constraint | How this plan satisfies it |
|---|---|
| I. Deterministic | `bundle` reads a stored run only, never scans, never touches the network. Re-render byte-equality is an acceptance test. `rules fetch` pins a commit SHA; a fetch is not in the finding path. |
| II. Evidence, not verdict | `bundle.md` carries the same disclaimer block as the report and states counts, never compliance. |
| III. One scope list | The bundle template reads the measure list from `mapping/ens_rd311.yml` like the report does; the plan adds no fifth copy. |
| IV. Say what it can't see | The coverage disclosure (languages detected, rules run per language, languages not analysed, dependency analysis skipped) is mandatory in the bundle, not optional — a truncated view is exactly where a disclaimer gets dropped. |
| V. No CCN-STIC/BOE bulk text | Nothing new is quoted; measure ids and our wording only. |
| VI. Keep it small | This completes the declared surface (`bundle` is the fifth finding-path verb, `rules` is the declared bootstrap group) and adds nothing beyond it. Owner decision 2026-07-26 settled that the group is built rather than removed by amendment. |
| Rules never distributed | `rules fetch` clones into `.ens-rules/` (already in `SKIP_DIRS` and `.gitignore`); CI uploads `out/latest/` by explicit path and a test step fails the job if any rule-shaped file appears in the artifact staging directory. |
| Drift pinned or recorded | The rules SHA moves to a single tracked file, `.github/semgrep-rules.sha`; changing it triggers the fixture-corpus job that fails on new unmapped ids. |
| Engines are subprocesses | `git` is invoked as a subprocess, matching the existing pattern; no GitPython. |
| Injection surface | Scanned text reaches a document through `render.fence()` (blocks) or `render.inline_untrusted()` (paths and ids in cells, where a block cannot go); the fixture makes both testable instead of asserted. Building the proof found the second control to be unavoidable and found the report shipping without it — see [research.md](research.md) D6. |
| Docs move with the verbs | FR-013 is a task, not a courtesy: `SKILL.md`, `README.md`, `AGENTS.md` are edited in the same change that lands the verbs. |

## Project Structure

### Documentation (this feature)

```text
specs/003-bundle-and-ci/
├── plan.md              # This file
├── research.md          # Phase 0 — the four decisions and what was rejected
├── data-model.md        # Phase 1 — bundle model, rules state, pin file
├── quickstart.md        # Phase 1 — how to verify each story by hand
├── contracts/
│   ├── cli-bundle.md    # `ens-evidence bundle` surface and exit codes
│   └── cli-rules.md     # `ens-evidence rules fetch|status` surface and exit codes
├── checklists/
│   └── requirements.md  # specify-phase quality checklist
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
src/ens_evidence/
├── run.py                          # + cmd_bundle, cmd_rules_fetch, cmd_rules_status, subparsers
├── render.py                       # + render_bundle(model, template_dir), inline_untrusted()
└── templates/
    ├── report.md.j2                # inline untrusted fields now filtered (D6)
    └── bundle.md.j2                # NEW — paste-anywhere view of the same model

scripts/
└── unmapped_ids.py                 # NEW — stdlib; findings.jsonl → unmapped rule ids, exit 1 if any

tests/
├── test_bundle.py                  # NEW — bundle rendering, determinism, missing-run exit 2
├── test_injection.py               # NEW — every fixture injection string is fenced, none live
├── test_rules.py                   # NEW — licence gate, status output, fetch (marked `engines`)
└── fixtures/
    ├── injection-app/              # NEW content — hostile comments, paths, dependency metadata
    └── run-injection/              # NEW — stored run of injection-app, so the proof needs no engines

.github/
├── semgrep-rules.sha               # NEW — the single pinned rules SHA, read by both workflows
└── workflows/
    ├── ci.yaml                     # + rules-bump job (runs when the pin file changes)
    └── scan.yml                    # stub replaced: fetch rules → scan → report → upload out/latest only

samples/
└── informe-ejemplo.pdf             # NEW — real report, generated with --pdf-engine weasyprint
```

**Structure Decision**: unchanged from 001/002 — one src-layout package, flat module set, data
files under `src/ens_evidence/mapping/` and templates under `src/ens_evidence/templates/` so an
installed copy carries them. The only new top-level directory is `scripts/`, for the one
stdlib helper CI needs and tests can import; the alternative (inline `python -c` in YAML) is
untestable and was rejected in [research.md](research.md).

## Complexity Tracking

No constitution violation to justify.
