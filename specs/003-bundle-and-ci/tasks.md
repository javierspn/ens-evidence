# Tasks: bundle, rules bootstrap and CI

**Feature**: `003-bundle-and-ci` | **Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)

Tests are included because the constitution treats them as acceptance, not decoration:
determinism is an acceptance test, and the injection neutralisation (FR-005) is the security
proof of this feature. Every story's tests run under `pytest -m "not engines"` unless the task
says otherwise.

**Green check after every phase**:

```bash
.venv/bin/python -m pytest tests/ -q -m "not engines"
.venv/bin/python -m ruff check src/ tests/
.venv/bin/python -m bandit -ll -q -r src/
```

---

## Phase 1: Setup

- [x] T001 Create `.github/semgrep-rules.sha` containing the single pinned commit SHA `81634cfc9e68dc5f238a8062909a60ba34500648` (the commit the mapping corpus was authored against, per `docs/scan-baseline.md:513`), one line, trailing newline, no comment
- [x] T002 [P] Add `scripts/` to the repository with `scripts/README.md` stating it holds stdlib-only helpers that CI runs and tests import, never runtime code shipped in the package
- [x] T003 [P] Confirm `.ens-rules/` is ignored and skipped: assert the entry exists in `.gitignore` and in `SKIP_DIRS` in `src/ens_evidence/run.py`, and add whichever is missing

---

## Phase 2: Foundational (blocking prerequisites)

- [x] T004 Replace the `render_bundle` stub signature in `src/ens_evidence/render.py:187` with `render_bundle(model, template_dir)` rendering `bundle.md.j2` through the existing `_environment(template_dir)`, so the bundle inherits `StrictUndefined` and the `fence`/`truncate_untrusted` filters
- [x] T005 Extract the run-loading path shared by `cmd_report` and the new `cmd_bundle` in `src/ens_evidence/run.py` — `_resolve_run_dir` + `_build_model` already exist; verify `cmd_bundle` can use both unchanged and adjust only if it cannot

---

## Phase 3: User Story 1 — paste the evidence without pasting an attack (P1) 🎯 MVP

**Goal**: `ens-evidence bundle` emits a pasteable Markdown document from a stored run, and every
byte of scanned-repo text in it is provably data rather than instructions.

**Independent test**: `pytest tests/test_bundle.py tests/test_injection.py -q` passes with
neither Semgrep nor Trivy installed, and the rendered `bundle.md` read by eye carries the scope
header, coverage disclosure, unmapped count and disclaimer.

### Fixture and stored run

- [x] T006 [P] [US1] Populate `tests/fixtures/injection-app/` with hostile content across the three surfaces that reach a document: source comments carrying directives ("ignore previous instructions…", a fake system prompt), a file path containing a directive, and a lockfile whose package description carries one — each file also containing a real vulnerability pattern so the engines actually report findings
- [x] T007 [US1] Add `tests/fixtures/injection-app/injection-strings.txt`, the checked-in list of every injected directive, one per line, used as the test's oracle so a fixture edit that forgets the test fails loudly
- [x] T008 [US1] Extend the fixture with the two evasion cases the plan names: a string containing the fence delimiter ` ``` `, and a string carrying zero-width and bidirectional control characters
- [x] T009 [US1] Generate and commit `tests/fixtures/run-injection/` (`findings.jsonl` + `run.json`) by scanning `tests/fixtures/injection-app/` from a separate git work tree per the procedure in `tests/fixtures/run/README.md`, then rewrite `run.json`'s `target` to `.` and recompute `counts` so no absolute host path is committed
- [x] T010 [US1] Write `tests/fixtures/run-injection/README.md` recording what is real engine output, what (if anything) was constructed and why, the engine and rule versions used, and the regeneration procedure — matching the discipline of `tests/fixtures/run/README.md`

### Template and verb

- [x] T011 [US1] Create `src/ens_evidence/templates/bundle.md.j2` rendering, in order: what was analysed and when (`target_name`, `record.run.date`, `record.run.git_short_sha`), the canonical scope list from `scope`/`measures_meta`, the full `coverage` disclosure, the `triage` findings with their measures, the accounting line from `totals` including `unmapped`, the provenance line from `record.engines`/`record.rules`/`record.mapping`, and the evidence-not-verdict disclaimer
- [x] T012 [US1] In `bundle.md.j2`, route every field carrying scanned-repo text (`msg`, `file`, `snippet`, dependency names) through the `fence` filter — or `truncate_untrusted` only where a value must stay inline — and never interpolate such a field raw
- [x] T013 [US1] Add `cmd_bundle` and the `bundle` subparser to `src/ens_evidence/run.py` per [contracts/cli-bundle.md](contracts/cli-bundle.md): `[PATH] [--run DIR] [--json]`, writes `<run>/bundle.md`, exit 0 on success, exit 2 naming what is missing on an unreadable or incomplete run with nothing written

### Tests

- [x] T014 [P] [US1] `tests/test_bundle.py`: renders the stored `tests/fixtures/run/` bundle and asserts the required sections are present — scope list, coverage including languages not analysed, unmapped count, disclaimer
- [x] T015 [P] [US1] `tests/test_bundle.py`: determinism — render twice and assert byte equality (Principle I)
- [x] T016 [P] [US1] `tests/test_bundle.py`: exit 2 and no file written for a missing run directory, a missing `findings.jsonl`, and a missing `run.json`; and assert no absolute host path appears in the rendered output
- [x] T017 [US1] `tests/test_injection.py`: for every line of `injection-strings.txt`, assert it appears in the rendered bundle only inside a `FENCE_OPEN`…`FENCE_CLOSE` block headed by `FENCE_HEADER`, and zero times outside one
- [x] T018 [US1] `tests/test_injection.py`: assert the fence cannot be closed early — an injected ` ``` ` is defanged — and that the control-character case is truncated and fenced like any other value
- [x] T019 [US1] `tests/test_injection.py`: assert the same guarantee holds for the **report** rendered from the injection run, not only the bundle, so the two documents cannot diverge on the security property

---

## Phase 4: User Story 2 — the tool scans itself in CI and publishes the result (P2)

**Goal**: `rules fetch|status` exist, and the self-scan workflow uses them to produce a
downloadable run artifact that provably contains no rule file.

**Independent test**: the licence gate exits 2 with nothing fetched; a workflow run on a branch
uploads `out/latest/` and the pre-upload guard fails when pointed at a directory containing a
rule file.

- [ ] T020 [US2] Add the licence-acknowledgement gate to `src/ens_evidence/run.py`: a module constant summarising the Semgrep Rules License v1.0 terms **in our own words** plus the upstream licence URL (never the licence text verbatim), printed on stderr with exit 2 when neither `--accept-rules-license` nor `ENS_EVIDENCE_ACCEPT_RULES_LICENSE=1` is present
- [ ] T021 [US2] Implement `cmd_rules_fetch` in `src/ens_evidence/run.py` per [contracts/cli-rules.md](contracts/cli-rules.md): `git init` → `git remote add origin <repo>` → `git fetch --depth 1 origin <sha>` → `git checkout FETCH_HEAD` as subprocesses into `--rules-root` (default `.ens-rules`), exit 2 with a naming message when `git` is absent, the SHA is not found, or the destination exists and is not a git work tree
- [ ] T022 [US2] Implement `cmd_rules_status` printing the existing `rules_info(cfg)` payload as one `{"schema": "ens-evidence/1", …}` line, exit 0 in both `local` and `registry` mode, stating in registry mode that the configuration is not reproducible
- [ ] T023 [US2] Add the `rules` subparser group (`fetch`, `status`) with `--sha`, `--repo`, `--rules-root`, `--accept-rules-license` to `build_parser` in `src/ens_evidence/run.py`
- [ ] T024 [P] [US2] `tests/test_rules.py`: the gate — `rules fetch` without acknowledgement exits 2, prints the terms, and creates nothing on disk (no network, runs under `-m "not engines"`)
- [ ] T025 [P] [US2] `tests/test_rules.py`: `rules status` in registry mode reports `mode: registry`, `sha: null`, and the non-reproducibility note; in local mode, against a temporary git work tree with two fake language directories, reports the SHA and the per-language counts
- [ ] T026 [P] [US2] `tests/test_rules.py`: mark the real network fetch test `@pytest.mark.engines` so the default job stays offline, asserting a pinned SHA checkout and that `rules_info` then reports it
- [ ] T027 [US2] Replace the stub in `.github/workflows/scan.yml`: trigger on push to `main` and `workflow_dispatch`, install pinned Semgrep and Trivy, `pip install .`, `rules fetch --sha "$(cat .github/semgrep-rules.sha)" --accept-rules-license`, `scan . --fail-on high`, `report` and `bundle`, then upload
- [ ] T028 [US2] Add the pre-upload licence guard step to `.github/workflows/scan.yml`: fail the job if the upload path contains any file under a `.ens-rules` path or any rule file copied from the rules root, and upload `out/latest/` by explicit path only — never the repository root
- [ ] T029 [US2] Make the guard's failure mode observable: document in the workflow how to verify it fires (point it at a directory that does contain a rule file) so a guard that scans nothing cannot pass forever
- [ ] T030 [US2] Ensure the self-scan reports rather than gates unrelated work: the job surfaces findings and the exit code, and never runs `baseline update` (which would silently accept the repository's own findings)

---

## Phase 5: User Story 3 — bumping the rules cannot silently lose mapping coverage (P3)

**Goal**: a rules-SHA bump that would leave findings unmapped fails CI, naming the ids.

**Independent test**: `scripts/unmapped_ids.py tests/fixtures/run/findings.jsonl` exits 1 naming
`mysteryengine:SOME-RULE-1`; a pull request touching only the pin file runs the job, one that
does not touch it does not.

- [ ] T031 [US3] Write `scripts/unmapped_ids.py` (stdlib only): reads one or more `findings.jsonl` paths, applies `mapper.classify` against `src/ens_evidence/mapping/ens_rd311.yml`, prints each `tool:rule` whose measures are `["unmapped"]` sorted and de-duplicated, exit 1 if any and 0 if none
- [ ] T032 [P] [US3] `tests/test_unmapped_ids.py`: exit 1 and the expected id list on `tests/fixtures/run/findings.jsonl` (which carries exactly one unmapped row by construction), and exit 0 on a findings file with none — the negative case is what proves the check is not scanning nothing
- [ ] T033 [US3] Add a `rules-bump` job to `.github/workflows/ci.yaml` triggered when `.github/semgrep-rules.sha` changes in a pull request: fetch rules at the new SHA, scan the committed fixture corpus (`tests/fixtures/vulnerable-app`, `tests/fixtures/injection-app`) from throwaway work trees, and run `scripts/unmapped_ids.py` over each run's `findings.jsonl`
- [ ] T034 [US3] Handle the local-rules id shape in that job: a local rules root yields path-derived rule ids (`DESIGN.md:179`), so assert the job's unmapped output is reported in the same id shape the mapping's language catch-alls match, and fail with the raw ids listed when it is not
- [ ] T035 [US3] Document in the job's own comments that a bump which *removes* upstream ids is not a failure (stale mapping entries), only new unmapped ids are

---

## Phase 6: User Story 4 — a stranger can read a real report before installing (P4)

**Goal**: a committed sample report and a tagged release, neither containing a rule file.

**Independent test**: the sample opens as a real rendered report with no host path and no verdict
language; a clean-venv install from the tag runs the console command.

- [ ] T036 [US4] Generate the sample: `ens-evidence scan .` then `ens-evidence report . --format pdf --pdf-engine weasyprint`, and commit the result as `samples/informe-ejemplo.pdf`
- [ ] T037 [US4] Read the generated PDF before committing it and confirm: no absolute path from the generating machine, coverage table present, no sentence that reads as a compliance verdict — the defects of this class in 002 were found only by reading the render
- [ ] T038 [US4] Update `samples/README.md` to state which run produced the sample, on what date, and that it was rendered with `--pdf-engine weasyprint`
- [ ] T039 [US4] Verify the release assets carry no rule file and that a non-editable install into a clean 3.12 venv exposes the `ens-evidence` console command from a directory containing no copy of this repository
- [ ] T040 [US4] Tag the release once phases 3–5 are green, with release notes naming the verbs that ship and the six measures in scope by reference, not by restating the list

---

## Phase 7: Polish & cross-cutting

- [x] T041 [P] Update `SKILL.md` (FR-013): `bundle` and the `rules` group now exist — remove the "not implemented" marker on `bundle`, document the real `rules fetch|status` surface, and keep the status banner accurate
- [x] T042 [P] Update `README.md` Uso and English summary to the shipped five-verb + `rules` surface, replacing the manual-clone instructions with `rules fetch`
- [x] T043 [P] Update `AGENTS.md` where it describes obtaining rules, so it names the verb rather than a manual clone
- [ ] T044 Update `tests/test_packaging.py` to assert `bundle.md.j2` is present in an installed copy, alongside the existing template and mapping assertions
- [ ] T045 Run the full quickstart in [quickstart.md](quickstart.md) end to end and record any divergence between it and the shipped behaviour, fixing the code or the document
- [ ] T046 Reconcile the working plan and write the session session notes once 003 is merged

---

## Dependencies

- Phase 1 → Phase 2 → Phases 3–6. Phase 7 last.
- **US1 (Phase 3)** depends only on T004/T005. It is the MVP and ships alone.
- **US2 (Phase 4)** depends on US1 for the `bundle` step in the workflow (T027); the `rules`
  verbs themselves (T020–T026) are independent and can be built in parallel with US1.
- **US3 (Phase 5)** depends on the `rules` verbs (T021) for the bump job's fetch; T031/T032 are
  independent of everything.
- **US4 (Phase 6)** depends on US1–US3 being green — a release that predates them advertises
  behaviour that is not yet proven.
- T041–T043 must land in the same change as the verbs they document (FR-013), not later.

## Parallel opportunities

- T002, T003 in Phase 1.
- Fixture authoring (T006–T008) in parallel with template work (T011–T012); they meet at T009.
- Bundle tests T014–T016 in parallel with each other.
- `rules` verb tests T024–T026 in parallel; the whole `rules` group in parallel with US1.
- T031/T032 (the unmapped script and its tests) in parallel with anything.
- Doc updates T041–T043 in parallel.

## Implementation strategy

**MVP = Phase 1 + 2 + 3.** That is the fifth finding-path verb plus the injection proof — the
security-relevant half of the feature, shippable and testable on its own with no CI change.

Then US2 (credibility artifact), US3 (drift gate), US4 (release). Stop after any story and the
repository is in a coherent state: no story leaves a half-wired workflow behind, because each
CI change lands with its own guard and its own way of proving the guard fires.
