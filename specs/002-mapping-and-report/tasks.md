# Tasks: Mapping and Report

**Input**: Design documents from `/specs/002-mapping-and-report/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/](contracts/)

**Tests**: included — Principle II ("evidence, never verdict") and Principle III (one
scope list) are only real if a gate enforces them; every one of 002's tests runs
engine-free from the committed fixture run.

**Organization**: grouped by user story; each story independently testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable (different files, no incomplete-task dependency)
- **[Story]**: US1 Spanish report · US2 top-10 triage · US3 unmapped appendix · US4 `explain`

## Phase 1: Setup

**Purpose**: the data file, the dependency and the engine-free fixture every story reads

- [X] T001 Add `Jinja2>=3.1` to `requirements-dev.txt` (first use in the repo; the CI test job installs from this file)
- [X] T002 [P] Create `src/ens_evidence/mapping/measures_es.yml` per data-model.md: `version`, `verified` (BOE check date 2026-07-25), and for each in-scope measure plus `unmapped` a `title` + `gloss` in **our own Spanish wording** — never BOE or CCN-STIC text (Principle V)
- [X] T003 Build the committed fixture run at `tests/fixtures/run/`: copy `findings.jsonl` + `run.json` from a real vulnerable-app scan, then append exactly two constructed rows — one `security: false` finding and one unknown-*engine* finding (`mysteryengine:SOME-RULE-1`) — each labelled as constructed in the fixture's README, because the real run produces neither (research.md R9)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: mapping lookup and the untrusted-input helper — every story needs both

**⚠️ CRITICAL**: no user story work before this phase completes

- [X] T004 [P] Tests for the mapper in `tests/test_mapper.py`: first-match-wins ordering, `re.search` semantics matching the contract test's reference implementation, `$`-anchored rules (`trivy:KSV-0013`) beating the later generic `trivy:KSV-.*`, no match → the file's declared default, patterns compiled once (research.md R1)
- [X] T005 Implement `load_rules` and `measures_for` in `src/ens_evidence/mapper.py`: compile patterns at load, walk in file order, return the first hit's measures or the file's default — zero mapping knowledge in the code (FR-001, FR-002)
- [X] T006 [P] Implement the untrusted-input helper in `src/ens_evidence/render.py` plus its unit tests: truncate scanned-repo text to `SNIPPET_MAX_CHARS` with the truncation marked, wrap in a delimited block headed as untrusted input; it is the only path such text may take into a document (FR-009, research.md R6)
- [X] T007 [P] Implement `counts_toward_measures` in `src/ens_evidence/mapper.py` per data-model.md: a finding counts only when the engines tagged it `security` **and** a rule matched it (FR-003)

**Checkpoint**: findings can be mapped and scanned-repo text can be safely rendered

---

## Phase 3: User Story 1 - Spanish evidence report (Priority: P1) 🎯 MVP

**Goal**: render a Spanish evidence report from a stored run — scope list verbatim,
coverage table, staleness disclosures, per-measure evidence or its explicit absence, and
nothing that reads as a verdict.

**Independent Test**: quickstart.md §1–§3 — render the committed fixture run, check the
header, the `mp.s.2` empty-measure wording, and byte-identical re-render.

### Tests for User Story 1 (write first, watch them fail)

- [X] T008 [P] [US1] Add `src/ens_evidence/templates/report.md.j2` to `SCOPE_DOCS` in `tests/test_mapping_contract.py` as Principle III's fourth binding site, with the same verbatim-count assertion as the other three (FR-004)
- [X] T009 [P] [US1] Test in `tests/test_render.py` that the **rendered** report carries the canonical scope list verbatim — separate from T008, because a template can hold the line and still not emit it (research.md R4)
- [X] T010 [P] [US1] Test in `tests/test_render.py` for section order and required blocks per contracts/report.md: title/header, what-this-is-not, coverage, staleness, triage, per-measure, full table, unmapped appendix, non-security appendix
- [X] T011 [P] [US1] Test in `tests/test_render.py` that the coverage table renders all four fields from `run.json.coverage`, including the `registry-uncounted` and `skipped-no-lockfile` states (FR-005)
- [X] T012 [P] [US1] Test in `tests/test_render.py` that staleness disclosures render: rules mode + SHA, vulnerability-DB version and date, checks bundle, engine versions, mapping version, measure-list verification date (FR-007)
- [X] T013 [P] [US1] **No-verdict test** in `tests/test_render.py`: scan the rendered Spanish text against a forbidden-phrase list (compliance / conformity / pass / approved wording) and fail on any hit; assert the zero-finding measure renders "no evidence gathered" **and** the sentence saying that is not compliance (FR-006, research.md R7)
- [X] T014 [P] [US1] Determinism test in `tests/test_render.py`: two renders of the committed fixture run produce identical content (FR-013, SC-005)
- [X] T015 [P] [US1] Test in `tests/test_render.py` that `report` renders with the engines absent from PATH — no scan, no engine dependency (SC-008)

### Implementation for User Story 1

- [X] T016 [US1] Author `src/ens_evidence/templates/report.md.j2` per contracts/report.md: Spanish throughout, canonical scope list **literal** in the header, section order fixed, measure sections driven by `src/ens_evidence/mapping/measures_es.yml`, empty measures rendering the explicit no-evidence sentence
- [X] T017 [US1] Implement `render_report` in `src/ens_evidence/render.py`: load the stored run, map every finding, build the report model from data-model.md, render with Jinja2 configured for deterministic output (sorted iteration, `keep_trailing_newline`), no clock and no environment reads (FR-013, research.md R10)
- [X] T018 [US1] Implement the `report` verb in `src/ens_evidence/run.py` per contracts/cli.md: `--run` defaulting to `out/latest`, writes `report.md` inside the run directory, exit 2 on a missing or unreadable run, never exit 1
- [X] T019 [US1] Implement the PDF path in `src/ens_evidence/run.py`/`src/ens_evidence/render.py`: external converter subprocess; `--format pdf` with the binary missing → exit 2 naming it; `--format auto` with it missing → Markdown written, omission noted on stderr **and in the document**, exit 0 (research.md R3, contracts/cli.md)

**Checkpoint**: MVP — a Spanish evidence report an auditor can read, from a stored run

---

## Phase 4: User Story 2 - Top-10 triage (Priority: P2)

**Goal**: the report opens with the ten findings most worth attention, ranked
deterministically.

**Independent Test**: render the fixture run; assert ≤10 entries, documented order,
identical across renders.

### Tests for User Story 2

- [X] T020 [P] [US2] Tests for triage ranking in `tests/test_render.py`: severity first, new-before-accepted at equal severity, remaining ties broken by `(file, class, rule, fingerprint)`; exactly ten when more exist, all of them when fewer, never padded (FR-008, research.md R5)
- [X] T021 [P] [US2] Test in `tests/test_render.py` that triage order is stable across two renders and unaffected by the order findings appear in the JSONL

### Implementation for User Story 2

- [X] T022 [US2] Implement triage selection in `src/ens_evidence/render.py` per research.md R5 and bind it to the triage section of `src/ens_evidence/templates/report.md.j2`

**Checkpoint**: a reader who stops after page one knows where to start

---

## Phase 5: User Story 3 - Unmapped findings surface (Priority: P2)

**Goal**: findings no rule matched reach their own appendix; non-security findings are
present but count toward nothing; every finding is accounted for exactly once.

**Independent Test**: quickstart.md §4–§5 — the accounting reconciliation and the
fall-through probes.

### Tests for User Story 3

- [X] T023 [P] [US3] Test in `tests/test_mapper.py` that the unknown-*engine* shape (`mysteryengine:SOME-RULE-1`) falls through to the default, and that every probe in `tests/mapping-cases.yml`'s `unmapped` block still falls through (FR-001, SC-004)
- [X] T024 [P] [US3] Test in `tests/test_render.py` that unmapped findings render in their own appendix, never under a measure, and are described as awaiting a mapping decision
- [X] T025 [P] [US3] Test in `tests/test_render.py` that a non-security finding appears in the report but contributes to **no** measure count (FR-003)
- [X] T026 [P] [US3] **Accounting invariant test** in `tests/test_render.py`: every finding in the fixture run appears exactly once across measure sections, the unmapped appendix and the non-security appendix — no finding lost, none double-counted (SC-002, research.md R8)

### Implementation for User Story 3

- [X] T027 [US3] Implement the unmapped and non-security appendices in `src/ens_evidence/render.py` + `src/ens_evidence/templates/report.md.j2`, and reconcile the per-measure counts so a finding filed under two measures is counted once in the accounting

**Checkpoint**: the appendix that forces mapping maintenance is real and tested

---

## Phase 6: User Story 4 - `explain` one finding (Priority: P3)

**Goal**: answer why a single finding was filed where it was — the matched pattern, the
measures, and the reasoning.

**Independent Test**: quickstart.md §7 — explain a known id, and an unknown one.

### Tests for User Story 4

- [X] T028 [P] [US4] Tests for `explain` in `tests/test_cli.py`: a known id returns the finding, the matched pattern and the measures; an unmapped finding reports awaiting-mapping rather than an error; an unknown id exits 2 naming it (FR-011, SC-007)
- [X] T029 [P] [US4] Test in `tests/test_cli.py` that `explain --json` emits the explanation object per data-model.md with the schema marker, and that the finding's message is fenced and truncated like everywhere else

### Implementation for User Story 4

- [X] T030 [US4] Implement `matched_rule` reporting in `src/ens_evidence/mapper.py` (return which pattern matched, not only the measures) and the `explain` verb in `src/ens_evidence/run.py` per contracts/cli.md

**Checkpoint**: a disputed classification can be resolved without reading the mapping file

---

## Phase 7: Polish & Cross-Cutting

- [X] T031 Run the full quickstart.md validation (§1–§9) including the optional PDF path; fix what fails
- [X] T032 [P] Reconcile the working plan (drop the three shipped 002 items) and update `specs/002-mapping-and-report/README.md` status line
- [X] T033 [P] Review the rendered `report.md` and `src/ens_evidence/mapping/measures_es.yml` end to end for Spanish wording quality and Principle V compliance — our own words throughout, no copied legal text

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (1)**: none — T003 needs a real scan (engines) or the existing scratch run
- **Foundational (2)**: after Setup — blocks all stories
- **US1 (3)**: after Phase 2 — the MVP; T016 must precede T008's assertion passing
- **US2 (4)**: after US1's template exists (T016), since triage binds into it
- **US3 (5)**: after US1's template exists; T026 reconciles against the rendered document
- **US4 (6)**: after Phase 2 (T030 extends the mapper); independent of the template
- **Polish (7)**: after US1–US4

### Story Dependencies

- US1: independent once Phase 2 lands — the deliverable
- US2, US3: both bind sections into US1's template, so they follow it; their tests are
  written engine-free against the same fixture run
- US4: touches `mapper.py` and `run.py` only — can proceed in parallel with US2/US3

### Parallel Opportunities

- T002 ∥ T003 (Setup); T004 ∥ T006 ∥ T007 (Foundational)
- All test-first blocks within a story: T008–T015 ∥, T020–T021 ∥, T023–T026 ∥, T028–T029 ∥
- US4 (T028–T030) ∥ US2 and US3 once the template exists
- T032 ∥ T033 (Polish)

## Implementation Strategy

MVP = Phase 1 + 2 + US1 → validate quickstart §1–§3 → then US3 (the accounting invariant
is what makes the document evidence) → US2 (readability) → US4 (auditability of the
mapping itself) → Polish. The repo's CI gate (`pytest -m "not engines"`) must stay green
at every checkpoint; all of 002's tests are engine-free by construction.
