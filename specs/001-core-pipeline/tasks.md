# Tasks: Core Pipeline

**Input**: Design documents from `/specs/001-core-pipeline/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/](contracts/)

**Tests**: included — the constitution makes determinism an acceptance test, not an
aspiration; normaliser tests run engine-free from captured SARIF fixtures.

**Organization**: grouped by user story; each story independently testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable (different files, no incomplete-task dependency)
- **[Story]**: US1 deterministic scan · US2 baseline gating · US3 auditable run record

## Phase 1: Setup

**Purpose**: fixtures and data files every story consumes

- [X] T001 Capture engine SARIF fixtures: run Semgrep + Trivy per research.md R1 on `tests/fixtures/vulnerable-app/`, commit sanitised output pairs to `tests/fixtures/sarif/` (semgrep.sarif, trivy.sarif) plus an order-shuffled copy of each (same findings, permuted `results` arrays) for the byte-identity test
- [X] T002 [P] Create `mapping/defect_classes.yml` per data-model.md: version field + the two baseline-proven classes (`container-runs-as-root`, `pod-runs-as-root`), first-match-wins regex semantics
- [X] T003 [P] Register the `engines` pytest marker (tests needing real binaries) in the repo's pytest config, so `pytest -m "not engines"` runs everywhere the CI gate does

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: CLI skeleton and shared plumbing every verb sits on

**⚠️ CRITICAL**: no user story work before this phase completes

- [X] T004 Implement config resolution in `src/run.py`: flags → `ENS_EVIDENCE_*` env → `.ens-evidence.yml` → defaults (keys per contracts/cli.md), plus sha256 of the resolved config; nothing interactive
- [X] T005 [P] Implement canonical serialisation helpers in `src/normalise.py`: schema line constant, sorted-keys/compact/ascii `dumps_line()`, JSONL writer per research.md R6
- [X] T006 Implement CLI skeleton in `src/run.py`: argparse for `scan [PATH]` and `baseline update [PATH]` with `--fail-on/--force/--json`, exit-code plumbing (0/1/2), machine JSON → stdout, chatter → stderr
- [X] T007 [P] Unit tests for config resolution precedence and config hash stability in `tests/test_cli.py`

**Checkpoint**: `ens-evidence scan --help` works; foundation ready

---

## Phase 3: User Story 1 - Deterministic scan (Priority: P1) 🎯 MVP

**Goal**: `scan` runs both engines hermetically and writes a sorted, deduplicated,
canonically-identified `findings.jsonl` into a fresh run dir — byte-identical on re-run.

**Independent Test**: quickstart.md §1 — scan the fixture twice with `--force`, `cmp`
the two findings files; repeat offline.

### Tests for User Story 1 (write first, watch them fail)

- [X] T008 [P] [US1] Tests for `canonical_rule_id` in `tests/test_normalise.py`: registry id passes through, dotted rules-root prefix stripped, same canonical id from both modes (FR-003)
- [X] T009 [P] [US1] Tests for the security split in `tests/test_normalise.py`: tagged best-practice rule counts as security, untagged rule stays in JSONL with `security: false` (FR-004, scan-baseline counter-examples)
- [X] T010 [P] [US1] Tests for path normalisation + dedupe in `tests/test_normalise.py`: `%SRCROOT%`/`ROOTPATH` bases unify; `missing-user`+`DS-0002` fixture findings collapse to one per file with `merged_from` populated; unlisted rule ids self-class and never merge (FR-005)
- [X] T011 [P] [US1] Tests for severity normalisation in `tests/test_normalise.py`: engine scales map via `mapping/severity.yml`; unknown severity raises, never defaults (FR-006)
- [X] T012 [P] [US1] Tests for `fingerprint` in `tests/test_normalise.py`: line numbers absent from hash, added-import shift keeps fingerprint, identical snippets in one file get distinct ordinals (FR-007, research.md R5)
- [X] T013 [P] [US1] Byte-identity test in `tests/test_normalise.py`: normalise the shuffled SARIF fixtures → output bytes equal the unshuffled run (FR-008, SC-001)

### Implementation for User Story 1

- [X] T014 [US1] Implement `canonical_rule_id(raw_id, rules_root)` in `src/normalise.py` (research.md R3)
- [X] T015 [US1] Implement SARIF ingestion in `src/normalise.py`: parse both engines' files, extract rule/message/snippet/region/tags, normalise path bases to repo-relative POSIX (research.md R4)
- [X] T016 [US1] Implement the security split on engine tags in `src/normalise.py` (FR-004)
- [X] T017 [US1] Implement severity normalisation from `mapping/severity.yml` in `src/normalise.py`, hard error on unknown scales (FR-006)
- [X] T018 [US1] Implement dedupe on (normalised path, defect class) from `mapping/defect_classes.yml` in `src/normalise.py`: highest-severity representative survives, `merged_from` records the rest (research.md R4)
- [X] T019 [US1] Implement `fingerprint(rule_id, snippet, ordinal)` in `src/normalise.py`: whitespace-collapse, sha256, 16-hex prefix (research.md R5)
- [X] T020 [US1] Implement `normalise()` assembly in `src/normalise.py`: ingest → canonicalise → split → severity → dedupe → fingerprint → sort by `(file, class, rule, fingerprint)` → serialised lines (FR-008)
- [X] T021 [US1] Implement engine invocation in `src/run.py`: research.md R1 command lines via subprocess, missing binary → exit 2 naming it, engine version probes, SBOM run (FR-001, FR-002)
- [X] T022 [US1] Implement run-dir landing in `src/run.py`: temp dir → `out/<date>_<short-sha>/` atomic rename, `latest` symlink swap last, `findings.jsonl` + `sbom.cdx.json` written (FR-010 subset; full run.json is US3)
- [X] T023 [US1] Integration test (marked `engines`) in `tests/test_cli.py`: two `--force` scans of `tests/fixtures/vulnerable-app/` produce byte-identical `findings.jsonl` (quickstart §1)

**Checkpoint**: MVP — deterministic findings file from a real scan

---

## Phase 4: User Story 2 - Baseline gating (Priority: P2)

**Goal**: explicit `baseline update`; `scan --fail-on` exits 1 only on new-since-baseline.

**Independent Test**: quickstart.md §2 — baseline a fixture, add one high finding,
gate flips 0 → 1; import-line shift does not.

### Tests for User Story 2

- [X] T024 [P] [US2] Tests for baseline read/write + `new` marking in `tests/test_normalise.py`: fingerprint ∉ baseline ⇒ `new: true`; missing baseline file ⇒ all new; baseline schema per contracts/artifacts.md (FR-009)
- [X] T025 [P] [US2] Tests for the gate in `tests/test_cli.py`: exit 0 with gate off / nothing new, exit 1 with one new ≥ threshold, threshold comparison across all severity levels (FR-009)

### Implementation for User Story 2

- [X] T026 [US2] Implement baseline loading and `new` flag in `src/normalise.py` + `src/run.py`: read `.ens-baseline.yml`, mark findings, baseline sha256 exposed for the run record (FR-009)
- [X] T027 [US2] Implement `baseline update` verb in `src/run.py`: rewrite `.ens-baseline.yml` (sorted fingerprints, schema, date) from `out/latest/findings.jsonl`; exit 2 when no run exists (contracts/cli.md)
- [X] T028 [US2] Implement `--fail-on` gate in `src/run.py`: severity-threshold check over `new` findings only, exit codes per contracts/cli.md
- [X] T029 [US2] Integration test (marked `engines`) in `tests/test_cli.py`: quickstart §2 sequence — baseline, new high finding → 1, import shift → 0 (SC-003, SC-007)

**Checkpoint**: CI gate usable end to end

---

## Phase 5: User Story 3 - Auditable run record (Priority: P3)

**Goal**: every run's `run.json` records all drifting inputs + coverage; unchanged skip
key skips the run; store stays append-only.

**Independent Test**: quickstart.md §3–4 — inspect `run.json` fields, lockfile-less and
Elixir-file fixtures, immediate re-scan skips.

### Tests for User Story 3

- [X] T030 [P] [US3] Tests for the coverage record in `tests/test_run_store.py`: extension census, rules-per-language from a fake rules root, `registry-uncounted` in registry mode, `skipped-no-lockfile`, detected-but-zero-rules language listed (FR-011)
- [X] T031 [P] [US3] Tests for skip key + immutability in `tests/test_run_store.py`: key equality ⇒ skip exit 0 and no new dir; any component change ⇒ real run; existing run dirs never modified; interrupted run leaves no visible dir (FR-010)
- [X] T032 [P] [US3] Tests for run.json completeness in `tests/test_run_store.py`: every data-model.md field present and non-null (except `baseline_sha256` when absent), counts consistent with findings (SC-006)

### Implementation for User Story 3

- [X] T033 [US3] Implement version collection in `src/run.py`: `trivy version --format json` → DB + checks-bundle versions, semgrep/trivy binary versions, rules mode/URL/SHA/per-language counts from the rules root (FR-002, research.md R2)
- [X] T034 [US3] Implement the coverage record in `src/run.py`: language extension census (data-driven table), rules-per-language, not-analysed list, lockfile detection (FR-011, research.md R8)
- [X] T035 [US3] Implement `run.json` assembly + counts in `src/run.py` per contracts/artifacts.md, written inside the temp dir before the atomic rename (FR-010)
- [X] T036 [US3] Implement the skip key in `src/run.py`: sha256 over the research.md R7 tuple, pre-scan comparison against `out/*/run.json`, skip ⇒ print existing path + exit 0, `--force` bypass (FR-010)

**Checkpoint**: all three stories independently functional

---

## Phase 6: Polish & Cross-Cutting

- [X] T037 Run the full quickstart.md validation (§1–§6) against real engines; fix whatever fails; record engine versions used in the PR description
- [X] T038 [P] Reconcile the working plan (drop the six shipped 001 items) and update `specs/001-core-pipeline/README.md` status line

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (1)**: none — start immediately; T001 needs engine binaries locally
- **Foundational (2)**: after Setup — blocks all stories
- **US1 (3)**: after Phase 2 — the MVP
- **US2 (4)**: after Phase 2; integration test T029 needs US1's scan path
- **US3 (5)**: after Phase 2; T035–T036 touch `src/run.py` after US1's T021–T022 land
- **Polish (6)**: after US1–US3

### Story Dependencies

- US1: independent (MVP)
- US2: testable engine-free on top of Phase 2 + captured fixtures (T024–T028); only T029 consumes US1
- US3: run.json wraps the run dir US1 creates; unit-testable against fakes (T030–T032) before US1 completes

### Parallel Opportunities

- T002 ∥ T003 (Setup); T005 ∥ T007 (Foundational)
- All test-first tasks within a story: T008–T013 ∥, T024–T025 ∥, T030–T032 ∥
- Normaliser implementation (US1 T014–T020, single file — sequential) ∥ nothing; but US2's T024–T025 and US3's T030–T032 can start once Phase 2 lands

## Implementation Strategy

MVP = Phase 1 + 2 + US1 → validate quickstart §1 → then US2 (the gate is what CI buys) →
US3 (the audit record) → Polish. One logical commit per task or tight group; the repo's
CI test gate (`pytest -m "not engines"`) must stay green at every checkpoint.
