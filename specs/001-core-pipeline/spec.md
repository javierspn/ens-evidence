# Feature Specification: Core Pipeline

**Feature Branch**: `001-core-pipeline`

**Created**: 2026-07-25

**Status**: Implemented

**Input**: User description: "001-core-pipeline: core scan pipeline. Requirements from the working plan: (1) canonicalise rule ids; (2) split security from non-security findings on the engines' `security` tag; (3) hermetic engine invocation; (4) dedupe on (normalised path, defect class), never rule id; (5) coverage table in every report; (6) sort findings before writing JSONL."

> The why lives in [DESIGN.md](../../DESIGN.md); the non-negotiables in
> [constitution.md](../../.specify/memory/constitution.md); the evidence behind every
> requirement below in [docs/scan-baseline.md](../../docs/scan-baseline.md). This spec
> owns: CLI contract, run store, engines → SARIF → JSONL → baseline. Mapping semantics
> and report rendering are spec 002; bundle and CI are spec 003.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Deterministic scan of a repository (Priority: P1)

An operator points the tool at a repository (locally or in CI). The tool runs both
engines hermetically, merges their output into one normalised finding list, and stores
it in a new immutable run directory. Running the same scan twice on the same input
produces byte-identical findings output.

**Why this priority**: This is the product. Every other verb consumes what `scan`
produces, and Principle I (Deterministic) is only testable once this exists.

**Independent Test**: Scan the vulnerable fixture repo twice with `--force`; diff the
two `findings.jsonl` files — they must be byte-identical. Disable network access and
scan again — same result.

**Acceptance Scenarios**:

1. **Given** the vulnerable fixture repo, **When** `scan` runs twice with `--force`,
   **Then** the two `findings.jsonl` files are byte-identical.
2. **Given** a machine with no network access and pinned local rules, **When** `scan`
   runs, **Then** it completes with the same findings as an online run — no engine
   reaches the network on the finding path.
3. **Given** an engine binary missing from PATH, **When** `scan` runs, **Then** it
   exits 2 with a message naming the missing binary.
4. **Given** the same repo scanned from two different checkouts (different absolute
   paths, or local-pinned rules vs registry mode), **When** the outputs are compared,
   **Then** rule ids and file paths in the findings are identical — no
   machine-specific key appears anywhere.

---

### User Story 2 - Baseline gating in CI (Priority: P2)

An operator accepts the current findings as a reviewed baseline. From then on, scans
report and gate only on findings that are new since that baseline, so CI fails on
regressions without re-litigating known, accepted findings.

**Why this priority**: The exit-code gate is what makes the tool usable in CI at all,
but it needs a correct finding list (Story 1) to gate on.

**Independent Test**: Scan a fixture, run `baseline update`, re-scan (exit 0), add one
new high-severity defect to the fixture, re-scan with `--fail-on high` (exit 1).

**Acceptance Scenarios**:

1. **Given** a fixture with accepted baseline, **When** `scan --fail-on high` runs and
   nothing changed, **Then** exit code is 0.
2. **Given** the same fixture with one new high finding introduced, **When**
   `scan --fail-on high` runs, **Then** exit code is 1 and only the new finding is
   reported as new.
3. **Given** a finding whose file gains one added import line above it, **When** the
   repo is re-scanned, **Then** the finding still matches its baseline fingerprint
   (fingerprints never depend on file+line).
4. **Given** any scan, **When** the baseline would change, **Then** it changes only via
   an explicit `baseline update` — never implicitly during `scan`.

---

### User Story 3 - Auditable run record (Priority: P3)

Each run lands in an append-only run store with a machine-readable run record: every
version of every moving part (engine versions, vulnerability DB and checks-bundle
versions, rules mode + SHA, mapping version + hash, baseline hash, config hash) plus
per-run coverage data — which languages were detected, how many rules ran per
language, which languages were not analysed, and whether dependency analysis was
skipped for lack of a lockfile.

**Why this priority**: Principle IV — a clean output on a C or Swift codebase must
read "nothing ran", not "nothing found". The run record is also what makes past
evidence reproducible without re-scanning (drift discipline, constitution 1.4.0).

**Independent Test**: Scan any fixture; assert the run directory contains a run record
with all listed fields non-empty, and coverage data consistent with the fixture's
languages. Re-run with an unchanged skip key; assert the run is skipped with exit 0
and no new run directory.

**Acceptance Scenarios**:

1. **Given** a completed scan, **When** the run record is inspected, **Then** it
   contains engine versions, vulnerability DB and checks-bundle versions, rules
   mode/URL/SHA and per-language rule counts, mapping version + hash, baseline hash,
   and config hash.
2. **Given** a fixture in a language the rule set barely covers, **When** it is
   scanned, **Then** the coverage data states that language as detected-but-not-
   analysed (or the rule count that ran), rather than the run passing silently.
3. **Given** a repo with no lockfile, **When** it is scanned, **Then** coverage data
   records that dependency analysis was skipped and why.
4. **Given** an unchanged skip key (same source SHA, engine versions, DB versions,
   rules pin, mapping, baseline, config), **When** `scan` runs again, **Then** the
   whole run is skipped with exit 0; a change in any one component makes the next
   scan a real scan.
5. **Given** any re-run, **When** it completes, **Then** no existing run directory was
   modified or partially reused — runs are all-or-nothing and append-only.

---

### Edge Cases

- Engine emits a finding with an empty or missing `security` tag list → the finding
  stays in the JSONL, marked non-security; it must never count toward a measure.
- Engine reports the same defect under two different rule ids, or under path bases
  from different machines (`%SRCROOT%` vs `ROOTPATH` style) → one deduplicated
  finding per (normalised path, defect class).
- Local pinned rules produce path-derived rule ids (rules-root prefix baked in) →
  canonicalisation strips the prefix before anything downstream sees the id.
- Repository with zero findings → valid empty findings file, full run record and
  coverage data still written (an empty scan is evidence too, per Principle IV).
- Engine output arrives in a different order between runs → output order is
  irrelevant: findings are sorted by a total, content-derived order before writing.
- Network unavailable mid-scan → no effect on the finding path; only the explicit
  rules-fetch bootstrap (out of scope here) touches the network.
- Scan interrupted mid-run → no partial run directory is left presentable as a
  completed run.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The tool MUST provide the `scan` verb: run both v1 engines as external
  subprocesses against a target path, producing one normalised finding list per run.
  A missing engine binary exits 2 with a message naming it.
- **FR-002**: Engine invocation MUST be hermetic: dependency scanning runs in offline
  mode, rules come from a pinned local root or an explicitly-flagged registry config,
  and no network access occurs on the finding path. The vulnerability DB version and
  misconfiguration checks-bundle version — absent from engine output — MUST be read
  from the engine's cache metadata and recorded in the run record.
- **FR-003**: Rule ids MUST be canonicalised before deduplication, mapping, or
  storage: the rules-root path prefix of locally-pinned rules is stripped so the same
  rule yields the same id in registry mode, local mode, and on any machine.
- **FR-004**: Findings MUST be split into security and non-security on the engines'
  own `security` tag — never on rule-id namespace. Non-security and untagged findings
  stay in the findings file, marked as such, and MUST be excluded from measure
  counting downstream.
- **FR-005**: Findings MUST be deduplicated on (normalised file path, defect class),
  never on rule id. Path normalisation MUST unify engine-specific path bases so the
  same file compares equal across engines and machines.
- **FR-006**: Severity MUST be normalised from each engine's scale to the canonical
  scale via the severity data file; a severity the file's tables do not cover resolves
  to the file's own declared `default` (a reviewable data decision, never a silent
  in-code fallback), and is a hard error only when the file declares no default.
- **FR-007**: Each finding MUST carry a stable fingerprint derived from rule id,
  normalised snippet, and position relative to the enclosing function — never from
  file+line — so unrelated edits do not invalidate the baseline.
- **FR-008**: Findings MUST be sorted by a total, content-derived order before the
  findings file is written; determinism MUST NOT depend on engine output order.
- **FR-009**: The tool MUST provide `baseline update` as the only way to accept
  findings. `scan` gates on new-since-baseline findings only: exit 0 when no new
  finding at/above the `--fail-on` level, 1 when there is one, 2 on tool error.
- **FR-010**: Each run MUST land in a new immutable run-store directory (date + source
  short-SHA, with a `latest` pointer) containing the findings file and the run
  record. Re-runs never overwrite; partial engine-output reuse is forbidden. An
  unchanged skip key (source SHA + engine versions + DB/checks-bundle versions +
  rules mode/SHA + mapping hash + baseline hash + config hash) skips the whole run
  with exit 0; `--force` re-runs and must reproduce byte-identical findings.
- **FR-011**: Each run MUST record coverage data: languages detected, rules run per
  language, languages detected but not analysed, and whether dependency analysis was
  skipped for lack of a lockfile — the data behind the report's coverage table
  (rendered in spec 002).
- **FR-012**: Configuration MUST resolve flags → environment variables → repo config
  file → defaults, with nothing interactive. Machine output goes to stdout carrying
  the schema marker; human chatter goes to stderr.

### Key Entities

- **Finding**: one normalised defect — canonical rule id, engine, severity
  (canonical), security flag, normalised path, defect class, message, snippet,
  fingerprint. One per line in the findings file.
- **Run record**: the per-run manifest of every moving part's version plus coverage
  data; the reproducibility contract of the run store.
- **Baseline**: the set of accepted finding fingerprints; the reference point for
  "new".
- **Skip key**: the tuple of input versions whose identity means a scan can be
  skipped entirely.
- **Coverage record**: per-run languages detected / rules run / not analysed /
  dependency-analysis status.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Two forced scans of the same fixture produce byte-identical findings
  files, including with engine output order artificially shuffled between runs.
- **SC-002**: A scan of the fixture repo completes green in a bare Ubuntu CI runner
  from a three-line workflow.
- **SC-003**: With one new high-severity defect added to a baselined fixture,
  `--fail-on high` exits 1 and reports exactly that one finding as new; after
  `baseline update`, the next scan exits 0.
- **SC-004**: A scan with all network access disabled produces the same findings file
  as an online scan of the same input.
- **SC-005**: Zero machine-specific rule ids or paths appear in any output: the known
  corpus duplicates (one defect flagged under two unrelated rule ids across six
  identical files) collapse to one finding per (path, defect class).
- **SC-006**: Every run directory contains a run record with all version fields
  populated and coverage data matching the fixture's language mix; a repo with no
  lockfile yields an explicit "dependency analysis skipped" coverage entry.
- **SC-007**: One added import line above an accepted finding does not surface it as
  new on the next scan.

## Assumptions

- Engine binaries are pinned by the operator in their CI image (constitution: engines
  are subprocesses); this spec does not install engines.
- The `rules fetch` bootstrap group is specified by DESIGN.md's Rule sourcing section
  and is out of scope here except as an input (rules root + SHA consumed by `scan`).
- Rendering (Spanish report, coverage table presentation, top-10 triage) is spec 002;
  this spec only guarantees the data exists per run. Mapping semantics are spec 002;
  this spec guarantees canonical ids and the security split that the mapper consumes.
- Bundle output, self-scan workflow and packaging are spec 003. Additional engines
  are spec 004 and must not require interface changes here (SARIF is the seam).
- The scope list (six measures) is bound by Principle III and is deliberately not
  restated here.
