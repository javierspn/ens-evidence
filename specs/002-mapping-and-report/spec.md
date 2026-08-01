# Feature Specification: Mapping and Report

**Feature Branch**: `002-mapping-and-report`

**Created**: 2026-07-26

**Status**: Implemented

**Input**: User description: "002-mapping-and-report: mapping semantics, Spanish evidence report, top-10 triage, and the `explain` verb."

> The why lives in [DESIGN.md](../../DESIGN.md); the non-negotiables in
> [constitution.md](../../.specify/memory/constitution.md). The mapping data file
> (`src/ens_evidence/mapping/ens_rd311.yml`) and its contract fixture (`tests/mapping-cases.yml`) already
> exist, authored 2026-07-25 from real scans — this spec covers the **semantics** that
> consume them, never a rewrite of the table. Input is spec 001's output; the six-measure
> scope list is deliberately not restated here (Principle III).

## What the real output says

Written from the actual `findings.jsonl` spec 001 produces for the vulnerable-app
fixture (28 findings), not from imagination — the constitution requires it:

| Fact from the real run | Consequence for this spec |
|---|---|
| All 28 findings map; **zero** land unmapped | The unmapped appendix cannot be tested from this fixture — it needs the unknown-*engine* probe (see US3) |
| `mp.s.2` receives **zero** findings; the other five receive 2–19 | A measure with nothing filed under it must read as "no evidence gathered", never as "compliant" — this is the sharpest Principle II test the tool has |
| All 28 are `security: true` | The non-security exclusion needs a constructed case, not the fixture alone |
| Longest engine message is 734 chars | Truncation is load-bearing, not theoretical |
| Severity mix: 3 high, 11 medium, 14 low | Top-10 triage has real ranking work to do |

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Spanish evidence report an auditor can use (Priority: P1)

An operator who has scanned a repository renders a Spanish evidence report from the
stored run. The report states what was tested, when, with which engine and rule
versions, what was found, and — explicitly — what the scan could not see. It never
states that the organisation complies.

**Why this priority**: This is the deliverable the whole tool exists to produce. Every
other story in this spec supports it.

**Independent Test**: Render from the fixture's stored run; assert the header carries
the canonical scope list verbatim, the coverage table matches `run.json`, the
disclaimer is present, and no sentence asserts compliance.

**Acceptance Scenarios**:

1. **Given** a stored run, **When** the report is rendered, **Then** its header carries
   the canonical six-measure scope list **verbatim**, identical to the constitution,
   the README and the mapping file (Principle III's fourth binding site).
2. **Given** a stored run, **When** the report is rendered, **Then** it carries a
   coverage table stating languages detected, rules run per language, languages not
   analysed, and whether dependency analysis was skipped for lack of a lockfile.
3. **Given** a measure with zero findings (the fixture's `mp.s.2`), **When** the report
   is rendered, **Then** that measure is listed as having no evidence gathered, with no
   wording that could be read as a pass, a clean bill, or compliance.
4. **Given** a run whose rules came from the versionless registry, **When** the report
   is rendered, **Then** the coverage table states the ruleset is non-reproducible
   rather than reporting a rule count it cannot know.
5. **Given** any report, **When** its full text is searched, **Then** it contains the
   staleness disclosures (rules SHA/mode, vulnerability-DB version and date, measure-list
   verification date) and the "static analysis is not an audit" disclaimer.

---

### User Story 2 - Top-10 triage first (Priority: P2)

The report opens with the ten findings most worth a human's attention, ranked, before
the full table. A reader who stops after one page still knows where to start.

**Why this priority**: The report is useless as evidence if the reader has to work
through 28 (or 453) findings to find the three that matter. Ranking is derived, so it
must be deterministic like everything else.

**Independent Test**: Render the fixture report; assert the triage section holds at most
ten findings in a documented, reproducible order, and that re-rendering yields the same
order.

**Acceptance Scenarios**:

1. **Given** a run with more than ten findings, **When** the report is rendered, **Then**
   the triage section holds exactly ten, ordered by severity first.
2. **Given** two renders of the same run, **When** the triage sections are compared,
   **Then** the orders are identical — ties broken deterministically, never by engine
   output order or dictionary iteration.
3. **Given** a run with fewer than ten findings, **When** the report is rendered, **Then**
   the triage section holds all of them and does not pad.
4. **Given** findings already accepted in the baseline, **When** the report is rendered,
   **Then** triage prefers findings new since the baseline over accepted ones at equal
   severity.

---

### User Story 3 - Unmapped findings surface for review (Priority: P2)

Findings whose rule id matches no mapping rule are filed in their own appendix rather
than silently dropped or forced into a measure. The appendix is the mechanism that keeps
mapping maintenance in step with rule drift.

**Why this priority**: The constitution makes the unmapped appendix the forcing function
for the rules-bump loop. Silently dropping an unmatched finding would break that loop and
lose evidence.

**Independent Test**: Map a finding from an unknown *engine* (`mysteryengine:SOME-RULE-1`);
assert it reaches the appendix, with the fixture built from that shape.

**Acceptance Scenarios**:

1. **Given** a finding from an engine the mapping does not know, **When** it is mapped,
   **Then** it lands in the unmapped appendix, never under a measure.
2. **Given** a finding whose rule id matches several mapping rules, **When** it is
   mapped, **Then** the **first** matching rule wins and the later ones are not applied.
3. **Given** a finding marked non-security by the engines' own tag, **When** the report
   is rendered, **Then** it appears in the report but counts toward **no** measure.
4. **Given** any rendered report, **When** the per-measure counts are summed against the
   findings list, **Then** every finding is accounted for exactly once: under its
   measures, in the unmapped appendix, or as non-security.

---

### User Story 4 - `explain` one finding (Priority: P3)

An operator (or an agent) asks why a single finding was filed where it was. The answer
names the finding, the mapping rule that matched it, the measures it produced, and the
reasoning — enough to challenge or defend the classification.

**Why this priority**: Auditability of the mapping itself. Valuable, but the report is
the deliverable; `explain` is how a disputed classification gets resolved.

**Independent Test**: Run `explain` against a known finding id from the fixture run;
assert the output names the matched pattern and the resulting measures.

**Acceptance Scenarios**:

1. **Given** a finding id from the latest run, **When** `explain` is called with it,
   **Then** the output shows the finding, the matching rule pattern, and the measures.
2. **Given** an unmapped finding's id, **When** `explain` is called, **Then** the output
   states that no rule matched and that the finding awaits mapping.
3. **Given** an id that does not exist in the latest run, **When** `explain` is called,
   **Then** it exits with a tool error naming the unknown id, never a silent empty result.

---

### Edge Cases

- A repository with zero findings → the report still renders, with the coverage table
  and disclaimers intact; an empty report is evidence of what ran, not of cleanliness.
- A measure receives findings only from non-security rules → it reads as no evidence
  gathered, exactly as if it had none.
- An engine message or snippet contains text shaped like instructions to an AI agent →
  it is truncated and fenced as untrusted input; it never reaches the reader as a
  directive (the fixture for this is `tests/fixtures/injection-app`, spec 003's
  acceptance, but the fencing must already hold here).
- An engine message contains characters that would break the document format → the
  document still renders correctly and the text is not silently dropped.
- The stored run predates the current mapping file → the report states the mapping
  version it was rendered with, so two reports of the same run are distinguishable.
- More than ten findings share the top severity → the triage cut is deterministic.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The mapper MUST match the string `<tool>:<rule-id>` against the mapping
  file's rules in order, first match wins, and MUST apply the file's declared default
  (the unmapped appendix) when nothing matches.
- **FR-002**: The mapper MUST NOT be the place where mapping knowledge lives: every
  pattern and every measure list comes from the data file, so adding a framework is a new
  data file rather than a code change.
- **FR-003**: Findings flagged non-security by the engines' own tag MUST appear in the
  report but MUST NOT contribute to any measure's evidence count.
- **FR-004**: The report MUST carry the canonical six-measure scope list verbatim in its
  header, and the automated check that binds the other three locations MUST be extended
  to cover the report template as its fourth site.
- **FR-005**: The report MUST carry the per-run coverage table sourced from the stored run
  record: languages detected, rules run per language, languages detected but not
  analysed, and dependency-analysis status.
- **FR-006**: The report MUST state, for every in-scope measure, either the evidence
  gathered or that none was gathered — and MUST NOT contain wording that asserts
  compliance, passing, or conformity for any measure or for the whole.
- **FR-007**: The report MUST disclose the age of every drifting input at scan time:
  rules mode and pin, vulnerability-DB version and date, mapping version, and the
  measure-list verification date.
- **FR-008**: The report MUST open with a triage section of at most ten findings, ranked
  by severity with deterministic tie-breaking, preferring findings new since the
  baseline at equal severity, followed by the full findings table and the unmapped
  appendix.
- **FR-009**: All text originating in the scanned repository (engine messages, code
  snippets) MUST be truncated to roughly 200 characters and presented inside delimited
  blocks marked as untrusted input, never as instructions.
- **FR-010**: The report MUST be written in Spanish, using the project's own wording for
  measure descriptions — never bulk-copied legal or CCN-STIC text.
- **FR-011**: The tool MUST provide `explain <id>`: the finding, the mapping rule that
  matched, the measures produced, and why; an unknown id is a tool error, and an unmapped
  finding is reported as awaiting mapping rather than as an error.
- **FR-012**: The tool MUST provide `report`: re-render from the stored run without
  re-scanning, so a mapping or template fix does not require re-running the engines.
- **FR-013**: Rendering MUST be deterministic: the same stored run and the same mapping
  and template produce the same document content on every render.

### Key Entities

- **Mapping rule**: a pattern over `<tool>:<rule-id>` plus the measures it produces;
  ordered, first match wins.
- **Measure section**: one in-scope measure, its gathered evidence (or explicit absence),
  and the findings filed under it.
- **Triage entry**: a finding selected into the top-ten, with its rank rationale.
- **Unmapped entry**: a finding no rule matched, awaiting a mapping decision.
- **Coverage table**: the run record's coverage data, rendered for the reader.
- **Explanation**: one finding, the rule that matched it, the measures, and the reasoning.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Rendering the fixture's stored run produces a Spanish report whose header
  carries the scope list verbatim; the automated four-location check passes with the
  report template as its fourth site.
- **SC-002**: Every one of the fixture's 28 findings is accounted for exactly once across
  measure sections, the unmapped appendix, and the non-security exclusion — counts
  reconcile with no residue.
- **SC-003**: The measure receiving zero findings in the fixture (`mp.s.2`) is rendered
  as no evidence gathered; a full-text search of the report for compliance assertions
  returns nothing.
- **SC-004**: A finding from an unknown engine reaches the unmapped appendix, and the
  contract fixture's fall-through probes all still fall through.
- **SC-005**: Two renders of the same stored run produce identical document content,
  including triage order.
- **SC-006**: No text originating in the scanned repository exceeds the truncation limit
  or appears outside an untrusted-input block anywhere in the report.
- **SC-007**: `explain` returns the matched pattern and resulting measures for any
  finding id in the latest run, and a tool error for an id that is not.
- **SC-008**: `report` re-renders from a stored run with the engines uninstalled — no
  re-scan, no engine dependency.

## Assumptions

- The mapping data file and its contract fixture already exist and were authored from
  real scanner output on 2026-07-25; this spec consumes and tests them, and does not
  re-derive the table. New rules are added only when a real finding demands one.
- Input is spec 001's stored run (findings file + run record). This spec adds no engine
  invocation and no new scanning.
- PDF generation is a rendering concern layered on the Markdown document; the Markdown
  is the source of truth for every assertion above, so the acceptance criteria hold
  whether or not a PDF is produced in a given environment.
- The unmapped appendix cannot be exercised by the current fixture (all 28 findings map),
  so its test fixture is built from the unknown-*engine* shape recorded in the contract
  file — the only shape ten repositories proved reliable.
- The injection fixture and the bundle output are spec 003; the fencing and truncation
  rules are specified here because the report is where scanned-repo text first reaches a
  reader.
- The six-measure scope list is bound by Principle III and is deliberately not restated
  in this document.
