# Research — 002 Mapping and Report

Phase 0. No open NEEDS CLARIFICATION: the stack is constitution-fixed, and the mapping
table, severity policy and contract fixture were authored 2026-07-25 from real scans.
What follows is the set of decisions the plan rests on, plus the two facts measured from
spec 001's real output that changed them.

## R1 — Match semantics: `re.search`, not `fullmatch`

**Decision**: `mapper.measures_for` uses `re.search` over the string `<tool>:<rule-id>`,
walking `rules` in file order and returning the first hit; no match → the file's
`default`. Patterns are compiled once at load.

**Rationale**: `tests/test_mapping_contract.py` already ships a reference implementation
described as *"mirroring what mapper.py must implement"*, and it uses `re.search`. The
table is written for that semantics: `trivy:KSV-0013$` and `trivy:KSV-0125$` carry `$`
anchors precisely because matching is otherwise unanchored, and they must beat the
generic `trivy:KSV-.*` that follows them. The leading `<tool>:` in every pattern anchors
the left side in practice, since no key contains another engine's prefix.

**Verified, not assumed**: across all 82 rule ids known to the repo (66 contract cases +
probes, plus the 28 ids in the real fixture run), `search` and `fullmatch` return
identical results — 0 divergences. So the choice is currently unobservable in behaviour
and is made to match the contract, not to change outcomes.

**Deliberate inconsistency worth preserving**: `src/ens_evidence/mapping/defect_classes.yml` (spec 001)
is matched with `fullmatch`, because its patterns are written as whole-key patterns.
Harmonising the two would silently change one file's meaning. Each loader states its
own semantics.

**Alternatives**: fullmatch everywhere — would require rewriting the `$`-anchored rules
and re-verifying the whole table against the corpus for no behavioural gain.

## R2 — Measure titles: a new data file, in our own words

**Decision**: `src/ens_evidence/mapping/measures_es.yml` maps each in-scope measure id to a short Spanish
title and a one-line gloss, both **our own wording**. The report renders id + title;
the file carries the BOE verification date in its header.

**Rationale**: an auditor-facing Spanish document that lists only `mp.sw.1` is poor
evidence, but Principle V forbids bulk-copying CCN-STIC or BOE text. Our own wording,
in a versioned data file, is the only way to satisfy both — and keeping it as data (not
template literals) makes it diffable and reviewable, which is what "our own wording"
needs to be auditable. The pre-release gate already treats measure titles as a concept
verified against Anexo II (constitution, Development Workflow).

**Alternatives**: bare ids — rejected as poor evidence; titles inline in the template —
makes Principle V compliance unreviewable and couples wording to layout.

## R3 — PDF via external binary

**Decision**: Markdown is the source of truth and always written. PDF is produced by an
external binary (`pandoc`) invoked as a subprocess. Requested explicitly (`--format pdf`)
with the binary missing → exit 2 naming it, exactly like an engine. In the default
(auto) mode, a missing binary writes the Markdown, notes the omission on stderr and in
the run's report metadata, and exits 0.

**Rationale**: the constitution pins the stack at stdlib + PyYAML + Jinja2; a Python PDF
library is framework-sized. The engines already establish the subprocess seam for exactly
this reason (users pin versions in their CI image, our dependency tree stays tiny). The
asymmetry with engines — degrade instead of failing — is justified because the evidence
document already exists in full at that point; only a presentation format is missing.
Staleness is reported, never inferred, so the omission is disclosed rather than silent.

**Amended 2026-07-26, after running quickstart §8**: there is a third state the original
decision missed. The converter can be *installed and still unable* — pandoc delegates to a
separate PDF engine and only discovers its absence mid-conversion. `auto` degrades for
that case too (a complete evidence document is not withheld over a presentation format),
while an explicit `--format pdf` still fails with the converter's own reason. The engine
is named by `--pdf-engine`/`ENS_EVIDENCE_PDF_ENGINE` and never auto-detected: detection
would pick a different engine per machine and silently change the PDF's appearance.

**Alternatives**: weasyprint/reportlab as a dependency (excluded by the stack line);
failing hard in auto mode (punishes a complete report for a missing converter);
degrading silently (violates "never let staleness be silent"); auto-detecting an engine
(machine-dependent output).

## R4 — Binding the scope list to the template

**Decision**: the template carries the canonical scope list as literal text, so
`SCOPE_DOCS` in `tests/test_mapping_contract.py` gains `src/ens_evidence/templates/report.md.j2` as its
fourth entry with the same verbatim-count assertion. A **second**, separate test asserts
the *rendered* report also contains the line — because a template can carry the text and
still fail to emit it (inside a conditional block, or escaped).

**Rationale**: Principle III binds four locations; three are checked by literal file
content today, and the template joins them the same way. But the constitution's intent is
that the *report header* carries it, and only the rendered output proves that.

**Alternatives**: injecting the list from the constitution at render time — the template
file itself would then not contain the line, breaking the uniform four-file check and
making the binding invisible to a reader of the template.

## R5 — Triage ranking

**Decision**: order by (severity index, accepted-before-new inverted → new first,
then `file`, `class`, `rule`, `fingerprint`); take the first ten. Fewer than ten
findings → take all, never pad.

**Rationale**: severity is the reader's primary question; newness breaks ties because a
regression deserves attention over an accepted finding of equal severity (FR-008); the
remaining keys are the same total order 001 sorts by, so ties are broken deterministically
rather than by dictionary iteration. The real fixture mix (3 high / 11 medium / 14 low)
means the cut lands inside the medium band, so tie-breaking is exercised, not theoretical.

**Alternatives**: severity alone — leaves an 11-way tie at the cut line resolved by input
order, which is exactly the non-determinism Principle I forbids.

## R6 — Untrusted-input fencing

**Decision**: every string originating in the scanned repository (engine `msg`, `snippet`)
passes through one helper that truncates to 200 characters (ellipsis marked) and emits it
inside a delimited block headed as untrusted input, not instructions. The renderer has no
other path for that text, and a test asserts no raw scanned-repo string appears outside a
fence.

**Rationale**: the report and (spec 003) `bundle.md` are pasted into chat windows by
design; scanned code is prompt-injection surface. The measured maximum engine message in
the real run is **734 characters**, so truncation is load-bearing rather than theoretical.
One helper rather than per-field handling means a new field cannot silently bypass it.

**Alternatives**: escaping only — does not address instruction-shaped prose, which is the
actual threat; truncating at render sites individually — the next added field forgets.

## R7 — Proving the absence of a verdict

**Decision**: a test scans the rendered Spanish text for a forbidden-phrase list
(compliance/conformity assertions, pass/approved wording) and fails on any hit. Per-measure
sections with no findings render an explicit "no evidence gathered" line rather than an
empty section.

**Rationale**: Principle II is the tool's reason to exist, and the fixture makes it
testable: `mp.s.2` receives **zero** findings from the real run, so the report necessarily
renders a measure with nothing under it. An empty section reads as a pass to a human;
saying so explicitly is the whole point of "evidence, not verdict".

**Alternatives**: reviewing the wording by hand — not a gate, and it drifts the first time
the template is edited.

## R8 — The accounting invariant

**Decision**: a test reconciles the rendered report against the findings file: every
finding appears exactly once across measure sections, the unmapped appendix, and the
non-security exclusion — no finding lost, none double-counted.

**Rationale**: this is the property that makes the document evidence rather than a
summary. It also catches the two most likely renderer bugs at once (a filter that drops
rows, a multi-measure finding counted twice per measure without being reconciled).

## R9 — A committed fixture run

**Decision**: commit a small stored run (`findings.jsonl` + `run.json`) under
`tests/fixtures/run/`, derived from the real vulnerable-app scan, and render tests from
it. It must include a non-security finding and an unmapped (unknown-engine) finding,
neither of which the real fixture produces.

**Rationale**: rendering tests must run engine-free in CI (the 001 gate runs
`-m "not engines"`). The real run maps 100% of findings and contains zero non-security
ones, so the two exclusion paths in the accounting invariant would otherwise ship
untested. Those two rows are constructed and labelled as such — the rest is real output.

**Alternatives**: scanning inside the test (reintroduces the engine dependency);
fabricating the whole fixture (violates the constitution's "written from real output").

## R10 — Deterministic rendering

**Decision**: the renderer reads only the stored run; no clock, no environment, no engine.
Jinja2 configured with `keep_trailing_newline` and explicit sorted iteration over every
mapping/dict. Report metadata (mapping version, template identity) comes from the data
files, and the render is byte-comparable.

**Rationale**: Principle I applies to the report as much as to the JSONL — DESIGN.md's
"mapping edits change reports with zero code changes" only stays auditable if two renders
of one run are otherwise identical.
