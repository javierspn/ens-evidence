# Research — 001 Core Pipeline

Phase 0. No open NEEDS CLARIFICATION: stack and constraints are constitution-fixed, and
every behavioural question was answered empirically by the 21-repo baseline exercise
([docs/scan-baseline.md](../../docs/scan-baseline.md)). This file records the design
decisions the plan builds on.

## R1 — Engine invocation lines

**Decision**:
- Semgrep: `semgrep scan --sarif --metrics=off --config <rules-root|p/...> <path>`
- Trivy findings: `trivy fs --scanners vuln,misconfig,secret --format sarif --offline-scan --skip-db-update --skip-check-update <path>`
- Trivy SBOM: separate `trivy fs --format cyclonedx` run (bypasses the mapper by design)

**Rationale**: `--offline-scan` because Trivy otherwise resolves Maven parent POMs over
the network (observed 429 + ~30 min IP block). `--skip-db-update`/`--skip-check-update`
keep the DB/checks bundle frozen *within* a run; cache priming is the operator's CI-image
concern, not the finding path's. `--metrics=off` kills Semgrep telemetry.

**Alternatives**: letting Trivy auto-update mid-pipeline — rejected, makes the skip key a
lie; wrapping engines as Python imports — constitution-forbidden.

## R2 — Where Trivy DB / checks-bundle versions come from

**Decision**: `trivy version --format json` → `VulnerabilityDB.Version/UpdatedAt` and
`PolicyBundle` fields, read after the scan, recorded in `run.json`.

**Rationale**: the versions are absent from SARIF (baseline finding); the version command
reads local cache metadata, no network. **Alternatives**: parsing
`~/.cache/trivy/db/metadata.json` directly — rejected, cache layout is not a stable
interface; the version command is.

## R3 — Canonical rule ids

**Decision**: `canonical_rule_id(raw_id, rules_root)` string-strips the dotted form of the
configured rules root when it prefixes the raw id; registry ids pass through unchanged.
Canonicalisation happens once, at SARIF ingestion, before dedupe/split/fingerprint.

**Rationale**: local runs emit `<rules-root-as-dots>.c.lang.security.double-free`; the
mapping keys on `tool:rule-id`, so unstripped ids are machine-specific and unmappable.
**Alternatives**: suffix-matching in the mapper — rejected, pushes a normalisation bug
into every downstream consumer and makes the unmapped appendix non-reproducible.

## R4 — Dedupe key: (normalised path, defect class)

**Decision**: normalise both engines' path bases (`%SRCROOT%`, `ROOTPATH`, absolute
roots) to repo-relative POSIX paths. Defect class comes from `mapping/defect_classes.yml`
(regex on `tool:rule-id` → class, first match wins); unlisted ids self-class as their
canonical `tool:rule-id`. Duplicate group → keep the highest-severity representative,
record the merged `(tool, rule)` pairs on the surviving finding.

**Rationale**: baseline proved rule identity cannot dedupe — `missing-user`/`DS-0002`
flagged the same 6 files, `run-as-non-root`/`KSV-0012` 5 of 5, under unrelated ids.
Self-classing makes absence-of-entry safe: the file only merges known equivalences.
**Alternatives**: fuzzy message matching — non-deterministic; hardcoded pairs in code —
violates "data files, not code".

## R5 — Fingerprint

**Decision**: `sha256(canonical rule-id + "\0" + normalised snippet + "\0" +
occurrence-ordinal)[:16]`, where the snippet is whitespace-collapsed and the ordinal is
the finding's rank among identical (rule, snippet) pairs *repo-wide*, ordered by
(file, position). No file path in the hash itself; never line numbers. Repo-global
ordinals keep `id` unique when identical snippets appear in two files, and a rename
can only permute ordinals within such a group — the fingerprint *set*, which is what
the baseline stores, is unaffected.

**Rationale**: DESIGN.md fixes "never file+line". The spec's ideal anchor (position
relative to enclosing function) needs per-language parsing Semgrep's SARIF does not
provide; occurrence-ordinal delivers the same invariant that matters — an added import
shifts every line but no ordinal. Two identical snippets in one file stay distinct;
moving a finding between files re-fingerprints only that finding.
**Alternatives**: SARIF's own `partialFingerprints` — engine-specific, not stable across
engine versions; function-relative position — deferred until an engine emits region
context, the constitution wording permits any line-free scheme.

## R6 — Deterministic serialisation and sort

**Decision**: sort findings by `(path, defect class, canonical rule id, fingerprint)`;
serialise each line with `json.dumps(..., sort_keys=True, ensure_ascii=True,
separators=(",", ":"))`, `\n` endings, UTF-8, no trailing newline variance. First line of
every machine document: `{"schema": "ens-evidence/1"}`.

**Rationale**: total, content-derived order — byte-identity must survive engine output
shuffling (SC-001). **Alternatives**: preserving engine order — explicitly forbidden by
FR-008.

## R7 — Skip key and run store

**Decision**: skip key = sha256 over the ordered tuple (git HEAD SHA, semgrep version,
trivy version, trivy DB version, checks-bundle version, rules mode+SHA, mapping file
hash, baseline file hash, resolved-config hash). Before scanning, compare against
`out/*/run.json`; equal → print the existing run path, exit 0. Run dir
`out/<YYYY-MM-DD>_<git-short-sha>/` written via temp-dir + atomic rename; `latest`
symlink swapped last. A crashed run leaves only a temp dir, never a presentable one.

**Rationale**: DESIGN.md's skip-key list verbatim plus atomicity for the "interrupted
mid-run" edge case. **Alternatives**: mtime-based skip — non-deterministic; in-place
writes — violates append-only.

## R8 — Coverage record (languages / rules / lockfiles)

**Decision**: languages detected by extension census over the scanned tree (stdlib map,
data-driven table in the module); rules-run-per-language counted from the rules root
(local mode) or reported as "registry — uncounted, non-reproducible" (registry mode);
dependency analysis marked skipped when Trivy finds no supported lockfile. All recorded
in `run.json.coverage`.

**Rationale**: Principle IV's coverage table needs data collected at scan time; Semgrep
SARIF omits rules-per-language, the rules root has it. **Alternatives**: language
detection via external tooling (linguist etc.) — new dependency, Principle VI.

## R9 — Baseline file

**Decision**: `.ens-baseline.yml` in the scanned repo: schema marker, created/updated
timestamps, sorted list of fingerprints. `baseline update` rewrites it from the latest
run's findings; `scan` only reads it. "New" = fingerprint not in baseline.

**Rationale**: reviewable diffable YAML in the repo matches "data files, not code" and
makes baseline changes visible in PRs. **Alternatives**: baseline inside `out/` —
rejected, `out/` is immutable evidence, the baseline is mutable operator state.
