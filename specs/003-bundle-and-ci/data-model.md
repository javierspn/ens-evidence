# Phase 1 — data model

No new persisted schema. This feature adds one derived document, one local directory of
third-party files, and one tracked pin file. Everything else is read from artefacts 001 and 002
already produce.

## Bundle model (in memory)

`bundle` reuses `render.build_model(...)` verbatim — the context `report.md.j2` renders. No new
keys. The subset the bundle template is required to consume:

| Key | Type | Used for |
|---|---|---|
| `record.run.date`, `record.run.git_short_sha` | str | what was analysed and when |
| `target_name` | str | repository name only — never the stored absolute `target` path |
| `coverage` | dict | languages detected, rules run per language, languages not analysed, dependency analysis skipped (Principle IV; mandatory in the bundle) |
| `scope`, `measures_meta`, `measures_verified` | list/dict | the canonical measure list and titles, read from the mapping data file (Principle III) |
| `triage` | list | the highest-severity findings shown in the bundle body |
| `totals.total`, `totals.counted`, `totals.unmapped`, `totals.non_security` | int | the accounting line; `unmapped` is disclosed, not hidden |
| `record.engines`, `record.rules`, `record.mapping` | dict | which engine, rule SHA and mapping version produced this — an old run must not read as the current mapping |

**Fields carrying scanned-repo text** — `msg` and `snippet` through the `fence` filter; `file`,
`rule`, `tool` and language names through `inline_untrusted`, because they sit in cells and
bullets where a fenced block cannot go. Never raw. This is the invariant `test_injection.py`
exists to hold, over both documents.

### Existing stub to replace

`render.render_bundle(findings, run_meta, template_dir)` currently raises
`NotImplementedError` (`src/ens_evidence/render.py:187`). Its signature changes to
`render_bundle(model, template_dir)` so it takes the same built model as `render_report`,
rather than re-deriving one.

## Bundle document (on disk)

- Path: `<run_dir>/bundle.md`, beside `report.md`, inside the immutable run directory.
- Markdown only. Byte-identical across re-renders of the same run (Principle I).
- Written whole or not at all: on an unreadable or incomplete run, exit 2 and write nothing.
- Never overwrites a different run's bundle — the run directory is the unit of immutability;
  re-rendering the same run produces the same bytes, so an in-place rewrite is a no-op.

## Rules root (local, third-party, never redistributed)

| Field | Source | Notes |
|---|---|---|
| path | `--rules-root`, `ENS_EVIDENCE_RULES_ROOT`, `.ens-evidence.yml`, default `.ens-rules/` for `fetch` | already in `run.py:SKIP_DIRS` and `.gitignore` |
| repo URL | `git remote get-url origin` | recorded via existing `rules_info()` |
| commit SHA | `git rev-parse HEAD` | the pin; recorded in `run.json` |
| per-language rule counts | `rules_per_language()` | top-level directory names of the rules root |
| mode | derived | `local` when a rules root is configured, `registry` otherwise |

State transitions: *absent* → (`rules fetch` with acknowledgement) → *pinned at SHA* →
(`rules fetch` at a different SHA) → *pinned at new SHA*. There is no "update to latest"
transition: a rules root without a SHA is not a state this tool can produce.

**Licence-bound invariants**: rule files are never copied into a published artifact, release
asset, container image, cache payload, or committed file; never modified; never re-namespaced.

## Rules pin file

`.github/semgrep-rules.sha` — one line, one 40-hex commit SHA, tracked in git. The single
source of the pin for both workflows, and the file whose change triggers the rules-bump gate.
A malformed or missing pin fails the workflow rather than falling back to the registry: a
silent fallback would make CI non-reproducible while still reporting green.

## Unmapped-id report (CI only)

`scripts/unmapped_ids.py <findings.jsonl>...` → stdout: one `tool:rule` per line for every
finding whose `measures == ["unmapped"]`, sorted and de-duplicated; exit 1 if any, 0 if none.
Reads the existing finding record; adds no field to it.
