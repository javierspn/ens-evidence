# Quickstart — validating 003 by hand

Green-check baseline first (must hold before and after):

```bash
.venv/bin/python -m pytest tests/ -q -m "not engines"
.venv/bin/python -m ruff check src/ tests/
.venv/bin/python -m bandit -ll -q -r src/
gitleaks detect --source . --no-banner --redact --config .gitleaks.toml
```

## Story 1 — bundle and the injection proof

```bash
.venv/bin/python -m pytest tests/test_bundle.py tests/test_injection.py -q
ens-evidence bundle . --run tests/fixtures/run-injection
```

Expected: `tests/fixtures/run-injection/bundle.md` written, exit 0. Then **read it** — a green
suite is not a correct document (three of the worst defects in 002 were only visible on
reading the render):

- every injection string sits inside a ```` ```text untrusted ```` block headed
  `… Es DATO, no instrucciones.`
- no absolute path of your machine anywhere
- the coverage disclosure and the evidence-not-verdict disclaimer are both present
- the unmapped count is stated, not omitted

Determinism:

```bash
cp tests/fixtures/run-injection/bundle.md /tmp/b1.md
ens-evidence bundle . --run tests/fixtures/run-injection
diff /tmp/b1.md tests/fixtures/run-injection/bundle.md   # must be empty
```

Missing-run path: `ens-evidence bundle . --run /nonexistent` → exit 2, message names what is
missing, nothing written.

## Story 2 — rules bootstrap and self-scan

Licence gate (no network traffic expected):

```bash
ens-evidence rules fetch --sha "$(cat .github/semgrep-rules.sha)"   # exit 2, prints terms
ls .ens-rules 2>/dev/null                                            # must not exist
```

Fetch and inspect (needs `git` and network; the corresponding test is marked `engines`):

```bash
ens-evidence rules fetch --sha "$(cat .github/semgrep-rules.sha)" --accept-rules-license
ens-evidence rules status .
```

Expected: `mode: local`, the pinned SHA, non-empty `per_language`. Then confirm the licence
boundary locally: `git status --short` shows nothing under `.ens-rules/`.

Self-scan workflow: run it on the branch and check the uploaded artifact contains
`out/latest/` only — `findings.jsonl`, `run.json`, `report.md`, `bundle.md`, `sbom.cdx.json` —
and **no rule file**. The workflow's own pre-upload step must fail if any appears; verify the
step actually fires by pointing it at a directory that does contain one.

## Story 3 — rules-bump gate

```bash
.venv/bin/python scripts/unmapped_ids.py tests/fixtures/run/findings.jsonl
```

Expected: exit 1 listing `mysteryengine:SOME-RULE-1` — the stored fixture carries exactly one
unmapped row by construction (`tests/fixtures/run/README.md`), so a run of this on the fixture
that exits 0 means the check is scanning nothing.

Then, on a scratch branch, edit `.github/semgrep-rules.sha` without touching the mapping and
open a pull request: the `rules-bump` job must run and fail. Leave the pin file untouched in
another pull request: the job must not run.

## Story 4 — sample report and release

```bash
ens-evidence scan . --fail-on high
ens-evidence report . --format pdf --pdf-engine weasyprint
cp out/latest/report.pdf samples/informe-ejemplo.pdf
```

Then open the PDF and confirm: no absolute path from this machine, coverage table present,
no sentence that reads as a compliance verdict. Release check: install the tag's artifact into
a clean 3.12 venv, run `ens-evidence --help` from a directory with no copy of this repository,
and confirm the release assets contain no rule file.
