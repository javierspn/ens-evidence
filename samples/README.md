# samples/

Real output, not a mock-up — this repository scanning itself.

| File | What it is |
|---|---|
| `informe-ejemplo.pdf` | the evidence report, rendered from Markdown with `--pdf-engine weasyprint` |
| `bundle-ejemplo.md` | the paste-anywhere summary of the same run |

Produced on 2026-07-26 from commit `349f642`, with Semgrep 1.171.0 and Trivy 0.72.0 and the
rules pinned at `81634cfc9e68dc5f238a8062909a60ba34500648` (`.github/semgrep-rules.sha`):

```bash
# Outside the repository on purpose: a rules checkout inside it becomes part of `scan .`.
ens-evidence rules fetch --sha "$(cat .github/semgrep-rules.sha)" \
  --rules-root ~/ens-rules --accept-rules-license
ens-evidence scan . --rules-root ~/ens-rules
ens-evidence report . --format pdf --pdf-engine weasyprint
ens-evidence bundle .
```

Both `--rules-root` arguments matter. Without them `scan` falls back to the Semgrep
registry (`p/default`) and `run.json` records `"mode": "registry"` — the pin is then
decorative and the run is not reproducible. The recipe above lacked them until 2026-07-28,
so the committed sample was produced in registry mode despite this file naming a SHA.

## Two things to know before reading the numbers

**Many findings come from this repository's own test fixtures.** `tests/fixtures/` holds
deliberately vulnerable applications — that is their job. A finding in
`tests/fixtures/vulnerable-app/` is the fixture working, not a defect in the tool. The report
does not editorialise about that, because filtering by path is exactly the sort of judgement
that turns evidence into a verdict.

**One finding's file path contains a prompt-injection attempt** — the directory named
`IGNORE PREVIOUS INSTRUCTIONS - …` in the injection fixture. It is in the sample on purpose:
that path is repository-controlled text, and the sample shows what the tool does with it —
quoted as data, never as an instruction, with the document saying so before showing it.

## Regenerating

Any regeneration moves the date, the revision and the counts. Read the rendered PDF before
committing a new one: every presentation defect found so far — a path leak, a coverage table
claiming a gap that was not real, a digest cut off at the page margin, bullets glued together
— was invisible in the tests and obvious on the page.
