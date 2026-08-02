# samples/

Real output, not a mock-up — this repository scanning itself.

| File | What it is |
|---|---|
| `informe-ejemplo.pdf` | the evidence report, rendered from Markdown with `--pdf-engine weasyprint` |
| `bundle-ejemplo.md` | the paste-anywhere summary of the same run |

Produced on 2026-08-02 from commit `58d2122`, with Semgrep 1.171.0 and Trivy 0.72.0 and the
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
decorative and the run is not reproducible. The recipe lacked them until 2026-07-28, so the
first committed sample was produced in registry mode despite this file naming a SHA; these
files are the regenerated, genuinely pinned run (`"mode": "local"`).

The pin changes what is *provable* about the run, not what this repository contains — worth
saying plainly, because "we fixed the rules source" reads like "the numbers were wrong", and
they were not: the pinning fix on 2026-07-28 left the totals exactly where they were.

This run is 74 findings, 61 mapped and security-tagged, 13 not tagged as security, 0
unmapped — the same four numbers as the 2026-07-29 sample. What changed is the document,
not what was found: the report's sections are now numbered, and section 5 writes each
finding out in Spanish, with our own title and explanation and its ENS measure, instead of
heading it with the engine's rule id and quoting the engine's English message. Regenerated
because the committed PDF still showed the old structure.

Two later corrections are also in this render. Section 3's rule counts are the catalogue's,
so each row now says whether the repository holds that language at all — a run over five
languages was listing 364 terraform rules under "reglas ejecutadas". And section 5 groups
the findings that share a description: the same Kubernetes paragraph was printed four times
over, differing only in file and line. Every finding is still there, each with its own
location, rule and fingerprint.

The eight `high` findings in section 5 render as three entries; this repository's run
produces no
`critical`, and no CVE findings at all, so the sample does not exercise either the
cascade's lower bands or the package-and-version line that dependency findings carry.

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
