# fixture: a stored run

A real `ens-evidence scan` of [`../vulnerable-app`](../vulnerable-app), committed so the
spec 002 rendering tests need **neither the engines nor a scan** — the CI test job runs
`pytest -m "not engines"` and must stay green on a machine with no Semgrep and no Trivy.

Captured 2026-07-26 with Semgrep 1.171.0 (`p/default`, registry mode) and Trivy 0.72.0.

## What is real and what is not

**28 of the 30 findings are real engine output**, byte-for-byte as spec 001 wrote them.

**Two rows are constructed**, and both say so in their `msg`. They exist because the real
corpus cannot produce them, which would leave two branches of the accounting invariant
(spec 002 SC-002) shipped untested:

| Constructed row | Why the real run cannot produce it |
|---|---|
| `semgrep:python.lang.best-practice.fixture-non-security` (`security: false`) | All 28 real findings are tagged `security` by their engine — the registry packs are security-only |
| `mysteryengine:SOME-RULE-1` | All 28 real findings match a mapping rule; the language catch-alls absorb unknown rules *within* a known engine, so an unknown **engine** is the only reliable way to reach the unmapped appendix (`../../mapping-cases.yml`) |

Only `run.json`'s `target` was edited (to `.`) and `counts` recomputed — a stored run must
not carry the absolute path of the machine that produced it.

## Regenerating

Scan `tests/fixtures/vulnerable-app` from a git work tree of its own (Semgrep reads only
git-tracked files, and its defaults skip anything under `tests/`), then re-append the two
constructed rows, re-sort by `(file, class, rule, fingerprint)` and recompute `counts`.
Any regeneration changes the fixture's findings, so expect the rendering tests' golden
assertions to move with it.
