# Quickstart — validating 002 Mapping and Report

Runnable checks for the spec's success criteria. Contracts:
[cli.md](contracts/cli.md) · [report.md](contracts/report.md).

## Prerequisites

- Python 3.12, `pip install -r requirements-dev.txt` (adds Jinja2)
- A stored run: either `tests/fixtures/run/` (committed, engine-free) or a real
  `ens-evidence scan` from spec 001
- `pandoc` for the PDF path — optional; every assertion below holds on the Markdown

## 1. Render and read it (SC-001, SC-003)

```sh
ens-evidence report --run tests/fixtures/run
grep -c 'mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.3` · `op.exp.4' \
  tests/fixtures/run/report.md      # 1 — scope list verbatim in the header
```

Open it. The `mp.s.2` section must say no evidence was gathered **and** that this does
not mean the measure is met. No section anywhere may claim compliance.

## 2. Engine-free re-render (SC-008)

```sh
PATH=/usr/bin ens-evidence report --run tests/fixtures/run; echo $?   # 0, no engines needed
```

## 3. Determinism (SC-005)

```sh
ens-evidence report --run tests/fixtures/run && cp tests/fixtures/run/report.md /tmp/a.md
ens-evidence report --run tests/fixtures/run && cmp /tmp/a.md tests/fixtures/run/report.md
```

## 4. Accounting (SC-002)

```sh
pytest tests/test_render.py -k accounting -q
```

Every finding appears exactly once across measure sections, the unmapped appendix and the
non-security appendix — no residue.

## 5. Unmapped fall-through (SC-004)

```sh
pytest tests/test_mapper.py tests/test_mapping_contract.py -q
```

The unknown-*engine* shape (`mysteryengine:SOME-RULE-1`) must reach the appendix, and
every contract probe must still fall through.

## 6. Fencing (SC-006)

```sh
pytest tests/test_render.py -k fencing -q
```

No scanned-repo string appears outside an untrusted-input block or above the truncation
limit. The reference message in the real corpus is 734 characters, so this is a real cut.

## 7. `explain` (SC-007)

```sh
ens-evidence explain <id> --run tests/fixtures/run     # pattern + measures + why
ens-evidence explain nosuchid --run tests/fixtures/run; echo $?    # 2
```

## 8. PDF path (optional)

```sh
ens-evidence report --run tests/fixtures/run --format pdf     # 0 with pandoc, 2 without (named)
```

## 9. Test suite

```sh
pytest tests/ -q -m "not engines"
```

All of 002's tests are engine-free by construction — they render from the committed run.
