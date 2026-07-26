# Quickstart — validating 001 Core Pipeline

Runnable end-to-end checks proving the spec's success criteria. Contracts:
[cli.md](contracts/cli.md) · [artifacts.md](contracts/artifacts.md).

## Prerequisites

- Python 3.12, `pip install pyyaml pytest`
- `semgrep` and `trivy` on PATH (versions pinned by you — recorded, not chosen, by the tool)
- Trivy cache primed once, outside the finding path: `trivy fs --download-db-only .`
- Local rules for hermetic runs: rules root at a pinned SHA (registry mode works but is
  flagged non-reproducible in coverage)

## 1. Determinism (SC-001, SC-004)

```sh
cd tests/fixtures/vulnerable-app
ens-evidence scan . --force
cp out/latest/findings.jsonl /tmp/a.jsonl
ens-evidence scan . --force
cmp /tmp/a.jsonl out/latest/findings.jsonl        # byte-identical or FAIL
```

Repeat with network disabled (e.g. `unshare -n` on Linux) — same bytes.

## 2. Baseline gate (SC-003, SC-007)

```sh
ens-evidence scan .                      # findings exist, gate off → exit 0
ens-evidence baseline update .
ens-evidence scan . --fail-on high; echo $?      # 0 — nothing new
# introduce one new high finding in the fixture, then:
ens-evidence scan . --fail-on high; echo $?      # 1 — exactly one finding new=true
# add an import line above an accepted finding, re-scan:
ens-evidence scan . --fail-on high; echo $?      # 0 — fingerprint survived the shift
```

## 3. Run record + coverage (SC-006)

```sh
python -m json.tool out/latest/run.json    # all engines/rules/mapping/skip_key fields non-null
```

Scan a lockfile-less fixture → `coverage.dependency_analysis == "skipped-no-lockfile"`.
Scan a fixture containing a `.ex` file → `elixir` in `coverage.languages_not_analysed`.

## 4. Skip key (US3 scenario 4)

```sh
ens-evidence scan .; echo $?     # real run
ens-evidence scan .; echo $?     # 0, prints existing run path, no new out/ dir
```

## 5. Failure modes (exit 2)

```sh
PATH=/usr/bin ens-evidence scan .            # missing semgrep → exit 2, message names it
ens-evidence baseline update /tmp/empty-repo # no run store → exit 2
```

## 6. Test suite

```sh
pytest tests/ -q
```

`tests/fixtures/sarif/` holds captured engine SARIF pairs so normaliser tests
(canonical ids, security split, dedupe, fingerprints, sort, byte-identity — including a
shuffled-input case) run without engines installed. CLI/run-store tests need the real
binaries and are marked accordingly. Tests pin `fixed_date` in config so run-dir names
are stable.
