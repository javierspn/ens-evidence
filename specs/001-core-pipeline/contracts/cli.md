# Contract — CLI (001 slice)

Verbs owned by 001; full contract in [DESIGN.md](../../../DESIGN.md#cli-contract).
`bundle`, `report`, `explain`, `rules` are other specs' slices — 001 must leave their
seams (JSONL + run store) exactly as contracted here.

## Verbs

```
ens-evidence scan [PATH] [--fail-on {critical,high,medium,low}] [--force] [--json]
ens-evidence baseline update [PATH]
```

- `PATH` defaults to cwd; must be a git work tree (short SHA feeds the run dir name).
- `--fail-on` default: forgiving (gate disabled unless given).
- `--force`: ignore skip key, re-run, MUST byte-reproduce `findings.jsonl` (SC-001).
- `baseline update`: rewrites `.ens-baseline.yml` from `out/latest` findings; refuses
  (exit 2) when no run exists.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no NEW finding at/above `--fail-on`; includes skip-key hits and gate-disabled runs |
| 1 | ≥1 new finding at/above `--fail-on` |
| 2 | tool error: missing engine binary (named in message), engine non-zero exit, unwritable run store, unknown severity, no run for `baseline update` |

## Config resolution (FR-012)

`flags` → `ENS_EVIDENCE_*` env → `.ens-evidence.yml` in scanned repo → defaults.
Nothing interactive, ever. Keys owned by 001: `fail_on`, `rules_root`, `rules_mode`,
`out_dir`, `fixed_date` (tests only — see quickstart).

## Streams

- stdout: machine JSON only, first object `{"schema":"ens-evidence/1"}`; under `--json`
  errors are JSON too.
- stderr: human progress/chatter. Nothing on stdout that a pipe can't parse.

## Engine seam (internal contract, spec-004-proof)

One engine = one subprocess invocation producing SARIF on disk + a version probe.
Adding an engine (gitleaks, Checkov) must touch an invocation table only — zero
interface changes in `normalise`/`mapper` (spec 004 acceptance).
