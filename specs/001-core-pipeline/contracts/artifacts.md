# Contract — Artifacts (001 slice)

Field semantics in [data-model.md](../data-model.md); serialisation rules in
[research.md R6](../research.md). These schemas are the seam specs 002/003 consume —
changing a key is a cross-spec breaking change.

## `out/<YYYY-MM-DD>_<git-short-sha>/findings.jsonl`

```jsonl
{"schema":"ens-evidence/1"}
{"class":"container-runs-as-root","file":"Dockerfile","fingerprint":"9be51f0ac20e77dc","id":"9be51f0a","line":1,"merged_from":[["semgrep","dockerfile.security.missing-user"],["trivy","DS-0002"]],"msg":"Image runs as root","new":false,"rule":"dockerfile.security.missing-user","security":true,"sev":"high","snippet":"FROM python:3.12-slim","tool":"semgrep"}
```

- keys sorted, compact separators, `ensure_ascii`, LF, one finding per line
- ordering: `(file, class, rule, fingerprint)` — byte-stable across engine output order
- optional keys (`merged_from`) omitted when empty, never `null`

## `out/<...>/run.json`

```json
{
  "schema": "ens-evidence/1",
  "run": {"date": "2026-07-25", "git_sha": "…", "git_short_sha": "a3f9c1d", "target": "."},
  "engines": {
    "semgrep": "1.171.0",
    "trivy": "0.72.0",
    "trivy_db": {"version": 2, "updated_at": "…"},
    "trivy_checks_bundle": "…"
  },
  "rules": {"mode": "local", "repo": "https://github.com/semgrep/semgrep-rules", "sha": "…", "root": ".ens-rules", "per_language": {"python": 456}},
  "mapping": {"severity_sha256": "…", "defect_classes_sha256": "…"},
  "baseline_sha256": null,
  "config_sha256": "…",
  "skip_key": "…",
  "coverage": {
    "languages_detected": {"python": 41, "dockerfile": 2},
    "rules_per_language": {"python": 456, "dockerfile": 12},
    "languages_not_analysed": ["elixir"],
    "dependency_analysis": "skipped-no-lockfile"
  },
  "counts": {"total": 48, "security": 36, "non_security": 12, "new": 1, "deduped_away": 11}
}
```

## `out/<...>/sbom.cdx.json`

Trivy CycloneDX output verbatim — pass-through, never edited, bypasses the mapper.

## `out/latest`

Symlink to the newest run dir; swapped atomically, last step of a successful run.
Crashed runs leave no visible run dir (temp-dir + rename, R7).

## `.ens-baseline.yml` (scanned repo, operator-owned)

```yaml
schema: ens-evidence/1
updated: 2026-07-25
fingerprints:
  - 9be51f0ac20e77dc
```

Sorted, plain strings. Written only by `baseline update`.
