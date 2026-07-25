# Scan baseline — what the engines actually emit

Build-order step 2: *"Run Semgrep + Trivy on one real repo, count the findings — the
mapping table and spec 002's criteria are written from that output, never before it."*

Done 2026-07-25 on **three** private repositories rather than one, because the first had no
access-control findings at all. This file is the evidence behind `mapping/ens_rd311.yml` and
`mapping/severity.yml`, and the record of where the design's assumptions met reality.

Engines: **Semgrep 1.171.0** `--config=p/default --sarif --metrics=off` ·
**Trivy 0.72.0** `fs --scanners vuln,misconfig,secret --format sarif` plus a separate
`--format cyclonedx` run for the SBOM. Raw SARIF is not committed (it contains findings for
private repos — see the trust-boundary rule); the inventory below is.

## Totals

| Repo | Character | Semgrep | Trivy | SBOM components |
|---|---|---|---|---|
| repo-a | Python app, Dockerfiles, CI | 36 (6 rules) | 12 (2 rules) | 1 |
| repo-b | Python, CI, agent config | 32 (6 rules) | 5 (3 rules) | 0 |
| repo-c | GitOps Kubernetes manifests | 8 (2 rules) | 86 (15 rules) | 0 |

**179 findings, 28 distinct `tool:rule` ids.** Every mapping rule in
`mapping/ens_rd311.yml` was authored against this inventory.

## Rule inventory

| `tool:rule` | n | SARIF level | security-severity |
|---|---|---|---|
| `semgrep:yaml.github-actions.security.github-actions-mutable-action-tag` | 33 | warning | — |
| `trivy:KSV-0118` (default security context) | 10 | error | 8.0 |
| `semgrep:python.lang.security.audit.exec-detected` | 10 | warning | — |
| `trivy:DS-0026` (no HEALTHCHECK) | 9 | note | 2.0 |
| `semgrep:dockerfile.security.missing-user` | 7 | error | — |
| `semgrep:python.lang.security.audit.dynamic-urllib-use-detected` | 7 | warning | — |
| `trivy:DS-0002` (image user is root) | 7 | error | 8.0 |
| `semgrep:package_managers.renovate.renovate-missing-minimum-release-age` | 6 | warning | — |
| `trivy:KSV-0001` (privilege escalation) | 6 | warning | 5.5 |
| `trivy:KSV-0012` (runs as root) | 6 | warning | 5.5 |
| `trivy:KSV-0014` (root FS not read-only) | 6 | error | 8.0 |
| `trivy:KSV-0104` (seccomp disabled) | 6 | warning | 5.5 |
| `trivy:KSV-{0003,0004,0011,0020,0021,0030,0106,0110}` | 6 each | note | 2.0 |
| `semgrep:yaml.kubernetes.security.run-as-non-root` | 5 | note | — |
| `semgrep:python.flask.security.xss.audit.direct-use-of-jinja2` | 3 | warning | — |
| `semgrep:yaml.kubernetes.security.allow-privilege-escalation-no-securitycontext` | 3 | warning | — |
| `trivy:KSV-0013` (`:latest` tag) · `trivy:KSV-0125` (untrusted registry) | 2 each | warning | 5.5 |
| `semgrep:yaml.github-actions.security.run-shell-injection` | 1 | error | — |
| `semgrep:python.sqlalchemy.security.sqlalchemy-execute-raw-query` | 1 | error | — |
| `trivy:github-fine-grained-pat` | 1 | error | 9.5 |

## What this changed

### 1. Cross-tool dedupe cannot key on rule identity

The two engines flag the same defect under unrelated ids, at different granularities:

| Same defect | Semgrep | Trivy | File overlap |
|---|---|---|---|
| Container runs as root | `dockerfile.security.missing-user` (6) | `DS-0002` (6) | 6 of 6 — identical set |
| Pod runs as root | `yaml.kubernetes.security.run-as-non-root` (5) | `KSV-0012` (6) | 5 of 5 |
| Privilege escalation allowed | `allow-privilege-escalation-no-securitycontext` (3) | `KSV-0001` (6) | 3 of 3 |

So `normalise.py` must dedupe on **(normalised path, defect class)**, with defect class
coming from the mapping layer — not on rule id, and not on message text. This is spec
001 work, not a later refinement.

### 2. Severity lives in different places per engine

Every Trivy rule carries `properties."security-severity"` (2.0 / 5.5 / 8.0 / 9.5). **No
Semgrep rule does**, and Semgrep results carry no `level` either — the only signal is the
rule's `defaultConfiguration.level` plus a `"<X> CONFIDENCE"` string in `properties.tags`.
Hence the two `strategy` values in `mapping/severity.yml`. Read severity from the rule
object, never the result.

### 3. Semgrep's fingerprint is unusable without an account

```json
"fingerprints": {"matchBasedId/v1": "requires login"}
```

Computing our own fingerprint (rule id + normalised snippet + offset within the enclosing
function) is now mandatory rather than merely preferable.

### 4. Path bases differ

Semgrep emits `uriBaseId: "%SRCROOT%"`, Trivy `"ROOTPATH"`. Normalising both to
repo-relative paths is a prerequisite for dedupe.

### 5. Trivy's SARIF message is an unstructured blob

```
Artifact: containers/auth-worker.Dockerfile
Type: dockerfile
Vulnerability DS-0002
Severity: HIGH
Message: Specify at least 1 USER command …
Link: [DS-0002](https://avd.aquasec.com/misconfig/ds-0002)
```

Parse nothing out of this. Take severity and title from the rule object; keep the blob out
of the report (principle: our template text, not scanner passthrough).

## Gaps this run did not close

1. **No CVEs, anywhere.** All three repos lack a lockfile Trivy understands, so the SCA
   half of the v1 engine story is unexercised and `trivy:CVE-.*` in the mapping file is
   unverified. Scan a repo with `uv.lock` / `package-lock.json` / `go.sum` before spec 002
   claims anything about `op.exp.4`.
2. **SBOMs are empty** (0–1 components) for the same reason. DESIGN.md bills Trivy as
   "SCA + SBOM"; on repos like these it delivers misconfiguration findings only. Per
   principle IV the report must state *no lockfile found → no dependency analysis*, or an
   empty SBOM will read as good news.
3. **Secret detection is a finding class the design does not mention.** DESIGN.md defers
   gitleaks to v2, but Trivy's secret scanner already fires today — and produced the single
   highest-severity finding of the whole exercise (9.5). Decide whether secrets are a v1
   class; `mapping/ens_rd311.yml` currently maps them to `op.acc.5`, the least certain call
   in that file.
4. **`op.acc.5` has thin evidence.** Only the secret finding maps there. No authn/authz
   code defect fired in any of the three repos, so a repo with real login code is needed to
   judge whether the measure is usefully covered.
5. **Measure titles remain unverified** against the BOE consolidated text of Anexo II. All
   mapping decisions above are by measure ID and our own reading; the pre-release gate
   stands.
