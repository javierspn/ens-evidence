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

## Round 2 — closing the gaps (2026-07-25, same day)

### CVEs and SBOM verified on lockfile repos

Scanned `repo-d` and `repo-e`, which pin dependencies in `requirements.txt`:

| Repo | CVE findings | distinct CVEs | SBOM components |
|---|---|---|---|
| repo-d | 17 | 12 | 44 (41 library, 3 application) |
| repo-e | 17 | 17 | — |

`trivy:CVE-.*` is now observed, not assumed. Trivy severity words on these: CRITICAL
through LOW, and the SBOM populates properly once a lockfile exists.

### Trivy's two severity fields disagree on CVEs

`CVE-2024-56201` (jinja2 3.1.4) ships:

```json
{"security-severity": "8.8", "cvssv3_baseScore": 8.8, "cvssv40_baseScore": 5.4,
 "tags": ["vulnerability", "security", "MEDIUM"]}
```

`security-severity` **is the CVSS v3 base score**, not Trivy's verdict — the tag says
MEDIUM. On misconfiguration checks the two agree, which is why round 1 (misconfig only) did
not catch this. `severity.yml` now reads the tag first and treats the numeric bands as a
fallback; a naive band lookup would have graded this finding `high`.

### Broader Semgrep rulesets do not help

`--config p/default --config p/secrets --config p/jwt` on repo-d: 17 findings, 5 rules.
Not one secret rule and not one JWT rule fired. One genuinely new rule appeared —
`python.django.security.django-no-csrf-token` — which **fell through to `unmapped`**,
exposing that the mapping only covered `python.lang.*` and `.security.audit.*`, not the web
framework namespaces. Fixed; `tests/mapping-cases.yml` pins it.

### Measure titles verified against the BOE

Extracted from the consolidated PDF of RD 311/2022 (`BOE-A-2022-7191`), Anexo II:

| Code | Published heading |
|---|---|
| `mp.sw.1` | Desarrollo de aplicaciones |
| `mp.sw.2` | Aceptación y puesta en servicio |
| `mp.s.2` | Protección de servicios y aplicaciones web |
| `op.exp.2` | Configuración de seguridad |
| `op.exp.4` | Mantenimiento y actualizaciones de seguridad |
| `op.acc.5` | **Mecanismo de autenticación (usuarios externos)** |

All six exist. Five match what the design assumed. **`op.acc.5` does not**: it governs the
authentication mechanism for users external to the organisation — a design and operational
control, not something a static scanner can observe. Neighbours for reference: `op.acc.6` is
the same measure for organisation users; `op.exp.1` is *Inventario de activos*; `op.exp.3`
is *Gestión de la configuración de seguridad*.

Consequence: mapping a leaked credential to `op.acc.5` is wrong, and `op.acc.5` has no
plausible automated evidence source at all. This needs a scope decision (principle III makes
it a four-file change), so the mapping keeps the disputed rule, flagged, until then.

## Gaps this run did not close

1. ~~No CVEs, anywhere.~~ **Closed** — verified on repo-d and repo-e (round 2).
2. ~~SBOMs are empty.~~ **Closed** — 44 components on a lockfile repo. The reporting
   obligation stands though: with no lockfile, the run must say *no lockfile found → no
   dependency analysis* (principle IV), or an empty SBOM reads as good news. That is spec
   002 work, tracked there rather than here.
3. **Secrets as a v1 finding class — adopted.** Trivy's secret scanner fires today at no
   extra dependency cost and produced the highest-severity finding in the corpus, so v1
   keeps `--scanners vuln,misconfig,secret`. gitleaks stays deferred to v2 as a *second*
   secret engine, not the first. What remains open is which measure secrets map to — see 4.
4. **`op.acc.5` is the wrong measure, and its replacement is a scope decision.** The BOE
   heading is *Mecanismo de autenticación (usuarios externos)*: no static-analysis finding
   can evidence it, and the leaked-credential mapping is a category error. Options, all
   four-file changes under principle III:
   - swap `op.acc.5` → `op.exp.1` *Inventario de activos*, which the CycloneDX SBOM
     evidences directly and well;
   - swap → `op.exp.3` *Gestión de la configuración de seguridad*, pairing with op.exp.2;
   - keep `op.acc.5` and report it as "no automated evidence available", which is honest
     but makes one of six measures dead weight.
   Until decided, `trivy:*-pat` keeps mapping to `op.acc.5` with a DISPUTED note in
   `tests/mapping-cases.yml`.
5. ~~Measure titles unverified.~~ **Closed** — all six verified against the consolidated BOE
   text; five confirmed, one (`op.acc.5`) contradicted the design's assumption. Re-verify if
   the scope list changes.
6. **New:** no repo in the corpus exercises `mp.s.2` beyond template-level findings
   (jinja2, CSRF). A repo with real HTTP routing and session handling would test whether the
   web-service measure gets useful evidence.
