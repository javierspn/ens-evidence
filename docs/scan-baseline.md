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

Consequence: mapping a leaked credential to `op.acc.5` was wrong, and `op.acc.5` had no
plausible automated evidence source at all. **Resolved in constitution 1.1.0:** scope swaps
`op.acc.5` → `op.exp.3` *Gestión de la configuración de seguridad*, and secrets move to
`mp.sw.1`. See the round-3 section below.

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
4. ~~`op.acc.5` is the wrong measure.~~ **Closed** — swapped for `op.exp.3` in constitution
   1.1.0; see round 3.
5. ~~Measure titles unverified.~~ **Closed** — all six verified against the consolidated BOE
   text; five confirmed, one (`op.acc.5`) contradicted the design's assumption. Re-verify if
   the scope list changes.
6. ~~`mp.s.2` has thin evidence.~~ **Closed** — 104 findings on a public vulnerable-app
   corpus; see round 4. The measure stays in scope.
7. ~~The `unmapped` appendix has never fired on real data.~~ **Closed** — the Java/Go corpus
   produced 30 unmapped findings (round 5). Two of six synthetic probes have now been proven
   wrong by real data.
8. **New, and the most important open item:** neither engine is hermetic. Trivy resolves
   Maven POMs over the network (and failed on a 429); Semgrep fetches a versionless ruleset
   from its registry. Principle I cannot hold without `--offline-scan` and a vendored,
   hash-recorded ruleset. Spec 001 owns this.

## Round 3 — scope amendment (constitution 1.1.0)

`op.acc.5` left the scope list, `op.exp.3` *Gestión de la configuración de seguridad* took
its place. Rationale: op.acc.5 governs the external-user authentication mechanism, a design
and operational control that no static scanner observes — it would have appeared in every
report with nothing under it. op.exp.3 is evidenced by findings already in the corpus.

The op.exp.2 / op.exp.3 split is deliberate and worth keeping straight:

- **op.exp.2** — the hardening settings themselves: runs as root, writable root filesystem,
  capabilities not dropped, seccomp unset, missing `USER`.
- **op.exp.3** — whether the deployed artefact is the one the manifest names: `:latest`
  tags (`KSV-0013`), untrusted registries (`KSV-0125`), mutable CI action references
  (`github-actions-mutable-action-tag`). Configuration you cannot pin is configuration you
  are not managing.

Secrets moved to `mp.sw.1`: a credential reaching the repository is a
development-and-handling defect, not a defect of an authentication mechanism.

Evidence distribution over the real 179-finding corpus after the swap:

| Measure | Findings |
|---|---|
| `op.exp.2` | 113 |
| `mp.sw.2` | 40 |
| `op.exp.3` | 37 |
| `mp.sw.1` | 22 |
| `op.exp.4` | 6 |
| `mp.s.2` | 4 |
| `unmapped` | 0 |

Two caveats on that table. `op.exp.4` looks thin only because the 179-finding corpus predates
the lockfile scan — the 34 CVE findings from repo-d and repo-e all land there. And
`mp.s.2` at 4 remains the weakest measure; see gap 6.

## Round 4 — public vulnerable-app corpus (mp.s.2)

`mp.s.2` had 4 findings across the private corpus, all incidental (a jinja2 template call, a
CSRF token). That is not enough to know whether the measure earns a place in the scope list,
and no private repo here is a conventional web application. So: three public, deliberately
vulnerable apps, cloned shallow into a scratch directory and **not** committed here.

| Repo | Stack | Findings |
|---|---|---|
| [pygoat](https://github.com/adeyosemanputra/pygoat) | Django | 292 |
| [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Flask | 101 |
| [juice-shop](https://github.com/juice-shop/juice-shop) | Express/TypeScript | 60 |

**453 findings, 218 distinct rule ids.** `mp.s.2` now draws 104 findings from rules that are
unambiguously web-service controls:

| Rule | n |
|---|---|
| `python.django.security.audit.csrf-exempt.no-csrf-exempt` | 25 |
| `python.django.security.django-no-csrf-token` | 19 |
| `python.django.security.audit.secure-cookies.django-secure-set-cookie` | 10 |
| `python.django.security.injection.request-data-write` | 4 |
| `python.django.security.audit.xss.direct-use-of-httpresponse` | 4 |
| `javascript.express.security.audit.express-res-sendfile` | 4 |
| `javascript.express.security.audit.express-check-directory-listing` | 4 |
| `python.flask.security.insecure-deserialization` | 3 |
| `python.django.security.injection.tainted-sql-string` | 3 |

CSRF exemptions, insecure cookies, XSS, directory listing, tainted SQL — `mp.s.2` stays.

### Four mapping gaps this corpus exposed

21 findings fell through to `unmapped`, in four families:

1. **Secret rules we had assumed would never fire.** `generic.secrets.*` (JWT tokens,
   generic secrets), `trivy:jwt-token`, `python.jwt.*`, `javascript.jsonwebtoken.*`.
   `tests/mapping-cases.yml` had `generic.secrets.security.detected-generic-api-key` listed
   as a **must-fall-through probe** — the public corpus fired its sibling 5 times. The
   probe was wrong, not the engines: `p/secrets` finding nothing on the private repos made a
   bad assumption look safe. Now mapped to `mp.sw.1`; the case carries that history.
2. **JS/TS outside a web framework** — `javascript.browser.security.eval-detected`,
   `javascript.audit.*`. Added `javascript.(browser|audit|lang)` and `typescript.*` →
   `mp.sw.1`.
3. **npm package policy** — `package_managers.npm.npm-missing-minimum-release-age`. The rule
   was Renovate-specific; generalised to `package_managers.*` → `mp.sw.2` + `op.exp.4`.
4. Nothing else. After the fixes, **0 unmapped** across all 453 findings.

Evidence over the public corpus after the fixes: `mp.sw.2` 242, `op.exp.4` 219, `mp.sw.1`
188, `mp.s.2` 104, `op.exp.2` 23, `op.exp.3` 17.

### A caveat about 0 unmapped

Zero unmapped across every corpus scanned so far is *not* reassuring. It means the catch-alls
absorb everything, and the appendix that exists to surface "we found something nobody has
classified" has never fired on real data. Spec 002 should build its unmapped fixture from a
deliberately alien engine output rather than hoping for a real one.

## Round 5 — Java and Go (the ecosystem question)

Two more public repos, chosen to answer one question: was the mapping Python/JS-biased?

| Repo | Stack | Findings | Rule ids |
|---|---|---|---|
| [WebGoat](https://github.com/WebGoat/WebGoat) | Java / Spring / Maven | 252 | 62 |
| [govwa](https://github.com/0c34/govwa) | Go / go.mod | 55 | 31 |

**Yes, it was biased.** 30 findings fell through to `unmapped` — the first real unmapped
findings in the whole exercise, after four rounds of zero:

| Unmapped family | n | Now mapped to |
|---|---|---|
| `java.spring.security.*` (unrestricted request mapping, tainted SQL/URL/path) | 15 | `mp.sw.1` + `mp.s.2` |
| `java.servlets.security.*` (insecure cookies) | 3 | `mp.sw.1` + `mp.s.2` |
| `java.lang.security.*` (servlet path traversal) | 1 | `mp.sw.1` |
| `go.lang.security.injection.*` (raw HTML format) | 3 | `mp.sw.1` |
| `html.security.plaintext-http-link` | 6 | `mp.s.2` |
| `yaml.docker-compose.security.*` | 2 | `op.exp.2` |

The docker-compose family was a **must-fall-through probe** in
`tests/mapping-cases.yml`, excluded on the reasoning "deliberate, we scan k8s and
Dockerfiles". govwa ships a compose file with the same hardening settings Kubernetes
manifests carry. That is the second of six probes proven wrong by real data; the list encodes
assumptions, not facts, and should be read that way.

So the earlier "0 unmapped is not reassuring" caveat was right, and for the reason given: the
corpus was homogeneous, not the mapping complete. Java/Go coverage now exists, and the
remaining blind spots are ecosystems nobody here writes (Ruby, PHP, .NET, Rust) plus IaC.

### The engines are not hermetic — this threatens Principle I

`trivy fs` on WebGoat **failed outright**:

```
FATAL Error remote Maven repository returned 429 Too Many Requests for
https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/4.1.0/spring-boot-starter-parent-4.1.0.pom.
Retry-After: 1777.
```

Trivy resolves parent POMs over the network to build a Maven dependency tree. Consequences,
all of which the design must answer before spec 001:

1. **Determinism (Principle I) is conditional on network state.** The same commit scanned
   twice can yield different findings, or none. `trivy fs --offline-scan` fixes it — the
   WebGoat scan succeeded immediately with that flag — at the cost of an incomplete Maven
   tree. v1 should pass `--offline-scan` by default and say so in the report.
2. **Semgrep has the same problem, less visibly.** `--config=p/default` fetches a versionless
   ruleset from the registry: the rules can change between runs with no input change, so a
   re-run months later is not reproducible. Determinism at the level the design promises
   requires vendoring the ruleset (or pinning a Docker image that contains it) and recording
   its hash in `run.json`.
3. **The trust boundary needs a footnote.** "Your code never leaves your infrastructure"
   stays true — but dependency *coordinates* (group, artifact, version) go to Maven Central,
   and Semgrep config fetches go to the registry. Both are metadata about the codebase
   leaving the perimeter. The README claim should be precise about this rather than absolute.
4. **A rate-limited engine blocks for ~30 minutes.** Retrying is useless. Exit 2 with the
   engine's own message is the right behaviour (already the contract), and per-run
   all-or-nothing means no half-populated report — but the CI failure mode deserves a line in
   the docs.

## Round 6 — five more ecosystems (the generic-tool argument)

Rounds 1–5 optimised for the repos at hand. That is the wrong target: this is a tool other
people run on code we will never see, so the mapping's breadth is a product requirement, not
a convenience. Five more public repos, chosen purely to add ecosystems:

| Repo | Stack | Findings | Rule ids | Unmapped before |
|---|---|---|---|---|
| [terragoat](https://github.com/bridgecrewio/terragoat) | Terraform / IaC | 638 | 415 | **277** |
| [railsgoat](https://github.com/OWASP/railsgoat) | Ruby / Rails, Gemfile.lock | 126 | 96 | 19 |
| [DVWA](https://github.com/digininja/DVWA) | PHP | 92 | 22 | **67** |
| [mdBook](https://github.com/rust-lang/mdBook) | Rust, Cargo.lock | 28 | 3 | 0 |
| [dotnet/samples](https://github.com/dotnet/samples) (core subset) | C# | 23 | 5 | 0 |

**363 unmapped findings across 186 rule ids** — by far the largest gap of any round, and it
would have shipped invisibly. Families added:

| Family | Now → |
|---|---|
| `trivy:(AWS|AZU|GCP|DIG|GITHUB|OPNSTK|CLDSTK|NIF|AVD)-*` cloud checks | `op.exp.2` |
| `semgrep:terraform.*`, `cloudformation`, `ansible`, `helm`, `bicep` | `op.exp.2` |
| `php.lang.security.injection.*`, `*cors*`, `php.(laravel|symfony|wordpress).*` | `mp.sw.1` + `mp.s.2` |
| `ruby.(rails|rack|sinatra).*` | `mp.sw.1` + `mp.s.2` |
| `(php|ruby|rust|csharp|kotlin|scala|swift|c|cpp|elixir).lang.*` | `mp.sw.1` |

Rust and C# produced zero unmapped findings — but on 3 and 5 rule ids respectively, which is
too thin to call coverage. Treat those two as unverified rather than clean.

A third must-fall-through probe fell: `semgrep:terraform.aws.security.aws-s3-bucket-public-read`
was excluded as "IaC namespace not covered", and terragoat fired its sibling. **Three of the
original six probes have now been contradicted by real data.** The remaining probes were
rewritten around unknown *engines* (`gitleaks:`, `checkov:`, a fictitious one) because the
language catch-alls absorb unknown rules within a known engine — after ten repos, unknown
engine is the only reliable route to the appendix, and that is the shape spec 002's fixture
should take.

## Corpus totals

15 repositories · 23 SARIF documents · **1718 findings · 822 distinct `tool:rule` ids · 0
unmapped**

| Measure | Findings |
|---|---|
| `mp.sw.2` | 800 |
| `op.exp.4` | 722 |
| `mp.sw.1` | 580 |
| `op.exp.2` | 332 |
| `mp.s.2` | 291 |
| `op.exp.3` | 67 |

Ecosystems covered: Python (Django, Flask, FastAPI, SQLAlchemy), JavaScript/TypeScript
(Express), Java (Spring, servlets), Go, Ruby (Rails), PHP, Rust, C#, Terraform, CloudFormation
shapes, Kubernetes, Docker/Compose, GitHub Actions, and the package ecosystems Trivy reads
(pip, npm, Maven, Go modules, Cargo, RubyGems).

Not covered, and honest about it: Elixir, Scala, Kotlin, Swift, C/C++ (patterns exist for
their `*.lang.*` namespaces but no repo has exercised them), plus every engine other than
Semgrep and Trivy.
