# Constitution — ens-evidence

Seeded verbatim from the "Rules (non-negotiable)" section of [DESIGN.md](../../DESIGN.md).
Changes here are changes to the project's identity: edit DESIGN.md and this file in the
same commit, or they drift.

## Rules (non-negotiable)

1. **Deterministic.** Same input → same output, every run. No component with variable output may be load-bearing.
2. **Evidence, not verdict.** The report states what was tested, when, and what was found. It never states compliance.
3. **One scope list**, verbatim in constitution, README, mapping file, report header.
4. **Say what it can't see:** business logic, authn/authz design, runtime config. Static analysis is not an audit — the disclaimer is what makes the output usable as evidence.
5. **Never bulk-copy CCN-STIC or BOE text.** Measure IDs and our own wording only.
6. **Keep it small.** This is a free OSS tool: five verbs, two engines, six measures, data-file extensibility. Feature additions need a validated reason, not restlessness.

## Scope — canonical measure list

Rule 3 binds this list to the README, `mapping/ens_rd311.yml` and the report header.
Divergence between the four is a release blocker.

> `mp.sw.1` · `mp.sw.2` · `mp.s.2` · `op.exp.2` · `op.exp.4` · `op.acc.5`

Measure titles are working labels until verified against the BOE consolidated text of
RD 311/2022 Anexo II (pre-release task).
