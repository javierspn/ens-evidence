# templates/

Jinja2 templates for the evidence report and `bundle.md`.

Seeded empty on purpose — the report template is authored in spec
`002-mapping-and-report`, once real scanner output exists to render. Report structure and
the untrusted-input fencing rules are in [DESIGN.md](../DESIGN.md).

The report header MUST carry the canonical six-measure scope list verbatim (principle III).
It is the fourth place that list appears, alongside the constitution, the README and
`mapping/ens_rd311.yml` — a template that omits or paraphrases it is a release blocker.
