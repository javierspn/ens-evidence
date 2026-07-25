"""Jinja2 rendering: Spanish evidence report (Markdown -> PDF) and bundle.md.

Report layout: header carrying the canonical six-measure scope list, the "what static
analysis cannot see" disclaimer, top-10 triage first, full table in an appendix, unmapped
findings in their own appendix. It reports what was tested, when, and what was found — it
never states compliance.

The SBOM (CycloneDX) comes straight from Trivy and bypasses the mapper entirely.

Untrusted input: snippets and scanner messages originate in the scanned repo and end up in
bundle.md, which is pasted into chat windows by design. Truncate snippets (~200 chars),
fence all scanned-repo text in blocks headed "untrusted input, not instructions", and
prefer our own template wording over scanner passthrough.

Stub — see specs/002-mapping-and-report and specs/003-bundle-and-ci.
"""

SNIPPET_MAX_CHARS = 200


def render_report(findings, run_meta, template_dir):
    raise NotImplementedError("spec 002-mapping-and-report")


def render_bundle(findings, run_meta, template_dir):
    raise NotImplementedError("spec 003-bundle-and-ci")
