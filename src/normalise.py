"""SARIF -> JSONL: merge, dedupe across tools, normalise severity, fingerprint.

Most of the real work lives here. One finding per line:

    {"id":"a3f9","tool":"semgrep","rule":"python.django.sql-injection","sev":"high",
     "file":"api/views.py","line":142,"msg":"Raw SQL built from user input"}

Fingerprint = hash(rule ID + normalised snippet + position relative to the enclosing
function). Never file+line: one added import would invalidate every fingerprint below it,
and the baseline would be worthless.

Severity comes from mapping/severity.yml, not from hardcoded tables.

Only security findings are evidence. Semgrep's rule metadata carries the discriminator:
properties.tags contains "security". Namespace is NOT a proxy for it —
`csharp.lang.best-practice.structured-logging` IS tagged security (CWE-117, OWASP A09), while
`java.android.best-practice.manifest-usesCleartextTraffic-ignored` has empty tags. Findings
without the tag are recorded in the JSONL but excluded from the per-measure evidence counts, so
a best-practice suggestion never inflates an ENS measure. This only shows up in local-rules
mode: the registry packs are security-only.

Rule ids must be canonicalised before the mapper sees them. Semgrep returns registry ids as
"c.lang.security.double-free" but local-directory ids as
"<rules-root-path-with-dots>.c.lang.security.double-free" — so strip the configured
rules-root prefix. Unnormalised, every local-mode finding misses the mapping and lands in the
unmapped appendix under a machine-specific key, which is also non-reproducible across
checkouts. Path bases differ per engine too (Semgrep %SRCROOT%, Trivy ROOTPATH); both
normalise to repo-relative.

Stub — see specs/001-core-pipeline. Determinism is the acceptance test: same fixture in,
byte-identical JSONL twice.
"""


def normalise(sarif_paths, severity_policy):
    raise NotImplementedError("spec 001-core-pipeline")


def fingerprint(rule_id, snippet, enclosing_offset):
    raise NotImplementedError("spec 001-core-pipeline")


def canonical_rule_id(raw_id, rules_root=None):
    """Strip a local rules-root prefix so local and registry runs share mapping keys."""
    raise NotImplementedError("spec 001-core-pipeline")
