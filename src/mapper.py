"""Table lookup: "<tool>:<rule-id>" -> list of ENS measures. Deterministic, no cleverness.

Rules come from mapping/ens_rd311.yml, matched first-to-last; anything unmatched gets the
file's `default` (``unmapped``) and surfaces in the report's appendix for human review.
Adding a framework means adding a data file, never touching this module.

No LLM anywhere in this path.

Stub — see specs/002-mapping-and-report.
"""


def load_rules(path):
    raise NotImplementedError("spec 002-mapping-and-report")


def measures_for(tool, rule_id, rules):
    raise NotImplementedError("spec 002-mapping-and-report")
