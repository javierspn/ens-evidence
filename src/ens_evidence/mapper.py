"""Table lookup: "<tool>:<rule-id>" -> list of ENS measures. Deterministic, no cleverness.

Rules come from mapping/ens_rd311.yml, matched first-to-last; anything unmatched gets the
file's `default` (``unmapped``) and surfaces in the report's appendix for human review.
Adding a framework means adding a data file, never touching this module — so this module
holds no measure names, no patterns and no special cases.

MATCH SEMANTICS: `re.search`, not `fullmatch`. tests/test_mapping_contract.py ships the
reference implementation ("mirroring what mapper.py must implement") and uses search, and
the table is written for it: `trivy:KSV-0013$` and `trivy:KSV-0125$` carry `$` anchors
precisely because matching is otherwise unanchored, and they must beat the generic
`trivy:KSV-.*` that follows them. The leading `<tool>:` anchors the left side in practice.

Note the deliberate difference from mapping/defect_classes.yml (spec 001), which is
matched with `fullmatch` because its patterns are written as whole-key patterns.
Harmonising the two would silently change one file's meaning. Verified 2026-07-26:
across all 82 rule ids the repo knows, search and fullmatch agree here — the choice is
made to match the contract, not to change outcomes.

No LLM anywhere in this path.
"""

import re
from pathlib import Path

import yaml


def load_rules(path):
    """-> [(compiled pattern, measures)], in file order, with the default last.

    Patterns are compiled once here so lookup never recompiles.
    """
    data = yaml.safe_load(Path(path).read_text())
    rules = [(re.compile(r["match"]), list(r["measures"])) for r in data["rules"]]
    rules.append((None, list(data["default"]["measures"])))
    return rules


def classify(tool, rule_id, rules):
    """-> (measures, matching pattern) — the pattern is what `explain` reports.

    `None` as the pattern means nothing matched and the file's default applied.
    """
    key = f"{tool}:{rule_id}"
    for pattern, measures in rules:
        if pattern is None:  # the default, always last
            return list(measures), None
        if pattern.search(key):
            return list(measures), pattern.pattern
    raise AssertionError("rules must end with the file's default")


def measures_for(tool, rule_id, rules):
    return classify(tool, rule_id, rules)[0]


def counts_toward_measures(finding):
    """Evidence for a measure requires BOTH: the engines tagged it security, and a rule
    matched it. A best-practice suggestion never inflates a measure (spec 002 FR-003),
    and an unmapped finding awaits a human decision rather than being filed."""
    return bool(finding["security"]) and finding["measures"] != ["unmapped"]
