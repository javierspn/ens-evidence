"""Gates for the data files, which are this repo's real asset and its real risk.

`src/` is all stubs, so lint and bandit have almost nothing to read here. What can
actually break is the mapping: a regex edit that silently stops matching, a measure
that drifts out of scope, or the canonical measure list diverging between the four
places principle III binds together. None of that is visible to a python linter.

These tests replace the ad-hoc snippet used while authoring the mapping across ten
scan rounds (see docs/scan-baseline.md).
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent

# Principle III: this list is the contract. Changing it is a four-file commit.
SCOPE = ["mp.sw.1", "mp.sw.2", "mp.s.2", "op.exp.2", "op.exp.3", "op.exp.4"]
SCOPE_LINE = " · ".join(f"`{m}`" for m in SCOPE)

# The four places that must carry the list verbatim, and how many times each does.
SCOPE_DOCS = {
    "README.md": 2,
    "DESIGN.md": 1,
    ".specify/memory/constitution.md": 1,
    # The fourth site: the report header (principle III). The template carries the line
    # literally, exactly as the other three do. That a template CONTAINS it does not
    # prove the rendered report EMITS it, so tests/test_render.py asserts the rendered
    # side separately — both are required.
    "templates/report.md.j2": 1,
}


@pytest.fixture(scope="module")
def mapping():
    return yaml.safe_load((ROOT / "mapping" / "ens_rd311.yml").read_text())


@pytest.fixture(scope="module")
def severity():
    return yaml.safe_load((ROOT / "mapping" / "severity.yml").read_text())


@pytest.fixture(scope="module")
def contract():
    return yaml.safe_load((ROOT / "tests" / "mapping-cases.yml").read_text())


def measures_for(key, mapping):
    """First-match-wins lookup, mirroring what mapper.py must implement."""
    for rule in mapping["rules"]:
        if re.search(rule["match"], key):
            return rule["measures"]
    return mapping["default"]["measures"]


def test_every_pattern_compiles(mapping):
    for rule in mapping["rules"]:
        re.compile(rule["match"])


def test_no_measure_outside_scope(mapping):
    used = {m for rule in mapping["rules"] for m in rule["measures"]}
    assert used <= set(SCOPE), f"off-scope measures: {sorted(used - set(SCOPE))}"


def test_every_scope_measure_has_at_least_one_rule(mapping):
    """A measure with no rule appears in every report with nothing filed under it —
    which is how op.acc.5 was caught and dropped in constitution 1.1.0."""
    used = {m for rule in mapping["rules"] for m in rule["measures"]}
    assert set(SCOPE) <= used, f"measures with no rule: {sorted(set(SCOPE) - used)}"


@pytest.mark.parametrize("doc,count", SCOPE_DOCS.items())
def test_scope_list_is_verbatim_everywhere(doc, count):
    text = (ROOT / doc).read_text()
    assert text.count(SCOPE_LINE) == count, (
        f"{doc} must carry the canonical scope list {count}x, verbatim (principle III)"
    )


def test_mapping_header_carries_scope_list(mapping):
    header = (ROOT / "mapping" / "ens_rd311.yml").read_text().split("version:")[0]
    for measure in SCOPE:
        assert measure in header, f"{measure} missing from mapping header"


def test_observed_cases_map_as_expected(contract, mapping):
    wrong = [
        (c["id"], c["measures"], measures_for(c["id"], mapping))
        for c in contract["cases"]
        if measures_for(c["id"], mapping) != c["measures"]
    ]
    assert not wrong, f"mapping changed for observed rule ids: {wrong}"


def test_probes_still_fall_through(contract, mapping):
    """These are assumptions, not facts: three earlier probes were disproven by real
    scans. If one starts matching, either a catch-all grew too broad or an ecosystem
    is now covered — both need a deliberate commit, not a silent pass."""
    matched = [
        (c["id"], measures_for(c["id"], mapping))
        for c in contract["unmapped"]
        if measures_for(c["id"], mapping) != ["unmapped"]
    ]
    assert not matched, f"expected unmapped, now matching: {matched}"


def test_local_rule_ids_do_not_map_before_canonicalisation(mapping):
    """Local (non-registry) semgrep runs prefix ids with the rules-root path. That form
    must NOT map — it is normalise.py's job to strip it first (see canonical_rule_id)."""
    raw = "semgrep:tmp.rules.semgrep-rules.c.lang.security.double-free"
    canonical = "semgrep:c.lang.security.double-free"
    assert measures_for(raw, mapping) == ["unmapped"]
    assert measures_for(canonical, mapping) == ["mp.sw.1"]


def test_severity_policy_covers_both_engines(severity):
    assert set(severity["engines"]) == {"semgrep", "trivy"}
    # Trivy's numeric security-severity is the CVSS base score and disagrees with its
    # own severity tag on CVEs, so the tag must be read first.
    assert severity["engines"]["trivy"]["strategy"] == "severity_tag_then_bands"
    assert severity["engines"]["semgrep"]["strategy"] == "sarif_level_with_confidence"
    assert severity["default"] in severity["canonical"]
