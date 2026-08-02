"""Mapper tests (T004, T007, T023): first-match-wins lookup over `<tool>:<rule-id>`.

The authority for match semantics is `tests/test_mapping_contract.py`, whose reference
implementation uses `re.search` and is documented as "mirroring what mapper.py must
implement". These tests pin mapper.py to that behaviour and to the ordering the table
depends on.
"""

from pathlib import Path

import pytest
import yaml

from ens_evidence import MAPPING_DIR, mapper

ROOT = Path(__file__).resolve().parent.parent
MAPPING = MAPPING_DIR / "ens_rd311.yml"
CASES = ROOT / "tests" / "mapping-cases.yml"


@pytest.fixture(scope="module")
def rules():
    return mapper.load_rules(MAPPING)


@pytest.fixture(scope="module")
def contract():
    return yaml.safe_load(CASES.read_text())


# --- T004 lookup semantics ---------------------------------------------------


def test_first_match_wins_over_file_order(rules):
    """`trivy:KSV-0013` is `$`-anchored and precedes the generic `trivy:KSV-.*`; if
    ordering or anchoring broke, it would land under op.exp.2 instead of op.exp.3."""
    assert mapper.measures_for("trivy", "KSV-0013", rules) == ["op.exp.3"]
    assert mapper.measures_for("trivy", "KSV-0125", rules) == ["op.exp.3"]
    assert mapper.measures_for("trivy", "KSV-0118", rules) == ["op.exp.2"]


def test_unmatched_falls_through_to_the_files_default(rules):
    assert mapper.measures_for("mysteryengine", "SOME-RULE-1", rules) == ["unmapped"]


def test_matches_the_contract_tests_reference_implementation(rules, contract):
    """Every observed case in the contract fixture must map as recorded."""
    wrong = []
    for case in contract["cases"]:
        tool, rule_id = case["id"].split(":", 1)
        got = mapper.measures_for(tool, rule_id, rules)
        if got != case["measures"]:
            wrong.append((case["id"], case["measures"], got))
    assert not wrong, f"mapper disagrees with the contract: {wrong}"


def test_patterns_are_compiled_once(rules):
    """load_rules returns compiled patterns; measures_for must not recompile per call.
    The last entry is the file's default, carried as a None sentinel so lookup stays a
    single loop."""
    import re  # noqa: PLC0415

    *patterns, default = rules
    assert all(isinstance(pattern, re.Pattern) for pattern, _, _ in patterns)
    assert default[0] is None


def test_rules_are_data_not_code(rules):
    """Every measure the mapper can emit comes from the data file."""
    raw = yaml.safe_load(MAPPING.read_text())
    from_file = {m for rule in raw["rules"] for m in rule["measures"]}
    from_file |= set(raw["default"]["measures"])
    emitted = {m for _, measures, _ in rules for m in measures}
    assert emitted <= from_file


def test_matched_rule_is_reported(rules):
    """`explain` needs the pattern that matched, not only the measures."""
    measures, pattern, _ = mapper.classify("trivy", "KSV-0013", rules)
    assert measures == ["op.exp.3"]
    assert "KSV-0013" in pattern

    measures, pattern, _ = mapper.classify("mysteryengine", "SOME-RULE-1", rules)
    assert measures == ["unmapped"]
    assert pattern is None


def test_classify_carries_the_entrys_own_prose(rules):
    """The report heads a finding with our Spanish wording, so the matching entry's
    `title`/`why` must travel with the measures — a second matching pass to fetch them
    could disagree with the first about which entry won."""
    _, _, prose = mapper.classify("trivy", "KSV-0013", rules)
    assert prose["title"] and prose["why"]

    _, _, prose = mapper.classify("mysteryengine", "SOME-RULE-1", rules)
    assert prose == {"title": None, "why": None}


# --- T023 fall-through probes ------------------------------------------------


def test_every_unmapped_probe_still_falls_through(rules, contract):
    """These are assumptions awaiting contradiction, not settled facts — three earlier
    probes were disproven by real scans. A probe that starts matching means either a
    catch-all grew too broad or an ecosystem is now covered; both need a deliberate
    commit, not a silent pass."""
    matched = []
    for probe in contract["unmapped"]:
        tool, rule_id = probe["id"].split(":", 1)
        got = mapper.measures_for(tool, rule_id, rules)
        if got != ["unmapped"]:
            matched.append((probe["id"], got))
    assert not matched, f"expected unmapped, now matching: {matched}"


def test_local_rule_ids_do_not_map_before_canonicalisation(rules):
    """Spec 001 canonicalises ids; the raw local form must NOT map, or a local-mode run
    would file findings under a machine-specific key."""
    raw = "tmp.rules.semgrep-rules.c.lang.security.double-free"
    assert mapper.measures_for("semgrep", raw, rules) == ["unmapped"]
    assert mapper.measures_for("semgrep", "c.lang.security.double-free", rules) == ["mp.sw.1"]


# --- T007 non-security exclusion ---------------------------------------------


@pytest.mark.parametrize(
    "security,measures,expected",
    [
        (True, ["mp.sw.1"], True),
        (False, ["mp.sw.1"], False),  # engine did not tag it security
        (True, ["unmapped"], False),  # no rule matched
        (False, ["unmapped"], False),
    ],
)
def test_counts_toward_measures(security, measures, expected):
    finding = {"security": security, "measures": measures}
    assert mapper.counts_toward_measures(finding) is expected
