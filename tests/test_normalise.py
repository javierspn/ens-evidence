"""Normaliser tests — engine-free, driven by the captured SARIF fixtures in
tests/fixtures/sarif/ (Semgrep 1.171.0 + Trivy 0.72.0 over fixtures/vulnerable-app).

The byte-identity test is the constitution's acceptance test in miniature: the
shuffled fixtures hold the same findings with permuted result arrays, and the
output bytes must not care.
"""

import json
from pathlib import Path

import pytest

from ens_evidence import MAPPING_DIR, normalise

ROOT = Path(__file__).resolve().parent.parent
SARIF = ROOT / "tests" / "fixtures" / "sarif"
SEVERITY = MAPPING_DIR / "severity.yml"
CLASSES = MAPPING_DIR / "defect_classes.yml"


def run_normalise(paths=None, baseline=frozenset()):
    return normalise.normalise(
        sarif_paths=paths or [SARIF / "semgrep.sarif", SARIF / "trivy.sarif"],
        severity_policy=normalise.load_severity(SEVERITY),
        defect_classes=normalise.load_defect_classes(CLASSES),
        baseline=baseline,
    )


# --- T008 canonical rule ids -------------------------------------------------


def test_registry_id_passes_through():
    assert (
        normalise.canonical_rule_id("c.lang.security.double-free") == "c.lang.security.double-free"
    )


def test_local_rules_root_prefix_is_stripped():
    raw = "home.user..ens-rules.c.lang.security.double-free"
    assert (
        normalise.canonical_rule_id(raw, rules_root="/home/user/.ens-rules")
        == "c.lang.security.double-free"
    )


def test_both_modes_share_the_canonical_id():
    registry = normalise.canonical_rule_id("dockerfile.security.missing-user")
    local = normalise.canonical_rule_id(
        "opt.rules.dockerfile.security.missing-user", rules_root="/opt/rules"
    )
    assert registry == local == "dockerfile.security.missing-user"


def test_basename_prefix_is_stripped_which_is_the_shape_semgrep_emits():
    """The two cases above assume semgrep prefixes the whole config path. It does not: it
    uses the last component only, and drops the leading dot of a hidden directory. Observed
    2026-07-28 with semgrep 1.171.0 — every pinned-mode run emitted `ens-rules.<id>`
    regardless of where the checkout lived, so nothing was ever stripped in production and
    every finding fell through to the unmapped appendix."""
    for root in ("/private/tmp/scratch/.ens-rules", ".ens-rules", "/opt/.ens-rules"):
        assert (
            normalise.canonical_rule_id(
                "ens-rules.dockerfile.security.missing-user", rules_root=root
            )
            == "dockerfile.security.missing-user"
        )


# --- T009 security split -----------------------------------------------------


def test_tagged_findings_are_security():
    by_rule = {f["rule"]: f for f in run_normalise()}
    # every rule in the fixture corpus is tagged security by its engine
    assert by_rule["python.lang.security.audit.exec-detected.exec-detected"]["security"] is True
    assert by_rule["DS-0026"]["security"] is True


def test_untagged_finding_stays_in_jsonl_marked_non_security(tmp_path):
    sarif = json.loads((SARIF / "semgrep.sarif").read_text())
    run = sarif["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    rule["properties"]["tags"] = ["CWE-000: Something"]  # tag removed
    p = tmp_path / "untagged.sarif"
    p.write_text(json.dumps(sarif))
    findings = run_normalise(paths=[p])
    target = [f for f in findings if f["rule"] == rule["id"]]
    assert target and all(f["security"] is False for f in target)
    # non-security findings are present but flagged — never dropped
    assert len(findings) == len(json.loads(json.dumps(findings)))


# --- T010 path normalisation + dedupe ---------------------------------------


def test_paths_are_repo_relative_posix():
    for f in run_normalise():
        assert not f["file"].startswith("/")
        assert "%SRCROOT%" not in f["file"] and "ROOTPATH" not in f["file"]
        assert not f["file"].startswith("./")


def test_cross_engine_duplicates_collapse():
    findings = run_normalise()
    roots = [f for f in findings if f["class"] == "container-runs-as-root"]
    assert len(roots) == 1
    merged = roots[0]["merged_from"]
    assert ["trivy", "DS-0002"] in merged
    assert any(r.startswith("dockerfile.security.missing-user") for _, r in merged)
    pods = [f for f in findings if f["class"] == "pod-runs-as-root"]
    assert len(pods) == 1


def test_same_rule_same_file_collapses():
    # trivy flags KSV-0118 twice on deploy/k8s.yaml; self-class dedupes them
    findings = run_normalise()
    assert len([f for f in findings if f["rule"] == "KSV-0118"]) == 1


def test_unlisted_rules_never_merge():
    findings = run_normalise()
    # two distinct self-classed rules on the same file stay distinct
    k8s_rules = {f["rule"] for f in findings if f["file"] == "deploy/k8s.yaml"}
    assert {"KSV-0001", "KSV-0014"} <= k8s_rules


# --- T011 severity -----------------------------------------------------------


def test_severities_follow_the_policy():
    by_rule = {f["rule"]: f for f in run_normalise()}
    # trivy severity word from the rule's tags
    assert by_rule["DS-0026"]["sev"] == "low"  # tag LOW
    # semgrep error level -> high
    assert (
        by_rule[
            "yaml.github-actions.security.github-actions-mutable-action-tag"
            ".github-actions-mutable-action-tag"
        ]["sev"]
        == "medium"
    )
    # LOW CONFIDENCE downgrade: warning(medium) -> low
    assert (
        by_rule[
            "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected"
        ]["sev"]
        == "low"
    )


def test_unknown_severity_resolves_to_the_files_declared_default(tmp_path):
    sarif = json.loads((SARIF / "semgrep.sarif").read_text())
    run = sarif["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    rule["defaultConfiguration"]["level"] = "bizarre"
    p = tmp_path / "weird.sarif"
    p.write_text(json.dumps(sarif))
    findings = run_normalise(paths=[p])
    target = [f for f in findings if f["rule"] == rule["id"]]
    # severity.yml declares `default: medium` — a data-file decision, not a silent one
    assert target and all(f["sev"] == "medium" for f in target)


def test_missing_default_makes_unknown_severity_a_hard_error(tmp_path):
    policy = normalise.load_severity(SEVERITY)
    policy.pop("default", None)
    sarif = json.loads((SARIF / "semgrep.sarif").read_text())
    sarif["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"] = "bizarre"
    p = tmp_path / "weird.sarif"
    p.write_text(json.dumps(sarif))
    with pytest.raises(normalise.UnknownSeverityError):
        normalise.normalise(
            sarif_paths=[p],
            severity_policy=policy,
            defect_classes=normalise.load_defect_classes(CLASSES),
        )


# --- T012 fingerprints -------------------------------------------------------


def test_fingerprint_ignores_lines():
    a = normalise.fingerprint("rule-x", "exec(payload)", 0)
    b = normalise.fingerprint("rule-x", "exec(payload)", 0)
    assert a == b and len(a) == 16


def test_identical_snippets_get_distinct_ordinals():
    assert normalise.fingerprint("r", "s", 0) != normalise.fingerprint("r", "s", 1)


def test_snippet_whitespace_is_collapsed():
    assert normalise.fingerprint("r", "exec(  payload )", 0) == normalise.fingerprint(
        "r", "exec( payload )", 0
    )


def test_added_import_shift_keeps_fingerprints(tmp_path):
    baseline_fps = {f["fingerprint"] for f in run_normalise()}
    sarif = json.loads((SARIF / "semgrep.sarif").read_text())
    for res in sarif["runs"][0]["results"]:
        region = res["locations"][0]["physicalLocation"]["region"]
        region["startLine"] += 1
        region["endLine"] += 1
    p = tmp_path / "shifted.sarif"
    p.write_text(json.dumps(sarif))
    shifted = normalise.normalise(
        sarif_paths=[p, SARIF / "trivy.sarif"],
        severity_policy=normalise.load_severity(SEVERITY),
        defect_classes=normalise.load_defect_classes(CLASSES),
    )
    assert {f["fingerprint"] for f in shifted} == baseline_fps


# --- T013 byte identity ------------------------------------------------------


def test_shuffled_engine_output_produces_identical_bytes(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    normalise.write_jsonl(a, run_normalise())
    normalise.write_jsonl(
        b,
        run_normalise(paths=[SARIF / "semgrep.shuffled.sarif", SARIF / "trivy.shuffled.sarif"]),
    )
    assert a.read_bytes() == b.read_bytes()


def test_jsonl_shape(tmp_path):
    p = tmp_path / "f.jsonl"
    normalise.write_jsonl(p, run_normalise())
    lines = p.read_text().splitlines()
    assert lines[0] == '{"schema":"ens-evidence/1"}'
    for line in lines[1:]:
        obj = json.loads(line)
        assert list(obj.keys()) == sorted(obj.keys())
    # sorted by (file, class, rule, fingerprint)
    keys = [
        (o["file"], o["class"], o["rule"], o["fingerprint"]) for o in map(json.loads, lines[1:])
    ]
    assert keys == sorted(keys)


# --- T024 baseline marking ---------------------------------------------------


def test_new_marking_against_baseline():
    all_new = run_normalise(baseline=frozenset())
    assert all(f["new"] for f in all_new)
    fps = {f["fingerprint"] for f in all_new}
    known = run_normalise(baseline=frozenset(fps))
    assert all(not f["new"] for f in known)
    partial = run_normalise(baseline=frozenset(list(fps)[:3]))
    assert sum(1 for f in partial if not f["new"]) == 3
