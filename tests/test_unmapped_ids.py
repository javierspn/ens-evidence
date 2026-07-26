"""The rules-bump gate's check. Engine-free: it reads committed stored runs.

Constitution 1.4.0 requires new unmapped ids to be mapped before a rules-SHA bump merges.
The negative case matters as much as the positive one: a check that silently scans nothing
passes forever, which is exactly how the previous scan.yml stub survived.
"""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STORED_RUN = ROOT / "tests" / "fixtures" / "run" / "findings.jsonl"
INJECTION_RUN = ROOT / "tests" / "fixtures" / "run-injection" / "findings.jsonl"


def load_script():
    spec = importlib.util.spec_from_file_location(
        "unmapped_ids_script", ROOT / "scripts" / "unmapped_ids.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script():
    return load_script()


def test_exits_1_and_names_the_unmapped_id(script, capsys):
    """The stored fixture carries exactly one unmapped SECURITY row by construction —
    `mysteryengine:SOME-RULE-1`, an unknown engine (tests/fixtures/run/README.md)."""
    assert script.main([str(STORED_RUN)]) == 1
    captured = capsys.readouterr()
    assert captured.out.splitlines() == ["mysteryengine:SOME-RULE-1"]
    assert "ens_rd311.yml" in captured.err


def test_exits_0_when_everything_is_mapped(script, tmp_path, capsys):
    """The negative case. Without it, a check that reads nothing looks like a pass."""
    rows = [
        json.loads(line)
        for line in STORED_RUN.read_text().splitlines()
        if "rule" in json.loads(line)
    ]
    mapped = [r for r in rows if r["tool"] != "mysteryengine"]
    assert mapped, "fixture must still contain mapped rows"
    findings = tmp_path / "findings.jsonl"
    findings.write_text("\n".join(json.dumps(r) for r in mapped) + "\n")
    assert script.main([str(findings)]) == 0
    assert capsys.readouterr().out == ""


def test_non_security_findings_are_not_counted_as_lost_coverage(script, tmp_path):
    """A non-security rule never counts toward a measure, so an unmapped one is a hint, not
    a coverage gap. Counting it would fail the gate on noise and teach people to bypass it."""
    findings = tmp_path / "findings.jsonl"
    findings.write_text(
        json.dumps(
            {
                "tool": "semgrep",
                "rule": "python.lang.best-practice.some-unmapped-hint",
                "security": False,
            }
        )
        + "\n"
    )
    assert script.main([str(findings)]) == 0


def test_ids_are_deduplicated_and_sorted(script, tmp_path, capsys):
    findings = tmp_path / "findings.jsonl"
    rows = [
        {"tool": "z", "rule": "zzz", "security": True},
        {"tool": "a", "rule": "aaa", "security": True},
        {"tool": "z", "rule": "zzz", "security": True},
    ]
    findings.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    assert script.main([str(findings)]) == 1
    assert capsys.readouterr().out.splitlines() == ["a:aaa", "z:zzz"]


def test_several_runs_are_reported_together(script, capsys):
    """The bump job scans the whole fixture corpus, so the ids from every run must arrive in
    one list — a maintainer edits the mapping once, not once per fixture."""
    assert script.main([str(STORED_RUN), str(INJECTION_RUN)]) == 1
    ids = capsys.readouterr().out.splitlines()
    assert ids == sorted(set(ids))
    assert "mysteryengine:SOME-RULE-1" in ids


def test_pinned_mode_rule_ids_are_canonical_not_path_derived(script):
    """A local rules root makes semgrep emit path-derived ids
    (`…scratchpad.semgrep-rules.python.lang.…`, DESIGN.md:179). The normaliser canonicalises
    them, so the ids this gate reports are the ones a mapping pattern can match — otherwise
    every bump would report ids no maintainer could act on."""
    ids = [
        json.loads(line)["rule"]
        for line in INJECTION_RUN.read_text().splitlines()
        if "rule" in json.loads(line)
    ]
    assert ids, "fixture must carry findings"
    assert not any("/" in rule_id or rule_id.startswith("private.") for rule_id in ids)


def test_usage_error_exits_2(script, capsys):
    assert script.main([]) == 2
    assert "findings.jsonl" in capsys.readouterr().err


def test_unreadable_input_exits_2(script, tmp_path, capsys):
    assert script.main([str(tmp_path / "nope.jsonl")]) == 2
    assert "unmapped_ids" in capsys.readouterr().err
