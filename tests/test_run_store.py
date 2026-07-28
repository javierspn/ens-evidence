"""Run-store tests: coverage record (T030), skip key + immutability (T031),
run.json completeness (T032). Engine-free — the engine seam is faked exactly as in
test_cli.py."""

import copy
import json
import subprocess

import pytest

from ens_evidence import run
from tests.test_cli import fake_engines, make_repo, scan


def run_dirs(repo):
    return sorted(
        p
        for p in (repo / "out").iterdir()
        if p.is_dir() and not p.is_symlink() and not p.name.startswith(".")
    )


def latest_run_json(repo):
    return json.loads((repo / "out" / "latest" / "run.json").read_text())


# --- T030 coverage -----------------------------------------------------------


def test_language_census_is_extension_driven(tmp_path):
    tree = tmp_path / "t"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "x.py").write_text("")
    (tree / "a" / "y.py").write_text("")
    (tree / "z.ex").write_text("")
    (tree / "Dockerfile").write_text("")
    (tree / ".git").mkdir()
    (tree / ".git" / "junk.py").write_text("")
    census = run.language_census(tree)
    assert census == {"dockerfile": 1, "elixir": 1, "python": 2}


def test_rules_per_language_counts_local_root(tmp_path):
    root = tmp_path / "rules"
    (root / "python" / "lang").mkdir(parents=True)
    (root / "python" / "lang" / "a.yaml").write_text("")
    (root / "python" / "lang" / "b.yml").write_text("")
    (root / "c").mkdir()
    (root / "c" / "x.yaml").write_text("")
    assert run.rules_per_language(root) == {"c": 1, "python": 2}


def test_coverage_local_mode_flags_not_analysed(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    # Tracked, not merely present: the census counts what the engines can see, and semgrep
    # reads only git-tracked files.
    (repo / "demo.ex").write_text("")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "ex"],
        cwd=repo,
        check=True,
    )
    rules = tmp_path / "rules"
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "a.yaml").write_text("")
    fake_engines(monkeypatch)
    monkeypatch.setenv("ENS_EVIDENCE_RULES_ROOT", str(rules))
    assert scan(repo) == 0
    cov = latest_run_json(repo)["coverage"]
    assert "elixir" in cov["languages_not_analysed"]
    assert cov["rules_per_language"] == {"python": 1}
    assert cov["dependency_analysis"] == "skipped-no-lockfile"


def test_coverage_registry_mode_says_uncounted(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    cov = latest_run_json(repo)["coverage"]
    assert cov["rules_per_language"] == "registry-uncounted"


def test_coverage_lockfile_detection(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    (repo / "requirements.txt").write_text("pyyaml==6.0\n")
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    assert latest_run_json(repo)["coverage"]["dependency_analysis"] == "done"


# --- T031 skip key + immutability -------------------------------------------


def test_unchanged_skip_key_skips_the_run(tmp_path, monkeypatch, capsys):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    assert len(run_dirs(repo)) == 1
    assert scan(repo) == 0  # same key -> skip
    assert len(run_dirs(repo)) == 1
    out = capsys.readouterr().out
    assert '"skipped":true' in out.replace(" ", "")


def test_any_component_change_makes_a_real_run(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    # baseline hash is part of the key
    assert run.main(["baseline", "update", str(repo)]) == 0
    assert scan(repo) == 0
    assert len(run_dirs(repo)) == 2
    # engine version is part of the key
    bumped = dict(run._engine_versions())
    bumped["semgrep"] = "9.9.9"
    monkeypatch.setattr(run, "_engine_versions", lambda: bumped)
    assert scan(repo) == 0
    assert len(run_dirs(repo)) == 3


def test_force_reruns_and_never_overwrites(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    first = run_dirs(repo)[0]
    stamp = (first / "findings.jsonl").read_bytes()
    assert scan(repo, "--force") == 0
    assert len(run_dirs(repo)) == 2  # append-only, no overwrite
    assert (first / "findings.jsonl").read_bytes() == stamp
    # the two runs' findings are byte-identical (determinism)
    a, b = run_dirs(repo)
    assert (a / "findings.jsonl").read_bytes() == (b / "findings.jsonl").read_bytes()


def test_interrupted_run_leaves_no_visible_run_dir(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("mid-run crash")

    monkeypatch.setattr(run.normalise, "normalise", boom)
    with pytest.raises(RuntimeError):
        run.main(["scan", str(repo)])
    assert run_dirs(repo) == []
    assert not (repo / "out" / "latest").exists()


# --- T032 run.json completeness ----------------------------------------------


def test_run_json_records_every_moving_part(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    doc = latest_run_json(repo)
    assert doc["schema"] == "ens-evidence/1"
    assert doc["run"]["git_sha"] and doc["run"]["git_short_sha"]
    eng = doc["engines"]
    assert eng["semgrep"] and eng["trivy"] and eng["trivy_db"] and eng["trivy_checks_bundle"]
    assert doc["rules"]["mode"] in ("local", "registry")
    assert doc["mapping"]["severity_sha256"] and doc["mapping"]["defect_classes_sha256"]
    assert doc["baseline_sha256"] is None  # no baseline yet
    assert doc["config_sha256"] and doc["skip_key"]
    assert set(doc["coverage"]) == {
        "languages_detected",
        "rules_per_language",
        "languages_not_analysed",
        "dependency_analysis",
    }


def test_counts_are_consistent_with_findings(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    doc = latest_run_json(repo)
    lines = (repo / "out" / "latest" / "findings.jsonl").read_text().splitlines()[1:]
    findings = [json.loads(ln) for ln in lines]
    c = doc["counts"]
    assert c["total"] == len(findings)
    assert c["security"] == sum(1 for f in findings if f["security"])
    assert c["non_security"] == c["total"] - c["security"]
    assert c["new"] == sum(1 for f in findings if f["new"])
    assert c["deduped_away"] > 0  # the fixture corpus contains known duplicates


# --- SARIF pruning (T030c) ---------------------------------------------------


SARIF_WITH_CATALOGUE = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [
                        {"id": "fired.rule", "fullDescription": {"text": "matched"}},
                        {"id": "quiet.rule", "fullDescription": {"text": "never matched"}},
                        {"id": "also.quiet", "fullDescription": {"text": "never matched"}},
                    ],
                }
            },
            "results": [{"ruleId": "fired.rule", "message": {"text": "x"}}],
        }
    ]
}


def test_pruning_keeps_only_the_rules_that_fired(tmp_path):
    """A pinned rules root puts the WHOLE ruleset in the driver's catalogue — 2126 rule
    descriptions for 9 findings, measured 2026-07-26. The run store is the portable
    evidence unit, so it must not carry third-party rule documentation."""
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(SARIF_WITH_CATALOGUE))
    assert run.prune_sarif_rules(path) == {"kept": 1, "dropped": 2}
    driver = json.loads(path.read_text())["runs"][0]["tool"]["driver"]
    assert [r["id"] for r in driver["rules"]] == ["fired.rule"]


def test_pruning_keeps_the_provenance_of_every_reported_finding(tmp_path):
    """The fired rules stay: they are why a finding says what it says, and without them
    the stored SARIF cannot be checked against findings.jsonl."""
    document = copy.deepcopy(SARIF_WITH_CATALOGUE)
    document["runs"][0]["results"].append({"ruleId": "also.quiet", "message": {"text": "y"}})
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(document))
    assert run.prune_sarif_rules(path) == {"kept": 2, "dropped": 1}
    fired = {r["ruleId"] for r in json.loads(path.read_text())["runs"][0]["results"]}
    kept = {r["id"] for r in json.loads(path.read_text())["runs"][0]["tool"]["driver"]["rules"]}
    assert fired == kept


def test_pruning_is_deterministic_and_idempotent(tmp_path):
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(SARIF_WITH_CATALOGUE))
    run.prune_sarif_rules(path)
    once = path.read_bytes()
    assert run.prune_sarif_rules(path) == {"kept": 1, "dropped": 0}
    assert path.read_bytes() == once


def test_pruning_tolerates_a_sarif_without_a_catalogue(tmp_path):
    path = tmp_path / "trivy.sarif"
    path.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "trivy"}}}]}))
    assert run.prune_sarif_rules(path) == {"kept": 0, "dropped": 0}


def test_run_json_records_what_was_pruned(tmp_path, monkeypatch):
    """A stored artifact that is no longer byte-identical engine output has to say so, or
    the provenance claim is false."""
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    assert scan(repo) == 0
    pruned = latest_run_json(repo)["sarif_rules_pruned"]
    assert set(pruned) == {"semgrep", "trivy"}
    assert all({"kept", "dropped"} == set(v) for v in pruned.values())


# --- coverage defects found by reading the sample render (phase 6) ------------


def test_census_counts_what_the_engines_can_see(tmp_path):
    """A filesystem walk counted a virtualenv: 1500 python files against the 117 semgrep
    actually scanned, observed 2026-07-26 in the sample render. Semgrep reads only
    git-tracked files, so a larger census discloses a repository nobody analysed."""
    repo = make_repo(tmp_path)
    vendored = repo / ".venv" / "lib" / "site-packages"
    vendored.mkdir(parents=True)
    for n in range(5):
        (vendored / f"dep{n}.py").write_text("")
    (repo / "untracked.py").write_text("")
    assert run.language_census(repo) == {"python": 1}  # app.py only


def test_census_falls_back_to_a_walk_without_git(tmp_path):
    tree = tmp_path / "plain"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "a.py").write_text("")
    (tree / "Dockerfile").write_text("")
    assert run.language_census(tree) == {"dockerfile": 1, "python": 1}


def test_a_language_with_rules_under_another_name_is_not_reported_as_a_gap():
    """The coverage table said "shell — no rules ran" while 6 bash rules had just run on it.
    Principle IV cuts both ways: a claimed gap that is not real makes the real gaps less
    believable."""
    rules = {"mode": "local", "per_language": {"bash": 6}}
    coverage = run.build_coverage_from_census({"shell": 9}, False, rules)
    assert coverage["languages_not_analysed"] == []


def test_a_language_with_no_rules_anywhere_is_still_reported():
    rules = {"mode": "local", "per_language": {"bash": 6}}
    coverage = run.build_coverage_from_census({"shell": 9, "elixir": 2}, False, rules)
    assert coverage["languages_not_analysed"] == ["elixir"]
