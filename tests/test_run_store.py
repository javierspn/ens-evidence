"""Run-store tests: coverage record (T030), skip key + immutability (T031),
run.json completeness (T032). Engine-free — the engine seam is faked exactly as in
test_cli.py."""

import json

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
    (repo / "demo.ex").write_text("")
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
