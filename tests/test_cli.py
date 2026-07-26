"""CLI tests: config resolution (T007), the --fail-on gate (T025), and the
real-engine integration scenarios (T023, T029 — marked `engines`).

Unit tests fake the engine seam (run._invoke_engines / run._engine_versions) so the
whole scan path runs from the captured SARIF fixtures, engine-free.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src import run

ROOT = Path(__file__).resolve().parent.parent
SARIF = ROOT / "tests" / "fixtures" / "sarif"


# --- helpers -----------------------------------------------------------------


def make_repo(tmp_path, name="repo"):
    repo = tmp_path / name
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=repo,
        check=True,
    )
    return repo


FAKE_VERSIONS = {
    "semgrep": "1.171.0",
    "trivy": "0.72.0",
    "trivy_db": {"version": 2, "updated_at": "2026-07-25T07:31:15Z"},
    "trivy_checks_bundle": "sha256:test",
}


def fake_engines(monkeypatch, semgrep=SARIF / "semgrep.sarif", trivy=SARIF / "trivy.sarif"):
    def _invoke(target, cfg, tmp):
        shutil.copy(semgrep, tmp / "semgrep.sarif")
        shutil.copy(trivy, tmp / "trivy.sarif")
        (tmp / "sbom.cdx.json").write_text('{"bomFormat": "CycloneDX"}\n')
        return tmp / "semgrep.sarif", tmp / "trivy.sarif"

    monkeypatch.setattr(run, "_invoke_engines", _invoke)
    monkeypatch.setattr(run, "_engine_versions", lambda: dict(FAKE_VERSIONS))
    monkeypatch.setattr(run, "_require_binaries", lambda: None)


def scan(repo, *argv):
    return run.main(["scan", str(repo), *argv])


# --- T007 config resolution --------------------------------------------------


def test_flags_beat_env_beat_file_beat_defaults(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    (repo / ".ens-evidence.yml").write_text("fail_on: low\n")
    cfg, _ = run.resolve_config({}, {}, repo)
    assert cfg["fail_on"] == "low"
    cfg, _ = run.resolve_config({}, {"ENS_EVIDENCE_FAIL_ON": "medium"}, repo)
    assert cfg["fail_on"] == "medium"
    cfg, _ = run.resolve_config({"fail_on": "high"}, {"ENS_EVIDENCE_FAIL_ON": "medium"}, repo)
    assert cfg["fail_on"] == "high"


def test_defaults_apply_without_any_source(tmp_path):
    repo = make_repo(tmp_path)
    cfg, digest = run.resolve_config({}, {}, repo)
    assert cfg["fail_on"] is None and cfg["rules_root"] is None
    assert len(digest) == 64


def test_config_hash_is_stable_and_value_sensitive(tmp_path):
    repo = make_repo(tmp_path)
    _, a = run.resolve_config({"fail_on": "high"}, {}, repo)
    _, b = run.resolve_config({"fail_on": "high"}, {}, repo)
    _, c = run.resolve_config({"fail_on": "low"}, {}, repo)
    assert a == b != c


# --- T025 gate ---------------------------------------------------------------


def _finding(sev, new=True):
    return {"sev": sev, "new": new}


def test_gate_thresholds():
    findings = [_finding("high"), _finding("low")]
    assert run.gate_exit(findings, "critical") == 0
    assert run.gate_exit(findings, "high") == 1
    assert run.gate_exit(findings, "medium") == 1
    assert run.gate_exit(findings, "low") == 1
    assert run.gate_exit(findings, None) == 0  # gate off by default


def test_gate_counts_new_findings_only():
    findings = [_finding("critical", new=False)]
    assert run.gate_exit(findings, "high") == 0


def test_scan_gates_end_to_end(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fake_engines(monkeypatch)
    # everything is new, gate off -> 0
    assert scan(repo) == 0
    # accept, rescan gated -> 0
    assert run.main(["baseline", "update", str(repo)]) == 0
    assert scan(repo, "--fail-on", "high", "--force") == 0
    # unknown-to-baseline high findings -> 1
    (repo / ".ens-baseline.yml").unlink()
    assert scan(repo, "--fail-on", "high", "--force") == 1


def test_baseline_update_without_a_run_exits_2(tmp_path):
    repo = make_repo(tmp_path)
    assert run.main(["baseline", "update", str(repo)]) == 2


def test_missing_engine_binary_exits_2_naming_it(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    code = run.main(["scan", str(repo)])
    assert code == 2


# --- integration, real engines (T023, T029) ----------------------------------

VULNAPP = ROOT / "tests" / "fixtures" / "vulnerable-app"


def _copy_vulnapp(tmp_path):
    repo = tmp_path / "vulnapp"
    shutil.copytree(VULNAPP, repo)
    (repo / ".semgrepignore").unlink(missing_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=repo,
        check=True,
    )
    return repo


@pytest.mark.engines
def test_two_forced_scans_are_byte_identical(tmp_path):
    repo = _copy_vulnapp(tmp_path)
    assert run.main(["scan", str(repo), "--force"]) == 0
    first = (repo / "out" / "latest" / "findings.jsonl").read_bytes()
    assert run.main(["scan", str(repo), "--force"]) == 0
    second = (repo / "out" / "latest" / "findings.jsonl").read_bytes()
    assert first == second


@pytest.mark.engines
def test_baseline_gate_scenario(tmp_path):
    repo = _copy_vulnapp(tmp_path)
    assert run.main(["scan", str(repo), "--force"]) == 0
    assert run.main(["baseline", "update", str(repo)]) == 0
    assert run.main(["scan", str(repo), "--force", "--fail-on", "high"]) == 0

    # one new high finding: a second root container (missing-user is SARIF error
    # -> high; exec-detected is only warning -> medium, useless for a high gate)
    new = repo / "web" / "Dockerfile"
    new.parent.mkdir()
    new.write_text('FROM alpine:3.20\nCMD ["sh"]\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    assert run.main(["scan", str(repo), "--force", "--fail-on", "high"]) == 1

    # an added import above the accepted findings must NOT resurface them; gate at
    # medium so a broken fingerprint (exec-detected, medium) would flip the exit
    shutil.rmtree(new.parent)
    main_py = repo / "app" / "main.py"
    main_py.write_text("import os  # noqa: F401\n" + main_py.read_text())
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    assert run.main(["scan", str(repo), "--force", "--fail-on", "medium"]) == 0


@pytest.mark.engines
def test_cli_entrypoint_runs():
    proc = subprocess.run(
        [sys.executable, "-m", "src.run", "--help"], capture_output=True, cwd=ROOT
    )
    assert proc.returncode == 0


# --- report + explain (spec 002: T015, T028, T029) ---------------------------

FIXTURE_RUN = ROOT / "tests" / "fixtures" / "run"


def test_report_renders_into_the_run_directory(tmp_path):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    assert run.main(["report", "--run", str(run_dir), "--format", "md"]) == 0
    report = (run_dir / "report.md").read_text()
    assert "Informe de evidencias" in report
    # read-only over the stored run: spec 002 never rewrites 001's artifacts
    for name in ("findings.jsonl", "run.json"):
        assert (run_dir / name).read_bytes() == (FIXTURE_RUN / name).read_bytes()


def test_report_needs_no_engines(tmp_path, monkeypatch):
    """SC-008: re-rendering must work with Semgrep and Trivy uninstalled."""
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert run.main(["report", "--run", str(run_dir), "--format", "md"]) == 0


def test_report_without_a_stored_run_exits_2(tmp_path):
    assert run.main(["report", "--run", str(tmp_path / "nope")]) == 2


def test_report_never_returns_1(tmp_path):
    """The gate belongs to `scan`. Findings existing is not an error."""
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    assert run.main(["report", "--run", str(run_dir), "--format", "md"]) == 0


def test_pdf_requested_without_converter_exits_2(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert run.main(["report", "--run", str(run_dir), "--format", "pdf"]) == 2


def test_auto_format_degrades_and_discloses_in_the_document(tmp_path, monkeypatch):
    """Never silent: a CI log can be discarded, the evidence file cannot."""
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert run.main(["report", "--run", str(run_dir), "--format", "auto"]) == 0
    report = (run_dir / "report.md").read_text()
    assert not (run_dir / "report.pdf").exists()
    assert "No se ha generado la versión PDF" in report


def _first_finding(run_dir, predicate):
    lines = (run_dir / "findings.jsonl").read_text().splitlines()[1:]
    return next(f for f in map(json.loads, lines) if predicate(f))


def test_explain_reports_pattern_and_measures(tmp_path, capsys):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    finding = _first_finding(run_dir, lambda f: f["tool"] == "trivy" and f["rule"] == "KSV-0013")
    assert run.main(["explain", finding["id"], "--run", str(run_dir), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["measures"] == ["op.exp.3"]
    assert "KSV-0013" in out["matched_rule"]
    assert out["counts_toward_measures"] is True
    assert "primera" in out["why"]


def test_explain_on_an_unmapped_finding_is_not_an_error(tmp_path, capsys):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    finding = _first_finding(run_dir, lambda f: f["tool"] == "mysteryengine")
    assert run.main(["explain", finding["id"], "--run", str(run_dir), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["measures"] == ["unmapped"]
    assert out["matched_rule"] is None
    assert out["counts_toward_measures"] is False
    assert "espera de una decisión humana" in out["why"]


def test_explain_on_a_non_security_finding_says_why_it_counts_for_nothing(tmp_path, capsys):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    finding = _first_finding(run_dir, lambda f: not f["security"])
    assert run.main(["explain", finding["id"], "--run", str(run_dir), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["counts_toward_measures"] is False
    assert "NO etiquetó" in out["why"]


def test_explain_unknown_id_exits_2(tmp_path):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    assert run.main(["explain", "nosuchid", "--run", str(run_dir)]) == 2


def test_explain_json_carries_the_schema_and_truncates(tmp_path, capsys):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    longest = max(
        (json.loads(x) for x in (run_dir / "findings.jsonl").read_text().splitlines()[1:]),
        key=lambda f: len(f["msg"]),
    )
    assert run.main(["explain", longest["id"], "--run", str(run_dir), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["schema"] == "ens-evidence/1"
    assert len(out["finding"]["msg"]) <= 200
    assert out["finding"]["msg"] != longest["msg"]


def test_converter_present_but_unable_degrades_in_auto(tmp_path, monkeypatch):
    """Found by the quickstart, not by design: pandoc can be installed and still fail,
    because producing a PDF needs a separate engine it only checks at conversion time.
    `auto` must degrade — a complete evidence document is not withheld over a missing
    presentation format."""
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        run.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 47, "", "'pdflatex' not found"),
    )
    assert run.main(["report", "--run", str(run_dir), "--format", "auto"]) == 0
    report = (run_dir / "report.md").read_text()
    assert not (run_dir / "report.pdf").exists()
    assert "No se ha generado la versión PDF" in report
    assert "pdflatex" in report


def test_converter_present_but_unable_fails_when_pdf_is_explicit(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    shutil.copytree(FIXTURE_RUN, run_dir)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        run.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 47, "", "'pdflatex' not found"),
    )
    assert run.main(["report", "--run", str(run_dir), "--format", "pdf"]) == 2
