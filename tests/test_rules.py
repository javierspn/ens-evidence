"""The rules bootstrap group. Everything here is offline except one test marked `engines`,
because the licence gate and the status payload are exactly what must work on a machine with
no network — and the gate is the control that keeps third-party rule files out of anything we
publish (Semgrep Rules License v1.0).
"""

import json
import subprocess
from pathlib import Path

import pytest

from ens_evidence import run

PIN_FILE = Path(__file__).resolve().parent.parent / ".github" / "semgrep-rules.sha"


def git(root, *argv):
    subprocess.run(["git", "-C", str(root), *argv], check=True, capture_output=True)


# --- the licence gate --------------------------------------------------------


def test_fetch_without_acknowledgement_exits_2_and_downloads_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ENS_EVIDENCE_ACCEPT_RULES_LICENSE", raising=False)
    dest = tmp_path / "rules"
    assert run.main(["rules", "fetch", "--sha", "deadbeef", "--rules-root", str(dest)]) == 2
    assert not dest.exists()
    err = capsys.readouterr().err
    assert "Semgrep Rules License v1.0" in err
    assert run.RULES_LICENCE_URL in err
    assert "Nothing has been downloaded" in err


def test_the_notice_summarises_rather_than_copying_the_licence():
    """Principle V's reflex: we do not bulk-copy someone else's text, we point at it."""
    assert "in summary, not" in run.RULES_LICENCE_NOTICE
    assert run.RULES_LICENCE_URL in run.RULES_LICENCE_NOTICE
    assert len(run.RULES_LICENCE_NOTICE) < 2000


def test_the_env_var_grants_the_acknowledgement(tmp_path, monkeypatch):
    """Accepted in CI without a flag, but only as an act: the variable has to be set for
    the run, and a config-file key deliberately cannot do it."""
    monkeypatch.setenv("ENS_EVIDENCE_ACCEPT_RULES_LICENSE", "1")
    monkeypatch.setattr(run.shutil, "which", lambda _: None)  # stop before any network
    dest = tmp_path / "rules"
    assert run.main(["rules", "fetch", "--sha", "deadbeef", "--rules-root", str(dest)]) == 2


def test_a_config_file_cannot_grant_the_acknowledgement(tmp_path, monkeypatch):
    monkeypatch.delenv("ENS_EVIDENCE_ACCEPT_RULES_LICENSE", raising=False)
    (tmp_path / ".ens-evidence.yml").write_text("accept_rules_license: true\n")
    dest = tmp_path / "rules"
    assert run.main(["rules", "fetch", "--sha", "deadbeef", "--rules-root", str(dest)]) == 2
    assert not dest.exists()


# --- failure modes name what is wrong ----------------------------------------


def test_missing_git_binary_exits_2_naming_it(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(run.shutil, "which", lambda _: None)
    code = run.main(
        [
            "rules",
            "fetch",
            "--sha",
            "deadbeef",
            "--accept-rules-license",
            "--rules-root",
            str(tmp_path / "rules"),
        ]
    )
    assert code == 2
    assert "git" in capsys.readouterr().err


def test_destination_that_is_not_a_work_tree_exits_2(tmp_path, capsys):
    dest = tmp_path / "rules"
    dest.mkdir()
    (dest / "something.txt").write_text("not a checkout\n")
    code = run.main(
        ["rules", "fetch", "--sha", "deadbeef", "--accept-rules-license", "--rules-root", str(dest)]
    )
    assert code == 2
    assert "not a git work tree" in capsys.readouterr().err


def test_unknown_sha_exits_2_without_leaving_a_checkout(tmp_path, capsys):
    """No network needed: the remote is a local repository that simply lacks the SHA."""
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    git(upstream, "init", "--quiet")
    (upstream / "python").mkdir()
    (upstream / "python" / "rule.yaml").write_text("rules: []\n")
    git(upstream, "add", "-A")
    git(upstream, "-c", "user.email=f@x", "-c", "user.name=f", "commit", "-qm", "rules")

    dest = tmp_path / "rules"
    code = run.main(
        [
            "rules",
            "fetch",
            "--sha",
            "0" * 40,
            "--repo",
            str(upstream),
            "--accept-rules-license",
            "--rules-root",
            str(dest),
        ]
    )
    assert code == 2
    assert "could not fetch" in capsys.readouterr().err
    assert not list(dest.glob("python/*.yaml"))


# --- fetch against a local upstream ------------------------------------------


def test_fetch_pins_the_requested_commit(tmp_path, capsys):
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    git(upstream, "init", "--quiet")
    (upstream / "python").mkdir()
    (upstream / "python" / "rule.yaml").write_text("rules: []\n")
    git(upstream, "add", "-A")
    git(upstream, "-c", "user.email=f@x", "-c", "user.name=f", "commit", "-qm", "rules")
    sha = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    dest = tmp_path / "rules"
    code = run.main(
        [
            "rules",
            "fetch",
            "--sha",
            sha,
            "--repo",
            str(upstream),
            "--accept-rules-license",
            "--rules-root",
            str(dest),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["mode"] == "local"
    assert payload["sha"] == sha
    assert payload["per_language"] == {"python": 1}
    assert (dest / "python" / "rule.yaml").is_file()


def test_fetch_is_idempotent_and_can_move_the_pin(tmp_path, capsys):
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    git(upstream, "init", "--quiet")
    (upstream / "python").mkdir()
    (upstream / "python" / "rule.yaml").write_text("rules: []\n")
    git(upstream, "add", "-A")
    git(upstream, "-c", "user.email=f@x", "-c", "user.name=f", "commit", "-qm", "one")
    first = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    (upstream / "go").mkdir()
    (upstream / "go" / "rule.yaml").write_text("rules: []\n")
    git(upstream, "add", "-A")
    git(upstream, "-c", "user.email=f@x", "-c", "user.name=f", "commit", "-qm", "two")
    second = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    dest = tmp_path / "rules"
    args = ["--repo", str(upstream), "--accept-rules-license", "--rules-root", str(dest)]
    assert run.main(["rules", "fetch", "--sha", first, *args]) == 0
    assert run.main(["rules", "fetch", "--sha", second, *args]) == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["sha"] == second
    assert payload["per_language"] == {"go": 1, "python": 1}


# --- which configs a local checkout yields -----------------------------------


def _rule_file(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "rules:\n"
        "  - id: x\n"
        "    pattern: x\n"
        "    message: x\n"
        "    languages: [python]\n"
        "    severity: WARNING\n"
    )


def test_configs_are_the_rule_directories_not_the_checkout_root(tmp_path):
    """The bug this exists for: passing the checkout root to semgrep makes it reject the
    whole run (exit 7, 0 files scanned) because the upstream repository ships YAML that is
    not a ruleset. Observed 2026-07-26 with `stats/` and `.github/stale.yml`."""
    root = tmp_path / "rules"
    _rule_file(root / "python" / "lang" / "r.yaml")
    _rule_file(root / "go" / "r.yaml")
    (root / "stats").mkdir()
    (root / "stats" / "web_frameworks.yml").write_text("django:\n  - 4.0\n")
    (root / ".github").mkdir()
    (root / ".github" / "stale.yml").write_text("daysUntilStale: 60\n")

    configs = run.semgrep_configs(root)
    assert configs == [str(root / "go"), str(root / "python")]


def test_rule_test_fixtures_do_not_disqualify_their_directory(tmp_path):
    """`*.test.yaml` files sit beside the rules they test and carry no `rules:` key;
    semgrep tolerates them, so excluding java/ruby/yaml over them would drop most of the
    ruleset."""
    root = tmp_path / "rules"
    _rule_file(root / "java" / "r.yaml")
    (root / "java" / "r.test.yaml").write_text("some: fixture\n")
    assert run.semgrep_configs(root) == [str(root / "java")]


def test_a_checkout_with_no_rule_directory_is_an_engine_error(tmp_path):
    root = tmp_path / "rules"
    (root / "stats").mkdir(parents=True)
    (root / "stats" / "x.yml").write_text("a: b\n")
    assert run.semgrep_configs(root) == []


# --- status ------------------------------------------------------------------


def test_status_reports_registry_mode_as_not_reproducible(tmp_path, capsys):
    assert run.main(["rules", "status", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert payload["mode"] == "registry"
    assert payload["sha"] is None
    assert payload["reproducible"] is False
    assert "not reproducible" in captured.err.lower()


def test_status_reports_a_pinned_root(tmp_path, capsys):
    root = tmp_path / "rules"
    root.mkdir()
    git(root, "init", "--quiet")
    for lang, count in (("python", 2), ("go", 1)):
        (root / lang).mkdir()
        for n in range(count):
            (root / lang / f"r{n}.yaml").write_text("rules: []\n")
    git(root, "add", "-A")
    git(root, "-c", "user.email=f@x", "-c", "user.name=f", "commit", "-qm", "rules")

    assert run.main(["rules", "status", str(tmp_path), "--rules-root", str(root)]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["mode"] == "local"
    assert payload["per_language"] == {"go": 1, "python": 2}
    assert payload["reproducible"] is True


# --- the real upstream -------------------------------------------------------


@pytest.mark.engines
def test_fetch_from_the_real_upstream_at_the_pinned_sha(tmp_path, capsys):
    """Marked `engines` because it needs the network, not because it needs an engine: the
    default job must stay offline."""
    pin = PIN_FILE.read_text().strip()
    assert len(pin) == 40, "the tracked pin file must hold one full commit SHA"
    dest = tmp_path / "rules"
    assert (
        run.main(
            ["rules", "fetch", "--sha", pin, "--accept-rules-license", "--rules-root", str(dest)]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["sha"] == pin
    assert payload["per_language"]["python"] > 100
