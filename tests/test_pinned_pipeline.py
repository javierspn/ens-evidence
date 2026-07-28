"""The pinned pipeline, end to end, on a real machine with real engines.

Every defect of 2026-07-28 lived here and nowhere else. The unit suite stayed green
through all six because it renders a committed fixture and never runs an engine:

  * Trivy refused --skip-db-update on a runner with no database;
  * and then declared no checks bundle, so the report crashed slicing a None digest;
  * `scan` without --rules-root silently used the Semgrep registry, making the pin
    decorative and the published evidence non-reproducible;
  * canonical_rule_id handled only the prefix shape semgrep emits for a rules root OUTSIDE
    the working directory, so the DEFAULT layout — `rules fetch` writes ./.ens-rules inside
    the repository — produced ids that matched no mapping pattern and filed every finding
    as unmapped;
  * a rules checkout inside the working tree became part of the scan — 1304 of 1380
    published findings were about semgrep's own fixtures.

These assertions are the contract those defects broke. They need a rules checkout, so
the `engines` mark keeps them out of the offline data gate; the `pinned-pipeline` CI job
is what actually runs them. If that job is ever dropped, this file stops protecting
anything — the defects above are exactly the kind that pass a green unit suite.

ENS_TEST_RULES_ROOT points at a checkout fetched at .github/semgrep-rules.sha. It must be
OUTSIDE the scanned tree; the test asserts that rather than trusting the caller.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ens_evidence import MAPPING_DIR, mapper, normalise, run

ROOT = Path(__file__).resolve().parent.parent
PIN_FILE = ROOT / ".github" / "semgrep-rules.sha"
VULNAPP = ROOT / "tests" / "fixtures" / "vulnerable-app"

pytestmark = pytest.mark.engines


@pytest.fixture(scope="module")
def rules_root():
    configured = os.environ.get("ENS_TEST_RULES_ROOT")
    if not configured:
        pytest.skip("set ENS_TEST_RULES_ROOT to a semgrep-rules checkout at the pinned SHA")
    root = Path(configured).resolve()
    if not root.is_dir():
        pytest.skip(f"ENS_TEST_RULES_ROOT does not exist: {root}")
    return root


@pytest.fixture(scope="module")
def pinned_run(tmp_path_factory, rules_root):
    """One pinned scan, shared: it costs minutes, and every assertion reads the same run."""
    repo = tmp_path_factory.mktemp("pinned") / "vulnapp"
    shutil.copytree(VULNAPP, repo)
    (repo / ".semgrepignore").unlink(missing_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=repo,
        check=True,
    )
    assert rules_root not in repo.parents, "the rules checkout must not contain the scan target"
    # Exit 1 is "there are findings", which this fixture corpus guarantees.
    assert run.main(["scan", str(repo), "--rules-root", str(rules_root), "--force"]) in (0, 1)
    store = repo / "out" / "latest"
    findings = [json.loads(line) for line in (store / "findings.jsonl").read_text().splitlines()]
    return {
        "repo": repo,
        "store": store,
        "record": json.loads((store / "run.json").read_text()),
        "findings": [f for f in findings if "schema" not in f or "class" in f],
    }


def test_the_scan_used_the_pin_and_not_the_registry(pinned_run):
    """`scan` without --rules-root falls back to `p/default` and records mode "registry".
    The workflow did exactly that for its whole life: it fetched the rules at the pinned
    SHA, printed `rules status`, and then scanned with the registry."""
    rules = pinned_run["record"]["rules"]
    assert rules["mode"] == "local"
    assert rules["sha"] == PIN_FILE.read_text().strip()
    assert rules["config"] is None


def test_the_engines_declared_a_checks_bundle(pinned_run):
    """Trivy declares no CheckBundle until it has been fetched once. A runner that never
    fetched it scans for misconfigurations with no checks — thin evidence that looks
    identical to clean evidence — and the report then crashed slicing the None digest."""
    engines = pinned_run["record"]["engines"]
    assert engines["trivy_checks_bundle"], "no checks bundle: the misconfig scan had no checks"
    assert engines["trivy_db"]["version"]


def test_no_finding_is_about_the_rules_checkout(pinned_run, rules_root):
    """A rules checkout inside the scanned tree becomes part of the evidence. Published
    2026-07-28: 1304 of 1380 findings described semgrep's own rule fixtures."""
    strays = [
        f["file"]
        for f in pinned_run["findings"]
        if "ens-rules" in f["file"] or str(rules_root) in f["file"]
    ]
    assert not strays, f"findings about the rules checkout: {sorted(set(strays))[:5]}"


def test_rule_ids_are_canonical_so_the_mapping_can_match(pinned_run, rules_root):
    """Covers the out-of-tree layout only, because that is where `pinned_run` puts the rules.
    The in-tree layout is the one that actually broke; it has its own test below."""
    dotted = str(rules_root).strip("/").replace("/", ".")
    offenders = [
        f["rule"]
        for f in pinned_run["findings"]
        if f["rule"].startswith(dotted + ".")
        or f["rule"].startswith(rules_root.name.lstrip(".") + ".")
    ]
    assert not offenders, f"rules-root prefix survived canonicalisation: {offenders[:5]}"


def test_the_default_in_tree_rules_root_still_maps(tmp_path, rules_root, monkeypatch):
    """The layout `rules fetch` produces by default: the checkout sits INSIDE the scanned
    repository, and semgrep then emits the relative prefix (`ens-rules.<id>`) rather than
    the absolute one. Nothing stripped it until 2026-07-28, so every finding of an ordinary
    pinned run was unmapped — the published self-scan included.

    The working directory is what decides the shape, not the layout on disk: semgrep dots
    the path it walked from cwd to the config. So this scans from inside the repository with
    a relative --rules-root, which is what `cd repo && ens-evidence scan .` does. Running it
    from elsewhere yields the absolute form and proves nothing.

    One rule directory rather than all 28: the shape of the id is what is under test, and a
    21 MB copy per run is not worth the seconds."""
    repo = tmp_path / "intree"
    (repo / ".ens-rules").mkdir(parents=True)
    shutil.copytree(rules_root / "dockerfile", repo / ".ens-rules" / "dockerfile")
    (repo / "Dockerfile").write_text('FROM alpine:3.20\nCMD ["sh"]\n')
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=repo,
        check=True,
    )

    monkeypatch.chdir(repo)
    assert run.main(["scan", ".", "--rules-root", ".ens-rules", "--force"]) in (0, 1)
    findings = [
        json.loads(line)
        for line in (repo / "out" / "latest" / "findings.jsonl").read_text().splitlines()
    ]
    semgrep = [f for f in findings if f.get("tool") == "semgrep"]
    assert semgrep, "the fixture Dockerfile must fire at least one semgrep rule"
    assert not [f for f in semgrep if f["rule"].startswith("ens-rules.")]

    rules = mapper.load_rules(MAPPING_DIR / "ens_rd311.yml")
    assert not [
        f for f in semgrep if mapper.measures_for(f["tool"], f["rule"], rules) == ["unmapped"]
    ]


def test_the_pinned_corpus_maps_completely(pinned_run):
    """The mapping is the asset; a pinned run that maps nothing is the failure mode this
    whole file exists for. Anything genuinely out of scope belongs in the mapping as an
    explicit decision, not as an id nobody ruled on."""
    rules = mapper.load_rules(MAPPING_DIR / "ens_rd311.yml")
    unmapped = sorted(
        {
            f"{f['tool']}:{f['rule']}"
            for f in pinned_run["findings"]
            if mapper.measures_for(f["tool"], f["rule"], rules) == ["unmapped"]
        }
    )
    assert not unmapped, f"unmapped rule ids in a pinned run: {unmapped}"


def test_the_report_and_the_bundle_render_from_a_pinned_run(pinned_run):
    """The render reads fields the fixture-based tests never see populated — the checks
    bundle digest and the pinned rules block among them."""
    repo = pinned_run["repo"]
    assert run.main(["report", str(repo)]) == 0
    assert run.main(["bundle", str(repo)]) == 0
    report = (pinned_run["store"] / "report.md").read_text()
    assert PIN_FILE.read_text().strip() in report
    assert "ens-rules." not in report


def test_canonicalisation_matches_what_this_semgrep_actually_emits(pinned_run, rules_root):
    """Guards the assumption itself. canonical_rule_id was written against a full dotted
    path and two unit tests agreed with it, so nothing was stripped in production for the
    life of the feature. This one asks the engine instead of the author."""
    raw = f"{rules_root.name.lstrip('.')}.dockerfile.security.missing-user"
    assert (
        normalise.canonical_rule_id(raw, rules_root=str(rules_root))
        == "dockerfile.security.missing-user"
    )
