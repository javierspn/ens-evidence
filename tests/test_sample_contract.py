"""Gate for `samples/`, whose prose is maintained by hand and can silently go stale.

`samples/README.md` names a commit, a date, two engine versions, a rules SHA and four
counts — none of which are generated. `samples/bundle-ejemplo.md` is generated and
carries every one of the same facts. So the drift is mechanically visible: the README
claims, the bundle records, and a divergence between them is a documentation defect
that otherwise only a human reading both would notice.

Two facts reach outside the pair: the rules SHA must still be the pinned one in
`.github/semgrep-rules.sha` (the rules-bump gate moves that file and does not touch the
sample), and the named commit must still be reachable from HEAD.
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture(scope="module")
def readme():
    return (SAMPLES / "README.md").read_text()


@pytest.fixture(scope="module")
def bundle():
    return (SAMPLES / "bundle-ejemplo.md").read_text()


def claim(text, pattern):
    """The one value `pattern` captures, or a failure naming what went missing."""
    found = re.search(pattern, text)
    assert found, f"sample no longer states {pattern!r} — the check cannot read it"
    return found.group(1)


def row_in(text, label):
    """The value cell of a `| label | value |` row in the generated bundle."""
    found = re.search(rf"^\|\s*{re.escape(label)}\s*\|\s*(.+?)\s*\|$", text, flags=re.MULTILINE)
    assert found, f"bundle-ejemplo.md no longer has a `{label}` row"
    return found.group(1)


def test_readme_names_the_commit_the_bundle_was_produced_at(readme, bundle):
    stated = claim(readme, r"from commit `([0-9a-f]{7,40})`")
    recorded = row_in(bundle, "Revisión").strip("`")
    assert stated == recorded, (
        f"README says the sample came from {stated}, bundle-ejemplo.md records {recorded}"
    )


def test_the_named_commit_is_still_reachable(readme):
    """A sample attributed to a commit that was rebased or force-pushed away is
    evidence of nothing. Needs full history — the `test` CI job fetches depth 0."""
    stated = claim(readme, r"from commit `([0-9a-f]{7,40})`")
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if shallow.stdout.strip() != "false":
        pytest.fail("shallow checkout: this gate cannot run, fetch the full history")
    found = subprocess.run(["git", "merge-base", "--is-ancestor", stated, "HEAD"], cwd=ROOT)
    assert found.returncode == 0, (
        f"commit {stated} named by samples/README.md is not an ancestor of HEAD"
    )


def test_readme_date_matches_the_bundle(readme, bundle):
    stated = claim(readme, r"Produced on (\d{4}-\d{2}-\d{2})")
    assert stated == row_in(bundle, "Fecha del análisis")


def test_readme_engine_versions_match_the_bundle(readme, bundle):
    semgrep = claim(readme, r"with Semgrep ([\d.]+) and")
    trivy = claim(readme, r"and Trivy ([\d.]+) and")
    assert semgrep == row_in(bundle, "Semgrep")
    # The bundle appends the vulnerability-database revision; the README names the binary.
    assert row_in(bundle, "Trivy").startswith(trivy)


def test_readme_counts_match_the_bundle(readme, bundle):
    total = claim(readme, r"This run is (\d+) findings")
    mapped = claim(readme, r"(\d+) mapped and security-tagged")
    untagged = claim(readme, r"(\d+) not tagged as security")
    unmapped = claim(readme, r"(\d+)\s+unmapped")
    assert total == row_in(bundle, "Hallazgos")
    assert mapped == row_in(bundle, "Con correspondencia y de seguridad")
    assert untagged == row_in(bundle, "No marcados como seguridad")
    assert unmapped == row_in(bundle, "Sin correspondencia")


def test_readme_rules_sha_matches_the_bundle(readme, bundle):
    stated = claim(readme, r"rules pinned at `([0-9a-f]{40})`")
    assert stated in row_in(bundle, "Origen de las reglas")


def test_the_sample_was_produced_against_the_pin_still_in_force(readme):
    """The rules-bump gate moves `.github/semgrep-rules.sha` on its own; nothing makes
    it regenerate the sample. A bump without a regeneration lands here."""
    stated = claim(readme, r"rules pinned at `([0-9a-f]{40})`")
    pinned = (ROOT / ".github" / "semgrep-rules.sha").read_text().strip()
    assert stated == pinned, (
        f"sample was produced against rules {stated}, the repo now pins {pinned} — "
        "regenerate samples/ (see its Regenerating section)"
    )


def test_the_sample_run_was_genuinely_pinned(bundle):
    """`registry` here means the SHA in the README was decorative and the run is not
    reproducible — the defect the 2026-07-28 regeneration fixed."""
    assert row_in(bundle, "Origen de las reglas").startswith("local")
