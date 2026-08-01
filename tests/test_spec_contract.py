"""Gate for `specs/`, where the plan of record drifts out of step with the shipped tool.

Spec Kit writes the header fields and the task checkboxes; nothing updates them
afterwards. Both had gone stale by v1.0.0: all three specs still said `Draft` after the
release, and 003 carried four unticked tasks that were in fact done. A spec that
describes the repo incorrectly is worse than no spec, because it is read as current.

The `repo-gates` skill ships a `spec_lint.py` for a different convention entirely (YAML
frontmatter, a `worker` field, repo-a worker names). It cannot read these files, so
this is a repo-local check in the idiom the rest of the gates already use — a contract
test in the `test` job rather than a script behind a new CI job.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPECS = ROOT / "specs"

STATUSES = {"Draft", "Implemented"}


def feature_dirs():
    return sorted(d for d in SPECS.glob("[0-9][0-9][0-9]-*") if d.is_dir())


def field(text, name):
    found = re.search(rf"^\*\*{name}\*\*:\s*(.+?)\s*$", text, flags=re.MULTILINE)
    assert found, f"spec has no **{name}** header field"
    return found.group(1)


def specced_dirs():
    """Feature dirs that carry a spec. A dir may hold only a README while its feature is
    deliberately unspecced — 004 stays that way until v2 is earned (DESIGN.md)."""
    return [d for d in feature_dirs() if (d / "spec.md").exists()]


def test_there_are_features_to_check():
    """Without this, every parametrised test below passes on an empty list."""
    assert specced_dirs(), "no specs/NNN-*/spec.md found — this gate is scanning nothing"


@pytest.mark.parametrize("d", feature_dirs(), ids=lambda d: d.name)
def test_a_feature_dir_has_either_a_full_spec_set_or_only_a_readme(d):
    if not (d / "spec.md").exists():
        assert (d / "README.md").exists(), (
            f"{d.name} has neither a spec.md nor a README saying why it is empty"
        )
        return
    for required in ("plan.md", "tasks.md"):
        assert (d / required).exists(), f"{d.name} has a spec.md but no {required}"


@pytest.mark.parametrize("d", specced_dirs(), ids=lambda d: d.name)
def test_feature_branch_field_matches_the_directory(d):
    stated = field((d / "spec.md").read_text(), "Feature Branch").strip("`")
    assert stated == d.name, (
        f"{d.name}/spec.md calls itself `{stated}` — a spec copied from another feature"
    )


@pytest.mark.parametrize("d", specced_dirs(), ids=lambda d: d.name)
def test_status_is_from_the_known_vocabulary(d):
    stated = field((d / "spec.md").read_text(), "Status")
    assert stated in STATUSES, f"{d.name}: unknown status {stated!r}, expected {STATUSES}"


@pytest.mark.parametrize("d", specced_dirs(), ids=lambda d: d.name)
def test_a_spec_with_no_open_tasks_does_not_still_say_draft(d):
    """The drift that shipped: 001–003 all read `Draft` after v1.0.0 was tagged. The
    inverse — `Implemented` with tasks still open — is the same defect facing the other
    way, so both directions fail here."""
    tasks = (d / "tasks.md").read_text()
    open_tasks = re.findall(r"^\s*- \[ \] (\S+)", tasks, flags=re.MULTILINE)
    stated = field((d / "spec.md").read_text(), "Status")
    if open_tasks:
        assert stated == "Draft", f"{d.name} is marked {stated} with tasks still open: {open_tasks}"
    else:
        assert stated == "Implemented", (
            f"{d.name} has every task ticked but is still marked {stated}"
        )
