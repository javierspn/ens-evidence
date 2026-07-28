"""Packaging guards.

These exist because of a real defect: `src/` imported jinja2 and yaml while only
requirements-dev.txt declared them, so anyone following the documented install path
got a tool that could not import its own modules — and CI stayed green throughout,
because CI installs the dev file. These tests make that class of drift fail loudly.
"""

import re
import tomllib
from pathlib import Path

import pytest

import ens_evidence

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text())


def _requirement_names(text):
    names = set()
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-r"):
            continue
        names.add(re.split(r"[<>=!~\[]", line)[0].strip().lower())
    return names


def test_declared_dependencies_match_requirements(pyproject):
    """pyproject and requirements.txt must not drift — one of them is what an
    installer reads, and the other is what CI reads."""
    declared = _requirement_names("\n".join(pyproject["project"]["dependencies"]))
    required = _requirement_names((ROOT / "requirements.txt").read_text())
    assert declared == required, f"pyproject {declared} vs requirements.txt {required}"


def test_every_third_party_import_is_declared(pyproject):
    """Whatever the package imports, an install must provide."""
    declared = _requirement_names("\n".join(pyproject["project"]["dependencies"]))
    aliases = {"yaml": "pyyaml"}
    found = set()
    import_re = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z_][\w]*)", re.M)
    for module in (ROOT / "src" / "ens_evidence").glob("*.py"):
        found.update(import_re.findall(module.read_text()))
    stdlib_and_self = {
        "argparse",
        "dataclasses",
        "datetime",
        "hashlib",
        "io",
        "json",
        "os",
        "pathlib",
        "re",
        "shutil",
        "subprocess",
        "sys",
        "tempfile",
        "typing",
        "unicodedata",
        "ens_evidence",
    }
    third_party = {aliases.get(m, m) for m in found - stdlib_and_self}
    assert third_party <= declared, f"imported but not declared: {sorted(third_party - declared)}"


def test_data_files_ship_inside_the_package(pyproject):
    """An installed tool with no mapping table or template cannot produce evidence."""
    patterns = pyproject["tool"]["setuptools"]["package-data"]["ens_evidence"]
    assert "mapping/*.yml" in patterns
    assert "templates/*.j2" in patterns

    assert (ens_evidence.MAPPING_DIR / "ens_rd311.yml").is_file()
    assert (ens_evidence.MAPPING_DIR / "severity.yml").is_file()
    assert (ens_evidence.MAPPING_DIR / "defect_classes.yml").is_file()
    assert (ens_evidence.MAPPING_DIR / "measures_es.yml").is_file()
    assert (ens_evidence.TEMPLATE_DIR / "report.md.j2").is_file()
    assert (ens_evidence.TEMPLATE_DIR / "bundle.md.j2").is_file()


def test_every_template_the_code_loads_is_present():
    """T044. Naming report.md.j2 alone let `bundle` ship broken in an installed copy with no
    test failing first — the template was added and the guard was not. Ask the source which
    templates it loads instead of maintaining a second list that can fall behind."""
    loaded = set(
        re.findall(
            r'get_template\(\s*["\']([^"\']+)["\']',
            (ROOT / "src" / "ens_evidence" / "render.py").read_text(),
        )
    )
    assert loaded, "no get_template call found — has the render entry point moved?"
    missing = sorted(name for name in loaded if not (ens_evidence.TEMPLATE_DIR / name).is_file())
    assert not missing, f"templates the code loads but the package does not ship: {missing}"


def test_data_lives_inside_the_package_dir():
    """Guards the packaging property itself: if these ever move back outside the
    package, package-data patterns silently ship nothing."""
    assert ens_evidence.MAPPING_DIR.is_relative_to(ens_evidence.PACKAGE_DIR)
    assert ens_evidence.TEMPLATE_DIR.is_relative_to(ens_evidence.PACKAGE_DIR)


def test_console_entry_point_resolves(pyproject):
    """`ens-evidence` must point at something callable, or the install produces a
    command that dies on first use."""
    target = pyproject["project"]["scripts"]["ens-evidence"]
    module_path, _, attr = target.partition(":")
    module = __import__(module_path, fromlist=[attr])
    assert callable(getattr(module, attr))


def test_the_two_declared_versions_agree(pyproject):
    """Two places state the version and nothing compared them, so a release could ship a
    wheel whose metadata and whose `__version__` disagree."""
    assert pyproject["project"]["version"] == ens_evidence.__version__
