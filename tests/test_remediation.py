"""remediation.md: the work queue that sits beside the report.

Engine-free — renders the committed stored run, so `pytest -m "not engines"` covers it.

Three things this file exists to protect:
  * the licence — the document may carry rule URLs, never rule text (test_no_rule_text);
  * principle II — advice is still not a verdict (test_states_it_is_not_evidence);
  * principle I  — two renders of one run are byte-identical.
"""

import json
from pathlib import Path

import pytest

from ens_evidence import MAPPING_DIR, TEMPLATE_DIR, mapper, normalise, render

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "tests" / "fixtures" / "run"
SARIF = ROOT / "tests" / "fixtures" / "sarif"
SCOPE = ["mp.sw.1", "mp.sw.2", "mp.s.2", "op.exp.2", "op.exp.3", "op.exp.4"]


def build(run_dir=RUN):
    findings, record = render.load_run(run_dir)
    return render.build_model(
        findings,
        record,
        mapper.load_rules(MAPPING_DIR / "ens_rd311.yml"),
        render.load_measures(MAPPING_DIR / "measures_es.yml"),
        SCOPE,
    )


@pytest.fixture(scope="module")
def model():
    return build()


@pytest.fixture(scope="module")
def doc(model):
    return render.render_remediation(model, TEMPLATE_DIR)


# --- references out of the SARIF ---------------------------------------------


def test_trivy_help_uri_becomes_a_reference():
    rule = {"id": "CVE-2020-28493", "helpUri": "https://avd.aquasec.com/nvd/cve-2020-28493"}
    assert normalise._references(rule) == ["https://avd.aquasec.com/nvd/cve-2020-28493"]


def test_semgrep_references_are_read_out_of_help_markdown():
    """Semgrep's SARIF has no references field: the links live inside the Markdown help
    text as a bullet list. Reading only `helpUri` would find nothing for every semgrep
    rule in the corpus."""
    rule = {
        "id": "r",
        "help": {
            "markdown": (
                "Do not pipe untrusted input to eval.\n\n<b>References:</b>\n"
                " - [https://docs.example.com/hooks](https://docs.example.com/hooks)\n"
            )
        },
    }
    assert normalise._references(rule) == ["https://docs.example.com/hooks"]


def test_references_are_deduplicated_capped_and_ordered():
    many = "\n".join(f"see https://example.com/{n}" for n in range(10))
    rule = {"id": "r", "helpUri": "https://example.com/0", "help": {"markdown": many}}
    refs = normalise._references(rule)
    assert refs == ["https://example.com/0", "https://example.com/1", "https://example.com/2"]
    assert len(refs) == normalise.REF_MAX


def test_a_rule_with_no_documentation_yields_no_reference():
    assert normalise._references({"id": "r"}) == []


def test_the_pipeline_carries_references_into_the_findings():
    findings = normalise.normalise(
        [SARIF / "trivy.sarif"],
        normalise.load_severity(MAPPING_DIR / "severity.yml"),
        normalise.load_defect_classes(MAPPING_DIR / "defect_classes.yml"),
    )
    assert any(f["refs"] for f in findings), "no finding carried a reference"
    for f in findings:
        assert all(url.startswith("http") for url in f["refs"])


# --- grouping ----------------------------------------------------------------


def test_grouped_by_rule_worst_first(model):
    groups = model["remediation"]
    assert groups, "the fixture run has security findings"
    keys = [(g["tool"], g["rule"]) for g in groups]
    assert len(keys) == len(set(keys)), "a rule must appear once"
    order = [normalise.CANONICAL.index(g["sev"]) for g in groups]
    assert order == sorted(order)


def test_non_security_findings_are_not_a_remediation_task(model):
    """They do not count toward a measure, so they are not security debt either."""
    listed = {f["fingerprint"] for g in model["remediation"] for f in g["hits"]}
    for f in model["non_security"]:
        assert f["fingerprint"] not in listed


def test_every_security_finding_appears_exactly_once(model):
    listed = [f["fingerprint"] for g in model["remediation"] for f in g["hits"]]
    expected = [f["fingerprint"] for f in model["findings"] if f["security"]]
    assert sorted(listed) == sorted(expected)
    assert len(listed) == len(set(listed))


def test_a_reported_fixed_version_is_carried():
    """Trivy names the version that closes a CVE; it is the one piece of concrete advice
    the engines give, and dropping it would leave the document with links only. The
    committed fixture predates `detail`, so the case is built here."""
    findings, record = render.load_run(RUN)
    findings[0]["detail"] = {"package": "jinja2", "installed": "2.11.2", "fixed": "2.11.3"}
    model = render.build_model(
        findings,
        record,
        mapper.load_rules(MAPPING_DIR / "ens_rd311.yml"),
        render.load_measures(MAPPING_DIR / "measures_es.yml"),
        SCOPE,
    )
    fixed = {pkg: ver for g in model["remediation"] for pkg, ver in g["fixed"].items()}
    assert fixed == {"jinja2": "2.11.3"}
    assert "`jinja2` → `2.11.3`" in render.render_remediation(model, TEMPLATE_DIR)


def test_runs_stored_before_references_existed_still_render():
    """The committed fixture predates the field. StrictUndefined turns a missing key into
    a render failure, so the model must fill it rather than the template guessing."""
    findings, record = render.load_run(RUN)
    assert not any("refs" in f for f in findings), "fixture regenerated: rewrite this test"
    model = build()
    assert all("refs" in f for f in model["findings"])


# --- the document ------------------------------------------------------------


def test_states_it_is_not_evidence(doc):
    flat = " ".join(doc.replace("**", "").split()).lower()
    assert "no es evidencia ni declaración de conformidad" in flat
    assert "cumple" not in flat


def test_no_rule_text(doc):
    """LICENCE: rule descriptions may not be redistributed. The document may name a rule
    and link to it; it may not carry what the rule says. The engine message is the
    shortest path to that mistake, so it is what this checks."""
    messages = [
        json.loads(line)["msg"]
        for line in (RUN / "findings.jsonl").read_text().splitlines()[1:]
        if line
    ]
    for msg in messages:
        assert msg[:60] not in doc


def test_paths_are_defanged(doc):
    """A path is scanned-repo text. `inline_untrusted` is the only way it may reach a
    bullet or a cell here, exactly as in the report."""
    hostile = "a`b|c.py"
    findings, record = render.load_run(RUN)
    findings[0]["file"] = hostile
    model = render.build_model(
        findings,
        record,
        mapper.load_rules(MAPPING_DIR / "ens_rd311.yml"),
        render.load_measures(MAPPING_DIR / "measures_es.yml"),
        SCOPE,
    )
    rendered = render.render_remediation(model, TEMPLATE_DIR)
    assert hostile not in rendered
    assert "a'b¦c.py" in rendered


def test_two_renders_are_byte_identical(model):
    assert render.render_remediation(model, TEMPLATE_DIR) == render.render_remediation(
        model, TEMPLATE_DIR
    )


def test_report_writes_it_beside_the_report(tmp_path):
    import shutil

    from ens_evidence import run

    dest = tmp_path / "out" / "latest"
    dest.parent.mkdir(parents=True)
    shutil.copytree(RUN, dest)
    assert run.main(["report", str(tmp_path), "--format", "md"]) == 0
    written = (dest / "remediation.md").read_text()
    assert written.startswith("# Remediación sugerida")


# --- test material -----------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "tests/fixtures/vulnerable-app/Dockerfile",
        "test/helpers.py",
        "app/testdata/seed.yaml",
        "pkg/__tests__/login.js",
        "api/test_views.py",
        "api/views_test.go",
        "web/login.spec.ts",
    ],
)
def test_paths_recognised_as_test_material(path):
    assert normalise.is_test_code(path)


@pytest.mark.parametrize(
    "path",
    [
        "src/ens_evidence/render.py",
        "specs/003-bundle-and-ci/plan.md",
        "app/latest.py",
        "deploy/k8s.yaml",
        "protest/main.py",
    ],
)
def test_product_paths_are_not_test_material(path):
    """`specs/` is documentation here, and a directory that merely contains the letters
    of a test directory is not one — the flag rides on whole path segments."""
    assert not normalise.is_test_code(path)


def test_nothing_is_dropped_for_being_test_material(model):
    """Principle IV: marked, never filtered. Excluding a path would make the report claim
    a coverage the run did not have."""
    assert model["totals"]["total"] == len(model["findings"])
    listed = {f["fingerprint"] for g in model["remediation"] for f in g["hits"]}
    for f in model["findings"]:
        if f["security"]:
            assert f["fingerprint"] in listed


def test_test_only_groups_sink_below_product_code_of_equal_severity():
    findings, record = render.load_run(RUN)
    findings[0]["file"] = "tests/fixtures/app.py"
    model = render.build_model(
        findings,
        record,
        mapper.load_rules(MAPPING_DIR / "ens_rd311.yml"),
        render.load_measures(MAPPING_DIR / "measures_es.yml"),
        SCOPE,
    )
    order = [(normalise.CANONICAL.index(g["sev"]), g["test_only"]) for g in model["remediation"]]
    assert order == sorted(order)


def test_the_document_marks_test_material():
    findings, record = render.load_run(RUN)
    findings[0]["file"] = "tests/fixtures/app.py"
    findings[0]["security"] = True
    model = render.build_model(
        findings,
        record,
        mapper.load_rules(MAPPING_DIR / "ens_rd311.yml"),
        render.load_measures(MAPPING_DIR / "measures_es.yml"),
        SCOPE,
    )
    assert "código de prueba" in render.render_remediation(model, TEMPLATE_DIR)
    assert model["totals"]["test_code"] >= 1
