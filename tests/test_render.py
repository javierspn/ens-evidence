"""Report rendering tests. Engine-free by construction: every one renders the committed
stored run in tests/fixtures/run/, so the CI gate (`pytest -m "not engines"`) covers them.

Two of these carry constitution principles rather than a feature:
  * test_report_states_no_verdict_anywhere  — principle II (evidence, never verdict)
  * test_rendered_report_carries_scope_list — principle III, rendered side
"""

import copy
import json
import re
from pathlib import Path

import pytest

from ens_evidence import MAPPING_DIR, TEMPLATE_DIR, mapper, render

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "tests" / "fixtures" / "run"
TEMPLATES = TEMPLATE_DIR
SCOPE = ["mp.sw.1", "mp.sw.2", "mp.s.2", "op.exp.2", "op.exp.3", "op.exp.4"]
SCOPE_LINE = " · ".join(f"`{m}`" for m in SCOPE)


def prose(text):
    """Markdown prose wraps across lines and carries emphasis markers; neither should
    decide whether an assertion about the wording passes."""
    return " ".join(text.replace("**", "").split()).lower()


def build(record=None, findings=None):
    loaded_findings, loaded_record = render.load_run(RUN)
    return render.build_model(
        findings if findings is not None else loaded_findings,
        record if record is not None else loaded_record,
        mapper.load_rules(MAPPING_DIR / "ens_rd311.yml"),
        render.load_measures(MAPPING_DIR / "measures_es.yml"),
        SCOPE,
    )


@pytest.fixture(scope="module")
def model():
    return build()


@pytest.fixture(scope="module")
def report(model):
    return render.render_report(model, TEMPLATES)


# --- T009 principle III, rendered side ---------------------------------------


def test_rendered_report_carries_scope_list(report):
    """Separate from the SCOPE_DOCS file check: a template can hold the line and still
    not emit it — inside a false conditional, or escaped."""
    assert report.count(SCOPE_LINE) == 1


# --- T010 structure ----------------------------------------------------------


def test_section_order_matches_the_contract(report):
    expected = [
        "# Informe de evidencias",
        "## 1. Alcance",
        "## 2. Descripción",
        "## 3. Cobertura",
        "## 4. Vigencia",
        "## 5. Hallazgos",
        "## 6. Evidencia por medida",
        "## 7. Anexos",
        "### 7.1 · Tabla completa de hallazgos",
        "### 7.2 · Hallazgos sin correspondencia asignada",
        "### 7.3 · Hallazgos no marcados como seguridad",
    ]
    positions = []
    for heading in expected:
        idx = report.find(heading)
        assert idx != -1, f"missing section: {heading}"
        positions.append(idx)
    assert positions == sorted(positions), "sections out of contract order"


def test_every_scope_measure_is_accounted_for(report):
    """Section 6 numbers only the measures that have evidence and gathers the rest under
    one "sin evidencia recogida" heading — six near-identical empty sections filled a
    page. Either way every measure in scope must be named somewhere in that section."""
    section = report.split("## 6. Evidencia por medida")[1].split("## 7. Anexos")[0]
    for measure in SCOPE:
        assert measure in section, f"measure absent from section 6: {measure}"


# --- T011 coverage -----------------------------------------------------------


def test_coverage_renders_all_four_fields(report):
    assert "## 3. Cobertura" in report
    assert "Lenguajes detectados" in report
    assert "Reglas del catálogo, por lenguaje" in report
    assert "Lenguajes detectados sin analizar" in report
    assert "Análisis de dependencias" in report


def test_registry_mode_is_declared_non_reproducible(report):
    """The fixture ran in registry mode: rule counts are unknowable and the report must
    say so rather than imply coverage it cannot prove."""
    assert "no es reproducible" in report.lower()


def test_counted_rules_render_when_the_ruleset_is_pinned():
    _, record = render.load_run(RUN)
    record = copy.deepcopy(record)
    record["coverage"]["rules_per_language"] = {"python": 456, "dockerfile": 12}
    out = render.render_report(build(record=record), TEMPLATES)
    assert "| python | 456 |" in out
    assert "no es reproducible" not in out.lower()


def test_rule_counts_do_not_claim_a_language_the_repository_lacks():
    """The catalogue ships rules for 30 languages; the 2026-08-02 sample printed all of
    them under "reglas ejecutadas" for a repository holding five. Each row now declares
    whether its language is present — an absent one evaluated nothing (principle IV)."""
    _, record = render.load_run(RUN)
    record = copy.deepcopy(record)
    record["coverage"]["languages_detected"] = {"python": 26, "shell": 9}
    record["coverage"]["rules_per_language"] = {"python": 337, "bash": 6, "terraform": 364}
    out = render.render_report(build(record=record), TEMPLATES)
    assert "| python | 337 | sí |" in out
    assert "| bash | 6 | sí |" in out, "the shell -> bash alias must survive the table"
    assert "| terraform | 364 | no |" in out
    assert "reglas ejecutadas por lenguaje" not in prose(out)


def test_missing_lockfile_is_stated_not_implied():
    _, record = render.load_run(RUN)
    record = copy.deepcopy(record)
    record["coverage"]["dependency_analysis"] = "skipped-no-lockfile"
    out = render.render_report(build(record=record), TEMPLATES)
    assert "**No realizado**" in out
    assert "no se han buscado" in out.lower()


def test_unanalysed_language_is_named():
    _, record = render.load_run(RUN)
    record = copy.deepcopy(record)
    record["coverage"]["languages_not_analysed"] = ["elixir"]
    out = render.render_report(build(record=record), TEMPLATES)
    assert "`elixir`" in out
    assert "no se ejecutó ninguna regla" in out


# --- T012 staleness ----------------------------------------------------------


def test_staleness_block_discloses_every_drifting_input(report):
    _, record = render.load_run(RUN)
    assert record["engines"]["semgrep"] in report
    assert record["engines"]["trivy"] in report
    assert str(record["engines"]["trivy_db"]["version"]) in report
    assert record["engines"]["trivy_db"]["updated_at"] in report
    # Prefix, not the full digest: the 71-character value overflowed the PDF's page margin
    # and was visually cut, so the report shows a documented prefix and points at run.json
    # for the complete value (observed 2026-07-26 in the sample render).
    assert record["engines"]["trivy_checks_bundle"][:19] in report
    assert "run.json" in report
    assert record["mapping"]["severity_sha256"][:12] in report
    assert "2026-07-25" in report  # measure-list verification date


def test_report_renders_without_a_checks_bundle_digest():
    """Trivy declares no CheckBundle until the bundle has been fetched once, and a runner
    that never fetched it produced None here — which crashed the render on a slice. The
    report must still render and must say the configuration checks may not have applied,
    because silence would read as "they ran"."""
    _, record = render.load_run(RUN)
    record = copy.deepcopy(record)
    record["engines"]["trivy_checks_bundle"] = None
    report = render.render_report(build(record=record), TEMPLATES)
    assert prose("las comprobaciones de configuración pueden no haberse aplicado") in prose(report)


# --- T013 principle II: no verdict -------------------------------------------

FORBIDDEN = [
    r"\bcumple\b",
    r"\bcumplen\b",
    r"\bcumpla\b",
    r"\bconforme\b",
    r"\bconformidad\b",
    r"\bcertifica\b",
    r"\bcertificado\b",
    r"\bapto\b",
    r"\baprobado\b",
    r"\bsuperado\b",
    r"\bsin riesgos?\b",
    r"\bes seguro\b",
]


def test_report_states_no_verdict_anywhere(report):
    """Principle II is the tool's reason to exist. Any wording a reader could take as a
    pass is a defect. The only permitted uses are inside an explicit denial, which is
    why the exception below is narrow and checked against surrounding context."""
    text = prose(report)
    hits = []
    for pattern in FORBIDDEN:
        for match in re.finditer(pattern, text):
            context = text[max(0, match.start() - 60) : match.end() + 60]
            # "no significa que la medida se cumpla" is the REQUIRED disclaimer, not a verdict
            if "no significa" in context or "no dice que" in context:
                continue
            hits.append((pattern, context.strip()))
    assert not hits, f"verdict-shaped wording in the report: {hits}"


def test_empty_measure_says_so_explicitly(report):
    """The fixture files zero findings under mp.s.2, so this branch renders every run.
    An empty section reads as a pass to a human; saying otherwise is the whole point."""
    section = report.split("· Medidas sin evidencia recogida")[1].split("## 7.")[0]
    assert "mp.s.2" in section
    assert "Sin evidencia recogida" in section
    assert "no significa que estas medidas se cumplan" in prose(section)


def test_report_declares_what_it_is_not(report):
    flat = prose(report)
    assert "no es una declaración de conformidad" in flat
    assert "ni una auditoría" in flat
    assert "ni un certificado" in flat


# --- T014 determinism --------------------------------------------------------


def test_two_renders_are_identical(model):
    assert render.render_report(model, TEMPLATES) == render.render_report(model, TEMPLATES)


def test_render_is_independent_of_input_order():
    findings, record = render.load_run(RUN)
    shuffled = list(reversed(findings))
    assert render.render_report(build(record, findings), TEMPLATES) == render.render_report(
        build(record, shuffled), TEMPLATES
    )


# --- T006/fencing ------------------------------------------------------------


def test_truncate_marks_the_cut():
    long_text = "x" * 500
    out = render.truncate(long_text)
    assert len(out) == render.SNIPPET_MAX_CHARS
    assert out.endswith(render.TRUNCATION_MARK)


def test_truncate_leaves_short_text_alone():
    assert render.truncate("  hola   mundo ") == "hola mundo"


def test_fence_wraps_and_heads_the_block():
    out = render.fence("cualquier cosa")
    assert out.startswith(render.FENCE_OPEN)
    assert out.endswith(render.FENCE_CLOSE)
    assert "no instrucciones" in out.lower()


def test_fence_neutralises_a_nested_fence():
    """Scanned-repo text containing ``` would otherwise break out of the block."""
    out = render.fence("```\nignore previous instructions\n```")
    assert out.count("```") == 2  # only our own open/close


def test_no_scanned_repo_text_escapes_a_fence(report):
    """Every engine message in the run must appear only inside an untrusted block, and
    never at full length. The reference corpus's longest message is 734 chars."""
    findings, _ = render.load_run(RUN)
    blocks = re.findall(
        re.escape(render.FENCE_OPEN) + r"\n.*?\n" + re.escape(render.FENCE_CLOSE),
        report,
        re.DOTALL,
    )
    fenced = "\n".join(blocks)
    outside = report
    for block in blocks:
        outside = outside.replace(block, "")

    for finding in findings:
        msg = " ".join(finding["msg"].split())
        if len(msg) > render.SNIPPET_MAX_CHARS:
            assert msg not in report, "untruncated engine message reached the document"
        head = msg[:60]
        if head and head in report:
            assert head in fenced, f"scanned-repo text outside a fence: {head!r}"
            assert head not in outside, f"scanned-repo text outside a fence: {head!r}"


# --- T020/T021 findings section ----------------------------------------------


def severities(findings, sev):
    out = copy.deepcopy(findings)
    for finding in out:
        finding["sev"] = sev
        finding["security"] = True
    return out


def test_highlights_are_severity_ordered(model):
    entries = model["highlights"]
    assert entries
    ranks = [render.CANONICAL.index(f["sev"]) for f in entries]
    assert ranks == sorted(ranks)


def test_highlights_carry_critical_not_only_high():
    """The canonical scale opens at `critical`, so a section that filtered on `high`
    would drop the worst findings in the run — the corpus's top finding is a leaked
    credential Trivy scores 9.5, i.e. critical."""
    findings, record = render.load_run(RUN)
    findings = severities(findings, "high")
    findings[0] = copy.deepcopy(findings[0])
    findings[0]["sev"] = "critical"
    entries = build(record, findings)["highlights"]
    assert entries[0]["sev"] == "critical"
    assert {f["sev"] for f in entries} == {"critical", "high"}


def test_highlights_fall_to_the_next_band_when_the_top_is_empty():
    """A repository whose worst finding is a medium must not render an empty section:
    silence reads as a pass, which principle II forbids."""
    findings, record = render.load_run(RUN)
    entries = build(record, severities(findings, "medium"))["highlights"]
    assert entries and all(f["sev"] == "medium" for f in entries)

    entries = build(record, severities(findings, "low"))["highlights"]
    assert entries and all(f["sev"] == "low" for f in entries)


def test_findings_sharing_a_description_render_as_one_entry(model, report):
    """The 2026-08-02 sample printed the same Kubernetes paragraph four times, differing
    only in file and line. One entry per description now, with every location under it —
    nothing dropped: the report is evidence, so each finding keeps its own fingerprint."""
    groups = model["highlight_groups"]
    assert sum(len(g["hits"]) for g in groups) == len(model["highlights"])
    titles = [g["lead"]["prose"].get("title") for g in groups]
    assert len(titles) == len(set(titles)) or None in titles, "a description repeats"
    for group in groups:
        for hit in group["hits"]:
            assert f"`{hit['id']}`" in report, "a grouped finding lost its fingerprint"


def test_grouping_keys_on_the_description_not_the_rule():
    """KSV-0014 and KSV-0118 map to one description: keying on the rule would still
    print it twice."""

    def finding(rule, file):
        return {
            "sev": "high",
            "rule": rule,
            "file": file,
            "measures": ["op.exp.2"],
            "prose": {"title": "Carga de trabajo sin restricción", "why": "..."},
        }

    groups = render.group_highlights(
        [finding("KSV-0014", "a/k8s.yaml"), finding("KSV-0118", "b/k8s.yaml")]
    )
    assert len(groups) == 1
    assert [h["file"] for h in groups[0]["hits"]] == ["a/k8s.yaml", "b/k8s.yaml"]


def test_a_differing_measure_keeps_findings_apart():
    """Same wording, different assigned measure: merging them would attach one location
    to a measure it was never mapped to."""
    base = {"sev": "high", "rule": "R", "file": "f", "prose": {"title": "T", "why": "w"}}
    groups = render.group_highlights(
        [{**base, "measures": ["op.exp.2"]}, {**base, "measures": ["mp.sw.1"]}]
    )
    assert len(groups) == 2


def test_highlights_never_promote_info():
    """`info` is the severity of what the engine could not classify. Promoting it would
    present unknowns as the findings that matter most."""
    findings, record = render.load_run(RUN)
    model = build(record, severities(findings, "info"))
    assert model["highlights"] == []
    assert model["highlights_band_total"] == 0


def test_highlights_exclude_non_security_findings():
    """A best-practice suggestion must not lead the report any more than it may count
    toward a measure (FR-003)."""
    findings, record = render.load_run(RUN)
    findings = copy.deepcopy(findings)
    for finding in findings:
        finding["sev"] = "critical"
        finding["security"] = False
    model = build(record, findings)
    assert model["highlights"] == []


def test_highlights_are_capped_and_the_cap_is_disclosed():
    """Truncating in silence would read as "these are all of them"."""
    findings, record = render.load_run(RUN)
    findings = severities(findings, "high")
    assert len(findings) > render.HIGHLIGHT_LIMIT, "fixture too small to exercise the cap"
    model = build(record, findings)
    assert len(model["highlights"]) == render.HIGHLIGHT_LIMIT
    assert model["highlights_band_total"] == len(findings)
    out = render.render_report(model, TEMPLATES)
    assert f"Se detallan {render.HIGHLIGHT_LIMIT} de {len(findings)}" in out


def test_highlights_prefer_new_at_equal_severity():
    findings, record = render.load_run(RUN)
    findings = severities(findings, "high")  # collapse severity so newness decides
    for finding in findings:
        finding["new"] = False
    findings[-1]["new"] = True
    entries = build(record, findings)["highlights"]
    assert entries[0]["fingerprint"] == findings[-1]["fingerprint"]


def test_highlights_take_all_when_fewer_than_the_limit():
    findings, record = render.load_run(RUN)
    entries = build(record, severities(findings[:3], "high"))["highlights"]
    assert len(entries) == 3


def test_highlights_ties_break_deterministically():
    findings, record = render.load_run(RUN)
    findings = severities(findings, "high")
    for finding in findings:
        finding["new"] = True
    first = [f["fingerprint"] for f in build(record, findings)["highlights"]]
    second = [f["fingerprint"] for f in build(record, list(reversed(findings)))["highlights"]]
    assert first == second


# --- T024/T025/T026 appendices and accounting --------------------------------


def test_unmapped_finding_reaches_its_appendix(model, report):
    assert len(model["unmapped"]) == 1
    entry = model["unmapped"][0]
    assert entry["tool"] == "mysteryengine"
    appendix = report.split("### 7.2 · Hallazgos sin correspondencia asignada")[1]
    assert entry["id"] in appendix
    for measure in SCOPE:
        assert entry not in model["by_measure"][measure]


def test_non_security_finding_counts_toward_nothing(model, report):
    assert len(model["non_security"]) == 1
    entry = model["non_security"][0]
    assert entry["security"] is False
    assert not entry["counts"]
    for measure in SCOPE:
        assert entry not in model["by_measure"][measure]
    appendix = report.split("### 7.3 · Hallazgos no marcados como seguridad")[1]
    assert entry["id"] in appendix


def test_accounting_every_finding_exactly_once(model):
    """SC-002: no finding lost, none double-counted. This is what makes the document
    evidence rather than a summary."""
    findings, _ = render.load_run(RUN)
    counted = {f["fingerprint"] for measure in SCOPE for f in model["by_measure"][measure]}
    unmapped = {f["fingerprint"] for f in model["unmapped"]}
    non_security = {f["fingerprint"] for f in model["non_security"]}

    assert not (counted & unmapped)
    assert not (counted & non_security)
    assert not (unmapped & non_security)
    assert counted | unmapped | non_security == {f["fingerprint"] for f in findings}
    assert model["totals"]["total"] == len(findings)
    assert model["totals"]["counted"] == len(counted)


def test_multi_measure_finding_is_counted_once_overall(model):
    """A CVE files under both op.exp.4 and mp.sw.2; the accounting must not double it."""
    multi = [f for f in model["findings"] if f["counts"] and len(f["measures"]) > 1]
    assert multi, "fixture should contain a multi-measure finding (CVEs map to two)"
    fingerprint = multi[0]["fingerprint"]
    appearances = sum(
        1 for m in SCOPE for f in model["by_measure"][m] if f["fingerprint"] == fingerprint
    )
    assert appearances == len(multi[0]["measures"])
    assert model["totals"]["counted"] == len(
        {f["fingerprint"] for m in SCOPE for f in model["by_measure"][m]}
    )


def test_model_matches_the_stored_counts(model):
    _, record = render.load_run(RUN)
    assert model["totals"]["total"] == record["counts"]["total"]
    assert model["totals"]["non_security"] == record["counts"]["non_security"]


def test_json_fixture_is_wellformed():
    lines = (RUN / "findings.jsonl").read_text().splitlines()
    assert lines[0] == '{"schema":"ens-evidence/1"}'
    for line in lines[1:]:
        json.loads(line)


# --- found by reading the rendered report (T033) ------------------------------


def test_registry_mode_does_not_claim_full_language_coverage(report):
    """Found by reading the real output: the template used to say "reglas ejecutadas
    sobre todos los lenguajes detectados" in registry mode — directly contradicting the
    paragraph above it, which says the rules cannot be counted. Claiming coverage you
    cannot demonstrate is the Principle IV failure this section exists to prevent."""
    flat = prose(report)
    assert "no se puede determinar" in flat
    assert "se ejecutaron reglas sobre todos los lenguajes detectados" not in flat


def test_report_does_not_leak_the_operators_filesystem_layout(report):
    """The stored run records an absolute path; an evidence document shared with an
    auditor should carry the repository name and the revision, not the directory
    structure of the machine that ran the scan."""
    _, record = render.load_run(RUN)
    assert record["run"]["git_sha"] in report
    assert "/private/tmp" not in report
    assert "/Users/" not in report
    assert "/home/" not in report


def test_target_name_is_stable_across_checkout_locations():
    _, record = render.load_run(RUN)
    a, b = copy.deepcopy(record), copy.deepcopy(record)
    a["run"]["target"] = "/home/ci/work/myrepo"
    b["run"]["target"] = "/Users/dev/projects/myrepo"
    assert build(record=a)["target_name"] == build(record=b)["target_name"] == "myrepo"
