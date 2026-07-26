"""SARIF -> JSONL: merge, dedupe across tools, normalise severity, fingerprint.

Most of the real work lives here. One finding per line:

    {"id":"a3f9","tool":"semgrep","rule":"python.django.sql-injection","sev":"high",
     "file":"api/views.py","line":142,"msg":"Raw SQL built from user input"}

Fingerprint = hash(canonical rule id + normalised snippet + occurrence ordinal). Never
file+line: one added import would invalidate every fingerprint below it, and the
baseline would be worthless. The ordinal is the finding's rank among identical
(rule, snippet) pairs within its file, ordered by position — a whole-file line shift
preserves ranks, so fingerprints survive it.

Severity comes from mapping/severity.yml, not from hardcoded tables, and is read from
the RULE object (tool.driver.rules[]), never from the result: Trivy's result level
disagrees with its own severity verdict for CVEs, and Semgrep results carry no level.
A severity the file's tables do not cover resolves to the file's declared `default`;
only a policy with no default makes it a hard error (UnknownSeverityError).

Only security findings are evidence. The engines' own `security` tag (rule
properties.tags) is the discriminator — namespace is NOT a proxy for it:
`csharp.lang.best-practice.structured-logging` IS tagged security (CWE-117, OWASP A09),
while an Android best-practice rule has empty tags. Findings without the tag are
recorded in the JSONL but flagged `security: false`, so a best-practice suggestion
never inflates an ENS measure.

Rule ids are canonicalised before dedupe/mapping/storage: local-directory runs emit
"<rules-root-path-with-dots>.c.lang.security.double-free"; the prefix is stripped so
both modes share mapping keys. Unnormalised, every local-mode finding would land in the
unmapped appendix under a machine-specific, non-reproducible key. Path bases differ per
engine too (Semgrep %SRCROOT%, Trivy ROOTPATH); both normalise to repo-relative POSIX.

Determinism duties (round 10): sort findings by (file, class, rule, fingerprint) —
engine output order is not guaranteed; never copy SARIF run metadata (Trivy embeds the
absolute scan root in originalUriBaseIds); run.json records Trivy's vulnerability-DB
version, which is absent from the SARIF and drifts daily. Acceptance: same fixture in,
byte-identical JSONL twice.
"""

import hashlib
import json
import re
from pathlib import Path

import yaml

SCHEMA = "ens-evidence/1"
SCHEMA_LINE = '{"schema":"ens-evidence/1"}'
CANONICAL = ["critical", "high", "medium", "low", "info"]


class UnknownSeverityError(Exception):
    """An engine emitted a severity signal the policy file does not cover, and the
    file declares no `default` to resolve it."""


# --- serialisation -----------------------------------------------------------


def dumps_line(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def write_jsonl(path, findings):
    lines = [SCHEMA_LINE] + [dumps_line(f) for f in findings]
    Path(path).write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


# --- data files --------------------------------------------------------------


def load_severity(path):
    return yaml.safe_load(Path(path).read_text())


def load_defect_classes(path):
    data = yaml.safe_load(Path(path).read_text())
    return [(re.compile(e["match"]), e["class"]) for e in data["classes"]]


def defect_class(tool, rule_id, classes):
    key = f"{tool}:{rule_id}"
    for pattern, cls in classes:
        if pattern.fullmatch(key):
            return cls
    return key  # self-class: an unlisted id can fail to merge, never mis-merge


# --- canonicalisation --------------------------------------------------------


def canonical_rule_id(raw_id, rules_root=None):
    """Strip a local rules-root prefix so local and registry runs share mapping keys."""
    if not rules_root:
        return raw_id
    dotted = str(rules_root).strip("/").replace("/", ".")
    if dotted and raw_id.startswith(dotted + "."):
        return raw_id[len(dotted) + 1 :]
    return raw_id


def _relative_path(uri, bases):
    """Engine path -> repo-relative POSIX, whatever base the engine used."""
    path = uri.removeprefix("file://")
    for base in bases:
        b = base.removeprefix("file://")
        if b and path.startswith(b):
            path = path[len(b) :]
            break
    path = path.lstrip("/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _normalise_snippet(text):
    return " ".join(text.split())


# --- severity ----------------------------------------------------------------


def _resolve_default(policy, detail):
    if "default" in policy:
        return policy["default"]
    raise UnknownSeverityError(detail)


def _severity(tool, rule, policy):
    cfg = policy["engines"].get(tool)
    if cfg is None:
        return _resolve_default(policy, f"no severity strategy for engine {tool!r}")
    tags = rule.get("properties", {}).get("tags", [])

    if cfg["strategy"] == "severity_tag_then_bands":
        for tag in tags:
            if tag in cfg["tags"]:
                return cfg["tags"][tag]
        score = rule.get("properties", {}).get("security-severity")
        if score is not None:
            score = float(score)
            for level in CANONICAL:
                if level in cfg["bands"] and score >= cfg["bands"][level]:
                    return level
        return _resolve_default(policy, f"{tool} rule {rule.get('id')!r}: no severity signal")

    if cfg["strategy"] == "sarif_level_with_confidence":
        level = rule.get("defaultConfiguration", {}).get("level", "warning")
        canonical = cfg["levels"].get(level)
        if canonical is None:
            return _resolve_default(policy, f"{tool} level {level!r} not in policy")
        step = 0
        for tag in tags:
            step += cfg.get("confidence_adjust", {}).get(tag, 0)
        idx = min(len(CANONICAL) - 1, max(0, CANONICAL.index(canonical) - step))
        return CANONICAL[idx]

    return _resolve_default(policy, f"unknown strategy {cfg['strategy']!r}")


# --- pipeline ----------------------------------------------------------------


def _tool_name(driver):
    return driver["name"].split()[0].lower()


def _extract(sarif_path, severity_policy, rules_root, target_root=None):
    """One SARIF file -> raw finding dicts (pre-dedupe)."""
    doc = json.loads(Path(sarif_path).read_text())
    out = []
    for run in doc["runs"]:
        driver = run["tool"]["driver"]
        tool = _tool_name(driver)
        rules = {r["id"]: r for r in driver.get("rules", [])}
        bases = [b.get("uri", "") for b in (run.get("originalUriBaseIds") or {}).values()]
        if target_root:
            # Semgrep given an absolute target emits absolute uris with no base entry
            bases.append(str(target_root).rstrip("/") + "/")
        for result in run["results"]:
            rule = rules.get(result["ruleId"], {"id": result["ruleId"]})
            loc = result["locations"][0]["physicalLocation"]
            region = loc.get("region", {})
            tags = rule.get("properties", {}).get("tags", [])
            out.append(
                {
                    "tool": tool,
                    "rule": canonical_rule_id(result["ruleId"], rules_root),
                    "sev": _severity(tool, rule, severity_policy),
                    "security": "security" in tags,
                    "file": _relative_path(loc["artifactLocation"]["uri"], bases),
                    "line": region.get("startLine", 0),
                    "col": region.get("startColumn", 0),
                    "msg": result.get("message", {}).get("text", ""),
                    "snippet": _normalise_snippet(region.get("snippet", {}).get("text", "")),
                }
            )
    return out


def _dedupe(raw, classes):
    groups = {}
    for f in raw:
        f["class"] = defect_class(f["tool"], f["rule"], classes)
        groups.setdefault((f["file"], f["class"]), []).append(f)

    survivors = []
    for members in groups.values():
        # highest severity survives; ties break deterministically, position last so
        # the same duplicate wins whatever order the engine emitted them in
        members.sort(
            key=lambda f: (
                CANONICAL.index(f["sev"]),
                f["tool"],
                f["rule"],
                f["line"],
                f["col"],
                f["snippet"],
            )
        )
        keep = members[0]
        if len(members) > 1:
            pairs = sorted({(f["tool"], f["rule"]) for f in members})
            keep["merged_from"] = [list(p) for p in pairs]
        survivors.append(keep)
    return survivors


def _fingerprint_all(survivors):
    groups = {}
    for f in survivors:
        groups.setdefault((f["rule"], f["snippet"]), []).append(f)
    for members in groups.values():
        # position ORDER, not position value: a whole-file shift preserves it. The
        # ordinal is repo-global so identical snippets in two files still get unique
        # ids; renames can only permute ordinals within the group, so the fingerprint
        # SET — which is what the baseline stores — is unaffected.
        members.sort(key=lambda f: (f["file"], f["line"], f["col"]))
        for ordinal, f in enumerate(members):
            f["fingerprint"] = fingerprint(f["rule"], f["snippet"], ordinal)
            f["id"] = f["fingerprint"][:8]


def fingerprint(rule_id, snippet, ordinal):
    payload = "\0".join([rule_id, _normalise_snippet(snippet), str(ordinal)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def normalise(
    sarif_paths,
    severity_policy,
    defect_classes,
    rules_root=None,
    baseline=frozenset(),
    target_root=None,
    stats=None,
):
    """Engine SARIF files -> sorted, deduplicated, fingerprinted finding dicts.

    `stats`, when given a dict, receives {"raw": <pre-dedupe finding count>} so the
    caller can report deduped_away without re-parsing the SARIF."""
    raw = []
    for p in sarif_paths:
        raw.extend(_extract(p, severity_policy, rules_root, target_root))
    if stats is not None:
        stats["raw"] = len(raw)
    survivors = _dedupe(raw, defect_classes)
    _fingerprint_all(survivors)
    for f in survivors:
        f["new"] = f["fingerprint"] not in baseline
        del f["col"]
    survivors.sort(key=lambda f: (f["file"], f["class"], f["rule"], f["fingerprint"]))
    return survivors
