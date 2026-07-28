"""Spanish ENS (RD 311/2022) evidence for a repository: evidence, never a verdict.

Five verbs on the finding path — `scan`, `baseline update`, `report`, `bundle`, `explain` —
plus the licence-gated `rules` bootstrap group, which fetches the operator's own pinned copy
of the Semgrep rules (never bundled with this tool: DESIGN.md "Rule sourcing").

Owns the run store under ``out/<date>_<git-short-sha>/`` (immutable, append-only,
written temp-dir-then-rename so a crashed run is never presentable), the skip key
(git SHA + engine versions + Trivy DB/checks-bundle versions + rules mode/SHA +
mapping hash + baseline hash + config hash), and config resolution:
flags -> ENS_EVIDENCE_* env -> .ens-evidence.yml -> defaults. Never interactive.

Engines are subprocess calls to pinned binaries, never Python imports; a missing
binary exits 2 with a message naming it. Neither engine is hermetic by default, so
Trivy runs --offline-scan --skip-db-update --skip-check-update (it otherwise resolves
Maven POMs over the network — observed dying on a 429) and Semgrep runs the configured
rules root; the registry config is permitted but recorded as non-reproducible.
run.json records every drifting input; see DESIGN.md "Drift".

Exit 0 = no NEW findings at/above --fail-on (or skip-key hit), 1 = there are,
2 = tool error. Machine JSON on stdout (schema-marked), human chatter on stderr.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

import yaml

from ens_evidence import MAPPING_DIR, TEMPLATE_DIR, mapper, normalise, render
from ens_evidence.normalise import CANONICAL, SCHEMA, dumps_line

CONFIG_DEFAULTS = {
    "fail_on": None,
    "rules_root": None,
    "out_dir": "out",
    "fixed_date": None,
}

# Language census is extension-driven and data-driven; anything unlisted is ignored
# rather than guessed.
EXTENSION_LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".ex": "elixir",
    ".exs": "elixir",
    ".go": "go",
    ".h": "c",
    ".java": "java",
    ".js": "javascript",
    ".kt": "kotlin",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sh": "shell",
    ".swift": "swift",
    ".tf": "terraform",
    ".ts": "typescript",
    ".yaml": "yaml",
    ".yml": "yaml",
}
FILENAME_LANGUAGES = {"Dockerfile": "dockerfile"}

# Analysed by Trivy misconfig even when the Semgrep rules root has no rules for them.
TRIVY_ANALYSED = {"dockerfile", "yaml", "terraform"}

# Our census language name -> the upstream rules directory that covers it. Without this the
# coverage table declared "shell — no rules ran" while 6 bash rules had just run against it
# (observed 2026-07-26 in the sample render). Principle IV cuts both ways: the table must not
# claim a gap it does not have, or the honest gaps stop being believed.
RULE_DIR_ALIASES = {"shell": "bash"}

LOCKFILE_NAMES = {
    "Cargo.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "composer.lock",
    "go.sum",
    "gradle.lockfile",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
}

SKIP_DIRS = {".git", ".ens-rules", "out"}


def _err(msg):
    print(f"ens-evidence: {msg}", file=sys.stderr)


# --- config ------------------------------------------------------------------


def resolve_config(flags, env, target):
    """flags -> ENS_EVIDENCE_* env -> .ens-evidence.yml -> defaults. Returns
    (resolved dict, sha256 of its canonical serialisation)."""
    cfg = dict(CONFIG_DEFAULTS)
    repo_file = Path(target) / ".ens-evidence.yml"
    if repo_file.is_file():
        loaded = yaml.safe_load(repo_file.read_text()) or {}
        cfg.update({k: v for k, v in loaded.items() if k in CONFIG_DEFAULTS})
    for key in CONFIG_DEFAULTS:
        env_key = "ENS_EVIDENCE_" + key.upper()
        if env.get(env_key):
            cfg[key] = env[env_key]
    cfg.update({k: v for k, v in flags.items() if v is not None and k in CONFIG_DEFAULTS})
    return cfg, hashlib.sha256(dumps_line(cfg).encode()).hexdigest()


# --- version + rules collection ----------------------------------------------


def _require_binaries():
    for binary in ("semgrep", "trivy"):
        if shutil.which(binary) is None:
            _err(f"required engine binary not found on PATH: {binary}")
            return binary
    return None


def _engine_versions():
    semgrep = subprocess.run(
        ["semgrep", "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    trivy = json.loads(
        subprocess.run(
            ["trivy", "version", "--format", "json"], capture_output=True, text=True, check=True
        ).stdout
    )
    db = trivy.get("VulnerabilityDB") or {}
    bundle = trivy.get("CheckBundle") or {}
    return {
        "semgrep": semgrep,
        "trivy": trivy.get("Version"),
        "trivy_db": {"version": db.get("Version"), "updated_at": db.get("UpdatedAt")},
        "trivy_checks_bundle": bundle.get("Digest"),
    }


def _git(target, *args):
    proc = subprocess.run(["git", "-C", str(target), *args], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def rules_per_language(rules_root):
    counts = {}
    root = Path(rules_root)
    for p in root.rglob("*.y*ml"):
        rel = p.relative_to(root)
        if len(rel.parts) < 2 or rel.parts[0].startswith("."):
            continue
        counts[rel.parts[0]] = counts.get(rel.parts[0], 0) + 1
    return dict(sorted(counts.items()))


def rules_info(cfg):
    root = cfg.get("rules_root")
    if not root:
        return {
            "mode": "registry",
            "config": "p/default",
            "repo": None,
            "sha": None,
            "root": None,
            "per_language": None,
        }
    return {
        "mode": "local",
        "config": None,
        "repo": _git(root, "remote", "get-url", "origin"),
        "sha": _git(root, "rev-parse", "HEAD"),
        "root": str(root),
        "per_language": rules_per_language(root),
    }


# --- coverage ----------------------------------------------------------------


def _census_files(target):
    """The files the census counts: git-tracked ones when the target is a work tree.

    Walking the filesystem counted a virtualenv — 1500 python files against the 117 semgrep
    actually scanned, observed 2026-07-26 in the sample render. The engines see git-tracked
    files (semgrep reads only those; trivy honours .gitignore), so a census that counts more
    describes a repository nobody analysed, and Principle IV's coverage table is then
    disclosing a fiction. Falls back to a walk when there is no git.
    """
    tracked = _git(target, "ls-files", "-z")
    if tracked is not None:
        return [Path(p) for p in tracked.split("\0") if p]
    found = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        found.extend(Path(dirpath).relative_to(target) / name for name in filenames)
    return found


def language_census(target):
    census = {}
    for path in _census_files(target):
        if path.parts and path.parts[0] in SKIP_DIRS:
            continue
        lang = FILENAME_LANGUAGES.get(path.name) or EXTENSION_LANGUAGES.get(path.suffix)
        if lang:
            census[lang] = census.get(lang, 0) + 1
    return dict(sorted(census.items()))


def _has_lockfile(target):
    for _, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(f in LOCKFILE_NAMES for f in filenames):
            return True
    return False


def build_coverage(target, rules):
    return build_coverage_from_census(language_census(target), _has_lockfile(target), rules)


def build_coverage_from_census(census, lockfile, rules):
    if rules["mode"] == "local":
        per_language = rules["per_language"]
        not_analysed = sorted(
            lang
            for lang in census
            if per_language.get(RULE_DIR_ALIASES.get(lang, lang), 0) == 0
            and lang not in TRIVY_ANALYSED
        )
    else:
        # registry configs are versionless: rule counts are not knowable, and the
        # coverage table must say so rather than guess (Principle IV)
        per_language = "registry-uncounted"
        not_analysed = []
    return {
        "languages_detected": census,
        "rules_per_language": per_language,
        "languages_not_analysed": not_analysed,
        "dependency_analysis": "done" if lockfile else "skipped-no-lockfile",
    }


# --- engines -----------------------------------------------------------------


RULE_FIXTURE_MARKERS = (".test.", ".fixed.")
RULES_TOP_KEY = re.compile(rb"^rules:", re.M)


def semgrep_configs(rules_root):
    """-> the `--config` arguments for a local rules checkout, sorted.

    NOT simply the checkout root: the upstream `semgrep-rules` repository ships YAML that
    is not a ruleset (`stats/` holds category metadata, `.github/stale.yml` is bot config),
    and ONE invalid config file makes semgrep reject the whole run with exit 7 — scanning
    nothing while looking like an engine failure. Verified 2026-07-26 against the pinned
    SHA: passing the root scans 0 files, passing the 28 rule directories scans normally.

    A directory qualifies when every non-fixture YAML under it declares a top-level
    `rules:` key. Rule *test* fixtures (`*.test.yaml`) are left in place — semgrep
    tolerates them — but they do not disqualify their directory.
    """
    root = Path(rules_root)
    configs = []
    for child in sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")):
        candidates = [
            f
            for f in child.rglob("*.y*ml")
            if not any(marker in f.name for marker in RULE_FIXTURE_MARKERS)
        ]
        if not candidates:
            continue
        if all(RULES_TOP_KEY.search(f.read_bytes()[:4096]) for f in candidates):
            configs.append(str(child))
    return configs


def prune_sarif_rules(path):
    """Keep only the rules that actually fired in a stored SARIF file.

    SARIF's `tool.driver.rules` is a catalogue: it describes every rule the engine COULD
    have matched. With a pinned rules root that is the whole ruleset — measured 2026-07-26:
    2126 rule descriptions, 3.9 MB, for 9 findings. The run store is the portable evidence
    unit, so the obvious next action with it (hand it over, attach it, upload it) would
    publish third-party rule documentation, which the Semgrep Rules License v1.0 does not
    permit. Rules that fired stay: they are the provenance of the findings we report, and
    without them the stored SARIF cannot be checked against findings.jsonl.

    The pruning is recorded in run.json — a stored artifact that is no longer byte-identical
    engine output must say so, or the provenance claim is false. Deterministic: same input,
    same bytes (principle I).

    -> {"kept": n, "dropped": n}
    """
    document = json.loads(path.read_text())
    kept = dropped = 0
    for run_block in document.get("runs", []):
        driver = run_block.get("tool", {}).get("driver", {})
        catalogue = driver.get("rules")
        if not catalogue:
            continue
        fired = {result.get("ruleId") for result in run_block.get("results", [])}
        keeping = [rule for rule in catalogue if rule.get("id") in fired]
        dropped += len(catalogue) - len(keeping)
        kept += len(keeping)
        driver["rules"] = keeping
    path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    return {"kept": kept, "dropped": dropped}


def _invoke_engines(target, cfg, tmp):
    """Both engines against `target`, SARIF into `tmp`. Hermetic per research.md R1."""
    semgrep_out = tmp / "semgrep.sarif"
    trivy_out = tmp / "trivy.sarif"
    if cfg["rules_root"]:
        configs = semgrep_configs(cfg["rules_root"])
        if not configs:
            raise EngineError(
                f"no semgrep rule directories under {cfg['rules_root']} — is it a "
                "semgrep-rules checkout?"
            )
    else:
        configs = ["p/default"]
    commands = [
        [
            "semgrep",
            "scan",
            "--sarif",
            "--metrics=off",
            *[f"--config={c}" for c in configs],
            "--output",
            str(semgrep_out),
            str(target),
        ],
        [
            "trivy",
            "fs",
            "--scanners",
            "vuln,misconfig,secret",
            "--format",
            "sarif",
            "--offline-scan",
            "--skip-db-update",
            "--skip-check-update",
            "-o",
            str(trivy_out),
            str(target),
        ],
        [
            "trivy",
            "fs",
            "--format",
            "cyclonedx",
            "--offline-scan",
            "--skip-db-update",
            "-o",
            str(tmp / "sbom.cdx.json"),
            str(target),
        ],
    ]
    for cmd in commands:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise EngineError(f"{cmd[0]} failed ({proc.returncode}): {proc.stderr.strip()[-500:]}")
    return semgrep_out, trivy_out


class EngineError(Exception):
    pass


# --- run store ---------------------------------------------------------------


def compute_skip_key(git_sha, versions, rules, mapping_hashes, baseline_sha, config_sha):
    parts = [
        git_sha,
        versions["semgrep"],
        versions["trivy"],
        dumps_line(versions["trivy_db"]),
        str(versions["trivy_checks_bundle"]),
        rules["mode"],
        str(rules["sha"]),
        dumps_line(mapping_hashes),
        str(baseline_sha),
        config_sha,
    ]
    return hashlib.sha256("\0".join(str(p) for p in parts).encode()).hexdigest()


def _sha256_file(path):
    p = Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def find_existing_run(out_dir, skip_key):
    if not out_dir.is_dir():
        return None
    for run_dir in sorted(out_dir.iterdir()):
        if run_dir.name.startswith(".") or not run_dir.is_dir():
            continue
        record = run_dir / "run.json"
        if record.is_file():
            try:
                if json.loads(record.read_text()).get("skip_key") == skip_key:
                    return run_dir
            except ValueError:
                continue
    return None


def _new_run_dir(out_dir, run_date, short_sha):
    base = f"{run_date}_{short_sha}"
    candidate = out_dir / base
    seq = 1
    while candidate.exists():
        seq += 1
        candidate = out_dir / f"{base}_{seq}"
    return candidate


def _swap_latest(out_dir, run_dir):
    tmp_link = out_dir / f".latest-{os.getpid()}"
    if tmp_link.is_symlink():
        tmp_link.unlink()
    tmp_link.symlink_to(run_dir.name)
    os.replace(tmp_link, out_dir / "latest")


# --- verbs -------------------------------------------------------------------


def gate_exit(findings, fail_on):
    if fail_on is None:
        return 0
    threshold = CANONICAL.index(fail_on)
    hits = sum(1 for f in findings if f["new"] and CANONICAL.index(f["sev"]) <= threshold)
    return 1 if hits else 0


def load_baseline(target):
    path = Path(target) / ".ens-baseline.yml"
    if not path.is_file():
        return frozenset(), None
    data = yaml.safe_load(path.read_text()) or {}
    return frozenset(data.get("fingerprints", [])), _sha256_file(path)


def cmd_scan(args):
    target = Path(args.path).resolve()
    git_sha = _git(target, "rev-parse", "HEAD")
    short_sha = _git(target, "rev-parse", "--short", "HEAD")
    if not git_sha:
        _err(f"{target} is not a git work tree")
        return 2

    cfg, config_sha = resolve_config(
        {"fail_on": args.fail_on, "rules_root": args.rules_root}, dict(os.environ), target
    )
    missing = _require_binaries()
    if missing:
        return 2

    try:
        versions = _engine_versions()
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        _err(f"engine version probe failed: {exc}")
        return 2

    rules = rules_info(cfg)
    mapping_hashes = {
        "severity_sha256": _sha256_file(MAPPING_DIR / "severity.yml"),
        "defect_classes_sha256": _sha256_file(MAPPING_DIR / "defect_classes.yml"),
    }
    baseline, baseline_sha = load_baseline(target)
    skip_key = compute_skip_key(git_sha, versions, rules, mapping_hashes, baseline_sha, config_sha)

    out_dir = target / cfg["out_dir"]
    if not args.force:
        existing = find_existing_run(out_dir, skip_key)
        if existing:
            _err(f"unchanged inputs — run already exists: {existing}")
            print(dumps_line({"schema": SCHEMA, "skipped": True, "run": str(existing)}))
            return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-run-", dir=out_dir))
    try:
        try:
            sarif_paths = _invoke_engines(target, cfg, tmp)
        except EngineError as exc:
            _err(str(exc))
            return 2

        stats = {}
        findings = normalise.normalise(
            sarif_paths=list(sarif_paths),
            severity_policy=normalise.load_severity(MAPPING_DIR / "severity.yml"),
            defect_classes=normalise.load_defect_classes(MAPPING_DIR / "defect_classes.yml"),
            rules_root=cfg["rules_root"],
            baseline=baseline,
            target_root=target,
            stats=stats,
        )
        normalise.write_jsonl(tmp / "findings.jsonl", findings)
        # After normalising, never before: the normaliser reads the driver's rule metadata.
        sarif_pruning = {p.stem: prune_sarif_rules(p) for p in sorted(sarif_paths)}

        record = {
            "schema": SCHEMA,
            "run": {
                "date": cfg["fixed_date"] or date.today().isoformat(),
                "git_sha": git_sha,
                "git_short_sha": short_sha,
                "target": str(target),
            },
            "engines": versions,
            "rules": rules,
            "sarif_rules_pruned": sarif_pruning,
            "mapping": mapping_hashes,
            "baseline_sha256": baseline_sha,
            "config_sha256": config_sha,
            "skip_key": skip_key,
            "coverage": build_coverage(target, rules),
            "counts": {
                "total": len(findings),
                "security": sum(1 for f in findings if f["security"]),
                "non_security": sum(1 for f in findings if not f["security"]),
                "new": sum(1 for f in findings if f["new"]),
                "deduped_away": stats["raw"] - len(findings),
            },
        }
        (tmp / "run.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")

        run_dir = _new_run_dir(out_dir, record["run"]["date"], short_sha)
        os.replace(tmp, run_dir)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)

    _swap_latest(out_dir, run_dir)
    code = gate_exit(findings, cfg["fail_on"])
    print(
        dumps_line(
            {"schema": SCHEMA, "run": str(run_dir), "counts": record["counts"], "exit": code}
        )
    )
    return code


def cmd_baseline_update(args):
    target = Path(args.path).resolve()
    cfg, _ = resolve_config({}, dict(os.environ), target)
    findings_file = target / cfg["out_dir"] / "latest" / "findings.jsonl"
    if not findings_file.is_file():
        _err(f"no run to accept: {findings_file} does not exist — scan first")
        return 2
    fingerprints = sorted(
        json.loads(line)["fingerprint"]
        for line in findings_file.read_text().splitlines()[1:]
        if line
    )
    baseline_path = target / ".ens-baseline.yml"
    baseline_path.write_text(
        yaml.safe_dump(
            {"schema": SCHEMA, "updated": date.today().isoformat(), "fingerprints": fingerprints},
            sort_keys=True,
            default_flow_style=False,
        )
    )
    print(
        dumps_line(
            {"schema": SCHEMA, "baseline": str(baseline_path), "fingerprints": len(fingerprints)}
        )
    )
    return 0


# --- report / explain (spec 002) ---------------------------------------------

PDF_CONVERTER = "pandoc"

# The canonical scope list lives in the constitution, the README, the mapping file and
# the report template (principle III). It is passed to the renderer as section ORDER,
# never as a redefinition — mapping/ens_rd311.yml remains the source of truth for which
# measures exist, and tests/test_mapping_contract.py gates the four copies against drift.
SCOPE = ["mp.sw.1", "mp.sw.2", "mp.s.2", "op.exp.2", "op.exp.3", "op.exp.4"]


def _resolve_run_dir(args):
    """-> a stored run directory, or None with the reason already reported."""
    target = Path(args.path).resolve()
    cfg, _ = resolve_config({}, dict(os.environ), target)
    run_dir = Path(args.run).resolve() if args.run else target / cfg["out_dir"] / "latest"
    if not (run_dir / "findings.jsonl").is_file():
        _err(f"no stored run at {run_dir} — scan first")
        return None
    return run_dir


def _pdf_engine(args):
    """Which PDF engine pandoc should use, if the operator named one.

    Deliberately NOT auto-detected: the tool would then pick a different engine per
    machine and silently change the PDF's appearance. Deliberately NOT part of
    CONFIG_DEFAULTS either — it is a rendering concern, and folding it into the config
    hash would put it in `scan`'s skip key, where it has no business.
    """
    return args.pdf_engine or os.environ.get("ENS_EVIDENCE_PDF_ENGINE") or None


def _pdf_note(reason):
    return (
        f"No se ha generado la versión PDF: {reason}. El contenido de este documento "
        "Markdown es íntegro y no depende de esa conversión."
    )


def _build_model(run_dir):
    findings, record = render.load_run(run_dir)
    return render.build_model(
        findings,
        record,
        mapper.load_rules(MAPPING_DIR / "ens_rd311.yml"),
        render.load_measures(MAPPING_DIR / "measures_es.yml"),
        SCOPE,
    )


def cmd_report(args):
    run_dir = _resolve_run_dir(args)
    if run_dir is None:
        return 2
    try:
        model = _build_model(run_dir)
    except (OSError, ValueError, KeyError) as exc:
        _err(f"unreadable run at {run_dir}: {exc}")
        return 2

    converter = shutil.which(PDF_CONVERTER)
    want_pdf = args.format in ("pdf", "auto")
    if args.format == "pdf" and converter is None:
        _err(f"--format pdf needs the {PDF_CONVERTER} binary, which is not on PATH")
        return 2

    def _write(note):
        """Any PDF note is disclosed IN THE DOCUMENT, not only on stderr: a CI log gets
        discarded, the evidence file does not."""
        report_md = run_dir / "report.md"
        report_md.write_text(render.render_report(model, TEMPLATE_DIR, pdf_note=note), "utf-8")
        return report_md

    reason = None
    if want_pdf and converter is None:
        reason = f"el conversor «{PDF_CONVERTER}» no estaba disponible"
    report_md = _write(_pdf_note(reason) if reason else None)

    written = [str(report_md)]
    if want_pdf and converter is not None:
        report_pdf = run_dir / "report.pdf"
        cmd = [converter, str(report_md), "-o", str(report_pdf)]
        engine = _pdf_engine(args)
        if engine:
            cmd.append(f"--pdf-engine={engine}")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            written.append(str(report_pdf))
        else:
            # A converter can be installed and still be unable to produce a PDF —
            # pandoc needs a separate PDF engine, and says so only when asked to
            # convert. `--format pdf` was an explicit request, so it fails; `auto`
            # degrades, because a complete evidence document must not be withheld
            # over a missing presentation format.
            detail = proc.stderr.strip().splitlines()[-1][:200] if proc.stderr.strip() else ""
            if args.format == "pdf":
                _err(f"{PDF_CONVERTER} could not produce a PDF: {detail}")
                return 2
            reason = f"«{PDF_CONVERTER}» no pudo generarlo ({detail})"
            report_md = _write(_pdf_note(reason))

    if reason:
        _err(f"PDF not produced: {reason}")

    print(dumps_line({"schema": SCHEMA, "written": written, "findings": model["totals"]}))
    return 0


RULES_REPO = "https://github.com/semgrep/semgrep-rules"
RULES_LICENCE_URL = "https://github.com/semgrep/semgrep-rules/blob/develop/LICENSE"
RULES_ROOT_DEFAULT = ".ens-rules"

# Our own summary, never the licence text: bulk-copying someone else's terms is the same
# reflex principle V forbids for the BOE. The operator is told what they are agreeing to
# and where to read it in full.
RULES_LICENCE_NOTICE = f"""\
Semgrep's detection rules are NOT part of this tool and are not distributed with it.
They are published under the Semgrep Rules License v1.0, which — in summary, not
verbatim — permits use for the licensee's own internal business purposes and forbids
redistributing them or offering them as a service.

What that means for you:
  * fetching them puts THIRD-PARTY files under your control, at a commit you choose;
  * you must not publish them — not in an image, a package, a release asset, a build
    artifact, or a commit;
  * this tool never mirrors, modifies or re-namespaces them.

Full terms: {RULES_LICENCE_URL}

Re-run with --accept-rules-license (or ENS_EVIDENCE_ACCEPT_RULES_LICENSE=1) to fetch.
Nothing has been downloaded."""


def _rules_root(args):
    return Path(getattr(args, "rules_root", None) or RULES_ROOT_DEFAULT).resolve()


def _git_ok(root, *argv):
    """-> (returncode, stderr tail). git is a subprocess here for the same reason the
    engines are: no new dependency, and the operator controls the binary."""
    proc = subprocess.run(
        ["git", "-C", str(root), *argv], capture_output=True, text=True, check=False
    )
    tail = proc.stderr.strip().splitlines()[-1][:200] if proc.stderr.strip() else ""
    return proc.returncode, tail


def _rules_payload(root):
    cfg = dict(CONFIG_DEFAULTS)
    cfg["rules_root"] = str(root)
    return {"schema": SCHEMA, **rules_info(cfg)}


def cmd_rules_fetch(args):
    """Pin the operator's own copy of the rules at a commit SHA. A depth-1 fetch of an
    explicit commit is the only shape that is both pinned and cheap — `git clone --branch`
    cannot take an arbitrary SHA."""
    accepted = args.accept_rules_license or os.environ.get("ENS_EVIDENCE_ACCEPT_RULES_LICENSE") in (
        "1",
        "true",
        "yes",
    )
    if not accepted:
        _err(RULES_LICENCE_NOTICE)
        return 2

    if shutil.which("git") is None:
        _err("rules fetch needs the git binary, which is not on PATH")
        return 2

    root = _rules_root(args)
    if root.exists() and not (root / ".git").is_dir():
        _err(f"{root} exists and is not a git work tree — move it or choose --rules-root")
        return 2

    root.mkdir(parents=True, exist_ok=True)
    if not (root / ".git").is_dir():
        code, detail = _git_ok(root, "init", "--quiet")
        if code != 0:
            _err(f"could not initialise {root}: {detail}")
            return 2
    # Idempotent: re-fetching a different SHA into an existing root is the normal way to
    # move the pin, so the remote is set rather than added.
    _git_ok(root, "remote", "remove", "origin")
    code, detail = _git_ok(root, "remote", "add", "origin", args.repo)
    if code != 0:
        _err(f"could not set the rules remote: {detail}")
        return 2

    code, detail = _git_ok(root, "fetch", "--depth", "1", "--quiet", "origin", args.sha)
    if code != 0:
        _err(f"could not fetch {args.sha} from {args.repo}: {detail}")
        return 2
    code, detail = _git_ok(root, "checkout", "--quiet", "FETCH_HEAD")
    if code != 0:
        _err(f"fetched {args.sha} but could not check it out: {detail}")
        return 2

    _err(f"rules pinned at {args.sha} in {root} — never publish these files")
    print(dumps_line(_rules_payload(root)))
    return 0


def cmd_rules_status(args):
    """What the next scan would use. Registry mode is a state to report, not an error —
    but it is reported as non-reproducible, because it is."""
    target = Path(args.path).resolve()
    cfg, _ = resolve_config({"rules_root": args.rules_root}, dict(os.environ), target)
    payload = {"schema": SCHEMA, **rules_info(cfg)}
    payload["reproducible"] = payload["mode"] == "local" and bool(payload["sha"])
    if not payload["reproducible"]:
        _err(
            "registry mode: the ruleset is not pinned, so this configuration is NOT "
            "reproducible — fetch the rules at a commit SHA for CI-grade runs"
        )
    print(dumps_line(payload))
    return 0


def cmd_bundle(args):
    """The paste-anywhere view of a stored run. Never scans, never renders a PDF: its
    purpose is being pasted into a chat window, which is also why every field of
    scanned-repo text in it goes through render's fencing filters."""
    run_dir = _resolve_run_dir(args)
    if run_dir is None:
        return 2
    try:
        model = _build_model(run_dir)
    except (OSError, ValueError, KeyError) as exc:
        _err(f"unreadable run at {run_dir}: {exc}")
        return 2

    bundle_md = run_dir / "bundle.md"
    bundle_md.write_text(render.render_bundle(model, TEMPLATE_DIR), "utf-8")
    print(dumps_line({"schema": SCHEMA, "bundle": str(bundle_md), "run": str(run_dir)}))
    return 0


def cmd_explain(args):
    run_dir = _resolve_run_dir(args)
    if run_dir is None:
        return 2
    model = _build_model(run_dir)
    match = next((f for f in model["findings"] if f["id"] == args.id), None)
    if match is None:
        _err(f"no finding with id {args.id!r} in {run_dir}")
        return 2

    if match["counts"]:
        why = (
            f"El patrón {match['matched_rule']!r} es el primero del fichero de "
            f"correspondencias que casa con {match['tool']}:{match['rule']}; las reglas se "
            f"evalúan en orden y gana la primera. El motor marcó el hallazgo como de "
            f"seguridad, así que cuenta como evidencia de: {', '.join(match['measures'])}."
        )
    elif not match["security"]:
        why = (
            "El motor NO etiquetó esta regla como de seguridad, así que el hallazgo se "
            "registra pero no cuenta para ninguna medida"
            + (
                f" (el patrón {match['matched_rule']!r} habría dado "
                f"{', '.join(match['measures'])})."
                if match["matched_rule"]
                else "."
            )
        )
    else:
        why = (
            "Ningún patrón del fichero de correspondencias casa con "
            f"{match['tool']}:{match['rule']}, así que el hallazgo queda a la espera de una "
            "decisión humana sobre a qué medida corresponde y figura en el apéndice de "
            "hallazgos sin correspondencia."
        )

    explanation = {
        "schema": SCHEMA,
        "id": match["id"],
        "finding": {
            "tool": match["tool"],
            "rule": match["rule"],
            "sev": match["sev"],
            "file": match["file"],
            "msg": render.truncate(match["msg"]),
        },
        "matched_rule": match["matched_rule"],
        "measures": match["measures"],
        "counts_toward_measures": match["counts"],
        "why": why,
    }

    if args.json:
        print(dumps_line(explanation))
    else:
        print(dumps_line(explanation))
        _err(render.fence(match["msg"]))
    return 0


# --- CLI ---------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ens-evidence", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="verb", required=True)

    scan = sub.add_parser("scan", help="engines -> normalise -> baseline -> run store")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument(
        "--fail-on",
        choices=CANONICAL[:-1],
        default=None,
        help="exit 1 on NEW findings at/above this severity (default: gate off)",
    )
    scan.add_argument(
        "--force",
        action="store_true",
        help="ignore the skip key; must reproduce byte-identical findings",
    )
    scan.add_argument(
        "--rules-root", default=None, help="pinned local semgrep-rules checkout (hermetic mode)"
    )
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=cmd_scan)

    report = sub.add_parser("report", help="re-render the evidence report from a stored run")
    report.add_argument("path", nargs="?", default=".")
    report.add_argument("--run", default=None, help="run directory (default: <out>/latest)")
    report.add_argument("--format", choices=["md", "pdf", "auto"], default="auto")
    report.add_argument(
        "--pdf-engine",
        default=None,
        help="engine pandoc should use (e.g. weasyprint, pdflatex); "
        "also ENS_EVIDENCE_PDF_ENGINE. Unset: pandoc's own default",
    )
    report.add_argument("--json", action="store_true")
    report.set_defaults(func=cmd_report)

    rules = sub.add_parser("rules", help="the rules bootstrap group (licence-gated)")
    rules_sub = rules.add_subparsers(dest="rules_verb", required=True)

    fetch = rules_sub.add_parser("fetch", help="pin the operator's own rules copy at a SHA")
    fetch.add_argument("--sha", required=True, help="upstream commit SHA to pin to")
    fetch.add_argument(
        "--repo", default=RULES_REPO, help=f"rules repository (default: {RULES_REPO})"
    )
    fetch.add_argument(
        "--rules-root", default=None, help=f"destination (default: {RULES_ROOT_DEFAULT})"
    )
    fetch.add_argument(
        "--accept-rules-license",
        action="store_true",
        help="acknowledge the Semgrep Rules License v1.0; also ENS_EVIDENCE_ACCEPT_RULES_LICENSE=1",
    )
    fetch.set_defaults(func=cmd_rules_fetch)

    status = rules_sub.add_parser("status", help="which rules the next scan would use")
    status.add_argument("path", nargs="?", default=".")
    status.add_argument("--rules-root", default=None)
    status.set_defaults(func=cmd_rules_status)

    bundle = sub.add_parser("bundle", help="paste-anywhere bundle.md from a stored run")
    bundle.add_argument("path", nargs="?", default=".")
    bundle.add_argument("--run", default=None, help="run directory (default: <out>/latest)")
    bundle.add_argument("--json", action="store_true")
    bundle.set_defaults(func=cmd_bundle)

    explain = sub.add_parser("explain", help="why one finding was filed where it was")
    explain.add_argument("id")
    explain.add_argument("path", nargs="?", default=".")
    explain.add_argument("--run", default=None, help="run directory (default: <out>/latest)")
    explain.add_argument("--json", action="store_true")
    explain.set_defaults(func=cmd_explain)

    baseline = sub.add_parser("baseline", help="baseline operations")
    baseline_sub = baseline.add_subparsers(dest="action", required=True)
    update = baseline_sub.add_parser("update", help="accept the latest run's findings")
    update.add_argument("path", nargs="?", default=".")
    update.set_defaults(func=cmd_baseline_update)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
