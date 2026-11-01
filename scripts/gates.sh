#!/usr/bin/env bash
# scripts/gates.sh — this repo's quality gate. One script, every caller:
#
#   .githooks/pre-commit        gates.sh staged        (git, any agent, any human)
#   CI                          gates.sh all
#   an agent's post-edit hook   gates.sh file <path>   (convenience: same findings, sooner)
#   once per clone              gates.sh install       (git config core.hooksPath .githooks)
#
# Exit 0 clean, 2 blocked. It never passes silently: a tool that is not installed
# is reported on stderr in local modes and FAILS the `all` mode (CI must have them).
#
# RATCHET: staged/file scan only what changed, so pre-existing debt never blocks
# unrelated work; `all` sweeps the tree. Tests dirs are excluded from the scans.
#
# EXTENSION SHIM: a script installed as a command has no .py suffix. ast-grep and
# ruff pick their parser from the extension, so such a file must be scanned via a
# .py copy or it matches nothing and the gate passes vacuously.
set -uo pipefail

ROOTS="src/ens_evidence scripts/unmapped_ids.py"                 # source dirs and files, space separated (no tests)
REQ="requirements-dev.txt"        # pip-audit target; missing file = pip-audit skipped
PYTEST_MARK="not engines and not rendering"                    # pytest -m expression, e.g. "not engines" when tests need binaries CI lacks
TEST_RE='(^|/)tests?/|/test_|_test\.py$'

mode=${1:-staged}
root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "gates: not a git repo" >&2; exit 2; }
cd "$root" || exit 2
for v in .venv .venv-test; do   # the repo's venv, if any, wins over global tools
  [ -x "$v/bin/python" ] && PATH="$root/$v/bin:$PATH" && break
done

if [ "$mode" = install ]; then
  git config core.hooksPath .githooks && echo "gates: core.hooksPath = .githooks"
  exit 0
fi

# ---- targets ---------------------------------------------------------------
in_roots() {              # path -> 0 if under one of ROOTS
  local f=$1 r
  for r in $ROOTS; do case "$f" in "$r"|"$r"/*) return 0 ;; esac; done
  return 1
}
is_py_like() { [ -f "$1" ] && { case "$1" in *.py) return 0 ;; esac; head -c 64 "$1" | grep -q '^#!.*python'; }; }

targets=()
case "$mode" in
  file)
    f=${2:?usage: gates.sh file <path>}
    f=${f#"$root"/}
    in_roots "$f" && is_py_like "$f" && ! [[ "$f" =~ $TEST_RE ]] && targets+=("$f")
    ;;
  staged)
    while IFS= read -r f; do
      [ -n "$f" ] && in_roots "$f" && is_py_like "$f" && ! [[ "$f" =~ $TEST_RE ]] && targets+=("$f")
    done < <(git diff --cached --name-only --diff-filter=ACM)
    ;;
  all)
    for r in $ROOTS; do
      if [ -d "$r" ]; then
        while IFS= read -r f; do [[ "$f" =~ $TEST_RE ]] || targets+=("$f"); done \
          < <(find "$r" -type f \( -name '*.py' -o -perm -u+x \) 2>/dev/null)
      elif [ -f "$r" ]; then targets+=("$r"); fi
    done
    tmp=(); for f in "${targets[@]}"; do is_py_like "$f" && tmp+=("$f"); done; targets=("${tmp[@]}")
    ;;
  *) echo "usage: gates.sh file <path> | staged | all | install" >&2; exit 2 ;;
esac

fail=0; missing=0
need() { command -v "$1" >/dev/null 2>&1 && return 0; echo "gates: $1 not installed — $2 SKIPPED" >&2; missing=1; return 1; }
block() { fail=1; printf '\n== %s ==\n%s\n' "$1" "$2" >&2; }

# ---- gates on targets --------------------------------------------------------
if [ ${#targets[@]} -gt 0 ]; then
  # shim: extension-less scripts get a .py twin; findings are mapped back below
  shim=$(mktemp -d); trap 'rm -rf "$shim"' EXIT
  scan=(); map=()
  for f in "${targets[@]}"; do
    case "$f" in
      *.py) scan+=("$f") ;;
      *) a="$shim/$(basename "$f").py"; cp "$f" "$a"; scan+=("$a"); map+=("$a=$f") ;;
    esac
  done
  unshim() { local o=$1 p; for p in "${map[@]:-}"; do [ -n "$p" ] && o=${o//${p%%=*}/${p#*=}}; done; printf '%s' "$o"; }

  if need ruff "lint"; then
    out=$(ruff check --no-fix --output-format concise "${scan[@]}" 2>&1); rc=$?
    [ $rc -ne 0 ] && block "ruff" "$(unshim "$out")"
  fi

  if need bandit "SAST"; then
    out=$(bandit -ll -q -f custom --msg-template '{relpath}:{line} [{severity}/{confidence}] {test_id} {msg}' "${scan[@]}" 2>/dev/null)
    [ -n "$out" ] && block "bandit (medium+)" "$(unshim "$out")"
  fi

  if [ -f sgconfig.yml ] && need ast-grep "structural scan"; then
    # Canary first, if the repo keeps one (.ast-grep/canary/*.py, deliberately defective):
    # ast-grep exits 0 on an unreadable ruleDir, so "no findings" and "scanner dead" look
    # identical without a file that MUST produce a finding.
    if ls .ast-grep/canary/*.py >/dev/null 2>&1; then
      if ! ast-grep scan -c sgconfig.yml --json=compact .ast-grep/canary/*.py 2>/dev/null | grep -q '"ruleId"'; then
        block "ast-grep canary" "the known-dirty canary produced no finding: the scanner or its rules are dead"
      fi
    fi
    ast-grep scan -c sgconfig.yml --json=compact "${scan[@]}" > "$shim/hits.json" 2>/dev/null
    out=$(python3 - "$shim/hits.json" <<'PY'
import json, sys
try:
    hits = json.load(open(sys.argv[1]))
except Exception:
    print("ast-grep: unreadable report - refusing to pass silently"); sys.exit(1)
warn = [h for h in hits if h.get("severity") in ("warning", "error")]
for h in warn:
    print(f'{h["file"]}:{h["range"]["start"]["line"] + 1} [{h["ruleId"]}] {h["message"]}')
sys.exit(1 if warn else 0)
PY
    ); rc=$?
    [ $rc -ne 0 ] && block "ast-grep (see .ast-grep/rules/ for why each rule exists)" "$(unshim "$out")"
  fi
fi

# ---- gates on the whole repo (not per file) ------------------------------------
if [ "$mode" != file ] && [ -f "$REQ" ] && need pip-audit "dependency CVEs"; then
  out=$(pip-audit -r "$REQ" --progress-spinner off 2>/dev/null)
  printf '%s' "$out" | grep -qiE 'GHSA-|PYSEC-|CVE-' && block "pip-audit" "$out"
fi

if [ "$mode" = all ] && [ -d tests ] && need pytest "tests"; then
  out=$(PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" pytest -q --tb=short ${PYTEST_MARK:+-m "$PYTEST_MARK"} tests 2>&1) || block "pytest" "$out"
fi

# ---- verdict -------------------------------------------------------------------
if [ "$mode" = all ] && [ "$missing" = 1 ]; then
  echo "gates: a tool is missing in CI — that is a failure, not a skip" >&2; fail=1
fi
if [ "$fail" = 1 ]; then
  echo -e "\nGATE BLOCKED ($mode). Fix the findings; never disable the gate." >&2
  exit 2
fi
[ "$mode" != file ] && echo "gates: clean ($mode, ${#targets[@]} file(s))"
exit 0
