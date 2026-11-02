#!/usr/bin/env bash
# scripts/gates.sh — this repo's quality gate. One script, every caller:
#
#   .githooks/pre-commit        gates.sh staged        (git, any agent, any human)
#   CI                          gates.sh all
#   an agent's post-edit hook   gates.sh file <path>   (convenience: same findings, sooner)
#   once per clone              gates.sh install       (git config core.hooksPath .githooks)
#
# CORE, identical in every repo — do not edit it here; it is the ai-tools `repo-gates`
# template, refreshed with `scaffold.sh --update`. What this repo checks lives next to it:
#
#   scripts/gates.conf        this repo's settings (roots, skips, test command)
#   scripts/gates.d/<lang>.sh one module per language the repo has (python, shell, yaml, go,
#                             node), copied from the template, never edited here
#   scripts/gates.d/local.sh  optional: checks only this repo has (owned here, never overwritten)
#
# A module defines <name>_add <path> (keep the path if it is the module's language) and
# <name>_run (check what it kept; whole-repo checks when mode != file). Helpers it can use:
# need, block, summary, under, astgrep_scan, and $mode, $root, $TMP.
#
# Exit 0 clean, 2 blocked. It never passes silently: a tool that is not installed is reported
# on stderr in local modes and FAILS the `all` mode (CI must have every tool).
# RATCHET: staged/file check only what changed, so old debt never blocks unrelated work;
# `all` sweeps the tree. Written for bash 3.2 (macOS): no assoc arrays, no empty "${a[@]}".
set -uo pipefail

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
case "$mode" in file|staged|all) ;; *) echo "usage: gates.sh file <path> | staged | all | install" >&2; exit 2 ;; esac

SKIP_RE='^$'      # paths no module sees (vendored, generated); gates.conf overrides
TEST_CMD=""       # `all` runs it instead of a module's default test runner, if set
# shellcheck source=/dev/null
[ -f scripts/gates.conf ] && . scripts/gates.conf

fail=0; missing=0; SUMMARY=""
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
need() { command -v "$1" >/dev/null 2>&1 && return 0; echo "gates: $1 not installed — $2 SKIPPED" >&2; missing=1; return 1; }
block() { fail=1; printf '\n== %s ==\n%s\n' "$1" "$2" >&2; }
summary() { SUMMARY="${SUMMARY:+$SUMMARY + }$1"; }
under() {         # under <path> <root>... -> 0 if path is one of the roots or inside one
  local f=$1 r; shift
  for r in "$@"; do case "$f" in "$r"|"$r"/*) return 0 ;; esac; done
  return 1
}

# ast-grep is language-neutral: one scanner, rules per language under .ast-grep/rules/<lang>/
# (each rule names its `language:`). Every file in .ast-grep/canary/ is deliberately
# defective and MUST produce a finding: ast-grep exits 0 on an unreadable ruleDir, so without
# a canary "no findings" and "scanner dead" look identical.
astgrep_canary_done=0
astgrep_scan() {  # astgrep_scan <file>... -> prints warning+ findings, returns 1 if any
  [ -f sgconfig.yml ] || return 0
  need ast-grep "structural scan" || return 0
  local c
  if [ "$astgrep_canary_done" = 0 ]; then
    astgrep_canary_done=1
    for c in .ast-grep/canary/*; do
      [ -f "$c" ] || continue
      ast-grep scan -c sgconfig.yml --json=compact "$c" 2>/dev/null | grep -q '"ruleId"' \
        || block "ast-grep canary" "$c produced no finding: the scanner or its rules are dead"
    done
  fi
  ast-grep scan -c sgconfig.yml --json=compact "$@" > "$TMP/hits.json" 2>/dev/null
  python3 - "$TMP/hits.json" <<'PY'
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
}

# ---- modules ------------------------------------------------------------------------------
modules=""
for m in scripts/gates.d/*.sh; do
  [ -f "$m" ] || continue
  # shellcheck source=/dev/null
  . "$m"
  modules="$modules $(basename "$m" .sh)"
done
[ -n "$modules" ] || { echo "gates: no module in scripts/gates.d/ — the gate would check nothing" >&2; exit 2; }

offer() {         # hand one path to every module
  local f=$1 m
  [ -f "$f" ] || return 0
  [[ "$f" =~ $SKIP_RE ]] && return 0
  case "$f" in .ast-grep/canary/*) return 0 ;; esac   # defective on purpose; astgrep_scan checks them
  for m in $modules; do "${m}_add" "$f"; done
}
case "$mode" in
  file)   f=${2:?usage: gates.sh file <path>}; offer "${f#"$root"/}" ;;
  staged) while IFS= read -r f; do [ -n "$f" ] && offer "$f"; done < <(git diff --cached --name-only --diff-filter=ACM) ;;
  all)    while IFS= read -r f; do offer "$f"; done < <(git ls-files) ;;
esac

for m in $modules; do "${m}_run"; done

if [ "$mode" = all ] && [ -n "$TEST_CMD" ]; then
  out=$(bash -c "$TEST_CMD" 2>&1) || block "tests ($TEST_CMD)" "$(printf '%s' "$out" | tail -60)"
fi

# ---- verdict ------------------------------------------------------------------------------
if [ "$mode" = all ] && [ "$missing" = 1 ]; then
  echo "gates: a tool is missing in CI — that is a failure, not a skip" >&2; fail=1
fi
if [ "$fail" = 1 ]; then
  echo -e "\nGATE BLOCKED ($mode). Fix the findings; never disable the gate." >&2
  exit 2
fi
[ "$mode" != file ] && echo "gates: clean ($mode: ${SUMMARY:-nothing to check})"
exit 0
