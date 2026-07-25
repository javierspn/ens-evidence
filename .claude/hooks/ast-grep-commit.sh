#!/usr/bin/env bash
# PreToolUse(Bash: git commit) — ast-grep the STAGED python sources.
#
# Mirrors repo-a's hook: a warning exits 2 and blocks the commit, so the
# finding is fixed in the same loop rather than discovered in review.
#
# RATCHET, not a sweep: only staged files are scanned. Pre-existing debt does not
# block unrelated commits, but the moment you touch a file it must come up to
# standard. Adopting a new rule by boiling the ocean is how a gate ends up disabled.
#
# EXTENSION SHIM: a script installed as a command has no .py suffix. ast-grep
# picks its parser from the extension, so scanning such a file directly matches
# NOTHING and reports success — a silently empty gate, which is worse than no
# gate. Copy it to a .py path, scan that, and map the name back.
#
# Rules live in .ast-grep/rules/ (vendored, so CI runs the same ones).
set -uo pipefail

command -v ast-grep >/dev/null 2>&1 || exit 0

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -f "$root/sgconfig.yml" ] || exit 0

staged=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null \
  | grep -E '^src/.*\.py$' \
  | grep -vE '(^|/)tests?/|/test_|_test\.py$' || true)
[ -z "$staged" ] && exit 0

# Checked BEFORE the scan, not at the point of use: a missing filter makes the
# report empty, so the gate would exit 0 on every defect it exists to block —
# and a clean commit would never reveal the misconfiguration.
filter="$(dirname "$0")/ast-grep-filter.py"
if [ ! -f "$filter" ]; then
  echo "ast-grep gate MISCONFIGURED: $filter missing — refusing to pass silently" >&2
  exit 2
fi

cd "$root" || exit 0
shim=$(mktemp -d) || exit 0
trap 'rm -rf "$shim"' EXIT

targets=()
declare -a mapping=()
for f in $staged; do
  [ -f "$f" ] || continue
  case "$f" in
    *.py) targets+=("$f") ;;
    *)
      # Extension-less script: scan a .py copy, remember the real name.
      alias_path="$shim/$(basename "$f").py"
      cp "$f" "$alias_path" || continue
      targets+=("$alias_path")
      mapping+=("$alias_path=$f")
      ;;
  esac
done
[ ${#targets[@]} -eq 0 ] && exit 0

out=$(ast-grep scan -c sgconfig.yml --json=compact "${targets[@]}" 2>/dev/null) || exit 0
[ -z "$out" ] && exit 0

# Map the shim paths back to the real ones before anyone reads the report.
for pair in "${mapping[@]:-}"; do
  [ -z "$pair" ] && continue
  out=${out//${pair%%=*}/${pair#*=}}
done

report=$(printf '%s' "$out" | python3 "$filter" 2>/dev/null)

if [ -n "$report" ]; then
  {
    echo "STRUCTURAL (ast-grep) — staged files:"
    echo "$report"
    echo "Each rule encodes a past production failure; see .ast-grep/rules/."
    echo "Fix it, or if the hit is genuinely routine, say why (a narrow expected"
    echo "exception logged at info is fine — the rules already exempt those)."
  } >&2
  exit 2
fi
exit 0
