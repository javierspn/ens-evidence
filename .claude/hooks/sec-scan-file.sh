#!/usr/bin/env bash
# PostToolUse(Edit|Write) — bandit-scan a just-edited kiosk/python source.
# Medium+ findings -> exit 2 so they are fed back to Claude and fixed in-loop.
#
# Scope: this repo's python sources, including any extension-less command script
# (bandit takes an explicit path regardless of suffix, unlike ast-grep).
# Skips tests/, non-python, missing files, or an absent bandit.
set -uo pipefail

input=$(cat)
f=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_response.filePath // empty' 2>/dev/null)

[ -z "$f" ] && exit 0
case "$f" in
  *.py) ;;   *) exit 0 ;;
esac
case "$f" in
  */tests/*|*/test_*) exit 0 ;;
esac
command -v bandit >/dev/null 2>&1 || exit 0   # bandit absent -> don't block edits
[ -f "$f" ] || exit 0

out=$(bandit -ll -q -f custom \
  --msg-template '{relpath}:{line} [{severity}/{confidence}] {test_id} {msg}' \
  "$f" 2>/dev/null) || true

if [ -n "$out" ]; then
  {
    echo "SECURITY (bandit, medium+) — $f:"
    echo "$out"
    echo "Fix these before continuing, or justify + allowlist if a false positive."
  } >&2
  exit 2
fi
exit 0
