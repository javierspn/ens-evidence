#!/usr/bin/env bash
# PreToolUse(Bash, git commit) — security gate before a commit lands.
# Runs bandit (medium+) over the kiosk sources and pip-audit on the dev deps.
# Any medium+ SAST finding or known dependency CVE -> exit 2, blocking the commit.
set -uo pipefail

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
fail=0
report=""

# --- SAST: bandit over this repo's sources (medium+ severity) ---
# An extension-less command script must be named explicitly: a recursive scan
# skips it, and the gate then passes without reading the file that matters.
if command -v bandit >/dev/null 2>&1; then
  targets=()

  while IFS= read -r p; do targets+=("$p"); done < <(
    find src -name '*.py' -not -path '*/tests/*' 2>/dev/null
  )
  if [ ${#targets[@]} -gt 0 ]; then
    b=$(bandit -ll -q -f custom \
      --msg-template '{relpath}:{line} [{severity}/{confidence}] {test_id} {msg}' \
      "${targets[@]}" 2>/dev/null) || true
    if [ -n "$b" ]; then
      fail=1
      report="${report}
bandit (medium+):
${b}"
    fi
  fi
fi

# --- Dependency CVEs: pip-audit over the dev requirement set ---
if command -v pip-audit >/dev/null 2>&1 && [ -f requirements-dev.txt ]; then
  p=$(pip-audit -r requirements-dev.txt --progress-spinner off 2>/dev/null) || true
  if printf '%s' "$p" | grep -qiE 'GHSA-|PYSEC-|CVE-'; then
    fail=1
    report="${report}
pip-audit (vulnerable dependencies):
${p}"
  fi
fi

if [ "$fail" = "1" ]; then
  {
    echo "COMMIT BLOCKED — security gate failed:"
    echo "$report"
    echo ""
    echo "Fix the findings, or (if accepted/unfixable) add a time-boxed allowlist with"
    echo "justification, then re-commit."
  } >&2
  exit 2
fi
exit 0
