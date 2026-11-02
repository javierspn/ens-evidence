# shellcheck shell=bash disable=SC2154  # sourced by scripts/gates.sh, which sets mode, root, TMP
# gates.d/python.sh — ruff, bandit, ast-grep on the python under PY_ROOTS; pip-audit on PY_REQ;
# pytest on tests/ in `all` (unless gates.conf sets TEST_CMD). Template module: do not edit here.
#
# gates.conf:  PY_ROOTS  source dirs and extension-less command scripts, no tests (required)
#              PY_REQ    pip-audit target (default requirements-dev.txt; missing = skipped)
#              PYTEST_MARK  pytest -m expression, e.g. "not engines" for tests needing binaries
#
# EXTENSION SHIM: a script installed as a command has no .py suffix. ast-grep, ruff and bandit
# pick their parser from the extension, so such a file is scanned via a .py copy and the
# findings are mapped back — but only under PY_ROOTS: a script not listed is never scanned.
PY_TEST_RE='(^|/)tests?/|/test_|_test\.py$'
py_files=()

python_add() {
  # shellcheck disable=SC2086  # PY_ROOTS is a space-separated list
  under "$1" ${PY_ROOTS:-} || return 0
  [[ "$1" =~ $PY_TEST_RE ]] && return 0
  case "$1" in *.py) ;; *) head -c 64 "$1" | grep -q '^#!.*python' || return 0 ;; esac
  py_files+=("$1")
}

python_run() {
  [ -n "${PY_ROOTS:-}" ] || { block "python" "gates.conf sets no PY_ROOTS: the python gate would check nothing"; return; }
  local out rc f a p scan=() map=()
  if [ ${#py_files[@]} -gt 0 ]; then
    for f in "${py_files[@]}"; do
      case "$f" in
        *.py) scan+=("$f") ;;
        *) a="$TMP/shim/$(basename "$f").py"; mkdir -p "$TMP/shim"; cp "$f" "$a"; scan+=("$a"); map+=("$a=$f") ;;
      esac
    done
    py_unshim() { local o=$1; if [ ${#map[@]} -gt 0 ]; then for p in "${map[@]}"; do o=${o//${p%%=*}/${p#*=}}; done; fi; printf '%s' "$o"; }

    if need ruff "lint"; then
      out=$(ruff check --no-fix --output-format concise "${scan[@]}" 2>&1); rc=$?
      [ $rc -ne 0 ] && block "ruff" "$(py_unshim "$out")"
    fi
    if need bandit "SAST"; then
      out=$(bandit -ll -q -f custom --msg-template '{relpath}:{line} [{severity}/{confidence}] {test_id} {msg}' "${scan[@]}" 2>/dev/null)
      [ -n "$out" ] && block "bandit (medium+)" "$(py_unshim "$out")"
    fi
    out=$(astgrep_scan "${scan[@]}") || block "ast-grep python (see .ast-grep/rules/ for why each rule exists)" "$(py_unshim "$out")"
  fi

  if [ "$mode" != file ] && [ -f "${PY_REQ:-requirements-dev.txt}" ] && need pip-audit "dependency CVEs"; then
    out=$(pip-audit -r "${PY_REQ:-requirements-dev.txt}" --progress-spinner off 2>/dev/null)
    printf '%s' "$out" | grep -qiE 'GHSA-|PYSEC-|CVE-' && block "pip-audit" "$out"
  fi

  if [ "$mode" = all ] && [ -z "$TEST_CMD" ] && [ -d tests ] && need pytest "tests"; then
    out=$(PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}" pytest -q --tb=short ${PYTEST_MARK:+-m "$PYTEST_MARK"} tests 2>&1) \
      || block "pytest" "$out"
  fi
  summary "${#py_files[@]} python"
}
