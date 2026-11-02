# shellcheck shell=bash disable=SC2154  # sourced by scripts/gates.sh, which sets mode, root, TMP
# gates.d/shell.sh — shellcheck (warning+) on every shell script in the repo: *.sh, *.bash and
# extension-less scripts with a sh/bash/dash/ksh shebang. Template module: do not edit here.
# The shellcheck binary reads the shebang itself, so bare scripts need no shim; -x follows `source`.
# zsh is not shellcheck's: a zsh script is left alone (name it in SKIP_RE if that is a gap).
sh_files=()

shell_add() {
  case "$1" in
    *.sh|*.bash) head -c 64 "$1" | grep -q '^#!.*zsh' || sh_files+=("$1") ;;
    *.*) ;;
    *) head -c 64 "$1" | grep -qE '^#!.*\b(ba|da|k)?sh\b' && sh_files+=("$1") ;;
  esac
  return 0
}

shell_run() {
  local out rc
  if [ ${#sh_files[@]} -gt 0 ] && need shellcheck "shell lint"; then
    out=$(shellcheck -x -S warning -f gcc "${sh_files[@]}" 2>&1); rc=$?
    [ $rc -ne 0 ] && block "shellcheck (warning+)" "$out"
  fi
  summary "${#sh_files[@]} shell"
}
