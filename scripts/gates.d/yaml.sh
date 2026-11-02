# shellcheck shell=bash disable=SC2154  # sourced by scripts/gates.sh, which sets mode, root, TMP
# gates.d/yaml.sh — yamllint on every *.yml / *.yaml, config .yamllint (the template ships a
# relaxed one: syntax, duplicate keys, truthy; style is not the gate). Template module.
#
# gates.conf:  YAML_SKIP_RE  yaml that is not yaml yet (templates with placeholders, Helm charts)
# A file with a line starting `{{` is a Go/Helm template and is skipped without being named.
YAML_SKIP_RE=${YAML_SKIP_RE:-'^$'}
yaml_files=()

yaml_add() {
  case "$1" in *.yml|*.yaml) ;; *) return 0 ;; esac
  [[ "$1" =~ $YAML_SKIP_RE ]] && return 0
  grep -q '^{{' "$1" && return 0
  yaml_files+=("$1")
}

yaml_run() {
  local out rc cfg=(-d relaxed)
  [ -f .yamllint ] && cfg=(-c .yamllint)
  if [ ${#yaml_files[@]} -gt 0 ] && need yamllint "yaml lint"; then
    out=$(yamllint "${cfg[@]}" -f parsable "${yaml_files[@]}" 2>&1); rc=$?
    [ $rc -ne 0 ] && block "yamllint (${cfg[*]})" "$out"
  fi
  summary "${#yaml_files[@]} yaml"
}
