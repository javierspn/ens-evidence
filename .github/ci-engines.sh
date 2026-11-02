#!/usr/bin/env bash
# Install the pinned engines on a host-mode runner (no sudo, nothing in /usr/local):
# semgrep into the job's venv, trivy and gitleaks into a per-version cache under $HOME,
# then warm trivy's databases so the scan's --skip-db-update / --skip-check-update work.
# Versions come from the environment (SEMGREP_VERSION, TRIVY_VERSION, GITLEAKS_VERSION;
# gitleaks is optional). The cache dir is appended to $GITHUB_PATH.
set -euo pipefail

: "${SEMGREP_VERSION:?}" "${TRIVY_VERSION:?}"
bin="$HOME/.cache/ens-ci/bin"
mkdir -p "$bin"

pip install -q "semgrep==${SEMGREP_VERSION}"

if [ ! -x "$bin/trivy-$TRIVY_VERSION" ]; then
  curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C "$bin" trivy
  mv "$bin/trivy" "$bin/trivy-$TRIVY_VERSION"
fi
ln -sf "trivy-$TRIVY_VERSION" "$bin/trivy"

if [ -n "${GITLEAKS_VERSION:-}" ]; then
  if [ ! -x "$bin/gitleaks-$GITLEAKS_VERSION" ]; then
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C "$bin" gitleaks
    mv "$bin/gitleaks" "$bin/gitleaks-$GITLEAKS_VERSION"
  fi
  ln -sf "gitleaks-$GITLEAKS_VERSION" "$bin/gitleaks"
fi

echo "$bin" >> "${GITHUB_PATH:?}"
export PATH="$bin:$PATH"

semgrep --version
trivy --version
[ -z "${GITLEAKS_VERSION:-}" ] || gitleaks version

# The scan runs Trivy with --skip-db-update and --skip-check-update, which it refuses on
# a host holding neither ("--skip-db-update cannot be specified on the first run"). The
# vulnerability DB has a download-only flag; the misconfiguration checks bundle does not,
# so it is fetched by scanning an empty directory. Both land in ~/.cache/trivy and stay.
trivy fs --download-db-only
trivy fs --scanners misconfig -o /dev/null "$(mktemp -d)"
