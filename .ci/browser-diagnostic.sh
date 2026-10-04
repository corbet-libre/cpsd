#!/usr/bin/env bash
# Original browser checks only; this never grants full acceptance.
set -euo pipefail
: "${CI:?CI only}"
export PYTHONDONTWRITEBYTECODE=1
scratch=$(mktemp -d /tmp/cpsd-browser.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
export CMEET_BROWSER_CACHE="$scratch/browser-cache"
mkdir "$CMEET_BROWSER_CACHE"
browser_setup=/nix/store/21z7gs8b28i9mrgcn0bkmyghv8919p4h-cmty-browser-tools/share/cmty-browser-tools/setup.sh
printf '%s  %s\n' 4b4687d368b60df48b6c598b947c3a4715adcb7a1d23eca8b2e080fbb0f1866b "$browser_setup" | sha256sum --check --strict
. "$browser_setup"
export CI_ACCEPTANCE_ARTIFACTS
CI_ACCEPTANCE_ARTIFACTS=$(mktemp -d "${CARGO_TARGET_DIR:?}/cpsd-browser-${CI_COMMIT_SHA:?}.XXXXXXXX")
printf 'Browser diagnostic artifacts: %s\n' "$CI_ACCEPTANCE_ARTIFACTS"
python3 .ci/browser-diagnostic.py
