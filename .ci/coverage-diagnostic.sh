#!/usr/bin/env bash
# Original strict coverage only; this never grants full acceptance.
set -euo pipefail
: "${CI:?CI only}"
export PYTHONDONTWRITEBYTECODE=1
export CI_ACCEPTANCE_COVERAGE_SETUP=/nix/store/hddk15hgahw73wk2hdfir1v0si7vcs61-cmty-wasm-coverage-tools/share/cmty-wasm-coverage-tools/setup.sh
export CI_ACCEPTANCE_COVERAGE_SHA256=b169bbb42929bbb673f1eda497d98cae1891803c4c6285471f8735d880047e3b
export CI_ACCEPTANCE_ARTIFACTS
CI_ACCEPTANCE_ARTIFACTS=$(mktemp -d "${CARGO_TARGET_DIR:?}/cpsd-coverage-${CI_COMMIT_SHA:?}.XXXXXXXX")
printf 'Coverage diagnostic artifacts: %s\n' "$CI_ACCEPTANCE_ARTIFACTS"
export CPSD_FUZZ_CORPUS="$CI_ACCEPTANCE_ARTIFACTS/fuzz-corpus"
mkdir "$CPSD_FUZZ_CORPUS"
python3 .ci/coverage-diagnostic.py
