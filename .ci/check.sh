#!/usr/bin/env bash
# Diagnostic owner checks only. This selector does not replace full acceptance.
set -euo pipefail
: "${CI:?CI only}"
export RUST_TEST_THREADS=2 CARGO_BUILD_JOBS=2 CARGO_NET_GIT_FETCH_WITH_CLI=true PYTHONDONTWRITEBYTECODE=1
report_dir="${CI_ACCEPTANCE_ARTIFACTS:-${CARGO_TARGET_DIR:?}/cpsd-qualification/${CI_COMMIT_SHA:?}}"
mkdir -p "$report_dir"
rustc -Vv
sha256sum Cargo.lock fuzz/Cargo.lock
python3 .github/check-first-party.py --archive
case "${1:?selected check required}" in
  resolve)
    cargo update
    cargo update --manifest-path fuzz/Cargo.toml
    python3 .github/check-first-party.py --archive
    date -u +%FT%TZ
    mkdir -p "$report_dir/resolved/fuzz"
    cp Cargo.lock "$report_dir/resolved/Cargo.lock"
    cp fuzz/Cargo.lock "$report_dir/resolved/fuzz/Cargo.lock"
    sha256sum Cargo.lock fuzz/Cargo.lock > "$report_dir/resolved/locks.sha256"
    { date -u +%FT%TZ; rustc -Vv; cargo -V; } > "$report_dir/resolved/resolver.txt"
    sha256sum "$report_dir/resolved/Cargo.lock" "$report_dir/resolved/fuzz/Cargo.lock" "$report_dir/resolved/resolver.txt"

    ;;
  native)
    cargo fmt --all --check
    node --test .github/check-pins.test.mjs
    cargo metadata --locked --format-version 1 > "$report_dir/dependency-metadata.json"
    node .github/check-pins.mjs "$report_dir/dependency-metadata.json"
    cargo tree --locked --target x86_64-unknown-linux-gnu -e features > "$report_dir/native-features.txt"
    sha256sum "$report_dir/dependency-metadata.json" "$report_dir/native-features.txt"
    cargo clippy --locked --all-targets -- -D warnings
    export CPSD_FUZZ_CORPUS="$report_dir/fuzz-corpus"
    mkdir -p "$CPSD_FUZZ_CORPUS"
    cargo test --locked -- --nocapture
    ;;
  wasm)
    # This diagnoses compilation only; actual browser tests are still mandatory.
    cargo check --locked --target wasm32-unknown-unknown
    ;;
  browser)
    : "${CPSD_MATCHED_RUNNER:?qualified matching runner required}"
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
    export WASM_BINDGEN_USE_BROWSER=1 WASM_BINDGEN_TEST_TIMEOUT=120
    export CHROMEDRIVER="$(command -v chromedriver)"
    unset NO_HEADLESS WASM_BINDGEN_USE_NODE_EXPERIMENTAL WASM_BINDGEN_USE_DENO
    unset WASM_BINDGEN_USE_DEDICATED_WORKER WASM_BINDGEN_USE_SHARED_WORKER WASM_BINDGEN_USE_SERVICE_WORKER
    chromium --version
    cargo test --release --locked --target wasm32-unknown-unknown --test browser --test opaque_holder --test boundaries --test privacy_diagnostics --test proof_vectors -- --nocapture
    ;;
  coverage)
    export CARGO_PROFILE_TEST_OPT_LEVEL=0
    cargo llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path "$report_dir/coverage.json"
    cargo llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path "$report_dir/coverage.lcov"
    cargo llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text --output-path "$report_dir/coverage.txt"
    python3 .github/test-source-coverage.py
    python3 .github/check-source-coverage.py "$report_dir/coverage.lcov" "$report_dir/coverage.json" "$report_dir/coverage.txt"
    ;;
  fuzz)
    cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 > "$report_dir/fuzz-metadata.json"
    test -d "$report_dir/fuzz-corpus"
    python3 .ci/fuzz.py
    ;;
  dependency-policy)
    cargo metadata --locked --format-version 1 > "$report_dir/dependency-metadata.json"
    export DEPENDENCY_METADATA="$report_dir/dependency-metadata.json"
    node .github/check-licenses.mjs
    node .github/check-advisory-exposure.mjs
    cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 > "$report_dir/fuzz-metadata.json"
    DEPENDENCY_METADATA="$report_dir/fuzz-metadata.json" node .github/check-licenses.mjs
    DEPENDENCY_METADATA="$report_dir/fuzz-metadata.json" node .github/check-advisory-exposure.mjs
    node .github/check-security.mjs
    cargo deny --locked check advisories licenses
    cargo deny --manifest-path fuzz/Cargo.toml --locked check advisories licenses
    ;;
  *) exit 2 ;;
esac
sha256sum Cargo.lock fuzz/Cargo.lock
