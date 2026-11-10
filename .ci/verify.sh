#!/usr/bin/env bash
set -euo pipefail
# Merge stderr into stdout so failure messages stay in the kept log.
# Output routing only; commands and gates unchanged.
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"

# dependency-policy gate (ci.yml dependency-policy job). The resolve job's
# cargo update (Cargo.lock and fuzz/Cargo.lock) is intentionally not preserved:
# verify runs against the committed snapshots.
python3 .github/check-first-party.py
# check gate (ci.yml check job).
rustc --version
cargo fmt --all --check
node --test .github/check-pins.test.mjs
cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-pins.mjs dependency-metadata.json
cargo clippy --locked --all-targets -- -D warnings
CPSD_FUZZ_CORPUS=fuzz/corpus/decode_encode cargo test --locked -- --nocapture
cargo check --locked --target wasm32-unknown-unknown

# Browser round trips and timing (ci.yml check job). CI installs
# wasm-bindgen-cli@0.2.104 via install-action (prebuilt upstream release
# asset); fetch the identical byte-pinned asset with its published checksum.
# google-chrome resolves to the pinned chromium via the runner compat shim.
version="0.2.104"
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="${WASM_BINDGEN_DOWNLOAD_BASE:-https://github.com/wasm-bindgen/wasm-bindgen/releases/download}/${version}"
runner_tmp="${RUNNER_TEMP}/cpsd-wasm-runner"
mkdir -p "$runner_tmp"
cd "$runner_tmp"
curl -A 'dependency-ci' --fail --location --retry 3 --remote-name "$base/$archive"
curl -A 'dependency-ci' --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xzf "$archive" --strip-components=1
echo "$PWD" >> "$GITHUB_PATH"
export PATH="$PWD:$PATH"
cd "$OLDPWD"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export WASM_BINDGEN_USE_BROWSER='1'
export WASM_BINDGEN_TEST_TIMEOUT='120'
export CHROMEDRIVER="$(command -v chromedriver)"
google-chrome --version
# Merge cargo stderr here (same command and flags) so a browser-leg
# failure keeps its message. Prior run died as `driver status: signal: 9
# (SIGKILL)`; killer and cause unknown from that evidence.
echo 'stage: browser chrome vectors'
# Chromium's singleton socket path must fit the Unix socket limit; keep the
# browser profile under a short TMPDIR (profiles stay unique per run).
TMPDIR=/tmp cargo test --release --locked --target wasm32-unknown-unknown --test it -- --nocapture 2>&1

# Dependency license inventory (ci.yml check job, always).
cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-licenses.mjs

# fuzz gate (ci.yml fuzz job, nightly). The resolve-artifact checksum
# (resolved-lock.sha256) is dropped: the resolve job is not preserved.
cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 > /dev/null
(
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" fuzz run decode_encode --target x86_64-unknown-linux-gnu -- -max_total_time=30 -max_len=262144
)

# audit gate (ci.yml audit job; deny itself stays a fresh check, the
# scripted exposure gates are preserved here).
cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-security.mjs
node .github/check-advisory-exposure.mjs

# coverage gate (ci.yml coverage job, nightly branch instrumentation).
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
)
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
