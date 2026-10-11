#!/usr/bin/env bash
# Resolve the changed integration graph; this is not a validation verdict.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
cargo update
cargo update --manifest-path fuzz/Cargo.toml
cp Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-Cargo.lock"
cp fuzz/Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-fuzz-Cargo.lock"
sha256sum Cargo.lock fuzz/Cargo.lock
echo 'Resolved dependency locks only; retain them in a commit and run verify.'
