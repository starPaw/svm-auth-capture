#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# This CLI and platform-tools pair was used for the retained local SVM evidence.
if [[ "$(cargo-build-sbf --version)" != *"solana-cargo-build-sbf 2.2.14"* ]]; then
  echo "SAC-001 requires cargo-build-sbf 2.2.14 for this pinned harness." >&2
  exit 1
fi
cargo-build-sbf --tools-version v1.53 --arch v0 -- --locked
cargo test --locked --test sac001 -- --nocapture
