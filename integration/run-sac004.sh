#!/usr/bin/env bash
# SAC-004 runner: rebuild the SBF program and run the unchanged component suites with the
# existing pinned runner, then run the x402 integration suite against that same binary.
set -euo pipefail
cd "$(dirname "$0")"

../scripts/test-sac003.sh
shasum -a 256 ../target/deploy/svm_auth_capture.so
npm ci --no-audit --no-fund
npm run typecheck
npm test -- --reporter=verbose
