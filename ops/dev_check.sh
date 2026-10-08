#!/usr/bin/env bash
set -euo pipefail
repo=${1:-/home/capture402-dev/projects/svm-auth-capture}
repo=$(realpath "$repo")
case "$repo" in
  /home/capture402-dev/projects/*) ;;
  *) printf 'Refusing checkout outside the development projects directory.\n' >&2; exit 2 ;;
esac
test -f "$repo/integration/package-lock.json"
test -f "$repo/target/deploy/svm_auth_capture.so"
common_git=$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)
case "$common_git" in
  /home/capture402-dev/projects/*) ;;
  *) printf 'Refusing Git metadata outside development projects.\n' >&2; exit 2 ;;
esac
# This helper uses the accepted binary only for unchanged program/build inputs.
# Compare the working tree too, so uncommitted core changes cannot pass unnoticed.
accepted=da3312b2979b2f2cb0a077f1c5d8cad41dfcab5c
git -C "$repo" cat-file -e "$accepted^{commit}"
while IFS= read -r -d '' path; do
  case "$path" in
    deploy.sh|integration/*|ops/*|docs/*|tasks/*|AGENTS.md|README.md|.github/CODEOWNERS|.github/pull_request_template.md|.github/workflows/components.yml|.github/workflows/deploy-demo.yml) ;;
    *) printf 'Program/build input changed: %s. Require a fresh SBF build in component CI.\n' "$path" >&2; exit 2 ;;
  esac
done < <(git -C "$repo" diff --no-renames --name-only -z "$accepted"; git -C "$repo" ls-files --others --exclude-standard -z)
printf 'adee4e8f51fbc52b046c4d5a846c63ecdb63d392b1d16b559d3f6c2984b27415  %s/target/deploy/svm_auth_capture.so\n' "$repo" | sha256sum --check
run_dir=$(mktemp -d /home/capture402-dev/evidence/check-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX)
chmod 0700 "$run_dir"
trap 'printf "%s\n" "$?" > "$run_dir/exit-status.txt"' EXIT
{
  git -C "$repo" rev-parse HEAD
  git -C "$repo" status --porcelain=v1
  node --version
  npm --version
  sha256sum "$repo/target/deploy/svm_auth_capture.so"
} > "$run_dir/identity.txt"
printf 'Evidence: %s\n' "$run_dir"
# A private network namespace keeps fixed nginx test ports away from production.
# Network is absent; dependencies must already be installed. No host capabilities.
nice -n 10 bwrap --unshare-net --unshare-pid --die-with-parent --new-session \
  --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
  --tmpfs /home --dir /home/capture402-dev --dir /home/capture402-dev/projects \
  --bind "$repo" "$repo" --dir /home/capture402-dev/evidence \
  --dir "$(dirname "$common_git")" --ro-bind "$common_git" "$common_git" \
  --bind "$run_dir" "$run_dir" \
  --setenv HOME /home/capture402-dev --setenv TMPDIR /tmp \
  --unsetenv SOLANA_RPC_URL --unsetenv OPENAI_API_KEY --unsetenv CODEX_API_KEY \
  --unsetenv SAC006_BEARER_TOKEN --unsetenv SAC006_MERCHANT_TOKEN \
  --setenv SAC006_TEST_NGINX /usr/sbin/nginx --chdir "$repo" \
  /bin/bash -c '
    set -euo pipefail
    npm run typecheck --prefix integration 2>&1 | tee "$1/typecheck.log"
    npm run build:wallet --prefix integration 2>&1 | tee "$1/wallet.log"
    git diff --exit-code -- integration/web/solflare.js integration/web/solflare.js.LEGAL.txt
    npm test --prefix integration -- --maxWorkers=2 2>&1 | tee "$1/tests.log"
  ' check "$run_dir"
git -C "$repo" status --porcelain=v1 > "$run_dir/final-status.txt"
printf 'PASS\n' > "$run_dir/result.txt"
printf 'Checks passed. Evidence: %s\n' "$run_dir"
