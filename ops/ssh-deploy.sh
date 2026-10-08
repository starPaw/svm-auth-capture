#!/usr/bin/env bash
# Install root-owned at /usr/local/libexec/capture402-ssh-deploy.
# Use ONLY with a single authorized_keys entry: command="...",restrict.
set -euo pipefail
original="${SSH_ORIGINAL_COMMAND:-}"
if [[ "$original" =~ ^deploy[[:space:]]([0-9a-f]{40})[[:space:]]([0-9a-f]{64})$ ]]; then
  exec sudo -n /usr/local/sbin/capture402-deploy "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
fi
echo "Only deploy <40-hex-main-sha> <64-hex-archive-sha256> is allowed" >&2
exit 1
