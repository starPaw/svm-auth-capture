#!/usr/bin/env bash
# Run only from an owner-approved root-owned snapshot, after external digest checks.
set -euo pipefail
[[ $# == 3 && $2 == --profile && $3 == e2e ]] || exit 64
case "$1" in init-budget|budget-status|accept-funding|observe-funding|plan-assets|assets|observe-assets|continue-assets-presigner-stop) ;; *) exit 64 ;; esac
[[ $(id -u) == 0 ]] || exit 77
snapshot=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# This verifier checks complete source/dependency/interpreter closure BEFORE Node imports.
/usr/bin/python3 -I -B "$snapshot/ops/p2-verify.py" "$snapshot" "$1"
mapfile -t rpc_ips < <(/usr/bin/python3 -I -B -c 'import json; print("\n".join(json.load(open("/etc/capture402-e2e/p2-network.json"))["addresses"]))')
[[ ${#rpc_ips[@]} -gt 0 ]] || exit 78
allow=(--property="IPAddressAllow=${rpc_ips[*]}")
credentials=()
if [[ $1 == assets || $1 == continue-assets-presigner-stop ]];then
 credentials+=(--property=LoadCredential=sponsor-key:/etc/capture402-e2e/keys/sponsor.json --property=LoadCredential=mint-key:/etc/capture402-e2e/keys/mint.json)
fi
exec /usr/bin/systemd-run --quiet --wait --pipe --collect --unit="capture402-e2e-p2-$(cat /proc/sys/kernel/random/uuid)" \
 --property=Type=exec --property=User=root --property=Group=root \
 --property=NoNewPrivileges=yes --property=ProtectSystem=strict --property=ProtectHome=yes \
 --property=ReadOnlyPaths=/tmp --property=ReadOnlyPaths=/var/tmp \
 --property="ReadWritePaths=/var/lib/capture402-e2e/setup /var/lib/capture402-e2e/facilitator/campaign-budget" \
 --property="InaccessiblePaths=-/etc/sac006 -/var/lib/sac006 -/opt/capture402 -/opt/svm-auth-capture -/etc/capture402-dev -/var/lib/capture402-dev -/opt/capture402-dev -/home/capture402-dev /etc/capture402-e2e/keys /etc/capture402-e2e/facilitator.env /etc/capture402-e2e/restaurant.env -/run/systemd/private -/run/dbus" \
 --property="BindReadOnlyPaths=/etc/capture402-e2e/p2-hosts:/etc/hosts" \
 --property=CapabilityBoundingSet= --property=AmbientCapabilities= "${credentials[@]}" \
 --property=RestrictAddressFamilies="AF_INET AF_INET6" --property=IPAddressDeny=any "${allow[@]}" \
 --property=SocketBindDeny=any --property="SystemCallFilter=~bind listen" --property=SystemCallErrorNumber=EPERM --property=RestrictNamespaces=yes --property=RestrictSUIDSGID=yes \
 --property=ProtectKernelTunables=yes --property=ProtectKernelModules=yes --property=ProtectControlGroups=yes \
 --property=ProtectProc=invisible --property=ProcSubset=pid --property=ProtectClock=yes --property=LockPersonality=yes --property=UMask=0077 \
 --property="WorkingDirectory=$snapshot/integration" \
 "$snapshot/node/bin/node" --experimental-strip-types "$snapshot/integration/operators/e2e-provision.ts" "$1" --profile e2e
