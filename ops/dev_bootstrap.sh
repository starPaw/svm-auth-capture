#!/usr/bin/env bash
# Operator preparation only: no stable service commands, ingress or payments.
# Explicitly run after reviewing this script and the two exact source revisions.
set -euo pipefail
umask 077
test "$(id -u)" = 0 || { printf 'Run as the authorized VPS operator.\n' >&2; exit 2; }
test "$#" = 2 || { printf 'Usage: dev_bootstrap.sh <app-sha> <tools-sha>\n' >&2; exit 2; }
# Independent enrollment cannot be erased by bootstrap/controller downgrade.
if test -e /etc/capture402-dev-admission || test -L /etc/capture402-dev-admission || test -e /usr/local/libexec/capture402-dev-admission.py; then
  /usr/bin/python3 -I -B /usr/local/libexec/capture402-dev-admission.py economic
fi
app_sha=$1
tools_sha=$2
[[ $app_sha =~ ^[a-f0-9]{40}$ && $tools_sha =~ ^[a-f0-9]{40}$ ]] || exit 2
repo=/home/capture402-dev/projects/svm-auth-capture
base=/opt/capture402-dev
private=/etc/capture402-dev
state=/var/lib/capture402-dev
runtime_group=capture402-dev-runtime
test ! -e "$base/current" && test ! -L "$base/current" || { printf 'Dev current already exists; no implicit release switch.\n' >&2; exit 2; }
test ! -e "$private/facilitator.env" && test ! -e "$private/restaurant.env" || exit 2

# Unprivileged archive/build steps never receive service keys or operator secrets.
archive_revision() {
  local sha=$1 destination=$2
  test ! -e "$destination" || { printf 'Prepared directory exists; preserve and inspect it.\n' >&2; exit 2; }
  install -d -m 0750 -o capture402-dev -g capture402-dev "$destination"
  runuser -u capture402-dev -- git -C "$repo" archive --format=tar "$sha" -- integration ops docs/evidence/sac-007/deployment-identity.v1.json |
    runuser -u capture402-dev -- tar --no-same-owner --no-same-permissions -xf - -C "$destination"
  runuser -u capture402-dev -- npm ci --prefix "$destination/integration" --ignore-scripts --no-audit --no-fund > "$state/setup/npm-$sha.log" 2>&1
  # Seal only the exact new dev tree. Never follow symlinks into live/private files.
  python3 - "$destination" <<'SEAL'
import os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve()
for directory, subdirs, names in os.walk(root, followlinks=False):
    p=Path(directory)
    os.chown(p,0,0,follow_symlinks=False); os.chmod(p,0o755)
    for name in subdirs+names:
        f=p/name
        info=f.lstat()
        if stat.S_ISLNK(info.st_mode):
            if not f.resolve().is_relative_to(root): raise SystemExit('dev release symlink escapes its tree')
            os.chown(f,0,0,follow_symlinks=False)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1: raise SystemExit('dev release hardlink refused')
            os.chown(f,0,0,follow_symlinks=False)
            os.chmod(f,0o755 if info.st_mode & 0o111 else 0o644)
        elif not stat.S_ISDIR(info.st_mode): raise SystemExit('dev release special file refused')
SEAL
}

getent group "$runtime_group" >/dev/null || groupadd --system "$runtime_group"
for role in setup facilitator restaurant; do
  name=capture402-dev-$role
  if ! id "$name" >/dev/null 2>&1; then
    useradd --system --no-create-home --gid "$runtime_group" --shell /usr/sbin/nologin "$name"
  fi
  test "$(id -Gn "$name")" = "$runtime_group"
  test "$(getent passwd "$name" | cut -d: -f7)" = /usr/sbin/nologin
done
install -d -m 0755 -o root -g root "$base" "$base/releases" "$base/tools" "$state"
install -d -m 0750 -o capture402-dev-setup -g "$runtime_group" "$private" "$private/keys"
install -d -m 0700 -o capture402-dev-setup -g "$runtime_group" "$state/setup"
install -d -m 0700 -o capture402-dev-facilitator -g "$runtime_group" "$state/facilitator"
install -d -m 0700 -o capture402-dev-restaurant -g "$runtime_group" "$state/restaurant"

archive_revision "$app_sha" "$base/releases/$app_sha"
if test "$app_sha" = "$tools_sha"; then
  ln -s "../releases/$app_sha" "$base/tools/$tools_sha"
else
  archive_revision "$tools_sha" "$base/tools/$tools_sha"
fi
ln -s "$base/releases/$app_sha" "$base/current"

# Even newly reviewed preparation code runs without root or live credentials.
systemd-run --quiet --wait --pipe --collect --unit=capture402-dev-prepare-keys \
  -p User=capture402-dev-setup -p Group="$runtime_group" \
  -p NoNewPrivileges=true -p CapabilityBoundingSet= -p ProtectSystem=strict \
  -p ProtectHome=true -p PrivateTmp=true -p PrivateNetwork=true \
  -p 'InaccessiblePaths=/etc/sac006 /var/lib/sac006 /opt/capture402 /opt/svm-auth-capture' \
  -p "ReadWritePaths=$private $state/setup" -p MemoryMax=512M -p CPUQuota=50% \
  -p "WorkingDirectory=$base/tools/$tools_sha/integration" \
  /usr/local/bin/node --experimental-strip-types evidence/dev-environment.ts keys

runuser -u capture402-dev-setup -- python3 -B "$base/tools/$tools_sha/ops/dev_environment.py" \
  --hostname dev.capture402.xyz --private-identities "$private/identities.json" \
  --output "$state/setup/prepared"
for role in facilitator restaurant; do
  install -o root -g root -m 0600 "$state/setup/prepared/$role.env" "$private/$role.env"
done
# Initial keys stay with the setup user until explicit funding/asset preparation
# finishes. Runtime cannot start prematurely; activation transfers only its own key.
printf 'Dev release and private configuration prepared. No service activated; no transaction submitted.\n'
