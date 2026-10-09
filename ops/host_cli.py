#!/usr/bin/env python3
"""Canonical VPS command. Operator authorization is separate from release eligibility."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

import deploy_demo as source
import release_policy as policy

TOKEN = Path('/etc/capture402/github-release-readonly')
COMMAND = Path('/usr/local/sbin/capture402')
OLD_COMMAND = Path('/usr/local/sbin/capture402-deploy')
FILES = ('deploy_demo.py', 'deploy_vps.py', 'host_cli.py', 'release_policy.py', 'deploy_dev.py')
# The release policy requires merge_commit_sha, removed in API 2026-03-10.
# GitHub supports this compatible schema until at least 2028-03-10.
API_VERSION = '2022-11-28'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class GitHub:
    def __init__(self):
        parent = TOKEN.parent.lstat()
        source.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and parent.st_mode & 0o022 == 0,
                       'release credential directory must be root-owned and not writable by others')
        info = TOKEN.lstat()
        source.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0,
                       'release API credential must be root-owned, private and not a symlink')
        self.token = TOKEN.read_text().strip()
        source.require(bool(self.token) and not any(c.isspace() for c in self.token), 'invalid release API credential')
        self.deadline = time.monotonic() + 90
        self.opener = urllib.request.build_opener(NoRedirect())

    def __call__(self, route):
        source.require(route.startswith('repos/' + policy.REPOSITORY + '/') and '\n' not in route,
                       'unexpected release metadata route')
        remaining = self.deadline - time.monotonic()
        source.require(remaining > 0, 'release API deadline exceeded')
        request = urllib.request.Request('https://api.github.com/' + route, headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': API_VERSION, 'User-Agent': 'Capture402-release'})
        try:
            with self.opener.open(request, timeout=min(10, remaining)) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            source.require(len(data) <= 2 * 1024 * 1024, 'release metadata response too large')
            return json.loads(data)
        except urllib.error.HTTPError as error:
            raise RuntimeError('release API HTTP ' + str(error.code)) from None
        except (OSError, ValueError):
            raise RuntimeError('release API unavailable or invalid') from None


def install_controllers(sha, files):
    source.require(bool(source.SHA_RE.fullmatch(sha)) and set(files) == set(FILES), 'invalid controller set')
    root = source.BASE / 'controllers' / sha
    for directory in (source.BASE, source.BASE / 'controllers', root):
        source.require(not directory.is_symlink(), 'controller directory is symlink')
        directory.mkdir(mode=0o755, exist_ok=True)
        source.require(directory.stat().st_uid == os.geteuid(), 'unsafe controller owner')
        directory.chmod(0o755)
    import deploy_vps as host
    for name, data in files.items():
        source.require(len(data) < 256 * 1024, 'controller too large')
        compile(data, name, 'exec')
        target = root / name
        source.require(not target.is_symlink(), 'controller is symlink')
        if target.exists():
            info = target.stat()
            source.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                           'unsafe immutable controller ownership/mode')
            source.require(target.read_bytes() == data, 'immutable controller changed')
        else:
            host.atomic_bytes(target, data)
    source.require(not COMMAND.is_symlink(), 'operator command is symlink')
    source.require(not OLD_COMMAND.is_symlink(), 'legacy operator command is symlink')
    host.atomic_bytes(COMMAND, ('#!/bin/sh\nexec /usr/bin/python3 -B ' + str(root / 'host_cli.py') + ' "$@"\n').encode(), 0o755)
    host.atomic_bytes(OLD_COMMAND, b'#!/bin/sh\nif [ "$#" -eq 2 ] && [ "$1" = "--manual" ]; then\n  exec /usr/local/sbin/capture402 deploy "$2"\nfi\nexec /usr/local/sbin/capture402 "$@"\n', 0o755)
    return root


def controllers(sha, api):
    files = {}
    for name in FILES:
        item = api('repos/' + policy.REPOSITORY + '/contents/ops/' + name + '?ref=' + sha)
        source.require(item.get('path') == 'ops/' + name and item.get('encoding') == 'base64', 'invalid controller response')
        data = base64.b64decode(item['content'], validate=False)
        digest = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        source.require(digest == item['sha'], 'controller Git blob mismatch')
        files[name] = data
    return install_controllers(sha, files)


def recover_first():
    if any((source.BASE / n).exists() for n in ('transaction.json', 'pending.json')):
        source.run('systemctl', 'start', 'capture402-recovery.service', timeout=330)
        source.require(not any((source.BASE / n).exists() for n in ('transaction.json', 'pending.json')),
                       'rollback remains unverified')
        return True
    return False


def main(argv):
    source.require(os.geteuid() == 0, 'use sudo capture402 on the VPS')
    if argv and argv[0] == 'dev':
        import deploy_dev
        try:
            deploy_dev.dispatch(argv[1:])
        except Exception:
            raise RuntimeError('dev deployment blocked; inspect dev receipts and retained transaction') from None
        return
    if argv == ['status']:
        receipt = source.BASE / 'last-result.json'
        import deploy_vps as host
        services = {}
        for name in (*host.LEGACY_SERVICES, *host.PRODUCT_SERVICES):
            try:
                active = source.run('systemctl', 'show', '-p', 'ActiveState', '--value', name)
                pid = source.run('systemctl', 'show', '-p', 'MainPID', '--value', name)
                cwd = os.readlink('/proc/' + pid + '/cwd') if pid.isdecimal() and int(pid) > 0 else None
                services[name] = {'state': active, 'pid': pid, 'cwd': cwd}
            except (OSError, subprocess.CalledProcessError):
                services[name] = {'state': 'unknown'}
        print(json.dumps({'lastResult': json.loads(receipt.read_text()) if receipt.exists() else None,
                          'current': str(source.CURRENT.resolve()) if source.CURRENT.is_symlink() else None,
                          'pending': any((source.BASE / n).exists() for n in ('transaction.json', 'pending.json')),
                          'maintenance': (source.BASE / 'maintenance').exists(), 'services': services}))
        return
    if argv == ['recover']:
        print('RECOVERED' if recover_first() else 'NO_PENDING')
        return
    source.require(len(argv) == 2 and argv[0] == 'deploy' and bool(source.SHA_RE.fullmatch(argv[1])),
                   'usage: capture402 deploy <40-hex-main-sha>|status|recover')
    if recover_first():
        raise RuntimeError('recovered offline; explicitly invoke capture402 deploy again')
    sha = argv[1]
    api = GitHub()
    acceptance = policy.verify(sha, api)
    root = controllers(sha, api)
    source.MANIFESTS.mkdir(mode=0o755, exist_ok=True)
    source.write_json(source.MANIFESTS / (sha + '.approval.json'), acceptance)
    unit = 'capture402-release-' + sha[:12] + '-' + str(time.time_ns())
    print('Deployment job: ' + unit, flush=True)
    result = subprocess.run(['systemd-run', '--unit=' + unit, '--wait', '--property=Type=exec',
        '--property=UMask=0077', '--property=RuntimeMaxSec=900',
        '--property=OnFailure=capture402-recovery.service', '/usr/bin/python3', '-B',
        str(root / 'deploy_vps.py'), sha])
    subprocess.run(['journalctl', '--no-pager', '-u', unit])
    source.require(result.returncode == 0, 'deployment job failed; inspect capture402 status and retained job')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as error:
        # Do not print private subprocess stderr, response bodies or credentials.
        print('DEPLOY_BLOCKED: ' + str(error), file=sys.stderr)
        sys.exit(1)
