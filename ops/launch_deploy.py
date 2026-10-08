#!/usr/bin/env python3
"""Owner-invoked single-command deployment; CI never receives VPS credentials."""
import io
import shlex
import subprocess
import sys
import tarfile

import deploy_demo as source

# This constant program only installs the explicitly selected controller files.
# SSH disconnect does not stop the systemd-owned deployment transaction.
INSTALLER = r'''
import io, os, pathlib, subprocess, sys, tarfile
sha = sys.argv[1]
assert len(sha) == 40 and all(c in '0123456789abcdef' for c in sha)
root = pathlib.Path('/opt/capture402/controllers') / sha
root.mkdir(parents=True, exist_ok=True, mode=0o755)
allowed = {'ops/deploy_demo.py', 'ops/deploy_vps.py'}
data = sys.stdin.buffer.read(1024 * 1024)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
    members = archive.getmembers()
    assert {m.name for m in members} == allowed and len(members) == len(allowed)
    assert all(m.isfile() and m.size < 256 * 1024 for m in members)
    for member in members:
        target = root / pathlib.Path(member.name).name
        payload = archive.extractfile(member).read()
        compile(payload, str(target), 'exec')
        if target.exists():
            assert target.read_bytes() == payload, 'existing controller changed'
        else:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, 'wb') as out:
                out.write(payload); out.flush(); os.fsync(out.fileno())
unit = 'capture402-release-' + sha[:12] + '-' + str(os.getpid())
print('Deployment job: ' + unit, flush=True)
result = subprocess.run(['systemd-run', '--unit=' + unit, '--wait',
    '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=900',
    '--property=OnFailure=capture402-recovery.service',
    '/usr/bin/python3', str(root / 'deploy_vps.py'), sha])
subprocess.run(['journalctl', '--no-pager', '-u', unit])
sys.exit(result.returncode)
'''


def require_acceptance(sha):
    import json
    api = 'repos/starPaw/svm-auth-capture'
    pulls = json.loads(source.run('gh', 'api', f'{api}/commits/{sha}/pulls'))
    matched = [p for p in pulls if p.get('merged_at') and p.get('merge_commit_sha') == sha
               and p['base']['ref'] == 'main']
    source.require(len(matched) == 1, 'main SHA lacks an unambiguous merged PR')
    pull = matched[0]
    reviews = json.loads(source.run('gh', 'api', '--paginate', '--slurp', f"{api}/pulls/{pull['number']}/reviews"))
    latest = {}
    for page in reviews:
        for review in page:
            user = review['user']
            if user['login'] in ('starPaw', 'gwinpin') or user.get('type') != 'User':
                continue
            if review['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
                latest[user['login']] = review
    accepted = [r for r in latest.values() if r['state'] == 'APPROVED'
                and r['commit_id'] == pull['head']['sha']]
    source.require(bool(accepted), 'independent exact-head human approval missing')
    # A merge conflict fix must not silently change the accepted application tree.
    source.run('git', 'fetch', 'origin', pull['head']['sha'], timeout=120)
    source.require(not source.run('git', 'diff', '--name-only', pull['head']['sha'], sha),
                   'merged tree differs from independently accepted head')


def main():
    if len(sys.argv) != 1:
        raise RuntimeError('usage: ./deploy.sh (deploys the clean, exact current main checkout)')
    source.require(source.run('git', 'remote', 'get-url', 'origin') == 'https://github.com/starPaw/svm-auth-capture.git', 'wrong repository')
    source.require(not source.run('git', 'status', '--porcelain'), 'deployment requires clean checkout')
    source.run('git', 'fetch', 'origin', 'main', timeout=120)
    sha = source.run('git', 'rev-parse', 'HEAD')
    source.require(sha == source.run('git', 'rev-parse', 'origin/main'), 'checkout differs from canonical main')
    # Require successful current-main CI and independent exact-head acceptance.
    # Invoking this command is the owner's explicit operational authorization.
    import json
    runs = json.loads(source.run('gh', 'run', 'list', '--commit', sha, '--workflow', 'components.yml',
        '--event', 'push', '--json', 'conclusion,headSha,status', '--limit', '1'))
    source.require(len(runs) == 1 and runs[0]['status'] == 'completed'
                   and runs[0]['conclusion'] == 'success' and runs[0]['headSha'] == sha,
                   'current main Components CI has not succeeded')
    require_acceptance(sha)
    blob = subprocess.run(['git', 'archive', '--format=tar', sha, 'ops/deploy_demo.py', 'ops/deploy_vps.py'],
                          check=True, capture_output=True).stdout
    # Git adds an ops/ directory; rebuild the small transfer as regular files only.
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(blob)) as archive, tarfile.open(fileobj=output, mode='w') as packed:
        for member in archive:
            if member.isfile(): packed.addfile(member, archive.extractfile(member))
    command = 'sudo -n python3 -c ' + shlex.quote(INSTALLER) + ' ' + sha
    subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'ConnectTimeout=10', 'ubuntu@89.168.83.156', command],
                   input=output.getvalue(), check=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('DEPLOY_BLOCKED: ' + str(error), file=sys.stderr)
        sys.exit(1)
