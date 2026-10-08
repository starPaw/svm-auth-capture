#!/usr/bin/env python3
"""Owner-invoked single-command deployment; CI never receives VPS credentials."""
import io
import shlex
import subprocess
import sys
import tarfile
import json

import deploy_demo as source
import release_policy as policy

# This constant program only installs the explicitly selected controller files.
# SSH disconnect does not stop the systemd-owned deployment transaction.
INSTALLER = r'''
import io, os, pathlib, stat, subprocess, sys, tarfile, tempfile
sha = sys.argv[1]
assert len(sha) == 40 and all(c in '0123456789abcdef' for c in sha)
root = pathlib.Path('/opt/capture402/controllers') / sha
for directory in (root.parent.parent, root.parent, root):
    assert not directory.is_symlink(), 'controller directory is symlink'
    directory.mkdir(exist_ok=True, mode=0o755)
    assert directory.stat().st_uid == os.geteuid(), 'controller directory owner changed'
    directory.chmod(0o755)
allowed = {'ops/deploy_demo.py', 'ops/deploy_vps.py', 'ops/host_cli.py', 'ops/release_policy.py'}
data = sys.stdin.buffer.read(1024 * 1024)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
    members = archive.getmembers()
    assert {m.name for m in members} == allowed and len(members) == len(allowed)
    assert all(m.isfile() and m.size < 256 * 1024 for m in members)
    for member in members:
        target = root / pathlib.Path(member.name).name
        payload = archive.extractfile(member).read()
        compile(payload, str(target), 'exec')
        assert not target.is_symlink(), 'controller file is symlink'
        if target.exists():
            info = target.stat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'unsafe controller ownership/mode'
            assert target.read_bytes() == payload, 'existing controller changed'
        else:
            fd, temporary = tempfile.mkstemp(prefix='.controller-', dir=root)
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, 'wb') as out:
                out.write(payload); out.flush(); os.fsync(out.fileno())
            os.replace(temporary, target)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
sys.path.insert(0, str(root))
import host_cli
host_cli.install_controllers(sha, {name: (root / name).read_bytes() for name in host_cli.FILES})
if len(sys.argv) == 3 and sys.argv[2] == '--install-cli':
    print('CLI_INSTALLED ' + sha, flush=True)
    sys.exit(0)
unit = 'capture402-release-' + sha[:12] + '-' + str(os.getpid())
print('Deployment job: ' + unit, flush=True)
result = subprocess.run(['systemd-run', '--unit=' + unit, '--wait',
    '--property=Type=exec', '--property=UMask=0077', '--property=RuntimeMaxSec=900',
    '--property=OnFailure=capture402-recovery.service',
    '/usr/bin/python3', '-B', str(root / 'deploy_vps.py'), sha])
subprocess.run(['journalctl', '--no-pager', '-u', unit])
sys.exit(result.returncode)
'''


# Use the already installed, approved recovery unit before any GitHub access.
RECOVER = r"""
from pathlib import Path
import subprocess
pending = any(Path(p).exists() for p in ('/opt/capture402/transaction.json', '/opt/capture402/pending.json'))
if pending:
    assert Path('/etc/systemd/system/capture402-recovery.service').is_file(), 'pending deployment lacks approved recovery unit'
    subprocess.run(['systemctl', 'start', 'capture402-recovery.service'], check=True)
    assert not any(Path(p).exists() for p in ('/opt/capture402/transaction.json', '/opt/capture402/pending.json')), 'rollback remains unverified'
    print('RECOVERED')
else:
    print('NO_PENDING')
"""
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=10', 'ubuntu@89.168.83.156']


def recover_first():
    result = subprocess.run([*SSH, 'sudo -n python3 -c ' + shlex.quote(RECOVER)],
                            check=True, capture_output=True, text=True, timeout=330)
    if result.stdout.strip() == 'RECOVERED':
        raise RuntimeError('interrupted deployment recovered offline; invoke ./deploy.sh again')
    source.require(result.stdout.strip() == 'NO_PENDING', 'unexpected recovery result')


def require_acceptance(sha):
    return policy.verify(sha, lambda route: json.loads(source.run('gh', 'api', route)))


def main():
    if sys.argv[1:] not in ([], ['--install-cli']):
        raise RuntimeError('usage: ./deploy.sh [--install-cli] (clean, exact current main checkout)')
    source.require(source.run('git', 'remote', 'get-url', 'origin') == 'https://github.com/starPaw/svm-auth-capture.git', 'wrong repository')
    source.require(not source.run('git', 'status', '--porcelain'), 'deployment requires clean checkout')
    recover_first()
    source.run('git', 'fetch', 'origin', 'main', timeout=120)
    sha = source.run('git', 'rev-parse', 'HEAD')
    source.require(sha == source.run('git', 'rev-parse', 'origin/main'), 'checkout differs from canonical main')
    # Shared eligibility policy is identical for local SSH and on-host operation.
    require_acceptance(sha)
    blob = subprocess.run(['git', 'archive', '--format=tar', sha, 'ops/deploy_demo.py', 'ops/deploy_vps.py', 'ops/host_cli.py', 'ops/release_policy.py'],
                          check=True, capture_output=True).stdout
    # Git adds an ops/ directory; rebuild the small transfer as regular files only.
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(blob)) as archive, tarfile.open(fileobj=output, mode='w') as packed:
        for member in archive:
            if member.isfile(): packed.addfile(member, archive.extractfile(member))
    command = 'sudo -n python3 -c ' + shlex.quote(INSTALLER) + ' ' + sha
    if sys.argv[1:]:
        command += ' --install-cli'
    subprocess.run([*SSH, command],
                   input=output.getvalue(), check=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('DEPLOY_BLOCKED: ' + str(error), file=sys.stderr)
        sys.exit(1)
