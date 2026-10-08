#!/usr/bin/env python3
"""Transactional host migration/release. No payment or journal recovery mutators."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

import deploy_demo as source

BASE = source.BASE
LEGACY = Path('/opt/svm-auth-capture')
STATE = Path('/var/lib/sac006')
PRIVATE = Path('/etc/sac006')
SNIPPET = Path('/etc/nginx/snippets/sac006-resource.conf')
UNITS = Path('/etc/systemd/system')
PENDING = BASE / 'transaction.json'
MAINTENANCE = BASE / 'maintenance'
BACKUPS = BASE / 'backups'
RECOVERY = UNITS / 'capture402-recovery.service'
GATE = UNITS / 'capture402-gate.service'
OVERRIDE = 'zz-capture402-release.conf'
GUARD = 'if (-f /opt/capture402/maintenance) { return 503; }\n'


def durable_remove(path):
    path.unlink(missing_ok=True)
    if path.parent.exists():
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_bytes(path, data, mode=0o644):
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.deploy-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def control_paths():
    return [SNIPPET] + [UNITS / (s + '.service.d') / OVERRIDE for s in (*source.SERVICES, 'nginx')]


def capture_controls():
    result = {}
    for p in control_paths():
        source.require(not p.is_symlink(), 'managed control file is symlink')
        result[str(p)] = (None if not p.exists() else {
            'bytes': base64.b64encode(p.read_bytes()).decode(), 'mode': p.stat().st_mode & 0o777})
    return result


def restore_controls(snapshot):
    source.require(set(snapshot) == {str(p) for p in control_paths()}, 'invalid rollback control paths')
    for name, value in snapshot.items():
        p = Path(name)
        if value is None:
            durable_remove(p)
        else:
            atomic_bytes(p, base64.b64decode(value['bytes'], validate=True), value['mode'])


def active_layout():
    cwds = [source.run('systemctl', 'show', '-p', 'WorkingDirectory', '--value', s)
            for s in source.SERVICES]
    if cwds == [str(LEGACY / 'integration')] * 2:
        sha = source.run('git', '-c', f'safe.directory={LEGACY}', '-C', str(LEGACY), 'rev-parse', 'HEAD')
        source.require(bool(source.SHA_RE.fullmatch(sha)), 'legacy checkout lacks exact SHA')
        source.require(not source.run('git', '-c', f'safe.directory={LEGACY}', '-C', str(LEGACY), 'status', '--porcelain'),
                       'legacy checkout is dirty; preserve and resolve before deployment')
        return {'sha': sha, 'root': str(LEGACY), 'legacy': True}
    source.check_unit_layout()
    sha = source.current_sha()
    return {'sha': sha, 'root': str(source.RELEASES / sha), 'legacy': False}


def health(layout, public=True, orders=True):
    root = Path(layout['root']).resolve(strict=True)
    for service in source.SERVICES:
        source.require(source.run('systemctl', 'is-active', service) == 'active', 'service inactive')
        pid = source.run('systemctl', 'show', '-p', 'MainPID', '--value', service)
        source.require(pid.isdecimal() and int(pid) > 0, 'missing process PID')
        source.require(Path(os.readlink(f'/proc/{pid}/cwd')).resolve() == root / 'integration',
                       'actual process source differs from expected SHA')
    record = json.loads((root / source.RECORD).read_text())
    for prefix in (['http://127.0.0.1:8788', 'https://capture402.xyz'] if public else ['http://127.0.0.1:8788']):
        status, body, _ = source.response(prefix + '/api/config')
        config = json.loads(body)
        source.require(status == 200 and config.get('configured') is True, 'runtime is unprovisioned')
        source.require(config.get('cluster') == 'devnet' and config.get('programId') == record['program']['program_id']
                       and config.get('network') == record['network']['caip2'], 'runtime identity mismatch')
        status, _, headers = source.response(prefix + '/resource')
        source.require(status == 402 and any(k.lower() == 'payment-required' for k in headers), 'missing x402 challenge')
    status, body, _ = source.response('http://127.0.0.1:8787/supported')
    source.require(status == 200 and isinstance(json.loads(body), dict), 'private facilitator unavailable')
    if public:
        for route in ('settle', 'verify', 'supported'):
            status, _, _ = source.response('https://capture402.xyz/' + route)
            source.require(status == 404, 'private facilitator route exposed')
        if orders:
            source.check_order_routes()
        else:
            # Legacy rollback intentionally restores the pre-existing nginx route.
            status, _, _ = source.response('https://capture402.xyz/api/orders', method='POST', data=b'{}')
            source.require(status in (403, 404), 'legacy route changed unexpectedly')


def ready(layout, public=True, orders=True, seconds=90):
    deadline = time.monotonic() + seconds
    while True:
        try:
            health(layout, public, orders)
            return
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(f'readiness exhausted: {error}') from error
            time.sleep(2)


def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inventory(roots):
    """Include every directory, historical wire, .busy lock and symlink without following links."""
    result = {}
    def add(p):
        info = p.lstat()
        if p.is_symlink():
            value = ('link', os.readlink(p))
        elif p.is_dir():
            value = ('dir', '')
        else:
            import stat
            source.require(stat.S_ISREG(info.st_mode), 'unsupported backup file type')
            value = ('file', digest_file(p))
        result[str(p).lstrip('/')] = (*value, info.st_mode & 0o7777, info.st_uid, info.st_gid)
        if value[0] == 'dir':
            for child in sorted(p.iterdir()):
                add(child)
    for root in roots:
        if root.exists() or root.is_symlink():
            add(root)
    return result


def verify_backup(archive, expected):
    actual = {}
    with tarfile.open(archive, 'r:') as tar:
        for item in tar:
            name = item.name.rstrip('/')
            source.require(name not in actual, 'duplicate backup member')
            if item.isdir(): value = ('dir', '')
            elif item.issym(): value = ('link', item.linkname)
            elif item.isfile():
                stream = tar.extractfile(item)
                h = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''): h.update(chunk)
                value = ('file', h.hexdigest())
            else: raise RuntimeError('unsupported backup member')
            actual[name] = (*value, item.mode, item.uid, item.gid)
    source.require(actual == expected, 'backup differs from quiesced source inventory')


def create_backup(archive, expected):
    # Write each regular file in full, including hardlinked dependency files.
    # Never dereference symlinks into keys or out of the selected backup roots.
    fd = os.open(archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as output, tarfile.open(fileobj=output, mode='w:') as tar:
        for name, value in sorted(expected.items()):
            p = Path('/') / name
            member = tar.gettarinfo(str(p), arcname=name)
            if value[0] == 'file':
                member.type = tarfile.REGTYPE
                member.linkname = ''
                member.size = p.stat().st_size
                with p.open('rb') as stream: tar.addfile(member, stream)
            else:
                tar.addfile(member)


def backup(transaction):
    directory = BACKUPS / transaction
    directory.mkdir(mode=0o700)
    roots = [PRIVATE, STATE, LEGACY, Path('/etc/nginx')]
    roots += [UNITS / (s + '.service') for s in source.SERVICES]
    roots += [UNITS / (s + '.service.d') for s in source.SERVICES]
    expected = inventory(roots)
    archive = directory / 'preserved.tar'
    create_backup(archive, expected)
    archive.chmod(0o600)
    with archive.open('rb') as f: os.fsync(f.fileno())
    verify_backup(archive, expected)
    source.require(inventory(roots) == expected, 'backup source changed while services stopped')
    digest = digest_file(archive)
    source.write_json(directory / 'verified.json', {'sha256': digest, 'entries': len(expected)})
    return {'path': str(archive), 'sha256': digest}


def reload_config():
    source.run('systemctl', 'daemon-reload')
    source.run('nginx', '-t')
    source.run('systemctl', 'reload', 'nginx')


def maintenance():
    atomic_bytes(MAINTENANCE, b'deployment in progress\n')


GATE_DEPENDENCY = '[Unit]\nRequires=capture402-gate.service\nAfter=capture402-gate.service\n'


def install_controls(sha):
    fragment = (source.RELEASES / sha / 'integration/deploy/nginx-resource.conf').read_bytes()
    source.require(b'location = /api/orders {' in fragment, 'candidate lacks POST order route')
    atomic_bytes(SNIPPET, GUARD.encode() + fragment)
    for p in control_paths()[1:]:
        content = GATE_DEPENDENCY
        if p.parent.name != 'nginx.service.d':
            content += f'[Service]\nWorkingDirectory={source.CURRENT}/integration\n'
        atomic_bytes(p, content.encode())
    source.switch_to(sha)
    fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    reload_config()
    source.check_unit_layout()


def install_recovery():
    # Runs offline on reboot; durable controller is installed before this unit.
    controller = Path(__file__).resolve()
    atomic_bytes(GATE, f'''[Unit]
Description=Close Capture402 ingress before booting an interrupted release
Before=nginx.service sac006-facilitator.service sac006-resource.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {controller} --gate
UMask=0077
[Install]
WantedBy=multi-user.target
'''.encode())
    atomic_bytes(RECOVERY, f'''[Unit]
Description=Recover interrupted Capture402 release without replaying payments
After=network-online.target nginx.service sac006-facilitator.service sac006-resource.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {controller} --recover
TimeoutStartSec=300
UMask=0077
[Install]
WantedBy=multi-user.target
'''.encode())
    source.run('systemctl', 'daemon-reload')
    source.run('systemctl', 'enable', 'capture402-gate.service', 'capture402-recovery.service')
    source.run('systemctl', 'start', 'capture402-gate.service')


def stop():
    source.run('systemctl', 'stop', *source.SERVICES, timeout=45)
    for service in source.SERVICES:
        source.require(source.run('systemctl', 'show', '-p', 'ActiveState', '--value', service) == 'inactive'
                       and source.run('systemctl', 'show', '-p', 'MainPID', '--value', service) == '0',
                       'service did not quiesce; no backup or cutover permitted')


def fail_closed():
    maintenance()
    source.run('systemctl', 'stop', *source.SERVICES, timeout=45)


def rollback(pending):
    maintenance()
    stop()
    if pending.get('backup'):
        archive = Path(pending['backup']['path'])
        source.require(archive.parent.parent == BACKUPS and archive.name == 'preserved.tar', 'invalid backup path')
        source.require(digest_file(archive) == pending['backup']['sha256'], 'verified backup changed')
    restore_controls(pending['controls'])
    # Keep a maintenance guard on the legacy layout too: rollback failure must
    # never expose a partially started old resource process. TLS site is untouched.
    fragment = SNIPPET.read_bytes()
    if not fragment.startswith(GUARD.encode()):
        atomic_bytes(SNIPPET, GUARD.encode() + fragment)
    for path in control_paths()[1:]:
        original = path.read_bytes() if path.exists() else b''
        if b'Requires=capture402-gate.service' not in original:
            atomic_bytes(path, GATE_DEPENDENCY.encode() + original)
    previous_link = pending['current']
    if previous_link is None:
        durable_remove(source.CURRENT)
    else:
        source.switch_to(previous_link)
    reload_config()
    source.restart()
    old = pending['previous']
    ready(old, public=False)
    durable_remove(MAINTENANCE)
    try:
        ready(old, orders=not old['legacy'])
    except Exception:
        maintenance()
        raise
    source.write_json(BASE / 'last-result.json', {'verdict': 'ROLLED_BACK', 'sha': old['sha'], 'backup': pending.get('backup')})
    durable_remove(PENDING)
    print('ROLLED_BACK ' + old['sha'], flush=True)


@contextmanager
def locked(recovery_only=False):
    source.require(os.geteuid() == 0, 'requires authorized sudo')
    BASE.mkdir(mode=0o755, exist_ok=True)
    for directory in (source.RELEASES, source.MANIFESTS): directory.mkdir(exist_ok=True)
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(BASE / 'deploy.lock', os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if source.PENDING.exists():
            # Recover the previous helper's format before installing a new layout.
            source.recover_pending()
        if PENDING.exists():
            pending = json.loads(PENDING.read_text())
            try: rollback(pending)
            except Exception as exc:
                fail_closed()
                raise RuntimeError('ROLLBACK_UNVERIFIED; pending evidence retained') from exc
            if not recovery_only:
                raise RuntimeError('interrupted deployment recovered; invoke ./deploy.sh again')
        yield
    finally:
        os.close(fd)


def deploy(sha):
    with locked():
        source.require(bool(source.SHA_RE.fullmatch(sha)), 'exact main SHA required')
        previous = active_layout()
        source.run('nginx', '-t')
        # Inspection only: legacy routing is known-broken but resource must be healthy.
        ready(previous, orders=not previous['legacy'])
        blob = source.manually_fetch_archive(sha)
        digest = hashlib.sha256(blob).hexdigest()
        source.verify_source_against_main(sha, blob)
        source.prepare_release(sha, digest, blob)
        # Verify sealed staged bytes even when an existing manifest is reused.
        fingerprints = source.archive_fingerprints(blob, 'r:gz')
        for name, (kind, fingerprint) in fingerprints.items():
            if kind == 'file':
                p = source.RELEASES / sha / name
                source.require(not p.is_symlink() and digest_file(p) == fingerprint, 'staged source substituted')
        if previous['sha'] == sha and not previous['legacy']:
            ready(previous)
            print('ALREADY_ACTIVE ' + sha, flush=True)
            return
        install_recovery()
        pending = {'previous': previous, 'target': sha, 'controls': capture_controls(),
                   'current': source.current_sha() if source.CURRENT.is_symlink() else None}
        # Persist recovery information BEFORE stopping anything or changing ingress.
        source.write_json(PENDING, pending)
        try:
            maintenance()
            # Legacy snippet has no maintenance guard. Backend shutdown quiesces writes.
            stop()
            pending['backup'] = backup(sha + '-' + str(time.time_ns()))
            source.write_json(PENDING, pending)
            preserved = inventory([PRIVATE, STATE])
            install_controls(sha)
            source.require(inventory([PRIVATE, STATE]) == preserved, 'private or payment state changed during cutover')
            source.restart()
            layout = {'sha': sha, 'root': str(source.RELEASES / sha), 'legacy': False}
            ready(layout, public=False)
            durable_remove(MAINTENANCE)
            ready(layout)
            source.write_json(BASE / 'last-result.json', {'verdict': 'DEPLOYED', 'sha': sha,
                'previous': previous, 'backup': pending['backup'], 'processSourceVerified': True,
                'publicOrderOriginGuard': True, 'rollbackLayoutCaptured': True})
            durable_remove(PENDING)
            print('DEPLOYED ' + sha, flush=True)
        except Exception as original:
            try:
                rollback(pending)
            except Exception as exc:
                fail_closed()
                raise RuntimeError('ROLLBACK_UNVERIFIED; maintenance and pending retained') from exc
            raise RuntimeError('cutover failed; verified rollback completed') from original


def main(argv):
    if argv == ['--gate']:
        if PENDING.exists() or source.PENDING.exists(): maintenance()
    elif argv == ['--recover']:
        with locked(recovery_only=True): pass
    elif len(argv) == 1:
        deploy(argv[0])
    else:
        raise RuntimeError('usage: deploy_vps.py <exact-main-sha>|--recover')


if __name__ == '__main__':
    try: main(sys.argv[1:])
    except Exception as error:
        # Never echo HTTP response bodies, private env or subprocess stderr.
        print('DEPLOY_BLOCKED: ' + str(error), file=sys.stderr, flush=True)
        sys.exit(1)
