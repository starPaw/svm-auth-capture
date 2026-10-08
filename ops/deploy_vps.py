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
NGINX_SERVICE = 'nginx'
GUARD = 'if (-f /opt/capture402/maintenance) { return 503; }\n'
PRODUCT_SERVICES = ('capture402-facilitator', 'capture402-restaurant')
LEGACY_SERVICES = tuple(source.SERVICES)


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
    return [SNIPPET] + [UNITS / (s + '.service.d') / OVERRIDE for s in (*source.SERVICES, NGINX_SERVICE)]


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
        data = b'' if value is None else base64.b64decode(value['bytes'], validate=True)
        mode = 0o644 if value is None else value['mode']
        # Never publish an unguarded intermediate file, even when the legacy
        # snapshot predates migration. A reboot may happen after ANY replace.
        data = guarded(data) if p == SNIPPET else gate_dependency(data)
        atomic_bytes(p, data, mode)


def active_layout():
    pairs = list(dict.fromkeys((tuple(LEGACY_SERVICES), tuple(PRODUCT_SERVICES))))
    active = []
    for pair in pairs:
        states = []
        for name in pair:
            try:
                states.append(source.run('systemctl', 'show', '-p', 'ActiveState', '--value', name))
            except subprocess.CalledProcessError:
                states.append('absent')
        if any(s == 'active' for s in states):
            source.require(states == ['active', 'active'], 'partial backend pair; inspect before deployment')
            active.append(pair)
    source.require(len(active) == 1, 'expected exactly one active backend pair')
    source.SERVICES = active[0]
    cwds = [source.run('systemctl', 'show', '-p', 'WorkingDirectory', '--value', s)
            for s in source.SERVICES]
    if cwds == [str(LEGACY / 'integration')] * 2:
        sha = source.run('git', '-c', f'safe.directory={LEGACY}', '-C', str(LEGACY), 'rev-parse', 'HEAD')
        source.require(bool(source.SHA_RE.fullmatch(sha)), 'legacy checkout lacks exact SHA')
        source.require(not source.run('git', '-c', f'safe.directory={LEGACY}', '-C', str(LEGACY), 'status', '--porcelain'),
                       'legacy checkout is dirty; preserve and resolve before deployment')
        return {'sha': sha, 'root': str(LEGACY), 'legacy': True, 'services': list(source.SERVICES)}
    source.check_unit_layout()
    sha = source.current_sha()
    return {'sha': sha, 'root': str(source.RELEASES / sha), 'legacy': False, 'services': list(source.SERVICES)}


def merchant_boundary(prefix, required):
    # No bearer, no payer cookie, nonexistent ID: authenticate before lookup or signing.
    url = prefix + '/api/orders/' + '0' * 32 + '/actions/beer'
    status, body, headers = source.response(url, method='POST', data=b'{}',
                                           headers={'Origin': 'https://capture402.xyz'})
    payload = json.loads(body)
    expected = {'error': 'missing bearer token'}
    source.require(status == 401 and payload == expected
                   or (not required and status == 503 and payload == {'error': 'merchant operations disabled'}),
                   'merchant authentication boundary unavailable or bypassed')


def health(layout, public=True, orders=True):
    root = Path(layout['root']).resolve(strict=True)
    for service, entry in zip(layout.get('services', source.SERVICES), ('devnet-server.ts', 'restaurant-server.ts')):
        source.require(source.run('systemctl', 'is-active', service) == 'active', 'service inactive')
        pid = source.run('systemctl', 'show', '-p', 'MainPID', '--value', service)
        source.require(pid.isdecimal() and int(pid) > 0, 'missing process PID')
        source.require(Path(os.readlink(f'/proc/{pid}/cwd')).resolve() == root / 'integration',
                       'actual process source differs from expected SHA')
        argv = Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        source.require(len(argv) == 3 and Path(os.fsdecode(argv[0])).name == 'node'
                       and argv[1:] == [b'--experimental-strip-types', ('src/' + entry).encode()],
                       'actual process entrypoint differs from reviewed source')
    record = json.loads((root / source.RECORD).read_text())
    for prefix in (['http://127.0.0.1:8788', 'https://capture402.xyz'] if public else ['http://127.0.0.1:8788']):
        status, body, _ = source.response(prefix + '/api/config')
        config = json.loads(body)
        source.require(status == 200 and config.get('configured') is True, 'runtime is unprovisioned')
        source.require(config.get('cluster') == 'devnet' and config.get('programId') == record['program']['program_id']
                       and config.get('network') == record['network']['caip2'], 'runtime identity mismatch')
        status, _, headers = source.response(prefix + '/resource')
        source.require(status == 402 and any(k.lower() == 'payment-required' for k in headers), 'missing x402 challenge')
        if not layout['legacy']:
            merchant_boundary(prefix, required=layout.get('merchantReady', False))
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
    if source.CURRENT.is_symlink():
        source.release_name(source.CURRENT)
        roots.append(source.CURRENT.resolve(strict=True))
    names = tuple(dict.fromkeys((*source.SERVICES, *PRODUCT_SERVICES, NGINX_SERVICE)))
    roots += [UNITS / (s + '.service') for s in names]
    roots += [UNITS / (s + '.service.d') for s in names]
    roots += [UNITS / 'multi-user.target.wants' / (s + '.service') for s in names]
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
    source.run('systemctl', 'reload', NGINX_SERVICE)


def maintenance():
    atomic_bytes(MAINTENANCE, b'deployment in progress\n')


def env_value(path, key):
    import shlex
    result = None
    for line in path.read_text().splitlines():
        if line.strip().startswith(key + '='):
            parts = shlex.split(line, comments=True, posix=True)
            source.require(len(parts) == 1 and parts[0].startswith(key + '='), 'unsupported private environment assignment')
            source.require(result is None, 'duplicate private environment assignment')
            result = parts[0].split('=', 1)[1]
    return result


def provision_merchant():
    """The existing merchant boundary requires a separate private bearer.

    No signer, key, on-chain authority or payer capability changes. Existing
    credentials are preserved; the generated file is retained even on rollback.
    """
    import secrets
    path = PRIVATE / 'merchant.env'
    configured = env_value(PRIVATE / 'resource.env', 'SAC006_MERCHANT_TOKEN')
    source.require(not path.is_symlink(), 'merchant environment is symlink')
    saved = env_value(path, 'SAC006_MERCHANT_TOKEN') if path.exists() else None
    source.require(not (configured and saved and configured != saved), 'conflicting merchant credentials')
    token = configured or saved
    bearer = env_value(PRIVATE / 'resource.env', 'SAC006_BEARER_TOKEN')
    if token:
        source.require(len(token) >= 32 and token.strip() == token and '\r' not in token and '\n' not in token
                       and token != bearer, 'merchant credential is not independent or invalid')
        if saved:
            source.require(path.stat().st_mode & 0o077 == 0, 'merchant environment must be private')
        return bool(saved)
    source.require(not path.exists(), 'existing merchant environment has no usable credential')
    # Never overwrite either original service env; never print or persist the token in evidence.
    token = secrets.token_urlsafe(48)
    atomic_bytes(path, ('SAC006_MERCHANT_TOKEN=' + token + '\n').encode(), 0o600)
    return True


def guarded(data):
    return data if data.startswith(GUARD.encode()) else GUARD.encode() + data


def gate_dependency(data=b''):
    name = GATE.name
    prefix = f'[Unit]\nRequires={name}\nAfter={name}\n'.encode()
    return data if f'Requires={name}'.encode() in data else prefix + data


def prepare_boot_boundary():
    # This is safety preflight, before transaction.json or service shutdown.
    # No source/environment switch and no requests are blocked without marker.
    atomic_bytes(SNIPPET, guarded(SNIPPET.read_bytes()))
    source.run('nginx', '-t')
    for path in control_paths()[1:]:
        source.require(not path.is_symlink(), 'managed dependency override is symlink')
        data = path.read_bytes() if path.exists() else b''
        atomic_bytes(path, gate_dependency(data))


def migration_snapshot(previous):
    if not previous.get('services') or tuple(previous['services']) == tuple(PRODUCT_SERVICES):
        return None
    result = {'previousServices': previous['services'], 'files': {}, 'enablement': {}}
    source.require(tuple(previous['services']) == tuple(LEGACY_SERVICES), 'unknown service namespace')
    for name in (*previous['services'], *PRODUCT_SERVICES):
        state = source.run('systemctl', 'show', '-p', 'UnitFileState', '--value', name)
        source.require(state in ('', 'enabled', 'disabled', 'static'), 'unsupported unit enablement; inspect before migration')
        result['enablement'][name] = state
    for name in PRODUCT_SERVICES:
        paths = [UNITS / (name + '.service')]
        directory = UNITS / (name + '.service.d')
        source.require(not directory.is_symlink(), 'product drop-in directory is symlink')
        if directory.exists():
            source.require(all(p.is_file() and not p.is_symlink() and p.suffix == '.conf' for p in directory.iterdir()),
                           'unexpected product drop-in entry')
            paths += list(directory.iterdir())
        for path in paths:
            source.require(not path.is_symlink() and (not path.exists() or path.is_file()), 'unsafe product unit file')
            result['files'][str(path)] = None if not path.exists() else {
                'bytes': base64.b64encode(path.read_bytes()).decode(), 'mode': path.stat().st_mode & 0o777}
    # Reject ambiguous source layouts before persisting pending state.
    for name in previous['services']:
        path = UNITS / (name + '.service')
        source.require(path.is_file() and not path.is_symlink(), 'migration requires regular /etc unit files')
        info = path.stat()
        source.require(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'unsafe legacy unit ownership/mode')
        actual = source.run('systemctl', 'show', '-p', 'FragmentPath', '--value', name)
        source.require(actual == str(path), 'unexpected service fragment; inspect before migration')
        source.require(not any(line.strip().startswith(('Alias=', 'Also=')) for line in path.read_text().splitlines()),
                       'unit aliases require a separate migration plan')
        directory = UNITS / (name + '.service.d')
        source.require(not directory.is_symlink(), 'legacy drop-in directory is symlink')
        if directory.exists():
            source.require(all(p.is_file() and not p.is_symlink() and p.suffix == '.conf' for p in directory.iterdir()),
                           'unexpected legacy drop-in entry')
            source.require(all(p.stat().st_uid == os.getuid() and not p.stat().st_mode & 0o022 for p in directory.iterdir()),
                           'unsafe legacy drop-in ownership/mode')
        effective = source.run('systemctl', 'show', '-p', 'DropInPaths', '--value', name).split()
        expected = [] if not directory.exists() else [str(p) for p in directory.iterdir()]
        source.require(set(effective) == set(expected), 'unmanaged service drop-ins; inspect before migration')
    return result


def renamed_unit(data, mapping, description=None):
    lines = []
    section = ''
    for line in data.decode().splitlines(keepends=True):
        if line.strip().startswith('['):
            section = line.strip()
        key, separator, value = line.partition('=')
        if section == '[Unit]' and key.strip() in ('After', 'Before', 'Requires', 'Wants', 'BindsTo', 'PartOf', 'Conflicts'):
            line = key + '=' + ' '.join(mapping.get(word, word) for word in value.split()) + '\n'
        elif section == '[Unit]' and key.strip() == 'Description' and description:
            line = 'Description=' + description + '\n'
        lines.append(line)
    return gate_dependency(''.join(lines).encode())


def migrate_services(snapshot):
    if snapshot is None:
        return
    old = snapshot['previousServices']
    mapping = {a + '.service': b + '.service' for a, b in zip(old, PRODUCT_SERVICES)}
    for legacy, product, description in zip(old, PRODUCT_SERVICES,
            ('Capture402 private Solana facilitator', 'Capture402 restaurant application')):
        target = UNITS / (product + '.service')
        atomic_bytes(target, renamed_unit((UNITS / (legacy + '.service')).read_bytes(), mapping, description))
        target_directory = UNITS / (product + '.service.d')
        if target_directory.exists():
            for path in target_directory.iterdir():
                durable_remove(path)
        directory = UNITS / (legacy + '.service.d')
        if directory.exists():
            for original in directory.iterdir():
                atomic_bytes(UNITS / (product + '.service.d') / original.name,
                             renamed_unit(original.read_bytes(), mapping))
    source.run('systemctl', 'daemon-reload')
    source.run('systemctl', 'disable', *old)
    source.run('systemctl', 'enable', *PRODUCT_SERVICES)
    source.SERVICES = tuple(PRODUCT_SERVICES)


def restore_service_names(snapshot):
    if snapshot is None:
        return
    source.require(tuple(snapshot['previousServices']) == tuple(LEGACY_SERVICES), 'invalid rollback service namespace')
    existing = [name for name in PRODUCT_SERVICES if (UNITS / (name + '.service')).exists()]
    if existing:
        source.run('systemctl', 'disable', *existing)
    for name in PRODUCT_SERVICES:
        paths = [UNITS / (name + '.service')]
        directory = UNITS / (name + '.service.d')
        if directory.exists():
            paths += list(directory.iterdir())
        paths += [Path(p) for p in snapshot['files'] if Path(p) == UNITS / (name + '.service')
                  or Path(p).parent == directory]
        for path in dict.fromkeys(paths):
            value = snapshot['files'].get(str(path))
            if value is None:
                durable_remove(path)
            else:
                atomic_bytes(path, gate_dependency(base64.b64decode(value['bytes'], validate=True)), value['mode'])
    source.run('systemctl', 'daemon-reload')
    for name, state in snapshot['enablement'].items():
        if state == 'enabled':
            source.run('systemctl', 'enable', name)
        elif state == 'disabled':
            source.run('systemctl', 'disable', name)
    source.SERVICES = tuple(snapshot['previousServices'])



def install_controls(sha, merchant_file=False):
    fragment = (source.RELEASES / sha / 'integration/deploy/nginx-resource.conf').read_bytes()
    source.require(b'location = /api/orders {' in fragment, 'candidate lacks POST order route')
    atomic_bytes(SNIPPET, guarded(fragment))
    for p in control_paths()[1:]:
        content = gate_dependency().decode()
        if p.parent.name != NGINX_SERVICE + '.service.d':
            content += f'[Service]\nWorkingDirectory={source.CURRENT}/integration\n'
            if merchant_file and p.parent.name == source.SERVICES[1] + '.service.d':
                content += f'EnvironmentFile={PRIVATE}/merchant.env\n'
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
    all_services = tuple(dict.fromkeys((*source.SERVICES, *PRODUCT_SERVICES)))
    atomic_bytes(GATE, f'''[Unit]
Description=Close Capture402 ingress before booting an interrupted release
Before={NGINX_SERVICE}.service {' '.join(s + '.service' for s in all_services)}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -B {controller} --gate
UMask=0077
[Install]
WantedBy=multi-user.target
'''.encode())
    atomic_bytes(RECOVERY, f'''[Unit]
Description=Recover interrupted Capture402 release without replaying payments
After=network-online.target {NGINX_SERVICE}.service {' '.join(s + '.service' for s in all_services)}
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B {controller} --recover
TimeoutStartSec=300
UMask=0077
[Install]
WantedBy=multi-user.target
'''.encode())
    prepare_boot_boundary()
    source.run('systemctl', 'daemon-reload')
    for service in (*source.SERVICES, NGINX_SERVICE):
        requires = source.run('systemctl', 'show', '-p', 'Requires', '--value', service).split()
        source.require(GATE.name in requires, 'boot gate dependency is not effective')
    source.run('systemctl', 'enable', GATE.name, RECOVERY.name)
    source.run('systemctl', 'start', GATE.name)
    # Activate the legacy guard before persisting a deployment transaction.
    source.run('systemctl', 'reload', NGINX_SERVICE)


def stop(names=None):
    names = tuple(source.SERVICES if names is None else dict.fromkeys(names))
    available = []
    for name in names:
        try:
            state = source.run('systemctl', 'show', '-p', 'LoadState', '--value', name)
        except subprocess.CalledProcessError as error:
            source.require((error.stdout or '').strip() == 'not-found', 'cannot determine backend load state')
            state = 'not-found'
        if state != 'not-found':
            available.append(name)
    if available:
        source.run('systemctl', 'stop', *available, timeout=45)
    for service in available:
        # A failed boot (e.g. interrupted WorkingDirectory installation) retains
        # failed state after stop. It is quiesced only with BOTH process IDs zero.
        source.require(source.run('systemctl', 'show', '-p', 'ActiveState', '--value', service) in ('inactive', 'failed')
                       and source.run('systemctl', 'show', '-p', 'MainPID', '--value', service) == '0'
                       and source.run('systemctl', 'show', '-p', 'ControlPID', '--value', service) == '0',
                       'service did not quiesce; no backup or cutover permitted')


def fail_closed():
    maintenance()
    try:
        stop((*LEGACY_SERVICES, *PRODUCT_SERVICES))
    except Exception as error:
        raise RuntimeError('ROLLBACK_UNVERIFIED; backend shutdown also unverified') from error


def rollback(pending):
    old = pending['previous']
    source.require(bool(source.SHA_RE.fullmatch(old['sha'])), 'invalid previous SHA')
    expected_root = LEGACY if old['legacy'] else source.RELEASES / old['sha']
    source.require(Path(old['root']) == expected_root, 'invalid previous source path')
    maintenance()
    previous_services = tuple(old.get('services', LEGACY_SERVICES))
    source.require(previous_services in (tuple(LEGACY_SERVICES), tuple(PRODUCT_SERVICES)), 'invalid rollback services')
    stop((*previous_services, *pending.get('targetServices', source.SERVICES)))
    if pending.get('backup'):
        archive = Path(pending['backup']['path'])
        source.require(archive.parent.parent == BACKUPS and archive.name == 'preserved.tar', 'invalid backup path')
        source.require(digest_file(archive) == pending['backup']['sha256'], 'verified backup changed')
    restore_service_names(pending.get('serviceMigration'))
    source.SERVICES = previous_services
    restore_controls(pending['controls'])
    # restore_controls() atomically retains the guard/dependencies on every file.
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
    for directory in (BASE, source.RELEASES, source.MANIFESTS):
        source.require(not directory.is_symlink(), 'managed release directory is symlink')
        directory.mkdir(mode=0o755, exist_ok=True)
        directory.chmod(0o755)
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    BACKUPS.chmod(0o700)
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
        migration = migration_snapshot(previous)
        if previous['sha'] == sha and not previous['legacy'] and migration is None:
            ready({**previous, 'merchantReady': True})
            print('ALREADY_ACTIVE ' + sha, flush=True)
            return
        install_recovery()
        pending = {'previous': previous, 'target': sha, 'controls': capture_controls(),
                   'current': source.current_sha() if source.CURRENT.is_symlink() else None,
                   'serviceMigration': migration,
                   'targetServices': list(PRODUCT_SERVICES if migration else source.SERVICES), 'stage': 'prepared'}
        # Boot enforcement is already durable and effective. Persist recovery
        # information before stopping services or switching the runtime.
        source.write_json(PENDING, pending)
        try:
            maintenance()
            # Prepared legacy guard also blocks requests on reboot during backup.
            stop()
            pending['backup'] = backup(sha + '-' + str(time.time_ns()))
            source.write_json(PENDING, pending)
            preserved = inventory([PRIVATE, STATE])
            merchant_file = provision_merchant()
            after = inventory([PRIVATE, STATE])
            source.require(all(after.get(name) == value for name, value in preserved.items()),
                           'historical private or payment state changed during provisioning')
            source.require(set(after) - set(preserved) <= {str(PRIVATE / 'merchant.env').lstrip('/')},
                           'unexpected private state added')
            preserved = after
            pending['stage'] = 'controls'
            source.write_json(PENDING, pending)
            migrate_services(migration)
            install_controls(sha, merchant_file)
            source.require(inventory([PRIVATE, STATE]) == preserved, 'private or payment state changed during cutover')
            source.restart()
            layout = {'sha': sha, 'root': str(source.RELEASES / sha), 'legacy': False,
                      'merchantReady': True, 'services': list(source.SERVICES)}
            ready(layout, public=False)
            durable_remove(MAINTENANCE)
            ready(layout)
            source.write_json(BASE / 'last-result.json', {'verdict': 'DEPLOYED', 'sha': sha,
                'previous': previous, 'backup': pending['backup'], 'processSourceVerified': True,
                'publicOrderOriginGuard': True, 'rollbackLayoutCaptured': True})
            durable_remove(PENDING)
            print('DEPLOYED ' + sha, flush=True)
        except Exception as original:
            source.write_json(BASE / 'last-failure.json', {'target': sha, 'stage': pending['stage'],
                              'errorType': type(original).__name__})
            try:
                rollback(pending)
            except Exception as exc:
                fail_closed()
                raise RuntimeError('ROLLBACK_UNVERIFIED; maintenance and pending retained') from exc
            raise RuntimeError('cutover failed; verified rollback completed') from original


def main(argv):
    if argv == ['--gate']:
        if PENDING.exists() or source.PENDING.exists():
            maintenance()
            # Defend retained pending records from the previous helper as well.
            atomic_bytes(SNIPPET, guarded(SNIPPET.read_bytes()))
            source.run('nginx', '-t')
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
