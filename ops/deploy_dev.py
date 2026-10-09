#!/usr/bin/env python3
"""Dev-only code deployment. Never restores state, signs, or broadcasts payments."""
from contextlib import contextmanager
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

import deploy_demo as source
import deploy_vps as host
import release_policy as policy

BASE = Path('/opt/capture402-dev')
RELEASES = BASE / 'releases'
CURRENT = BASE / 'current'
PENDING = BASE / 'transaction.json'
PRIVATE = Path('/etc/capture402-dev')
STATE = Path('/var/lib/capture402-dev')
PERMIT = Path('/run/capture402-dev-deploy-permit')
SERVICES = ('capture402-dev-facilitator', 'capture402-dev-restaurant')
CGROUP = Path('/sys/fs/cgroup')
SLICE = 'capture402-dev.slice'
UNITS = Path('/etc/systemd/system')
ORIGIN = 'https://dev.capture402.xyz'


def trusted(path, directory=False):
    info = path.lstat()
    source.require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                   and info.st_uid == 0 and info.st_mode & 0o022 == 0, 'unsafe dev operator path')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def current():
    source.require(CURRENT.is_symlink(), 'dev current must be a release symlink')
    root = CURRENT.resolve(strict=True)
    source.require(root.parent == RELEASES and source.SHA_RE.fullmatch(root.name), 'dev current escapes releases')
    trusted(root, True)
    return root.name


def switch(sha):
    source.require(bool(source.SHA_RE.fullmatch(sha)), 'invalid dev release SHA')
    trusted(RELEASES / sha, True)
    link = BASE / ('.current-' + str(os.getpid()))
    link.symlink_to(RELEASES / sha)
    try:
        os.replace(link, CURRENT)
        sync(BASE)
    finally:
        link.unlink(missing_ok=True)


def group_path(name):
    # systemd hyphenated slice names form a hierarchy, not a root-level cgroup.
    parts = SLICE.removesuffix('.slice').split('-')
    slices = ['-'.join(parts[:n]) + '.slice' for n in range(1, len(parts) + 1)]
    return '/' + '/'.join(slices) + '/' + name + '.service'


def units():
    for name, entry in zip(SERVICES, ('devnet-server.ts', 'restaurant-server.ts')):
        get = lambda key: source.run('systemctl', 'show', '-p', key, '--value', name)
        source.require(get('User') == name and get('WorkingDirectory') == str(CURRENT / 'integration')
                       and get('Restart') == 'no' and get('Slice') == SLICE, 'unexpected dev service layout')
        for key in ('Requires', 'Wants', 'Conflicts', 'BindsTo', 'PartOf', 'PropagatesStopTo'):
            source.require(not any(unit.startswith(('sac006-', 'capture402-facilitator.', 'capture402-restaurant.')) for unit in get(key).split()), 'dev dependency touches production')
        command = get('ExecStart')
        source.require('src/' + entry in command and 'capture402-facilitator.service' not in get('Requires')
                       and 'capture402-restaurant.service' not in get('Requires'), 'unsafe dev unit command/dependencies')
        group = get('ControlGroup')
        source.require(group == group_path(name),
                       'dev unit must use isolated cgroup')
        root = CGROUP / group.lstrip('/')
        source.require('populated ' in (root / 'cgroup.events').read_text() and (root / 'cgroup.kill').is_file(), 'cgroup v2 freeze/kill support required')


def populated(root):
    try:
        return 'populated 1' in (root / 'cgroup.events').read_text()
    except FileNotFoundError:
        # systemd may reap the cgroup immediately after its last task exits.
        return False


def stop(names=None):
    # Kill within a verified frozen cgroup, without systemd's automatic thaw before stop.
    # Every economic broadcast is preceded by a durable reservation. A clean frozen
    # snapshot cannot become dirty between inspection and killing the same cgroups.
    for name in reversed(SERVICES if names is None else names):
        group = source.run('systemctl', 'show', '-p', 'ControlGroup', '--value', name)
        source.require(group == group_path(name),
                       'unexpected dev cgroup')
        root = CGROUP / group.lstrip('/')
        source.require('frozen 1' in (root / 'cgroup.events').read_text(), 'refuse to kill an unfrozen dev unit')
        (root / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 10
        while populated(root):
            source.require(time.monotonic() < deadline, 'dev cgroup did not empty')
            time.sleep(0.05)
        source.run('systemctl', 'stop', name)
        source.require(source.run('systemctl', 'show', '-p', 'MainPID', '--value', name) == '0', 'dev unit still running')


def freeze():
    for name in SERVICES:
        source.run('systemctl', 'freeze', name)
        group = source.run('systemctl', 'show', '-p', 'ControlGroup', '--value', name)
        source.require(group == group_path(name),
                       'unexpected dev cgroup')
        source.require('frozen 1' in (CGROUP / group.lstrip('/') / 'cgroup.events').read_text(), 'dev freeze unverified')


def thaw():
    for name in SERVICES:
        source.run('systemctl', 'thaw', name)


def state_paths():
    expected = {
        ('facilitator', 'SAC006_FACILITATOR_JOURNAL_DIR'): STATE / 'facilitator/journal',
        ('restaurant', 'SAC006_STORE_DIR'): STATE / 'restaurant/operation-store',
        ('restaurant', 'SAC006_RECLAIM_JOURNAL_DIR'): STATE / 'restaurant/reclaim',
    }
    for (role, key), path in expected.items():
        trusted(PRIVATE / (role + '.env'))
        source.require(host.env_value(PRIVATE / (role + '.env'), key) == str(path), 'dev state path differs from isolated layout')
    return [*expected.values(), STATE / 'restaurant/operation-store-restaurant']


def clean_operations():
    # Fail closed on absent directories, partial writes, unknown schemas or outcomes.
    journal, operations, reclaim, orders = state_paths()
    for directory in (journal, operations, reclaim, orders):
        source.require(directory.is_dir() and not directory.is_symlink(), 'dev journal directory missing or unsafe')
        for path in directory.iterdir():
            source.require(path.is_file() and not path.is_symlink(), 'unsafe dev journal member')
            source.require(path.stat().st_size < 4 * 1024 * 1024, 'dev journal member too large')
            source.require('.tmp-' not in path.name and not path.name.endswith('.busy'), 'unfinished dev operation')
            if path.suffix == '.json':
                record = json.loads(path.read_text())
                if directory in (journal, reclaim):
                    fields = ('signature', 'messageHash', 'transactionBase64', 'blockhash', 'operation', 'payment', 'payer', 'expectedHeld', 'expectedRefundable')
                    source.require(all(isinstance(record.get(key), str) and record[key] for key in fields)
                                   and record['signature'] == path.stem
                                   and record['operation'] in ('authorize', 'capture', 'void', 'refund', 'reclaim', 'setup'), 'unresolved or malformed dev submission')
                    attempts = record.get('attempts')
                    source.require(isinstance(attempts, list) and attempts and all(
                        a.get('outcome', {}).get('result') in ('not-submitted', 'finalized-succeeded', 'finalized-failed')
                        for a in attempts), 'unresolved dev submission')
                elif directory == operations:
                    source.require(record.get('status') in ('authorize-rejected', 'completed'), 'unresolved dev resource operation')
                else:
                    source.require(record.get('status') in ('draft', 'active', 'closed', 'rejected')
                                   and isinstance(record.get('events'), list)
                                   and all(e.get('status') in ('finalized', 'rejected') for e in record['events']), 'unresolved dev order')
            elif path.name.endswith('.lock'):
                if directory == orders:
                    # Immutable event locks stay prepared forever; the mutable order
                    # must contain the same action/wire and a terminal event instead.
                    event = json.loads(path.read_text())
                    order = json.loads((directory / (path.name.split('.')[0] + '.json')).read_text())
                    source.require(any(e.get('action') == event.get('action') and e.get('transactionBase64') == event.get('transactionBase64')
                                       and e.get('status') in ('finalized', 'rejected') for e in order['events']), 'orphan dev action lock')
                elif directory == reclaim:
                    signature = path.read_text()
                    source.require((directory / (signature + '.json')).is_file(), 'orphan dev reclaim lock')
                else:
                    raise RuntimeError('unexpected dev lock')
            else:
                raise RuntimeError('unknown dev journal member')


def production():
    # Private values never enter the receipt: only a combined integrity digest.
    roots = [Path('/etc/sac006'), Path('/var/lib/sac006'), source.CURRENT, Path('/etc/nginx'), Path('/etc/letsencrypt')]
    services = {}
    for name in (*host.LEGACY_SERVICES, *host.PRODUCT_SERVICES):
        services[name] = {key: source.run('systemctl', 'show', '-p', key, '--value', name)
                          for key in ('MainPID', 'ActiveState', 'FragmentPath')}
        fragment = services[name]['FragmentPath']
        if fragment:
            roots.append(Path(fragment))
        roots.append(UNITS / (name + '.service.d'))
    source.require(any(s['ActiveState'] == 'active' for s in services.values()), 'production baseline unavailable')
    values = {'services': services, 'files': host.inventory(roots)}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def rpc():
    from host_cli import NoRedirect
    record = json.loads((RELEASES / current() / source.RECORD).read_text())
    for role in ('facilitator', 'restaurant'):
        url = host.env_value(PRIVATE / (role + '.env'), 'SOLANA_RPC_URL')
        source.require(url.startswith('https://'), 'dev RPC must use TLS')
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'getGenesisHash'}).encode()
        request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            data = response.read(65537)
        source.require(len(data) <= 65536 and json.loads(data).get('result') == record['network']['genesis_hash'], 'dev RPC identity unavailable')


def health(sha, public=True):
    for name, entry in zip(SERVICES, ('devnet-server.ts', 'restaurant-server.ts')):
        source.require(source.run('systemctl', 'is-active', name) == 'active', 'dev service inactive')
        pid = source.run('systemctl', 'show', '-p', 'MainPID', '--value', name)
        source.require(pid.isdecimal() and int(pid) > 0 and Path(os.readlink('/proc/' + pid + '/cwd')) == RELEASES / sha / 'integration',
                       'dev process source mismatch')
        argv = Path('/proc/' + pid + '/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        source.require(len(argv) == 3 and Path(os.fsdecode(argv[0])).name == 'node'
                       and argv[1:] == [b'--experimental-strip-types', ('src/' + entry).encode()], 'dev process entrypoint mismatch')
    for prefix in (['http://127.0.0.1:18888', ORIGIN] if public else ['http://127.0.0.1:18888']):
        for path, expected in (('/', 200), ('/resource', 402), ('/assets/homepage.css', 200), ('/assets/homepage.js', 200),
                               ('/assets/app.js', 200), ('/assets/style.css', 200), ('/assets/solflare.js', 200)):
            status, body, headers = source.response(prefix + path)
            source.require(status == expected and body, 'dev HTTP readiness failed')
            if path == '/resource':
                source.require(any(k.lower() == 'payment-required' for k in headers), 'dev challenge missing')
        status, body, _ = source.response(prefix + '/api/config')
        config = json.loads(body)
        record = json.loads((RELEASES / sha / source.RECORD).read_text())
        source.require(status == 200 and config.get('configured') is True and config.get('cluster') == 'devnet'
                       and config.get('programId') == record['program']['program_id'], 'dev identity readiness failed')
        env = PRIVATE / 'restaurant.env'
        source.require(all(config.get(field) == host.env_value(env, key) for field, key in (
            ('sponsor', 'SAC006_FEE_PAYER'), ('mint', 'SAC006_ASSET_MINT'))), 'dev signer/mint changed')
        source.require(config.get('merchant') == host.env_value(PRIVATE / 'facilitator.env', 'SAC006_ALLOWLIST_MERCHANT')
                       and config.get('mint') == host.env_value(PRIVATE / 'facilitator.env', 'SAC006_ALLOWLIST_MINT'), 'dev allowlist identity mismatch')


def ready(sha):
    deadline = time.monotonic() + 60
    while True:
        try:
            health(sha)
            return
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            source.require(time.monotonic() < deadline, 'dev readiness exhausted')
            time.sleep(1)


def seal(root):
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory)] + [Path(directory) / n for n in dirs + files]:
            info = path.lstat()
            source.require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), 'special dev release member')
            if stat.S_ISLNK(info.st_mode):
                source.require(path.resolve().is_relative_to(root.resolve()), 'dev dependency symlink escapes release')
            elif stat.S_ISREG(info.st_mode):
                source.require(info.st_nlink == 1, 'dev release hardlink')
    source.chown_tree(root, 0, 0)
    source.seal_runtime_permissions(root)


def release_inventory(root):
    # No release member may be writable by the builder after publishing.
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory)] + [Path(directory) / n for n in dirs + files]:
            info = path.lstat()
            source.require(info.st_uid == 0 and (path.is_symlink() or info.st_mode & 0o022 == 0), 'unsealed dev release')
            if path.is_symlink():
                source.require(path.resolve().is_relative_to(root.resolve()), 'dev release symlink escape')
    return hashlib.sha256(json.dumps(host.inventory([root]), sort_keys=True).encode()).hexdigest()


def verify_archive(tar, tree, api):
    metadata = api('repos/' + policy.REPOSITORY + '/git/trees/' + tree + '?recursive=1')
    source.require(metadata.get('sha') == tree and metadata.get('truncated') is False, 'incomplete dev source tree')
    expected = {}
    for entry in metadata['tree']:
        path = entry['path']
        if path.startswith('integration/') or path == source.RECORD:
            if entry['type'] == 'tree':
                continue
            source.require(entry['type'] == 'blob' and entry['mode'] in ('100644', '100755'), 'unsupported dev Git member')
            expected[path] = entry['sha']
    actual = {}
    with source.bounded_tar(tar, 'r:') as archive:
        for member in archive:
            if member.isdir():
                continue
            source.require(member.isfile(), 'unsupported dev archive member')
            data = archive.extractfile(member).read()
            actual[member.name] = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    source.require(expected and actual == expected, 'dev archive differs from approved Git blobs')


def stage(sha, acceptance, api):
    user = pwd.getpwnam('capture402-deploy')
    ssh = source.source_ssh_command(user)
    with tempfile.TemporaryDirectory(prefix='.source-', dir=RELEASES) as temporary:
        work = Path(temporary)
        os.chown(work, user.pw_uid, user.pw_gid)
        repo = work / 'repository'
        command = ('runuser', '-u', user.pw_name, '--', '/usr/bin/env', '-i', 'HOME=' + user.pw_dir,
                   'PATH=/usr/bin:/bin', 'GIT_TERMINAL_PROMPT=0', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                   '/usr/bin/git', '-c', 'credential.helper=', '-c', 'core.sshCommand=' + ssh)
        source.run(*command, 'clone', '--depth=1', '--single-branch', '--no-checkout', '--branch=' + acceptance['branch'],
                   source.SOURCE_REMOTE, str(repo), timeout=180)
        source.require(source.run(*command, '-C', str(repo), 'rev-parse', 'HEAD') == sha
                       and source.run(*command, '-C', str(repo), 'rev-parse', 'HEAD^{tree}') == acceptance['tree'], 'dev Git source differs from approval')
        tar = source.git_archive(repo, sha)
        source.require(0 < len(tar) <= source.MAX_TAR_STREAM, 'dev source archive too large')
        source.archive_fingerprints(tar, 'r:')
        verify_archive(tar, acceptance['tree'], api)
        blob = gzip.compress(tar, mtime=0)
        source.require(len(blob) <= source.MAX_ARCHIVE, 'dev compressed source too large')
        digest = hashlib.sha256(blob).hexdigest()
    target = RELEASES / sha
    manifest = BASE / 'manifests' / (sha + '.json')
    if target.exists():
        trusted(target, True)
        trusted(manifest)
        receipt = json.loads(manifest.read_text())
        source.require(receipt['archiveSha256'] == digest and receipt['sha'] == sha
                       and receipt['inventory'] == release_inventory(target), 'immutable dev release changed')
        return
    build = Path(tempfile.mkdtemp(prefix='.candidate-', dir=RELEASES))
    try:
        source.unpack_archive(blob, build)
        source.require((build / source.RECORD).read_bytes() == (RELEASES / current() / source.RECORD).read_bytes(), 'dev release changes accepted program identity')
        builder = user
        source.require(builder.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'), 'dev builder must be a noninteractive deployment account')
        source.chown_tree(build, builder.pw_uid, builder.pw_gid)
        build.chmod(0o700)
        # No branch code executes as root; build cannot read either environment's secrets.
        source.run('systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                   '--unit=capture402-dev-build-' + str(time.time_ns()),
                   '-p', 'User=capture402-deploy', '-p', 'NoNewPrivileges=true', '-p', 'CapabilityBoundingSet=',
                   '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=true', '-p', 'PrivateTmp=true',
                   '-p', 'InaccessiblePaths=/etc/sac006 /var/lib/sac006 /opt/capture402 /opt/svm-auth-capture /etc/capture402-dev /var/lib/capture402-dev',
                   '-p', 'ReadWritePaths=' + str(build), '-p', 'MemoryMax=512M', '-p', 'CPUQuota=50%',
                   '-p', 'TasksMax=64', '-p', 'RuntimeMaxSec=240', '-p', 'WorkingDirectory=' + str(build / 'integration'),
                   '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/tmp',
                   'npm', 'ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', timeout=270)
        seal(build)
        os.rename(build, target)
        sync(RELEASES)
        source.write_json(manifest, {'sha': sha, 'archiveSha256': digest, 'inventory': release_inventory(target)})
    finally:
        if build.exists():
            shutil.rmtree(build)


def install_gate():
    for name in SERVICES:
        directory = UNITS / (name + '.service.d')
        if not directory.exists():
            directory.mkdir(mode=0o755)
        trusted(directory, True)
        gate = directory / '90-dev-deployment.conf'
        content = b'[Service]\nExecCondition=+/usr/local/sbin/capture402 dev gate\n'
        if gate.exists():
            trusted(gate)
            source.require(gate.read_bytes() == content, 'dev boot gate differs; operator enrollment required')
        else:
            host.atomic_bytes(gate, content)
    source.run('systemctl', 'daemon-reload')


def gate():
    if not PENDING.exists():
        return
    trusted(PERMIT)
    source.require(PERMIT.read_text() == current(), 'pending dev deployment blocks service startup')


def start(sha):
    host.atomic_bytes(PERMIT, sha.encode(), 0o600)
    try:
        for name in SERVICES:
            # Inactive units can be garbage-collected; reset-failed rejects an
            # unloaded unit even though its installed fragment is valid.
            if source.run('systemctl', 'show', '-p', 'ActiveState', '--value', name) == 'failed':
                source.run('systemctl', 'reset-failed', name)
            source.run('systemctl', 'start', name)
        ready(sha)
    finally:
        host.durable_remove(PERMIT)


@contextmanager
def locked():
    trusted(BASE, True)
    trusted(RELEASES, True)
    trusted(BASE.parent, True)
    path = BASE / 'deploy.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        source.require(os.fstat(fd).st_uid == os.geteuid() and os.fstat(fd).st_mode & 0o077 == 0, 'unsafe dev lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def rollback(record):
    # A newly running candidate may have accepted a payment. Never interrupt it
    # on a blind rollback; retain the transaction and require original reconciliation.
    running = [name for name in SERVICES if source.run('systemctl', 'show', '-p', 'MainPID', '--value', name) != '0']
    if running:
        try:
            for name in running:
                source.run('systemctl', 'freeze', name)
            clean_operations()
            stop(running)
        except Exception:
            for name in running:
                source.run('systemctl', 'thaw', name)
            raise
    clean_operations()
    switch(record['previous'])
    start(record['previous'])
    source.require(production() == record['production'], 'production baseline changed')
    source.write_json(BASE / 'last-result.json', {'verdict': 'ROLLED_BACK', 'sha': record['previous'], 'target': record['target']})
    host.durable_remove(PENDING)


def recover():
    if not PENDING.exists():
        return False
    trusted(PENDING)
    record = json.loads(PENDING.read_text())
    source.require(source.SHA_RE.fullmatch(record['previous']) and source.SHA_RE.fullmatch(record['target']), 'invalid dev recovery record')
    host.durable_remove(PERMIT)
    if record['stage'] == 'freezing' and current() == record['previous']:
        running = [name for name in SERVICES if source.run('systemctl', 'show', '-p', 'MainPID', '--value', name) != '0']
        for name in running:
            source.run('systemctl', 'thaw', name)
        if len(running) != len(SERVICES):
            # Reboot may have blocked both units before any deployment stop.
            # Start the same old code; existing journals still block payment replay.
            start(record['previous'])
        source.write_json(BASE / 'last-result.json', {'verdict': 'RECOVERED_PRE_STOP', 'sha': record['previous'], 'target': record['target']})
        host.durable_remove(PENDING)
    else:
        rollback(record)
    return True


def deploy(sha, api):
    with locked():
        if recover():
            raise RuntimeError('dev recovered offline; explicitly invoke deploy again')
        previous = current()
        units()
        health(previous)
        baseline = production()
        clean_operations()
        private_digest = hashlib.sha256(json.dumps(host.inventory([PRIVATE]), sort_keys=True).encode()).hexdigest()
        rpc()
        acceptance = policy.verify_dev(sha, api)
        for directory in (BASE / 'manifests',):
            if not directory.exists():
                directory.mkdir(mode=0o755)
            trusted(directory, True)
        stage(sha, acceptance, api)
        # Fresh metadata client/deadline after a potentially long dependency install.
        from host_cli import GitHub
        fresh = policy.verify_dev(sha, GitHub())
        source.require(all(fresh[k] == acceptance[k] for k in ('sha', 'tree', 'branch', 'reviewedHead')), 'dev acceptance changed')
        rpc()
        health(previous)
        source.require(production() == baseline, 'production changed during preparation')
        source.require(hashlib.sha256(json.dumps(host.inventory([PRIVATE]), sort_keys=True).encode()).hexdigest() == private_digest, 'dev configuration changed during preparation')
        source.write_json(BASE / 'manifests' / (sha + '.approval.json'), fresh)
        if previous == sha:
            source.write_json(BASE / 'last-result.json', {'verdict': 'ALREADY_CURRENT', 'sha': sha, 'productionUnchanged': True})
            return
        install_gate()
        record = {'previous': previous, 'target': sha, 'production': baseline, 'stage': 'freezing'}
        source.write_json(PENDING, record)
        try:
            freeze()
            clean_operations()
        except BaseException:
            thaw()
            host.durable_remove(PENDING)
            raise
        record['stage'] = 'stopping'
        source.write_json(PENDING, record)
        try:
            stop()
            clean_operations()
            switch(sha)
            start(sha)
            source.require(production() == baseline, 'production changed during dev cutover')
            source.write_json(BASE / 'last-result.json', {'verdict': 'DEPLOYED', 'sha': sha, 'previous': previous,
                                                       'productionUnchanged': True, 'ciRun': fresh['ciRun']})
            host.durable_remove(PENDING)
        except BaseException as error:
            source.write_json(BASE / 'last-failure.json', {'target': sha, 'stage': record['stage'], 'errorType': type(error).__name__})
            try:
                rollback(record)
            except BaseException:
                raise RuntimeError('DEV_ROLLBACK_UNVERIFIED: retained transaction; reconcile originals before recovery') from None
            raise RuntimeError('DEV_DEPLOY_FAILED: previous code restored; inspect sanitized receipt') from None


def dispatch(argv):
    source.require(os.geteuid() == 0, 'dev deployment requires authorized local sudo')
    if len(argv) == 2 and argv[0] == 'deploy' and source.SHA_RE.fullmatch(argv[1]):
        with locked():
            if recover():
                raise RuntimeError('dev recovered offline; explicitly invoke deploy again')
        controller = str(Path(__file__).resolve())
        unit = 'capture402-dev-release-' + argv[1][:12] + '-' + str(time.time_ns())
        print('Dev deployment job: ' + unit, flush=True)
        result = subprocess.run(['systemd-run', '--unit=' + unit, '--wait', '--property=Type=exec',
            '--property=UMask=0077', '--property=RuntimeMaxSec=900',
            '--property=ExecStopPost=/usr/bin/python3 -B ' + controller + ' recover',
            '/usr/bin/python3', '-B', controller, *argv])
        source.require(result.returncode == 0, 'dev deployment failed; inspect dev status and retained job')
    else:
        main(argv)


def main(argv):
    source.require(os.geteuid() == 0, 'dev deployment requires authorized local sudo')
    if argv == ['gate']:
        gate()
        return
    if argv == ['recover']:
        with locked():
            print('RECOVERED' if recover() else 'NO_PENDING')
        return
    if argv == ['status']:
        print(json.dumps({'current': current(), 'pending': PENDING.exists(),
                          'lastResult': json.loads((BASE / 'last-result.json').read_text()) if (BASE / 'last-result.json').exists() else None}))
        return
    source.require(len(argv) == 2 and argv[0] == 'deploy' and source.SHA_RE.fullmatch(argv[1]), 'usage: capture402 dev deploy <40-hex-sha>|status|recover')
    from host_cli import GitHub
    # No metadata access before retained offline recovery.
    with locked():
        if recover():
            raise RuntimeError('dev recovered offline; explicitly invoke deploy again')
    deploy(argv[1], GitHub())


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except BaseException:
        # RPC URLs, subprocess output and private journal content stay private.
        print('DEV_DEPLOY_BLOCKED: inspect dev receipts and retained transaction', file=sys.stderr)
        sys.exit(1)
