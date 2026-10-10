#!/usr/bin/env python3
"""Prepare sealed, key-free B2 runtime roots; operator invocation only."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import quarantine as q

CONTROLLER_ROOT = Path(__file__).resolve().parent


def copy_regular(src, dst):
    raw, _ = q.read(src, 128 * 1024 * 1024, owner=0, allow_empty=True)
    dst.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    q.exclusive(dst, raw, 0o555 if src.stat().st_mode & 0o111 else 0o444)


def node_runtime(dst):
    # Trusted OS installation is an input to the pinned runtime, not a floating lookup at start.
    node = Path('/usr/local/bin/node').resolve(strict=True)
    q.require(node.name == 'node' and node.stat().st_uid == 0)
    copy_regular(node, dst / 'usr/bin/node')
    copy_regular(Path('/usr/bin/env'), dst / 'usr/bin/env')
    result = q.run('ldd', str(node))
    libs = set(re.findall(r'(/[^\s()]+)', result))
    q.require(libs)
    for lib in libs:
        p = Path(lib).resolve(strict=True)
        q.require(p.is_file() and p.stat().st_uid == 0)
        copy_regular(p, dst / lib.lstrip('/'))
    (dst / 'run/ingress').mkdir(parents=True, mode=0o755)
    (dst / 'tmp').mkdir(mode=0o755)
    # systemd may otherwise create usr-merge compatibility links/mountpoints at
    # first exec. Precreate directories so the sealed tree remains unchanged.
    for name in ('bin', 'dev', 'proc', 'sys', 'etc', 'root', 'home'):
        (dst / name).mkdir(mode=0o755)
    for p in (dst, dst / 'usr', dst / 'usr/bin', dst / 'run', dst / 'tmp'):
        q.fsync_dir(p)


def prepare(request):
    q.shape(request, ('candidate', 'previous', 'selected', 'public', 'ownerDisposition', 'merchantHash', 'operatorHash'))
    for name in ('candidate', 'previous'):
        q.require(re.fullmatch('[a-f0-9]{40}', request[name]))
    q.require(request['ownerDisposition'] == 'ACCEPTED_CONTINUED_OUTAGE_AND_INERT_ROLLBACK')
    q.require(all(re.fullmatch('[a-f0-9]{64}', request[k]) for k in ('merchantHash', 'operatorHash')) and request['merchantHash'] != request['operatorHash'])
    release = q.BASE / 'releases' / request['candidate']
    previous = q.BASE / 'releases' / request['previous']
    q.require(release.is_dir() and previous.is_dir() and not release.is_symlink() and not previous.is_symlink())
    identity_path = Path('docs/evidence/sac-007/deployment-identity.v1.json')
    identity_raw = q.read(release / identity_path, owner=0)[0]
    q.require(identity_raw == q.read(previous / identity_path, owner=0)[0])
    identity = q.strict_json(identity_raw)
    q.require(identity.get('record_status') == 'verified' and request['public'] == dict(network=identity['network']['caip2'], genesisHash=identity['network']['genesis_hash'], programId=identity['program']['program_id']))
    # Application archives intentionally do not carry ops code. D* is the
    # independently authenticated immutable controller directory, not C*.
    q.require(re.fullmatch('[a-f0-9]{40}', CONTROLLER_ROOT.name))
    q.require(q.read(CONTROLLER_ROOT / 'quarantine.py', owner=0)[0] == q.read(q.GUARD, owner=0)[0])
    root = q.BASE / 'views' / request['candidate']
    projector = q.BASE / 'projectors' / request['candidate']
    q.require(not q.exists(root) and not q.exists(projector))
    for p in (root, projector):
        p.mkdir(parents=True, mode=0o755)
        node_runtime(p)
    for name in ('quarantine-server.ts', 'quarantine-view.ts'):
        copy_regular(release / 'integration/src' / name, root / 'app' / name)
    for name in ('quarantine.css', 'quarantine.js'):
        copy_regular(release / 'integration/web/quarantine' / name, root / 'app' / name)
    q.exclusive(root / 'app/auth.json', q.encoded({k: request[k] for k in ('merchantHash', 'operatorHash')}), 0o444)
    for name in ('quarantine-projector.ts', 'quarantine-view.ts', 'program.ts'):
        copy_regular(release / 'integration/src' / name, projector / 'app' / name)
    copy_regular(release / 'integration/package.json', projector / 'app/package.json')
    modules = release / 'integration/node_modules'
    # Flatten only in-tree symlinks; runtime tree contains no symlink or writable node.
    for directory, dirs, files in os.walk(modules, followlinks=True):
        for name in files:
            src = Path(directory) / name
            real = src.resolve(strict=True)
            q.require(real.is_relative_to(modules.resolve()) and real.is_file())
            copy_regular(real, projector / 'app/node_modules' / src.relative_to(modules))
    inv = q.tree(root)
    e = dict(version=1, uids=[__import__('pwd').getpwnam(n).pw_uid for n in
                            ('capture402-dev-setup', *q.SERVICES, 'capture402-deploy')],
             guardSha256=q.digest(q.read(q.GUARD, owner=0)[0]), activation={},
             selected=request['selected'], public=request['public'], ownerDisposition=request['ownerDisposition'],
             viewerRoot=str(root), viewerInventory=inv)
    e['tuple'] = dict(candidate=request['candidate'], previous=request['previous'], controllerRevision=CONTROLLER_ROOT.name,
        controller=q.digest(b''.join(q.read(CONTROLLER_ROOT / n, owner=0)[0] for n in
                        ('deploy_dev.py', 'host_cli.py', 'quarantine.py', 'quarantine_prepare.py'))),
        guard=e['guardSha256'], validator=q.digest(q.read(projector / 'app/quarantine-projector.ts', owner=0)[0]),
        codecs=q.digest(q.read(projector / 'app/program.ts', owner=0)[0]),
        dependencies=q.digest(q.read(release / 'integration/package-lock.json', owner=0)[0]),
        build=q.digest(q.encoded(inv)), unit='0' * 64, routing='0' * 64,
        configuration=q.configuration(),
        projectionRuntime=q.digest(q.encoded(q.tree(projector))))
    e['tuple']['unit'] = q.digest(q.viewer_unit(e).encode())
    # Ingress config uses only an exact route/method allowlist, and the private socket.
    routing = routing_config().encode()
    e['tuple']['routing'] = q.digest(routing)
    return e, routing


def routing_config():
    return '''# B2 dev ingress fragment. Include inside the existing private dev server.
# The existing tester source-IP allowlist and TLS remain required.
if (-f /opt/capture402-dev/read-only-maintenance) { return 503; }
if ($request_method != GET) { return 403; }
proxy_set_header Host $host;
proxy_set_header Connection "";
proxy_http_version 1.1;
proxy_buffering off;
proxy_next_upstream off;
location = / { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location = /customer { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location = /merchant { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location = /assets/quarantine.css { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location = /assets/quarantine.js { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location = /api/config { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location = /api/quarantine/status { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location ~ "^/api/orders/[a-f0-9]{32}(/actions/(beer|salmon|finish|void|refund))?$" { proxy_pass http://unix:/run/capture402-dev-view/view.sock; }
location / { return 403; }
'''


def bootstrap(request):
    q.require(os.geteuid() == 0 and not q.exists(q.ROOT) and not q.exists(q.GUARD))
    q.require(not q.exists(q.BASE / 'transaction.json') and not q.exists(q.BASE / 'pending.json'))
    # Refuse unsupported enrollment before installing any exception. Existing A stays effective.
    require_users = ('capture402-dev-setup', *q.SERVICES, 'capture402-deploy')
    for name in require_users:
        user = __import__('pwd').getpwnam(name)
        q.require(user.pw_shell in ('/usr/sbin/nologin', '/bin/false'))
    q.require('include /etc/capture402-dev/nginx-routes.conf;' in q.run('nginx', '-T'))
    prefix = '/' + str(q.CGROUP.relative_to('/sys/fs/cgroup'))
    processes = q.uid_processes({__import__('pwd').getpwnam(n).pw_uid for n in require_users})
    q.require(all(v == prefix or v.startswith(prefix + '/') for v in processes.values()))
    q.private_capabilities({__import__('pwd').getpwnam(n).pw_uid for n in require_users})
    ingress = Path('/run/capture402-dev-view')
    s = ingress.lstat(); user = __import__('pwd').getpwnam(q.SERVICES[1])
    q.require(ingress.is_dir() and not ingress.is_symlink() and s.st_uid == user.pw_uid and s.st_gid == user.pw_gid and s.st_mode & 0o777 == 0o750)
    # Source copied as immutable independent guard, never changed by controller install.
    q.GUARD.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    q.exclusive(q.GUARD, Path(q.__file__).read_bytes(), 0o555)
    e, routing = prepare(request)
    q.ROOT.mkdir(mode=0o700)
    q.fsync_dir(q.ROOT.parent)
    for name in q.SERVICES:
        drop = q.UNITS / (name + '.service.d')
        drop.mkdir(mode=0o755, exist_ok=True)
        q.exclusive(drop / '95-independent-admission.conf',
                    ('[Unit]\nConditionPathExists=!' + str(q.ROOT / 'ECONOMICS_DENIED') + '\n[Service]\nExecCondition=+/usr/bin/python3 -I -B ' + str(q.GUARD) + ' economic\n').encode(), 0o644)
    q.exclusive(q.ROOT / 'routing.conf', routing, 0o600)
    q.run('systemctl', 'daemon-reload')
    e['activation'] = q.activation_inventory(e)
    q.exclusive(q.ROOT / 'enrollment.json', q.encoded(e))
    q.LinuxHost(q.enrollment()).verify()
    return e


def offline_projector(e):
    def project(stores, inv):
        runtime = q.BASE / 'projectors' / e['tuple']['candidate']
        q.require(q.digest(q.encoded(q.tree(runtime))) == e['tuple']['projectionRuntime'])
        payload = dict(stores=stores, selected=e['selected'], **e['public'], viewerSha=e['tuple']['candidate'],
                       inventorySha256=q.digest(q.encoded(inv)), tupleSha256=q.digest(q.encoded(e['tuple'])),
                       snapshotAt=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'))
        # stdio only; no host paths, capabilities, environment, sockets or RPC in the child.
        result = subprocess.run(['systemd-run', '--quiet', '--pipe', '--wait', '--collect',
            '--unit=capture402-b2-offline-projector', '-p', 'User=nobody', '-p', 'Group=nogroup',
            '-p', 'RootDirectory=' + str(runtime), '-p', 'WorkingDirectory=/app',
            '-p', 'PrivateNetwork=yes', '-p', 'RestrictAddressFamilies=AF_UNIX',
            '-p', 'SystemCallFilter=~@network-io @mount @privileged', '-p', 'NoNewPrivileges=yes',
            '-p', 'CapabilityBoundingSet=', '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=yes',
            '-p', 'RestrictNamespaces=yes', '-p', 'PrivateDevices=yes', '-p', 'MountAPIVFS=no',
            '-p', 'RuntimeMaxSec=60', '-p', 'MemoryMax=512M', '-p', 'TasksMax=32',
            '/usr/bin/env', '-i', 'PATH=/usr/bin', 'LANG=C', '/usr/bin/node', '--experimental-strip-types', '/app/quarantine-projector.ts'],
            input=q.encoded(payload), capture_output=True, timeout=90)
        q.require(result.returncode == 0 and 0 < len(result.stdout) < 16 * 1024 * 1024)
        p = q.strict_json(result.stdout)
        q.require(p['mode'] == 'READ_ONLY_QUARANTINE' and p['viewerSha'] == e['tuple']['candidate'] and p['inventorySha256'] == payload['inventorySha256'] and p['tupleSha256'] == payload['tupleSha256'])
        q.require(q.digest(q.encoded(q.tree(runtime))) == e['tuple']['projectionRuntime'])
        return result.stdout
    return project


def control(argv):
    q.require(os.geteuid() == 0)
    if len(argv) == 2 and argv[0] == 'bootstrap':
        request = q.strict_json(q.read(Path(argv[1]), owner=0)[0])
        # Preserve normal release eligibility. No draft/unmerged/force flag exists.
        import host_cli, release_policy, deploy_dev
        accepted = release_policy.verify_dev(request['candidate'], host_cli.GitHub())
        release_policy.verify_dev(CONTROLLER_ROOT.name, host_cli.GitHub())
        deploy_dev.units()
        q.configuration()
        for name, entry in zip(q.SERVICES, ('devnet-server.ts', 'restaurant-server.ts')):
            command = q.run('systemctl', 'show', '-p', 'ExecStart', '--value', name)
            q.require(command.count('path=') == 1 and 'path=/usr/bin/env ; argv[]=/usr/bin/env node --experimental-strip-types src/' + entry + ' ;' in command)
            q.require(q.run('systemctl', 'show', '-p', 'EnvironmentFiles', '--value', name) == str(q.PRIVATE / (('facilitator' if name == q.SERVICES[0] else 'restaurant') + '.env')) + ' (ignore_errors=no)')
            q.require(q.run('systemctl', 'show', '-p', 'Environment', '--value', name) == 'PATH=/usr/local/bin:/usr/bin:/bin')
        deploy_dev.stage(request['candidate'], accepted, host_cli.GitHub())
        bootstrap(request)
        return {'mode': 'A', 'enrollment': 'verified', 'economicsException': False}
    if argv == ['status']:
        q.require(q.exists(q.ROOT))
        try:
            e = q.enrollment()
            h = q.journal_phase(q.ROOT)
            return {'mode': 'ECONOMICS_DENIED' if q.exists(q.ROOT / 'ECONOMICS_DENIED') else 'A',
                    'phase': h[-1]['phase'] if h else 'NOT_ENTERED', 'tuple': e['tuple'],
                    'evidence': 'retained; no outcome application', 'economicCapabilities': False}
        except Exception:
            return {'mode': 'ADMISSION_DENIED', 'phase': 'UNAVAILABLE', 'economicCapabilities': False}
    q.require(argv and argv[0] in ('enter', 'recover', 'rollback', 'view-start'))
    try:
        e = q.enrollment()
    except BaseException:
        q.emergency_stop()
        raise
    q.require(len(argv) == 1 or argv[0] == 'enter' and len(argv) == 2 and argv[1] == e['tuple']['candidate'])
    import deploy_dev
    attempt = deploy_dev.Attempt.create(e['tuple']['candidate'])
    attempt.step('quarantine')
    try:
        with q.locked():
            host = q.LinuxHost(e)
            transition = q.Transition(q.ROOT, host, e, offline_projector(e))
            if argv[0] == 'enter':
                q.require(len(argv) == 2)
                import host_cli, release_policy
                release_policy.verify_dev(argv[1], host_cli.GitHub())
                transition.enter()
                host.open_view_ingress()
                result = {'mode': 'READ_ONLY_QUARANTINE', 'viewerSha': argv[1], 'economics': 'DENIED'}
            elif argv[0] == 'recover':
                result = transition.recover()
            elif argv[0] == 'rollback':
                result = transition.rollback()
            else:
                host.close()
                host.fence()
                host.stop()
                host.verify(stopped=True)
                host.start_view()
                host.open_view_ingress()
                result = {'mode': 'READ_ONLY_QUARANTINE', 'viewerSha': e['tuple']['candidate'], 'economics': 'DENIED'}
        attempt.finish('QUARANTINED')
        return result
    except BaseException:
        if q.exists(q.ROOT / 'ECONOMICS_DENIED'):
            q.emergency_stop()
        attempt.finish('FAILED')
        raise
