#!/usr/bin/env python3
"""Marked disposable VM only: rendered E2E units with synthetic daemons/state.

No RPC, real signers, deployment or payment engine. Production ExecStart alone is
substituted by a fixture drop-in. Permission/routing/boot evidence is real Linux;
operator preflight is modeled by tests, not a newly installed release controller.
"""
import hashlib
import http.client as http_client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import shutil
import ssl
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import dev_environment as env
import deploy_dev as legacy

ROOT = Path('/opt/capture402-e2e-disposable')
PRIVATE = Path('/etc/capture402-e2e')
STATE = Path('/var/lib/capture402-e2e')
BASE = Path('/opt/capture402-e2e')
UNITS = Path('/etc/systemd/system')
NAMES = ['capture402-e2e-facilitator', 'capture402-e2e-restaurant']
OLD = ['capture402-fixture-stable', 'capture402-dev-facilitator', 'capture402-dev-restaurant']
OLD_ROOTS = [Path(p) for p in ['/etc/sac006', '/var/lib/sac006', '/opt/capture402', '/opt/svm-auth-capture', '/etc/capture402-dev', '/var/lib/capture402-dev', '/opt/capture402-dev', '/home/capture402-dev']]
ORIGIN = 'https://e2e.capture402.xyz'
RESULTS = []


def run(*args, ok=True, timeout=15):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if ok and p.returncode:
        raise RuntimeError('command failed: ' + ' '.join(args[:3]) + ': ' + p.stderr[:500])
    return p.stdout.strip() if ok else p


def require(value, message='assertion failed'):
    if not value: raise RuntimeError(message)


def record(name, action):
    try:
        action(); RESULTS.append({'name': name, 'result': 'PASS', 'harnessSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    except Exception:
        RESULTS.append({'name': name, 'result': 'FAIL'}); save(); raise
    save(); print('PASS ' + name, flush=True)


def save():
    report = {'tests': RESULTS, 'counts': {s: sum(t['result'] == s for t in RESULTS) for s in ['PASS', 'FAIL']},
              'source': json.loads((ROOT/'identity.json').read_text()),
              'host': {'os': run('uname', '-sr'), 'systemd': run('systemctl', '--version').splitlines()[0],
                       'nginx': run('nginx', '-v', ok=False).stderr.strip(), 'cgroup': run('stat', '-fc', '%T', '/sys/fs/cgroup')}}
    (ROOT/'results.json').write_text(json.dumps(report, indent=2)+'\n')


def failed(action):
    try: action()
    except Exception: return
    raise RuntimeError('expected fail-closed refusal')


def write(path, content, mode=0o644, owner=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content); path.chmod(mode)
    if owner:
        uid = pwd.getpwnam(owner).pw_uid; os.chown(path, uid, pwd.getpwnam(owner).pw_gid)


def inventory(roots):
    result = {}
    for root in roots:
        for p in [root, *sorted(root.rglob('*'))]:
            s = p.lstat()
            result[str(p)] = {'uid': s.st_uid, 'gid': s.st_gid, 'mode': s.st_mode, 'inode': s.st_ino,
                              'value': os.readlink(p) if p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None}
    return result


def daemon(role):
    user = pwd.getpwuid(os.getuid()).pw_name
    port = int(os.environ['E2E_FIXTURE_PORT'])
    state = Path(os.environ['E2E_FIXTURE_STATE'])
    if (ROOT/'fail-readiness').exists() and role == 'restaurant': raise RuntimeError('injected startup failure')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def reply(self, code, value):
            self.send_response(code); self.end_headers(); self.wfile.write(json.dumps(value).encode())
        def do_GET(self):
            url = urlparse(self.path)
            if url.path == '/_identity':
                return self.reply(200, {'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(),
                    'user': user, 'cwd': os.getcwd(), 'cgroup': Path('/proc/self/cgroup').read_text().strip()})
            if url.path == '/_probe':
                q = parse_qs(url.query); p = Path(q['path'][0]); allowed = False
                try:
                    if q['access'][0] == 'r': p.read_bytes()
                    elif q['access'][0] == 'w':
                        with p.open('r+b'): pass  # Do not modify the marker when probing write.
                    elif q['access'][0] == 'x': list(p.iterdir())
                    allowed = True
                except OSError: pass
                return self.reply(200, {'allowed': allowed})
            if url.path == '/resource': return self.reply(402, {'discovery': 'synthetic'})
            return self.reply(200, {'fixture': True})
        def do_POST(self):
            if self.headers.get('Origin') != ORIGIN: return self.reply(403, {})
            if self.headers.get('Authorization') != 'Bearer ' + os.environ['E2E_FIXTURE_BEARER']: return self.reply(401, {})
            lock = state/'original.lock'
            try:
                with lock.open('x') as f: f.write('SYNTHETIC_ORIGINAL_RESERVATION')
            except FileExistsError: return self.reply(409, {})
            count = state/'submissions'; count.write_text(str(int(count.read_text())+1) if count.exists() else '1')
            if self.headers.get('X-Fixture-Lost-Response'): self.connection.shutdown(2); self.connection.close(); return
            return self.reply(202, {'host': self.headers.get('Host'), 'origin': self.headers.get('Origin')})
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()


def http(path='/', method='GET', headers=None, direct=None, denied=False):
    port = direct or 28968
    connection = http_client.HTTPConnection('127.0.0.1', port, timeout=3) if direct else http_client.HTTPSConnection(
        '127.0.0.1', port, context=ssl._create_unverified_context(), timeout=3,
        source_address=('127.0.0.2', 0) if denied else None)
    try:
        connection.request(method, path, headers={'Host': 'e2e.capture402.xyz', **(headers or {})})
        response = connection.getresponse(); data = response.read()
        return response.status, json.loads(data) if data.startswith(b'{') else None
    finally: connection.close()


def wait_ready(port):
    for _ in range(100):
        try:
            if http('/_identity', direct=port)[0] == 200: return
        except OSError: pass
        time.sleep(.05)
    raise RuntimeError('synthetic daemon readiness timeout')


def ingress(opened):
    write(ROOT/'ingress.conf', 'include '+str(ROOT/'rendered/nginx-routes.conf')+';\n' if opened else 'location / { return 503; }\n')
    run('nginx', '-t', '-p', str(ROOT)+'/', '-c', str(ROOT/'nginx.conf'))
    run('systemctl', 'reload', 'capture402-e2e-fixture-nginx')
    time.sleep(.1)


def state_paths():
    return [STATE/'facilitator/journal', STATE/'restaurant/operation-store', STATE/'restaurant/reclaim', STATE/'restaurant/operation-store-restaurant']


def operator_preflight():
    """Exercise the runbook boundary; not production deployment automation."""
    files = env.render('e2e.capture402.xyz', profile='e2e')
    for role, name in zip(['facilitator', 'restaurant'], NAMES):
        require((UNITS/(name+'.service')).read_text() == files[name+'.service'], 'wrong/stale unit identity')
        values = dict(line.split('=', 1) for line in (PRIVATE/(role+'.env')).read_text().splitlines() if '=' in line and not line.startswith('#'))
        require(values['SAC006_HOST'] == '127.0.0.1', 'wrong listener host')
        require(values['SAC006_PORT' if role == 'facilitator' else 'SAC006_RESOURCE_PORT'] == ('28887' if role == 'facilitator' else '28888'), 'stale listener port')
        if role == 'restaurant':
            require(values['SAC006_FACILITATOR_URL'] == 'http://127.0.0.1:28887' and values['SAC006_PUBLIC_ORIGIN'] == ORIGIN, 'cross-environment route')
        expected = pwd.getpwnam(name)
        require(run('id', '-Gn', name).split() == ['capture402-e2e-runtime'], 'extra runtime group')
        key = PRIVATE/'keys'/('sponsor.json' if role == 'facilitator' else 'merchant.json')
        s = key.lstat()
        require(not key.is_symlink() and s.st_nlink == 1 and s.st_uid == expected.pw_uid and s.st_mode & 0o777 == 0o600, 'unsafe signer path or permissions')
        require(len(run('getfacl', '-cp', str(key)).splitlines()) == 3, 'extended signer ACL')
    require(len({(PRIVATE/'keys'/(n+'.json')).read_bytes() for n in ['sponsor', 'merchant', 'payer', 'mint']}) == 4, 'reused signer/mint identity')
    with patch.object(legacy, 'PRIVATE', PRIVATE), patch.object(legacy, 'STATE', STATE):
        legacy.clean_operations()  # Existing ordinary refusal, with synthetic E2E roots only.


def prepare():
    require(all(not p.exists() for p in [BASE, PRIVATE, STATE, *OLD_ROOTS]), 'VM is not fresh; no overwrite/reset')
    files = env.render('e2e.capture402.xyz', profile='e2e'); env.verify_layout(files, profile='e2e')
    env.write_assets(ROOT/'rendered', files)
    for name in OLD:
        run('useradd', '--system', '--user-group', '--shell', '/usr/sbin/nologin', name)
    run('groupadd', '--system', 'capture402-e2e-runtime')
    for name in NAMES:
        run('useradd', '--system', '--no-create-home', '--gid', 'capture402-e2e-runtime', '--shell', '/usr/sbin/nologin', name)
    for p in OLD_ROOTS:
        p.mkdir(parents=True); p.chmod(0o700); os.chown(p, pwd.getpwnam(OLD[0] if 'sac006' in str(p) or str(p) in ['/opt/capture402', '/opt/svm-auth-capture'] else OLD[1]).pw_uid, 0)
        write(p/'retained.marker', 'SYNTHETIC_LEGACY_UNKNOWN_UNRESOLVED\n', 0o600)
    for p in [BASE/'releases/candidate/integration', BASE/'releases/previous/integration', PRIVATE/'keys', STATE/'facilitator', STATE/'restaurant']:
        p.mkdir(parents=True)
    for p in [PRIVATE, PRIVATE/'keys']:
        p.chmod(0o750); os.chown(p, 0, pwd.getpwnam(NAMES[0]).pw_gid)
    for role, name in zip(['facilitator', 'restaurant'], NAMES):
        directory = STATE/role; directory.chmod(0o700); os.chown(directory, pwd.getpwnam(name).pw_uid, pwd.getpwnam(name).pw_gid)
    for p in state_paths():
        p.mkdir(); p.chmod(0o700); owner = NAMES[0] if 'facilitator' in str(p) else NAMES[1]; os.chown(p, pwd.getpwnam(owner).pw_uid, pwd.getpwnam(owner).pw_gid)
    for n, owner in [('sponsor', NAMES[0]), ('merchant', NAMES[1]), ('payer', None), ('mint', None)]:
        write(PRIVATE/'keys'/(n+'.json'), 'SYNTHETIC_'+n, 0o600, owner)
    (BASE/'current').symlink_to(BASE/'releases/candidate')
    for role, name, port in [('facilitator', NAMES[0], 28887), ('restaurant', NAMES[1], 28888)]:
        text = files[role+'.env.example'] + f'\nE2E_FIXTURE_PORT={port}\nE2E_FIXTURE_STATE={STATE/role}\nE2E_FIXTURE_BEARER=synthetic-fixture-only\n'
        write(PRIVATE/(role+'.env'), text, 0o600)
        write(UNITS/(name+'.service'), files[name+'.service'])
        write(UNITS/(name+'.service.d/fixture.conf'), '[Service]\nExecStart=\nExecStart=/usr/bin/python3 -B '+str(Path(__file__).resolve())+' --daemon '+role+'\n')
    write(UNITS/'capture402-e2e.slice', files['capture402-e2e.slice'])
    # Existing ordinary dev boot guard refuses an interrupted legacy deployment.
    write(legacy.PENDING, '{"fixture":"interrupted-original"}', 0o600)
    for name, port in zip(OLD, [8788, 18887, 18888]):
        directory = ROOT/name; directory.mkdir()
        extra = 'ExecStartPre=+/usr/bin/python3 -B '+str(Path(__file__).resolve())+' --legacy-gate\n' if name in legacy.SERVICES else ''
        write(UNITS/(name+'.service'), '[Service]\nUser='+name+'\nEnvironment=E2E_FIXTURE_PORT='+str(port)+' E2E_FIXTURE_STATE='+str(directory)+'\n'+extra+'ExecStart=/usr/bin/python3 -B '+str(Path(__file__).resolve())+' --daemon old\n[Install]\nWantedBy=multi-user.target\n')
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=e2e.capture402.xyz', '-keyout', str(ROOT/'tls.key'), '-out', str(ROOT/'tls.crt'))
    write(ROOT/'ingress.conf', 'location / { return 503; }\n')
    write(ROOT/'nginx.conf', f'''daemon off;
user www-data;
pid {ROOT}/nginx.pid;
error_log {ROOT}/nginx-error.log;
events {{ worker_connections 64; }}
http {{ access_log off;
server {{ listen 127.0.0.1:28968 ssl; server_name e2e.capture402.xyz;
ssl_certificate {ROOT}/tls.crt; ssl_certificate_key {ROOT}/tls.key;
include {ROOT}/rendered/nginx-access.conf;
include {ROOT}/ingress.conf;
}} }}
''')
    write(UNITS/'capture402-e2e-fixture-nginx.service', f'[Service]\nExecStart=/usr/sbin/nginx -p {ROOT}/ -c {ROOT}/nginx.conf\nExecReload=/bin/kill -HUP $MAINPID\n[Install]\nWantedBy=multi-user.target\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', OLD[0], 'capture402-e2e-fixture-nginx')
    run('systemctl', 'start', OLD[0], 'capture402-e2e-fixture-nginx')
    finish_preparation()


def finish_preparation():
    wait_ready(8788)
    (ROOT/'old-baseline.json').write_text(json.dumps(inventory(OLD_ROOTS), sort_keys=True))
    (ROOT/'old-pid').write_text(run('systemctl', 'show', '-p', 'MainPID', '--value', OLD[0]))


def permissions():
    for role, name, port in [('facilitator', NAMES[0], 28887), ('restaurant', NAMES[1], 28888)]:
        identity = http('/_identity', direct=port)[1]
        require(identity['uid'] == pwd.getpwnam(name).pw_uid and identity['gid'] == pwd.getpwnam(name).pw_gid)
        require(identity['cwd'] == str(BASE/'releases/candidate/integration'))
        require('capture402-e2e.slice/'+name+'.service' in identity['cgroup'])
        require(identity['groups'] == [identity['gid']])
        probe = lambda p, access: http('/_probe?path='+str(p)+'&access='+access, direct=port)[1]['allowed']
        own_key = PRIVATE/'keys'/('sponsor.json' if role == 'facilitator' else 'merchant.json')
        require(probe(own_key, 'r') and not probe(own_key, 'w'))
        for n in ['sponsor', 'merchant', 'payer', 'mint']:
            p = PRIVATE/'keys'/(n+'.json')
            if p != own_key: require(not probe(p, 'r') and not probe(p, 'w'))
        for p in OLD_ROOTS: require(not probe(p, 'x') and not probe(p/'retained.marker', 'r') and not probe(p/'retained.marker', 'w'))
        other = STATE/('restaurant' if role == 'facilitator' else 'facilitator')
        require(not probe(other, 'x') and probe(STATE/role, 'x'))
        # Real writes in each permitted role's own ReadWritePaths sandbox.
        marker = STATE/role/'own.marker'; write(marker, 'SYNTHETIC_OWN_STATE', 0o600, name)
        require(probe(marker, 'r') and probe(marker, 'w'))
    for name in OLD:
        for path in [PRIVATE, PRIVATE/'keys/sponsor.json', PRIVATE/'keys/merchant.json', STATE/'facilitator', STATE/'restaurant']:
            require(run('runuser', '-u', name, '--', 'test', '-r', str(path), ok=False).returncode != 0)
            require(run('runuser', '-u', name, '--', 'test', '-w', str(path), ok=False).returncode != 0)
    for name in NAMES:
        require(run('systemctl', 'show', '-p', 'Restart', '--value', name) == 'no')
        require(run('systemctl', 'is-enabled', name, ok=False).stdout.strip() == 'static')
        require(run('systemctl', 'show', '-p', 'MemoryMax', '--value', name) == '402653184')
        require(run('systemctl', 'show', '-p', 'TasksMax', '--value', name) == '64')
    require(run('systemctl', 'show', '-p', 'CPUQuotaPerSecUSec', '--value', 'capture402-e2e.slice') == '500ms')
    require('127.0.0.1:28887' in run('ss', '-ltn') and '127.0.0.1:28888' in run('ss', '-ltn'))


def campaign():
    record('rendered-systemd-units-verify', lambda: run('systemd-analyze', 'verify', *(str(UNITS/(n+'.service')) for n in NAMES), str(UNITS/'capture402-e2e.slice')))
    record('operator-runbook-clean-preflight-reuses-ordinary-journal-refusal', operator_preflight)
    for role in NAMES: run('systemctl', 'start', role)
    wait_ready(28887); wait_ready(28888)
    record('real-UID-GID-cgroup-cwd-role-key-state-old-new-denial-resource-loopback-matrix', permissions)
    record('legacy-pending-boot-guard-refuses-without-touching-E2E', lambda: failed(legacy.gate))
    for n in legacy.SERVICES:
        require(run('systemctl', 'start', n, ok=False).returncode != 0)
    record('legacy-guard-systemd-activation-fails-E2E-stays-active', lambda: require(all(run('systemctl', 'is-active', n) == 'active' for n in NAMES)))
    # Adversarial operator configuration checks are synthetic and restored immediately.
    unit = UNITS/(NAMES[0]+'.service'); original = unit.read_text()
    for description, changed in [('wrong-UID', original.replace('User='+NAMES[0], 'User='+OLD[0])), ('stale-port-env-path', original.replace('/etc/capture402-e2e', '/etc/capture402-dev'))]:
        unit.write_text(changed); record(description+'-preflight-refused', lambda: failed(operator_preflight)); unit.write_text(original)
    key = PRIVATE/'keys/sponsor.json'; before = key.read_text(); uid = key.stat().st_uid; gid = key.stat().st_gid
    key.chmod(0o640); record('group-readable-key-preflight-refused', lambda: failed(operator_preflight)); key.chmod(0o600)
    run('setfacl', '-m', 'u:'+OLD[0]+':r', str(key)); record('extended-key-ACL-preflight-refused', lambda: failed(operator_preflight)); run('setfacl', '-b', str(key))
    key.write_text((PRIVATE/'keys/merchant.json').read_text()); record('reused-key-identity-preflight-refused', lambda: failed(operator_preflight)); key.write_text(before)
    key.unlink(); key.symlink_to(PRIVATE/'keys/merchant.json'); record('symlink-key-preflight-refused', lambda: failed(operator_preflight)); key.unlink(); write(key, before, 0o600); os.chown(key, uid, gid)
    ingress(True)
    record('nginx-TLS-admitted-402-discovery', lambda: require(http('/resource')[0] == 402))
    record('nginx-unadmitted-source-denied', lambda: require(http('/resource', denied=True)[0] == 403))
    for path in ['/supported', '/settle', '/verify', '/_identity', '/inspect', '/api/not-allowed']:
        require(http(path)[0] == 404)
    record('nginx-no-facilitator-inspector-or-unallowlisted-routes', lambda: None)
    path = '/api/orders/'+'a'*32+'/actions/refund'
    auth = {'Origin': ORIGIN, 'Authorization': 'Bearer synthetic-fixture-only'}
    record('nginx-preserves-Origin-and-bearer-denial', lambda: require(http(path, 'POST', {**auth, 'Origin': 'https://dev.capture402.xyz'})[0] == 403 and http(path, 'POST', {**auth, 'Authorization': 'Bearer wrong-fixture'})[0] == 401))
    code, echoed = http(path, 'POST', auth); require(code == 202 and echoed == {'host': 'e2e.capture402.xyz', 'origin': ORIGIN})
    record('nginx-preserves-host-origin-auth-on-one-synthetic-submission', lambda: None)
    preserved = inventory([PRIVATE, STATE]); (ROOT/'e2e-baseline.json').write_text(json.dumps(preserved, sort_keys=True))
    run('systemctl', 'restart', NAMES[1]); wait_ready(28888)
    record('explicit-E2E-restart-keeps-original-lock-and-refuses-duplicate', lambda: require(http(path, 'POST', auth)[0] == 409 and inventory([PRIVATE, STATE]) == preserved))
    # A separate synthetic original with a deliberately lost reply proves proxy retry cessation.
    lock = STATE/'restaurant/original.lock'; lock.rename(STATE/'restaurant/retained-original.lock')
    require(http(path, 'POST', {**auth, 'X-Fixture-Lost-Response': 'yes'})[0] == 502)
    require((STATE/'restaurant/submissions').read_text() == '2')
    record('lost-response-no-nginx-retry-one-original-retained', lambda: require(http(path, 'POST', auth)[0] == 409))
    ingress(False); run('systemctl', 'stop', NAMES[1], NAMES[0])
    record('operator-close-ingress-before-startup-failure', lambda: require(http('/resource')[0] == 503))
    write(ROOT/'fail-readiness', 'synthetic')
    run('systemctl', 'start', NAMES[0]); run('systemctl', 'start', NAMES[1], ok=False)
    time.sleep(.2)
    record('failed-E2E-readiness-stays-closed-no-automatic-restart', lambda: require(http('/resource')[0] == 503 and run('systemctl', 'show', '-p', 'NRestarts', '--value', NAMES[1]) == '0'))
    run('systemctl', 'stop', NAMES[1], NAMES[0]); (ROOT/'fail-readiness').unlink()
    # Rollback only code and ingress, retaining every original synthetic journal/lock.
    preserved = inventory([PRIVATE, STATE])
    (BASE/'current').unlink(); (BASE/'current').symlink_to(BASE/'releases/previous')
    record('E2E-only-code-rollback-preserves-keys-state-locks-originals', lambda: require(inventory([PRIVATE, STATE]) == preserved))
    write(STATE/'facilitator/journal/unexpected.json', '{"status":"UNKNOWN","wire":"SYNTHETIC_ORIGINAL"}', 0o600, NAMES[0])
    record('unexpected-pending-E2E-journal-blocks-runbook-activation-preserves-original', lambda: failed(operator_preflight))
    require(inventory(OLD_ROOTS) == json.loads((ROOT/'old-baseline.json').read_text()))
    require(run('systemctl', 'show', '-p', 'MainPID', '--value', OLD[0]) == (ROOT/'old-pid').read_text())
    record('old-stable-runtime-PID-and-legacy-UNKNOWN-bytes-unchanged-before-reboot', lambda: None)
    (ROOT/'e2e-baseline.json').write_text(json.dumps(inventory([PRIVATE, STATE]), sort_keys=True))
    (ROOT/'boot-before').write_text(Path('/proc/sys/kernel/random/boot_id').read_text())



def supplemental(recovery_only=False):
    RESULTS.extend(t for t in json.loads((ROOT/'results.json').read_text())['tests'] if t['result'] == 'PASS')
    # Existing synthetic UNKNOWN remains in place; isolate config assertions from
    # the expected pending-journal refusal when testing changed config inputs.
    if not recovery_only:
        with patch.object(legacy, 'clean_operations'):
            config = PRIVATE/'restaurant.env'; before = config.read_text()
            config.write_text(before.replace('SAC006_RESOURCE_PORT=28888', 'SAC006_RESOURCE_PORT=18888'))
            record('actual-stale-private-port-config-preflight-refused', lambda: failed(operator_preflight)); config.write_text(before)
            config.write_text(before.replace('SAC006_PUBLIC_ORIGIN='+ORIGIN, 'SAC006_PUBLIC_ORIGIN=https://dev.capture402.xyz'))
            record('actual-cross-environment-Origin-config-preflight-refused', lambda: failed(operator_preflight)); config.write_text(before)
    # Run only this new interaction case using the accepted boot harness setup,
    # interruption, gate, recovery and cleanup. No unchanged base test is repeated.
    from test_boot_gate import BootBoundaryTests
    class Interactions(BootBoundaryTests):
        def test_legacy_interruption_keeps_e2e_stopped_and_preserves_stores(self):
            baseline = inventory([PRIVATE, STATE]); old = inventory(OLD_ROOTS)
            self.test_partial_product_installation_boots_closed_then_recovers_legacy()
            self.assertEqual(inventory([PRIVATE, STATE]), baseline)
            self.assertEqual(inventory(OLD_ROOTS), old)
            for name in NAMES: self.assertEqual(run('systemctl', 'show', '-p', 'MainPID', '--value', name), '0')
            self.assertEqual(http('/resource')[0], 503)
    def interaction():
        import unittest
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([Interactions('test_legacy_interruption_keeps_e2e_stopped_and_preserves_stores')]))
        require(result.testsRun == 1 and not result.skipped and result.wasSuccessful(), 'new legacy recovery interaction failed')
    record('existing-boot-harness-interrupted-legacy-recovery-preserves-stopped-E2E-and-UNKNOWN', interaction)

def after_boot():
    RESULTS.extend(json.loads((ROOT/'results.json').read_text())['tests'])
    record('real-reboot-confirmed', lambda: require((ROOT/'boot-before').read_text() != Path('/proc/sys/kernel/random/boot_id').read_text()))
    record('real-reboot-E2E-remains-stopped-no-startup-or-recovery-resume', lambda: require(all(run('systemctl', 'show', '-p', 'MainPID', '--value', n) == '0' for n in NAMES)))
    record('real-reboot-E2E-ingress-closed', lambda: require(http('/resource')[0] == 503))
    record('real-reboot-all-E2E-keys-stores-original-locks-UNKNOWN-preserved', lambda: require(inventory([PRIVATE, STATE]) == json.loads((ROOT/'e2e-baseline.json').read_text())))
    record('real-reboot-old-UNKNOWN-and-release-marker-inventory-preserved', lambda: require(inventory(OLD_ROOTS) == json.loads((ROOT/'old-baseline.json').read_text())))
    record('real-reboot-pending-journal-still-blocks-explicit-activation', lambda: failed(operator_preflight))
    record('real-reboot-ordinary-legacy-pending-guard-still-refuses', lambda: failed(legacy.gate))


if __name__ == '__main__':
    require(Path('/etc/capture402-e2e-disposable').read_text().strip() == 'DISPOSABLE_SYNTHETIC_E2E_TEST_ONLY', 'explicit disposable VM marker required')
    if sys.argv[1:2] != ['--daemon']: require(os.geteuid() == 0, 'disposable VM operator UID required')
    if sys.argv[1:2] == ['--daemon']: daemon(sys.argv[2])
    elif sys.argv[1:] == ['--legacy-gate']: legacy.gate()
    elif sys.argv[1:] == ['prepare']: prepare()
    elif sys.argv[1:] == ['campaign']: campaign()
    elif sys.argv[1:] == ['supplemental']: supplemental()
    elif sys.argv[1:] == ['recovery-only']: supplemental(recovery_only=True)
    elif sys.argv[1:] == ['after-boot']: after_boot()
    else: raise RuntimeError('explicit prepare|campaign|after-boot required')
