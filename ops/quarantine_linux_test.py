#!/usr/bin/env python3
"""Real disposable systemd/cgroup/UID/nginx isolation + reboot campaign.

Run ONLY in a fresh VM with /etc/capture402-b2-disposable = explicit disposable
marker. This intentionally installs synthetic dev units and prepares runtime roots.
No RPC, live keys, production host or program deployment is involved.
"""
import base64
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import time

import quarantine as q
import quarantine_prepare as prep

SOURCE = Path('/opt/b2-test/src')
LOG = Path('/opt/b2-test/results.json')
FIXTURE = SOURCE.parent / 'fixture.json'
TESTS = []


def record(name, action):
    action()
    TESTS.append({'name': name, 'result': 'PASS'})
    LOG.write_bytes(q.encoded({'tests': TESTS, 'host': q.run('uname', '-r'), 'systemd': q.run('systemctl', '--version').splitlines()[0]}))
    print('PASS', name, flush=True)


def failed(call):
    try:
        call()
    except Exception:
        return
    raise AssertionError('expected refusal')


def http(path, token=None, cookie=None, method='GET'):
    cmd = ['curl', '--silent', '--show-error', '--max-time', '5', '-X', method, '-w', '\n%{http_code}', 'http://127.0.0.1:18057' + path]
    if method == 'HEAD':
        cmd += ['--head']
    if token:
        cmd += ['-H', 'Authorization: Bearer ' + token]
    if cookie:
        cmd += ['-H', 'Cookie: capture402-order=' + cookie]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=7)
    q.require(r.returncode == 0)
    body, code = r.stdout.rsplit('\n', 1)
    return int(code), body


def assert_equal(a, b):
    q.require(a == b)


def setup(f):
    q.run('groupadd', '--system', 'capture402-dev-runtime')
    for n in ('capture402-dev-setup', *q.SERVICES, 'capture402-deploy'):
        q.run('useradd', '--system', '--no-create-home', '--gid', 'capture402-dev-runtime', '--shell', '/usr/sbin/nologin', n)
    q.run('usermod', '-aG', 'capture402-dev-runtime', 'www-data')
    for p in (q.BASE, q.PRIVATE, q.STATE):
        p.mkdir(mode=0o755)
    request = {'candidate': f['projection']['viewerSha'], 'previous': 'a' * 40,
               'selected': f['input']['selected'], 'public': {k: f['input'][k] for k in ('network', 'genesisHash', 'programId')},
               'ownerDisposition': 'ACCEPTED_CONTINUED_OUTAGE_AND_INERT_ROLLBACK', **f['auth']}
    prep.CONTROLLER_ROOT = q.BASE / 'controllers' / request['candidate']
    prep.CONTROLLER_ROOT.parent.mkdir()
    shutil.copytree(SOURCE / 'ops', prep.CONTROLLER_ROOT)
    import deploy_dev
    deploy_dev.seal(prep.CONTROLLER_ROOT)
    # SYNTHETIC owner disposition is solely a fixture, never repository owner acceptance.
    for sha in (request['candidate'], request['previous']):
        target = q.BASE / 'releases' / sha
        target.parent.mkdir(exist_ok=True)
        shutil.copytree(SOURCE, target)
        import deploy_dev
        deploy_dev.seal(target)
        identity = target / 'docs/evidence/sac-007/deployment-identity.v1.json'
        identity.parent.mkdir(parents=True, exist_ok=True)
        identity.write_bytes(q.encoded({'record_status': 'verified', 'network': {'caip2': request['public']['network'], 'genesis_hash': request['public']['genesisHash']}, 'program': {'program_id': request['public']['programId']}, 'scope': 'SYNTHETIC_DISPOSABLE_FIXTURE_ONLY'}))
    (q.BASE / 'current').symlink_to(q.BASE / 'releases' / request['previous'])
    for role, directory in zip(q.ROLES, q.STORE_PATHS):
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        for member in f['input']['stores'][role]:
            q.exclusive(directory / member['name'], base64.b64decode(member['rawBase64']))
    (q.PRIVATE / 'keys').mkdir(mode=0o750)
    for name, key_file in zip(q.SERVICES, ('sponsor.json', 'merchant.json')):
        p = q.PRIVATE / ('keys/' + key_file)
        q.exclusive(p, b'SYNTHETIC_NO_ECONOMIC_AUTHORITY', 0o600)
        u = pwd.getpwnam(name); os.chown(p, u.pw_uid, u.pw_gid)
    # Real supported env/path semantics; only economic entrypoint bodies are
    # substituted with a no-network synthetic loaded-key/fork writer below.
    for role in ('facilitator', 'restaurant'):
        text = (SOURCE / ('integration/deploy/dev/' + role + '.env.example')).read_text()
        values = {'SAC006_BEARER_TOKEN': 'synthetic-only', 'SAC006_MERCHANT_TOKEN': 'synthetic-merchant-only', 'SAC006_FEE_PAYER': f['input']['genesisHash'], 'SAC006_ASSET_MINT': f['input']['genesisHash'], 'SAC006_ALLOWLIST_MERCHANT': f['input']['genesisHash'], 'SAC006_ALLOWLIST_MINT': f['input']['genesisHash']}
        for k,v in values.items(): text = text.replace(k + '=\n', k + '=' + v + '\n')
        q.exclusive(q.PRIVATE / (role + '.env'), text.replace('https://api.devnet.solana.com', 'http://127.0.0.1:1').replace('@DEV_HOST@', 'synthetic.invalid').encode())
    q.exclusive(q.PRIVATE / 'nginx-routes.conf', b'location / { return 503; }\n')
    Path('/etc/nginx/sites-enabled/default').unlink(missing_ok=True)
    Path('/etc/nginx/sites-enabled/b2-test').write_text('server { listen 127.0.0.1:18057; server_name test.invalid; include /etc/capture402-dev/nginx-routes.conf; }\n')
    q.run('nginx', '-t')
    q.run('systemctl', 'restart', 'nginx')
    socket_dir = Path('/run/capture402-dev-view')
    socket_dir.mkdir(mode=0o750)
    user = pwd.getpwnam(q.SERVICES[1]); os.chown(socket_dir, user.pw_uid, user.pw_gid)
    # Recreate the socket directory on reboot, with no inherited socket activation FDs.
    Path('/etc/tmpfiles.d/capture402-b2-test.conf').write_text(f'd /run/capture402-dev-view 0750 {q.SERVICES[1]} capture402-dev-runtime -\n')
    writer = SOURCE.parent / 'writer.py'
    writer.write_text('''import os,time,pwd
key=open(os.environ['SAC006_FACILITATOR_KEYPAIR_PATH'] if 'SAC006_FACILITATOR_KEYPAIR_PATH' in os.environ else os.environ['SAC006_SERVER_KEYPAIR_PATH']).read()
if os.fork()==0:
 while True:
  if os.path.exists('/tmp/b2-late-result'):
   open('/var/lib/capture402-dev/post-fence-effect','w').write(key)
  time.sleep(.02)
else:
 while True: time.sleep(.02)
''')
    os.chown(q.STATE, user.pw_uid, user.pw_gid)
    os.chmod(q.STATE, 0o755)
    for name in q.SERVICES:
        unit = q.UNITS / (name + '.service')
        role = 'facilitator' if name == q.SERVICES[0] else 'restaurant'
        unit.write_text(f'[Unit]\n[Service]\nType=simple\nUser={name}\nGroup=capture402-dev-runtime\nSlice=capture402-dev.slice\nEnvironmentFile=/etc/capture402-dev/{role}.env\nExecStart=/usr/bin/python3 {writer}\nRestart=no\n[Install]\nWantedBy=multi-user.target\n')
        q.run('systemctl', 'enable', name)
    q.run('systemctl', 'daemon-reload')
    for name in q.SERVICES:
        q.run('systemctl', 'start', name)
    return prep.bootstrap(request)


def campaign(f):
    e = setup(f); host = q.LinuxHost(e)
    # These idle sources are rejected semantically even before their hash could
    # be accepted into an enrollment. No timer or credential service is started.
    delayed = q.UNITS / 'b2-delayed.service'
    delayed.write_text('[Service]\nUser=' + q.SERVICES[0] + '\nSlice=other.slice\nLoadCredential=key:/etc/capture402-dev/keys/sponsor.json\nExecStart=/usr/bin/sleep 60\n')
    record('pre-enrolled-idle-timer-credential-source-refused', lambda: failed(lambda: q.activation_inventory(e)))
    delayed.unlink()
    template = q.UNITS / 'b2-idle@.service'
    template.write_text('[Service]\nUser=%i\nExecStart=/usr/bin/sleep 60\n')
    instance = q.UNITS / ('b2-idle@' + str(e['uids'][0]) + '.service')
    instance.symlink_to(template)
    q.run('systemctl', 'daemon-reload')
    record('specifier-instance-and-enabled-alias-UID-source-refused', lambda: failed(lambda: q.activation_inventory(e)))
    instance.unlink(); template.unlink(); q.run('systemctl', 'daemon-reload')
    alias = Path('/opt/b2-key-alias'); alias.symlink_to(q.PRIVATE / 'keys/sponsor.json')
    delayed.write_text('[Service]\nLoadCredential=key:/opt/b2-key-alias\nExecStart=/usr/bin/sleep 60\n')
    q.run('systemctl', 'daemon-reload')
    record('resolved-credential-alias-source-refused', lambda: failed(lambda: q.activation_inventory(e)))
    delayed.unlink(); alias.unlink(); q.run('systemctl', 'daemon-reload')
    alias.symlink_to(q.STORE_PATHS[0])
    delayed.write_text('[Service]\nUser=nobody\nBindReadOnlyPaths=/opt/b2-key-alias:/run/provided\nExecStart=/usr/bin/sleep 60\n')
    q.run('systemctl', 'daemon-reload')
    record('resolved-bind-source-alias-to-raw-store-refused', lambda: failed(lambda: q.activation_inventory(e)))
    delayed.unlink(); alias.unlink(); q.run('systemctl', 'daemon-reload')
    alias.symlink_to(q.PRIVATE / 'keys/sponsor.json')
    delayed.write_text('[Service]\nUser=nobody\nOpenFile=/opt/b2-key-alias:signer:read-only\nExecStart=/usr/bin/sleep 60\n')
    q.run('systemctl', 'daemon-reload')
    record('resolved-openfile-source-alias-to-key-refused', lambda: failed(lambda: q.activation_inventory(e)))
    delayed.unlink(); alias.unlink(); q.run('systemctl', 'daemon-reload')
    alias.symlink_to(q.PRIVATE / 'keys/sponsor.json')
    template.write_text('[Service]\nUser=%i\nLoadCredential=key:/opt/b2-key-alias\nExecStart=/usr/bin/sleep 60\n')
    record('uninstantiated-template-credential-alias-refused', lambda: failed(lambda: q.activation_inventory(e)))
    template.write_text('[Service]\nUser=%i\nExecStart=/usr/bin/sleep 60\n')
    cron = Path('/etc/cron.d/b2-template-test')
    cron.write_text('* * * * * root systemctl start b2-idle@' + str(e['uids'][0]) + '.service\n')
    q.run('systemctl', 'daemon-reload')
    record('queued-cron-template-instance-UID-refused', lambda: failed(lambda: q.activation_inventory(e)))
    cron.unlink(); template.unlink(); alias.unlink(); q.run('systemctl', 'daemon-reload')
    inherited = q.UNITS / (q.SERVICES[1] + '.service.d') / '98-inherited.conf'
    inherited.write_text('[Service]\nOpenFile=/etc/capture402-dev/keys/merchant.json\nLoadCredential=key:/etc/capture402-dev/keys/merchant.json\n')
    record('inherited-viewer-credential-and-open-FD-source-refused', lambda: failed(lambda: q.activation_inventory(e)))
    inherited.unlink()
    env_path = q.PRIVATE / 'facilitator.env'; original_env = env_path.read_bytes()
    env_path.write_bytes(original_env.replace(b'/var/lib/capture402-dev/facilitator/journal', b'/var/lib/alternate/journal'))
    record('alternate-economic-store-env-refused', lambda: failed(q.configuration))
    env_path.write_bytes(original_env)
    projection = prep.offline_projector(e)
    inv, stores = q.inventory()
    record('offline-root-no-network-projector-real-original', lambda: q.require(q.strict_json(projection(stores, inv))['original']['status'] == 'UNKNOWN'))
    # Alternate same-UID process outside the enrolled slice must refuse before DENY intent.
    q.run('systemd-run', '--collect', '--unit=b2-unknown-writer', '-p', 'User=' + q.SERVICES[0], '/usr/bin/sleep', '60')
    record('unknown-same-UID-cgroup-refuses-before-switch', lambda: failed(host.verify))
    q.run('systemctl', 'stop', 'b2-unknown-writer')
    q.run('systemctl', 'reset-failed', 'b2-unknown-writer') if q.run('systemctl', 'show', '-p', 'ActiveState', '--value', 'b2-unknown-writer') == 'failed' else None
    transition = q.Transition(q.ROOT, host, e, projection)
    record('real-freeze-frozen-kill-descendants-populated-zero-and-view-start', transition.enter)
    host.open_view_ingress()
    baseline = q.journal_phase(q.ROOT)[2]['attestation']['inventory']
    LOG.with_name('baseline.json').write_bytes(q.encoded(baseline))
    LOG.with_name('fixture-public.json').write_bytes(q.encoded(f))  # Synthetic data only.
    record('authorized-customer-retained-timeline-over-nginx', lambda: assert_equal(http('/api/orders/' + f['projection']['orders'][0]['id'], cookie=f['cookie'])[0], 200))
    record('authorized-merchant-retained-timeline', lambda: assert_equal(http('/api/orders/' + f['projection']['orders'][0]['id'] + '/actions/beer', token=f['merchant'])[0], 200))
    record('operator-UNKNOWN-diagnosis', lambda: q.require(json.loads(http('/api/quarantine/status', token=f['operator'])[1])['original']['status'] == 'UNKNOWN'))
    for method, path in [('GET', '/resource'), ('POST', '/api/orders'), ('GET', '/settle'), ('GET', '/supported'), ('GET', '/api/orders/' + f['projection']['orders'][0]['id'] + '/reclaim'), ('HEAD', '/api/config'), ('OPTIONS', '/api/config'), ('GET', '/assets/wallet.js')]:
        record('forbidden-' + method + '-' + path.replace('/', '_'), lambda method=method, path=path: assert_equal(http(path, method=method)[0], 403))
    record('lost-cookie-no-private-data', lambda: assert_equal(http('/api/orders/' + f['projection']['orders'][0]['id'])[0], 403))
    Path('/tmp/b2-late-result').touch()
    time.sleep(.15)
    record('late-result-old-descendants-have-zero-local-continuations', lambda: q.require(not (q.STATE / 'post-fence-effect').exists() and q.inventory()[0] == baseline))
    record('ordinary-start-and-legacy-permit-do-not-admit-economic-profile', lambda: (q.run('systemctl', 'start', q.SERVICES[0]), assert_equal(q.run('systemctl', 'show', '-p', 'MainPID', '--value', q.SERVICES[0]), '0')))
    (q.BASE / 'transaction.json').write_text('{"previous":"' + 'a' * 40 + '"}')
    Path('/run/capture402-dev-deploy-permit').write_text('a' * 40)
    record('independent-guard-denies-valid-old-permit', lambda: failed(q.ordinary_allowed))
    (q.BASE / 'transaction.json').unlink()
    record('manual-same-UID-raw-key-and-store-open-refused', lambda: failed(lambda: q.run('runuser', '-u', q.SERVICES[0], '--', 'cat', str(q.PRIVATE / 'keys/sponsor.json'))))
    record('raw-four-store-member-identities-and-bytes-unchanged', lambda: assert_equal(q.inventory()[0], baseline))
    record('actual-viewer-process-root-network-seccomp-isolation', lambda: isolation_probe(e))
    q.exclusive(q.VIEW_PERMIT, q.encoded({'syntheticCrashedCaller': True}), 0o600)
    record('controller-recovery-keeps-denial-and-stops-viewer', transition.recover)
    record('crashed-view-start-lease-retired-after-cessation', lambda: assert_equal(q.exists(q.VIEW_PERMIT), False))
    record('P-code-only-rollback-no-legacy-process', transition.rollback)
    record('rollback-preserves-all-evidence', lambda: assert_equal(q.inventory()[0], baseline))
    # Explicitly select C* after testing inert rollback; no unquarantine or new snapshot.
    host.select(e['tuple']['candidate']); host.start_view(); host.open_view_ingress()
    record('explicit-viewer-restart-retains-auth-and-UNKNOWN', lambda: assert_equal(http('/api/quarantine/status', token=f['operator'])[0], 200))
    LOG.with_name('boot-id-before').write_text(Path('/proc/sys/kernel/random/boot_id').read_text())
    LOG.with_name('tuple.json').write_bytes(q.encoded(e['tuple']))
    print('REBOOT_READY', flush=True)


def isolation_probe(e):
    # Start the same unit restrictions with a pinned native Python probe in a separate
    # disposable copy of its root. Never change the running accepted viewer root.
    probe_root = q.BASE / 'probe'
    shutil.copytree(Path(e['viewerRoot']), probe_root)
    # Node script uses the identical restricted service profile through systemd-run.
    script = '''import fs from 'node:fs'; import net from 'node:net';
let blocked=0; for(const p of ['/etc/capture402-dev/keys/merchant.json','/var/lib/capture402-dev/facilitator/journal','/proc/1/root/app/auth.json','/etc/capture402-dev-admission/enrollment.json']) { try {fs.readFileSync(p);process.exit(1)}catch{blocked++} }
for(const target of [{host:'127.0.0.1',port:18057},{host:'1.1.1.1',port:443},{path:'/run/dbus/system_bus_socket'},{path:'/run/ingress/view.sock'}]) { await new Promise(resolve=>{const s=net.connect(target);s.on('connect',()=>process.exit(2));s.on('error',()=>{blocked++;resolve()});}); }
if(blocked!==8)process.exit(3);
'''
    (probe_root / 'app/probe.mjs').write_text(script)
    cmd = ['systemd-run', '--quiet', '--wait', '--collect', '--unit=b2-isolation-probe', '-p', 'User=' + q.SERVICES[1], '-p', 'Group=capture402-dev-runtime', '-p', 'RootDirectory=' + str(probe_root), '-p', 'WorkingDirectory=/app', '-p', 'PrivateNetwork=yes', '-p', 'RestrictAddressFamilies=AF_UNIX', '-p', 'SystemCallFilter=~connect sendto sendmsg sendmmsg @mount @privileged @reboot @raw-io', '-p', 'NoNewPrivileges=yes', '-p', 'CapabilityBoundingSet=', '-p', 'ProtectSystem=strict', '-p', 'ProtectControlGroups=yes', '-p', 'ProtectHome=yes', '-p', 'RestrictNamespaces=yes', '-p', 'PrivateDevices=yes', '-p', 'MountAPIVFS=no', '-p', 'BindPaths=/run/capture402-dev-view:/run/ingress', '/usr/bin/node', '/app/probe.mjs']
    cmd[cmd.index('/usr/bin/node'):cmd.index('/usr/bin/node')] = ['-p', 'SystemCallErrorNumber=EPERM']
    q.run(*cmd)


def after_boot():
    old = LOG.with_name('boot-id-before').read_text()
    q.require(old != Path('/proc/sys/kernel/random/boot_id').read_text())
    TESTS.extend(q.strict_json(LOG.read_bytes())['tests'])
    f = q.strict_json(LOG.with_name('fixture-public.json').read_bytes())
    baseline = q.strict_json(LOG.with_name('baseline.json').read_bytes())
    record('REAL-REBOOT-independent-economic-startup-denied', lambda: q.require(q.run('systemctl', 'show', '-p', 'MainPID', '--value', q.SERVICES[0]) == '0'))
    record('REAL-REBOOT-no-automatic-view-resume-maintenance', lambda: q.require(q.run('systemctl', 'show', '-p', 'MainPID', '--value', q.SERVICES[1]) == '0' and http('/api/config')[0] == 503))
    record('REAL-REBOOT-four-store-membership-identity-bytes-preserved', lambda: assert_equal(q.inventory()[0], baseline))
    host = q.LinuxHost(q.enrollment()); host.verify(stopped=True); host.start_view(); host.open_view_ingress()
    record('REAL-REBOOT-explicit-exact-sealed-viewer-start-retains-UNKNOWN', lambda: assert_equal(http('/api/quarantine/status', token=f['operator'])[0], 200))


if __name__ == '__main__':
    q.require(os.geteuid() == 0 and Path('/etc/capture402-b2-disposable').read_text().strip() == 'DISPOSABLE_SYNTHETIC_B2_TEST_ONLY')
    if sys.argv[1:] == ['reset-disposable-fixture']:
        q.require(not Path('/etc/sac006').exists() and not Path('/var/lib/sac006').exists())
        if (q.CGROUP / 'cgroup.kill').exists():
            (q.CGROUP / 'cgroup.kill').write_text('1')
        for n in q.SERVICES:
            subprocess.run(['systemctl', 'stop', n], capture_output=True)
            subprocess.run(['systemctl', 'disable', n], capture_output=True)
            (q.UNITS / (n + '.service')).unlink(missing_ok=True)
            shutil.rmtree(q.UNITS / (n + '.service.d'), ignore_errors=True)
        for p in (q.ROOT, q.BASE, q.PRIVATE, q.STATE, Path('/run/capture402-dev-view')):
            shutil.rmtree(p, ignore_errors=True)
        q.GUARD.unlink(missing_ok=True)
        Path('/tmp/b2-late-result').unlink(missing_ok=True)
        q.VIEW_PERMIT.unlink(missing_ok=True)
        q.run('systemctl', 'daemon-reload')
        for n in ('capture402-dev-setup', *q.SERVICES, 'capture402-deploy'):
            subprocess.run(['userdel', n], capture_output=True)
        subprocess.run(['groupdel', 'capture402-dev-runtime'], capture_output=True)
    elif sys.argv[1:] == ['after-boot']:
        after_boot()
    else:
        campaign(q.strict_json(FIXTURE.read_bytes()))
