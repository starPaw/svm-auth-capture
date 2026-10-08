"""CI-only real systemd/nginx crash-boundary tests; no production units or payment code.

Run explicitly as root with CAPTURE402_SYSTEMD_TEST=1 on the disposable CI runner.
Only randomized capture402-test-* units and temporary loopback listeners are used.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

import deploy_demo as source
import deploy_vps as host


NATIVE_RUN = source.run


def configure(root):
    config = json.loads((root/'fixture.json').read_text())
    host.BASE = source.BASE = root
    host.LEGACY = root/'legacy'
    host.STATE = root/'state'
    host.PRIVATE = root/'private'
    host.SNIPPET = root/'snippet.conf'
    host.PENDING = root/'transaction.json'
    host.MAINTENANCE = root/'maintenance'
    host.BACKUPS = root/'backups'
    host.UNITS = Path('/run/systemd/system')
    host.GATE = host.UNITS/(config['prefix']+'-gate.service')
    host.RECOVERY = host.UNITS/(config['prefix']+'-recovery.service')
    host.NGINX_SERVICE = config['prefix']+'-nginx'
    host.GUARD = f'if (-f {host.MAINTENANCE}) {{ return 503; }}\n'
    source.SERVICES = (config['prefix']+'-facilitator', config['prefix']+'-resource')
    host.LEGACY_SERVICES = tuple(source.SERVICES)
    host.PRODUCT_SERVICES = (config['prefix']+'-product-facilitator', config['prefix']+'-product-restaurant')
    source.RELEASES = root/'releases'
    source.CURRENT = root/'current'
    source.MANIFESTS = root/'manifests'
    source.PENDING = root/'old-pending.json'
    def run(*args, **kwargs):
        if args[:2] == ('nginx', '-t'):
            args = ('nginx', '-t', '-p', str(root)+'/', '-c', str(root/'nginx.conf'))
        if args[:2] == ('systemctl', 'enable'):
            # Tests explicitly enqueue the boot transaction instead of enabling
            # fixtures in the runner's permanent multi-user target.
            return ''
        kwargs['timeout'] = min(kwargs.get('timeout', 90), 10)
        return NATIVE_RUN(*args, **kwargs)
    source.run = run
    return config


def event(root, name):
    with (root/'events.log').open('a') as log:
        log.write(name+'\n'); log.flush()


def request(port):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=1) as answer:
            return answer.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, urllib.error.URLError):
        return None


def wait_for(predicate, seconds=12):
    end = time.monotonic()+seconds
    while not predicate():
        if time.monotonic() >= end: raise RuntimeError('fixture readiness timed out')
        time.sleep(.05)


def driver(root, action):
    config = configure(root)
    if action == 'gate':
        event(root, 'gate-start')
        if (root/'gate-fail').exists(): raise RuntimeError('injected gate validation failure')
        host.main(['--gate'])
        event(root, 'gate-closed')
    elif action == 'recovery':
        event(root, 'recovery-start')
        wait_for(lambda: (root/'release-recovery').exists(), seconds=40)
        def ready(layout, public=True, **kwargs):
            if (root/'recovery-fail').exists(): raise RuntimeError('injected delayed rollback failure')
            port = config['publicPort'] if public else config['backendPort']
            wait_for(lambda: request(port) == 200)
        host.ready = ready
        host.main(['--recover'])
        event(root, 'recovery-verified')
    elif action == 'resource':
        from http.server import BaseHTTPRequestHandler, HTTPServer
        event(root, 'resource-start')
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                event(root, 'backend-request')
                self.send_response(200); self.end_headers(); self.wfile.write(b'fixture resource')
            def log_message(self, *args): pass
        HTTPServer(('127.0.0.1', config['backendPort']), Handler).serve_forever()
    elif action == 'facilitator':
        event(root, 'facilitator-start')
        while True: time.sleep(1)
    elif action == 'nginx-start':
        event(root, 'nginx-start')
    else: raise RuntimeError('invalid fixture action')


ENABLED = os.environ.get('CAPTURE402_SYSTEMD_TEST') == '1'


@unittest.skipUnless(ENABLED, 'explicit disposable Linux systemd test required')
class BootBoundaryTests(unittest.TestCase):
    def rename_transaction(self, fail_public=False, interrupt=False):
        source.run('systemctl', 'start', *host.LEGACY_SERVICES, host.NGINX_SERVICE)
        wait_for(lambda: request(self.cfg['publicPort']) == 200)
        previous = {**self.snapshot['previous'], 'services': list(host.LEGACY_SERVICES)}
        def ready(layout, public=True, **kwargs):
            if fail_public and public and layout.get('services') == list(host.PRODUCT_SERVICES):
                raise RuntimeError('injected product public readiness failure')
            wait_for(lambda: request(self.cfg['publicPort'] if public else self.cfg['backendPort']) == 200)
        real_write = host.atomic_bytes
        def write(path, data, mode=0o644):
            real_write(path, data, mode)
            if interrupt and path == host.UNITS / (host.PRODUCT_SERVICES[0] + '.service'):
                raise KeyboardInterrupt()
        with (mock.patch.object(host, 'active_layout', return_value=previous),
              mock.patch.object(host, 'ready', side_effect=ready),
              mock.patch.object(source, 'manually_fetch_archive', return_value=b'fixture'),
              mock.patch.object(source, 'verify_source_against_main'),
              mock.patch.object(source, 'require_current_main'),
              mock.patch.object(source, 'prepare_release'),
              mock.patch.object(source, 'archive_fingerprints', return_value={}),
              mock.patch.object(host, 'backup', return_value=None), mock.patch.object(host, 'provision_merchant', return_value=False),
              mock.patch.object(host, 'atomic_bytes', side_effect=write)):
            if interrupt:
                with self.assertRaises(KeyboardInterrupt): host.deploy('b' * 40)
            elif fail_public:
                with self.assertRaisesRegex(RuntimeError, 'verified rollback'): host.deploy('b' * 40)
            else:
                host.deploy('b' * 40)
        self.assertEqual(host.inventory([host.STATE, host.PRIVATE]), self.original_state)

    def test_product_names_replace_actual_units_without_duplicate_backend(self):
        self.rename_transaction()
        for name in host.PRODUCT_SERVICES:
            self.assertEqual(NATIVE_RUN('systemctl', 'show', '-p', 'ActiveState', '--value', name), 'active')
        for name in host.LEGACY_SERVICES:
            self.assertEqual(NATIVE_RUN('systemctl', 'show', '-p', 'MainPID', '--value', name), '0')
        self.assertEqual(request(self.cfg['publicPort']), 200)

    def test_product_startup_failure_restores_actual_legacy_units(self):
        self.rename_transaction(fail_public=True)
        for name in host.LEGACY_SERVICES:
            self.assertEqual(NATIVE_RUN('systemctl', 'show', '-p', 'ActiveState', '--value', name), 'active')
        for name in host.PRODUCT_SERVICES:
            self.assertFalse((host.UNITS / (name + '.service')).exists())
        self.assertEqual(request(self.cfg['publicPort']), 200)

    def test_partial_product_installation_boots_closed_then_recovers_legacy(self):
        self.rename_transaction(interrupt=True)
        self.snapshot = json.loads(host.PENDING.read_text())
        source.SERVICES = host.LEGACY_SERVICES
        source.run('systemctl', 'stop', host.GATE.name)
        (self.root / 'events.log').write_text('')
        self.boot()
        self.recover()

    def test_sealed_release_starts_as_nonroot_under_private_umask(self):
        release = source.RELEASES / ('b' * 40)
        previous_umask = os.umask(0o077)
        try:
            dependency = release / 'integration/node_modules/package'
            dependency.mkdir(parents=True)
            (dependency / 'runtime.txt').write_bytes(b'nonroot runtime readable\n')
        finally:
            os.umask(previous_umask)
        (release / 'integration').chmod(0o700)
        source.seal_runtime_permissions(release)
        result = subprocess.run([
            'systemd-run', '--unit=' + self.cfg['prefix'] + '-readable',
            '--wait', '--pipe', '--collect', '--property=User=nobody',
            '--property=WorkingDirectory=' + str(release / 'integration'),
            '/bin/cat', str(dependency / 'runtime.txt'),
        ], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'nonroot runtime readable\n')
        self.assertEqual(host.inventory([host.STATE, host.PRIVATE]), self.original_state)

    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(os.environ.get('GITHUB_ACTIONS'), 'true', 'never run root fixtures on the VPS')
        self.assertTrue(shutil.which('systemctl') and shutil.which('nginx'))
        self.tmp = tempfile.TemporaryDirectory(prefix='capture402-boot-')
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)
        prefix = 'capture402-test-'+self.root.name.rsplit('-',1)[-1]
        def port():
            with socket.socket() as s:
                s.bind(('127.0.0.1',0)); return s.getsockname()[1]
        cfg = {'prefix':prefix, 'publicPort':port(), 'backendPort':port()}
        (self.root/'fixture.json').write_text(json.dumps(cfg))
        # Patch module globals, including the shared source helper, for parent
        # setup/interruptions. Child unit processes load this same configuration.
        self.patches=[]
        for module in (host,source):
            for key,value in list(vars(module).items()):
                if key.isupper() or key == 'run':
                    patch=mock.patch.object(module,key,value); patch.start(); self.patches.append(patch)
        self.addCleanup(self.cleanup)
        self.cfg=configure(self.root)
        for p in (host.LEGACY/'integration',host.STATE,host.PRIVATE,host.BACKUPS,source.MANIFESTS,
                  source.RELEASES/('b'*40)/'integration/deploy'):
            p.mkdir(parents=True,exist_ok=True)
        (host.STATE/'pending.busy').write_bytes(b'original unresolved reservation')
        (host.STATE/'wire.json').write_bytes(b'original unresolved wire')
        self.original_state=host.inventory([host.STATE,host.PRIVATE])
        self.original_snippet=f'location / {{ proxy_pass http://127.0.0.1:{cfg["backendPort"]}; }}\n'.encode()
        host.SNIPPET.write_bytes(self.original_snippet)
        (source.RELEASES/('b'*40)/'integration/deploy/nginx-resource.conf').write_bytes(
            self.original_snippet+b'location = /api/orders { return 403; }\n')
        (self.root/'nginx.conf').write_text(f'''daemon off;
user root;
pid {self.root}/nginx.pid;
error_log {self.root}/nginx-error.log;
events {{ worker_connections 64; }}
http {{ access_log off; server {{ listen 127.0.0.1:{cfg['publicPort']}; include {host.SNIPPET}; }} }}
''')
        self.script=Path(__file__).resolve()
        for service,action in zip(source.SERVICES,('facilitator','resource')):
            (host.UNITS/(service+'.service')).write_text(f'[Service]\nType=simple\nWorkingDirectory={host.LEGACY}/integration\nExecStart={sys.executable} -B {self.script} --unit {self.root} {action}\nTimeoutStopSec=2\n')
        (host.UNITS/(host.NGINX_SERVICE+'.service')).write_text(f'[Service]\nType=simple\nExecStartPre={sys.executable} -B {self.script} --unit {self.root} nginx-start\nExecStart=/usr/sbin/nginx -p {self.root}/ -c {self.root}/nginx.conf\nExecReload=/bin/kill -HUP $MAINPID\nTimeoutStopSec=2\n')
        # Install the real production-generated units/dependencies. Only fixture
        # identifiers/paths and the controller entrypoint differ.
        real_write = host.atomic_bytes
        def fixture_entrypoint(path, data, mode=0o644):
            if path in (host.GATE, host.RECOVERY):
                action = 'gate' if path == host.GATE else 'recovery'
                argument = '--gate' if action == 'gate' else '--recover'
                data = data.replace(f'/usr/bin/python3 -B {Path(host.__file__).resolve()} {argument}'.encode(),
                                    f'{sys.executable} -B {self.script} --unit {self.root} {action}'.encode())
            real_write(path, data, mode)
        patch = mock.patch.object(host, 'atomic_bytes', side_effect=fixture_entrypoint)
        patch.start(); self.patches.append(patch)
        source.run('systemctl','daemon-reload')
        source.run('systemctl','start',*source.SERVICES,host.NGINX_SERVICE)
        wait_for(lambda: request(self.cfg['publicPort']) == 200)
        host.install_recovery()
        source.run('systemctl','daemon-reload')
        source.run('systemctl','stop',host.GATE.name)
        (self.root/'events.log').write_text('')
        self.snapshot={'previous':{'sha':'a'*40,'root':str(host.LEGACY),'legacy':True},
                       'target':'b'*40,'controls':host.capture_controls(),'current':None}

    def cleanup(self):
        try:
            if hasattr(self,'cfg'):
                names=[host.RECOVERY.name,host.GATE.name,*[s+'.service' for s in (*host.LEGACY_SERVICES,*host.PRODUCT_SERVICES,host.NGINX_SERVICE)]]
                result = getattr(self._outcome, 'result', None)
                if result and any(case is self for case, _ in result.failures + result.errors):
                    journal = subprocess.run(['journalctl','--no-pager','-n','120',*[a for name in names for a in ('-u',name)]],capture_output=True,text=True,timeout=10)
                    print(journal.stdout, flush=True)  # Fixtures contain no credentials/payment data.
                subprocess.run(['systemctl','stop',*names],capture_output=True,timeout=20)
                # Names were randomized and are confined to /run/systemd/system.
                for name in names:
                    path=host.UNITS/name
                    path.unlink(missing_ok=True)
                    directory=host.UNITS/(name+'.d')
                    if directory.exists(): shutil.rmtree(directory)
                subprocess.run(['systemctl','daemon-reload'],capture_output=True,timeout=10)
                subprocess.run(['systemctl','reset-failed',*names],capture_output=True,timeout=10)
        finally:
            for patch in reversed(self.patches): patch.stop()
            source.run=NATIVE_RUN
            self.tmp.cleanup()

    def boot(self, failed=False, partial=False):
        source.run('systemctl','stop',*source.SERVICES,host.NGINX_SERVICE,host.GATE.name)
        source.write_json(host.PENDING,self.snapshot)
        result=subprocess.run(['systemctl','start','--no-block',*[s+'.service' for s in (*source.SERVICES,host.NGINX_SERVICE)],host.RECOVERY.name],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        if failed:
            wait_for(lambda: NATIVE_RUN('systemctl','show','-p','ActiveState','--value',host.GATE.name)=='failed')
            self.assertNotIn(request(self.cfg['publicPort']),(200,201))
            self.assertFalse(any('-start' in s and not s.startswith('gate-') and not s.startswith('recovery-')
                                 for s in (self.root/'events.log').read_text().splitlines()))
            return
        expected = ('resource-start','nginx-start','recovery-start')
        if not partial: expected += ('facilitator-start',)
        wait_for(lambda: all(name in (self.root/'events.log').read_text().splitlines()
                            for name in expected))
        events=(self.root/'events.log').read_text().splitlines()
        for name in ('resource-start','facilitator-start','nginx-start','recovery-start'):
            # A partial candidate override can prevent a backend entrypoint
            # from running. Any process that starts must follow the gate.
            if name in events:
                self.assertLess(events.index('gate-closed'),events.index(name),events)
        wait_for(lambda: request(self.cfg['publicPort'])==503)
        for _ in range(10):
            self.assertEqual(request(self.cfg['publicPort']),503)
            time.sleep(.03)
        self.assertNotIn('backend-request',(self.root/'events.log').read_text())
        self.assertTrue(host.PENDING.exists())
        self.assertEqual(host.inventory([host.STATE,host.PRIVATE]),self.original_state)

    def recover(self, failed=False):
        if failed: (self.root/'recovery-fail').touch()
        (self.root/'release-recovery').touch()
        if failed:
            wait_for(lambda: NATIVE_RUN('systemctl','show','-p','ActiveState','--value',host.RECOVERY.name)=='failed',seconds=20)
            self.assertEqual(request(self.cfg['publicPort']),503)
            self.assertTrue(host.PENDING.exists())
            for s in source.SERVICES:
                self.assertEqual(NATIVE_RUN('systemctl','show','-p','MainPID','--value',s),'0')
        else:
            wait_for(lambda: not host.PENDING.exists(),seconds=20)
            self.assertEqual(request(self.cfg['publicPort']),200)
        self.assertEqual(host.inventory([host.STATE,host.PRIVATE]),self.original_state)

    def interrupted_deploy(self, before_backup=False):
        source.run('systemctl','start',*source.SERVICES,host.NGINX_SERVICE)
        wait_for(lambda: request(self.cfg['publicPort']) == 200)
        previous = self.snapshot['previous']
        def interrupt_backup(*args):
            # Partial private backup remains retained; no payment state is touched.
            (host.BACKUPS/'partial.tar').write_bytes(b'incomplete fixture backup')
            raise KeyboardInterrupt()
        real_json = source.write_json
        def interrupt_after_pending(path, value):
            real_json(path, value)
            if before_backup and path == host.PENDING: raise KeyboardInterrupt()
        with (mock.patch.object(host, 'active_layout', return_value=previous),
              mock.patch.object(host, 'ready'),
              mock.patch.object(source, 'manually_fetch_archive', return_value=b'fixture'),
              mock.patch.object(source, 'verify_source_against_main'),
              mock.patch.object(source, 'require_current_main'),
              mock.patch.object(source, 'prepare_release'),
              mock.patch.object(source, 'archive_fingerprints', return_value={}),
              mock.patch.object(host, 'backup', side_effect=interrupt_backup),
              mock.patch.object(source, 'write_json', side_effect=interrupt_after_pending)):
            with self.assertRaises(KeyboardInterrupt): host.deploy('b'*40)
        self.snapshot = json.loads(host.PENDING.read_text())
        self.assertTrue(host.SNIPPET.read_text().startswith(host.GUARD))
        for service in (*source.SERVICES,host.NGINX_SERVICE):
            self.assertIn(host.GATE.name,NATIVE_RUN('systemctl','show','-p','Requires','--value',service).split())
        source.run('systemctl','stop',host.GATE.name)
        (self.root/'events.log').write_text('')

    def test_interrupt_before_backup_delayed_recovery(self):
        self.interrupted_deploy(before_backup=True)
        self.boot(); self.recover()

    def test_interrupt_during_backup_delayed_recovery(self):
        self.interrupted_deploy()
        self.boot(); self.recover()
        self.assertEqual((host.BACKUPS/'partial.tar').read_bytes(),b'incomplete fixture backup')

    def test_partial_candidate_control_installation(self):
        real=host.atomic_bytes
        def interrupted(path,data,mode=0o644):
            real(path,data,mode)
            if path==host.control_paths()[1]: raise KeyboardInterrupt()
        with mock.patch.object(host,'atomic_bytes',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt): host.install_controls('b'*40)
        self.boot(partial=True); self.recover()

    def test_interruption_after_restoring_legacy_snippet(self):
        # Retained snapshots from the original helper may be unguarded.
        self.snapshot['controls'][str(host.SNIPPET)]['bytes']=__import__('base64').b64encode(self.original_snippet).decode()
        real=host.atomic_bytes
        def interrupted(path,data,mode=0o644):
            real(path,data,mode)
            if path==host.SNIPPET: raise KeyboardInterrupt()
        with mock.patch.object(host,'atomic_bytes',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt): host.restore_controls(self.snapshot['controls'])
        self.assertTrue(host.SNIPPET.read_text().startswith(host.GUARD))
        self.boot(); self.recover()

    def test_failed_recovery_keeps_http_closed_and_stops_backends(self):
        self.boot(); self.recover(failed=True)

    def test_failed_gate_blocks_nginx_and_both_backends(self):
        (self.root/'gate-fail').touch()
        self.boot(failed=True)


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--unit':
        driver(Path(sys.argv[2]),sys.argv[3])
    else: unittest.main()
