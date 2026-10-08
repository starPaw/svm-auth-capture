"""Adversarial tests for the first migration and subsequent release transactions."""
import json
import shutil
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import deploy_demo as source
import deploy_vps as host
import launch_deploy as launcher
from test_deploy_policy import PolicyFixture

INSTALL_RECOVERY = host.install_recovery

OLD = 'a' * 40
NEW = 'b' * 40


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.root = root
        for module, values in (
            (host, {'BASE': root, 'LEGACY': root/'legacy', 'STATE': root/'state',
                    'PRIVATE': root/'private', 'SNIPPET': root/'nginx/snippet',
                    'UNITS': root/'units', 'PENDING': root/'transaction.json',
                    'MAINTENANCE': root/'maintenance', 'BACKUPS': root/'backups',
                    'RECOVERY': root/'units/capture402-recovery.service', 'GATE': root/'units/capture402-gate.service'}),
            (source, {'BASE': root, 'RELEASES': root/'releases', 'CURRENT': root/'current',
                      'MANIFESTS': root/'manifests', 'PENDING': root/'old-pending.json'})):
            for name, value in values.items():
                patch = mock.patch.object(module, name, value)
                patch.start(); self.addCleanup(patch.stop)
        for directory in (host.LEGACY, host.STATE, host.PRIVATE, host.SNIPPET.parent, host.UNITS,
                          source.RELEASES/NEW/'integration/deploy', source.RELEASES/OLD, source.MANIFESTS):
            directory.mkdir(parents=True, exist_ok=True)
        host.SNIPPET.write_bytes(b'# legacy TLS include\nlocation /api/ { return 404; }\n')
        (source.RELEASES/NEW/'integration/deploy/nginx-resource.conf').write_bytes(b'location = /api/orders {\n}\n')
        (host.STATE/'pending.json').write_bytes(b'{"state":"pending","wire":"original"}')
        (host.STATE/'pending.json.busy').write_bytes(b'original reservation')
        (host.PRIVATE/'key').write_bytes(b'private original key')
        self.previous = {'sha': OLD, 'root': str(host.LEGACY), 'legacy': True}
        self.calls = []
        for name, value in (
            ('active_layout', self.previous), ('ready', None), ('install_recovery', None),
            ('backup', None), ('provision_merchant', False)):
            patch = mock.patch.object(host, name, return_value=value)
            obj = patch.start(); self.addCleanup(patch.stop)
            setattr(self, name + '_mock', obj)
        for name, value in (('manually_fetch_archive', b'blob'), ('verify_source_against_main', None),
                            ('prepare_release', None), ('archive_fingerprints', {}),
                            ('check_unit_layout', None), ('restart', None)):
            patch = mock.patch.object(source, name, return_value=value)
            obj = patch.start(); self.addCleanup(patch.stop)
            setattr(self, name + '_mock', obj)
        def run(*args, **kwargs):
            self.calls.append(args)
            if 'ActiveState' in args: return 'inactive'
            if 'MainPID' in args or 'ControlPID' in args: return '0'
            if 'Requires' in args: return host.GATE.name
            return ''
        patch = mock.patch.object(source, 'run', side_effect=run)
        self.run_mock = patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(source.os, 'geteuid', return_value=0)
        patch.start(); self.addCleanup(patch.stop)
        self.before = host.inventory([host.PRIVATE, host.STATE])

    def pending(self):
        return {'previous': self.previous, 'target': NEW, 'controls': host.capture_controls(), 'current': None}

    def assert_preserved(self):
        self.assertEqual(host.inventory([host.PRIVATE, host.STATE]), self.before)

    def test_first_migration_installs_route_and_units_in_one_transaction(self):
        host.deploy(NEW)
        self.assertEqual(source.current_sha(), NEW)
        self.assertIn(b'location = /api/orders', host.SNIPPET.read_bytes())
        for path in host.control_paths()[1:-1]:
            self.assertIn(str(source.CURRENT).encode(), path.read_bytes())
        self.assertFalse(host.PENDING.exists())
        self.assertFalse(host.MAINTENANCE.exists())
        self.assert_preserved()
        self.assertEqual(json.loads((host.BASE/'last-result.json').read_text())['verdict'], 'DEPLOYED')

    def test_private_merchant_file_is_loaded_by_resource_only(self):
        host.install_controls(NEW, merchant_file=True)
        for path in host.control_paths()[1:]:
            expected = path.parent.name == 'sac006-resource.service.d'
            self.assertEqual(('EnvironmentFile=' + str(host.PRIVATE/'merchant.env')) in path.read_text(), expected)

    def test_public_nginx_misrouting_restores_legacy_units_and_original_state(self):
        self.ready_mock.side_effect = [None, None, RuntimeError('nginx orders 404'), None, None]
        with self.assertRaisesRegex(RuntimeError, 'verified rollback'):
            host.deploy(NEW)
        self.assertFalse(source.CURRENT.exists())
        self.assertIn(b'location /api/ { return 404; }', host.SNIPPET.read_bytes())
        self.assertTrue(host.SNIPPET.read_text().startswith(host.GUARD))
        self.assertFalse(host.PENDING.exists())
        self.assert_preserved()

    def test_backup_failure_never_switches_source_and_rolls_back(self):
        self.backup_mock.side_effect = RuntimeError('backup inventory mismatch')
        with self.assertRaisesRegex(RuntimeError, 'verified rollback'):
            host.deploy(NEW)
        self.assertFalse(source.CURRENT.exists())
        self.assert_preserved()

    def test_rollback_failure_retains_pending_and_stops_services(self):
        self.ready_mock.side_effect = [None, RuntimeError('failed startup'), RuntimeError('rollback delayed beyond deadline')]
        with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_UNVERIFIED'):
            host.deploy(NEW)
        self.assertTrue(host.PENDING.exists())
        self.assertTrue(host.MAINTENANCE.exists())
        self.assertIn(('systemctl', 'stop', *host.LEGACY_SERVICES, *host.PRODUCT_SERVICES), self.calls)
        self.assert_preserved()

    def test_kill_between_pending_and_backup_recovers_without_network(self):
        self.backup_mock.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): host.deploy(NEW)
        self.assertTrue(host.PENDING.exists())
        self.manually_fetch_archive_mock.reset_mock()
        host.main(['--recover'])
        self.manually_fetch_archive_mock.assert_not_called()
        self.assertFalse(host.PENDING.exists())
        self.assertFalse(source.CURRENT.exists())
        self.assert_preserved()

    def test_kill_after_switch_recovery_restores_current_and_overrides(self):
        self.ready_mock.side_effect = [None, KeyboardInterrupt()]
        with self.assertRaises(KeyboardInterrupt): host.deploy(NEW)
        self.assertEqual(source.current_sha(), NEW)
        self.ready_mock.side_effect = None
        host.main(['--recover'])
        self.assertFalse(source.CURRENT.exists())
        self.assert_preserved()

    def test_recovery_failure_blocks_new_fetch(self):
        source.write_json(host.PENDING, self.pending())
        self.ready_mock.side_effect = RuntimeError('rollback failed')
        with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_UNVERIFIED'): host.deploy(NEW)
        self.manually_fetch_archive_mock.assert_not_called()
        self.assertTrue(host.PENDING.exists())
        self.assertTrue(host.MAINTENANCE.exists())

    def test_corrupt_verified_backup_fails_closed(self):
        directory = host.BACKUPS/'original'; directory.mkdir(parents=True)
        archive = directory/'preserved.tar'; archive.write_bytes(b'corrupted')
        pending = self.pending()
        pending['backup'] = {'path':str(archive), 'sha256': '0'*64}
        source.write_json(host.PENDING, pending)
        with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_UNVERIFIED'): host.main(['--recover'])
        self.restart_mock.assert_not_called()
        self.assertTrue(host.PENDING.exists())

    def test_service_that_did_not_stop_prevents_backup(self):
        self.run_mock.side_effect = lambda *args, **kwargs: 'active' if 'ActiveState' in args else ''
        with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_UNVERIFIED'): host.deploy(NEW)
        self.backup_mock.assert_not_called()
        self.assertFalse(source.CURRENT.exists())

    def test_failed_unit_with_no_main_or_control_process_can_be_recovered(self):
        self.run_mock.side_effect = lambda *args, **kwargs: 'failed' if 'ActiveState' in args else '0'
        host.stop()
        self.assert_preserved()

    def test_failed_unit_with_a_live_control_process_blocks_backup(self):
        def run(*args, **kwargs):
            if 'ActiveState' in args: return 'failed'
            if 'ControlPID' in args: return '123'
            return '0'
        self.run_mock.side_effect = run
        with self.assertRaisesRegex(RuntimeError, 'service did not quiesce'): host.stop()
        self.backup_mock.assert_not_called()

    def test_versioned_failed_cutover_rolls_back_exact_previous_release(self):
        source.CURRENT.symlink_to(source.RELEASES/OLD)
        self.previous.update(root=str(source.RELEASES/OLD), legacy=False)
        self.ready_mock.side_effect = [None, RuntimeError('startup failed'), None, None]
        with self.assertRaisesRegex(RuntimeError, 'verified rollback'): host.deploy(NEW)
        self.assertEqual(source.current_sha(), OLD)
        self.assert_preserved()

    def test_staged_source_tampering_blocks_before_downtime(self):
        self.archive_fingerprints_mock.return_value = {'integration/deploy/nginx-resource.conf': ('file', '0'*64)}
        with self.assertRaisesRegex(RuntimeError, 'staged source substituted'): host.deploy(NEW)
        self.backup_mock.assert_not_called()
        self.assertFalse(host.PENDING.exists())
        self.assertNotIn(('systemctl', 'stop', *source.SERVICES), self.calls)


    def test_boot_gate_blocks_public_routes_before_recovery(self):
        source.write_json(host.PENDING, self.pending())
        host.main(['--gate'])
        self.assertTrue(host.MAINTENANCE.exists())
        self.assertTrue(host.SNIPPET.read_bytes().startswith(host.GUARD.encode()))
        self.manually_fetch_archive_mock.assert_not_called()

    def test_recovery_units_have_valid_ordering_and_no_cycle(self):
        self.install_recovery_mock.side_effect = None
        # Exercise the real file writer; isolate all systemd commands.
        # Access the original function captured before setUp replaces it.
        INSTALL_RECOVERY()
        gate = host.GATE.read_text(); recovery = host.RECOVERY.read_text()
        self.assertIn('Before=nginx.service sac006-facilitator.service sac006-resource.service', gate)
        self.assertIn('--gate', gate)
        self.assertIn('After=network-online.target nginx.service sac006-facilitator.service sac006-resource.service', recovery)
        self.assertIn('--recover', recovery)
        if shutil.which('systemd-analyze'):
            for name in (*source.SERVICES, 'nginx'):
                (host.UNITS/(name+'.service')).write_text('[Unit]\nRequires=capture402-gate.service\nAfter=capture402-gate.service\n[Service]\nExecStart=/usr/bin/sleep 1\n')
            subprocess.run(['systemd-analyze', 'verify', str(host.GATE), str(host.RECOVERY),
                *[str(host.UNITS/(name+'.service')) for name in (*source.SERVICES, 'nginx')]],
                check=True, capture_output=True, text=True)


    def test_correct_cwd_cannot_hide_an_unapproved_absolute_entrypoint(self):
        original_readlink = host.os.readlink
        def readlink(path, *args, **kwargs):
            return str(host.LEGACY/'integration') if str(path).startswith('/proc/') else original_readlink(path, *args, **kwargs)
        with (mock.patch.object(source, 'run', side_effect=['active', '123']),
              mock.patch.object(host.os, 'readlink', side_effect=readlink),
              mock.patch.object(Path, 'read_bytes', return_value=b'node\0--experimental-strip-types\0/other/runtime.ts\0')):
            with self.assertRaisesRegex(RuntimeError, 'entrypoint differs'):
                host.health(self.previous)



class ServiceMigrationTests(unittest.TestCase):
    setUp = TransactionTests.setUp
    assert_preserved = TransactionTests.assert_preserved

    def migration_fixture(self):
        patch = mock.patch.object(source, 'SERVICES', tuple(host.LEGACY_SERVICES))
        patch.start(); self.addCleanup(patch.stop)
        self.previous['services'] = list(host.LEGACY_SERVICES)
        for index, name in enumerate(host.LEGACY_SERVICES):
            (host.UNITS / (name + '.service')).write_text('[Unit]\nDescription=legacy\nAfter=network-online.target sac006-facilitator.service\n[Service]\nUser=sac006\nEnvironmentFile=/etc/sac006/resource.env\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n')
        def run(*args, **kwargs):
            self.calls.append(args)
            name = args[-1]
            if 'FragmentPath' in args: return str(host.UNITS / (name + '.service'))
            if 'DropInPaths' in args:
                directory = host.UNITS / (name + '.service.d')
                return ' '.join(str(p) for p in directory.iterdir()) if directory.exists() else ''
            if 'UnitFileState' in args: return 'enabled' if name in host.LEGACY_SERVICES else ''
            if 'ActiveState' in args: return 'inactive'
            if 'MainPID' in args or 'ControlPID' in args: return '0'
            if 'LoadState' in args: return 'loaded' if (host.UNITS / (name + '.service')).is_file() else 'not-found'
            return ''
        self.run_mock.side_effect = run

    def test_names_migrate_only_after_backup_and_keep_user_environment_and_state(self):
        self.migration_fixture()
        host.deploy(NEW)
        self.assertEqual(source.SERVICES, host.PRODUCT_SERVICES)
        unit = (host.UNITS / (host.PRODUCT_SERVICES[1] + '.service')).read_text()
        self.assertIn('User=sac006', unit)
        self.assertIn('EnvironmentFile=/etc/sac006/resource.env', unit)
        self.assertIn('capture402-facilitator.service', unit)
        self.assertIn(('systemctl', 'disable', *host.LEGACY_SERVICES), self.calls)
        self.assertIn(('systemctl', 'enable', *host.PRODUCT_SERVICES), self.calls)
        self.assert_preserved()

    def test_startup_failure_restores_original_service_names_and_enablement(self):
        self.migration_fixture()
        self.restart_mock.side_effect = [RuntimeError('private diagnostic must not be logged'), None]
        with self.assertRaisesRegex(RuntimeError, 'verified rollback'): host.deploy(NEW)
        self.assertEqual(source.SERVICES, host.LEGACY_SERVICES)
        for name in host.PRODUCT_SERVICES: self.assertFalse((host.UNITS / (name + '.service')).exists())
        for name in host.LEGACY_SERVICES: self.assertIn(('systemctl', 'enable', name), self.calls)
        self.assertNotIn('private diagnostic', (host.BASE / 'last-failure.json').read_text())
        self.assert_preserved()

    def test_partial_name_installation_is_guarded_and_recovers_offline(self):
        self.migration_fixture()
        original = host.atomic_bytes
        def interrupted(path, data, mode=0o644):
            original(path, data, mode)
            if path == host.UNITS / (host.PRODUCT_SERVICES[0] + '.service'): raise KeyboardInterrupt()
        with mock.patch.object(host, 'atomic_bytes', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt): host.deploy(NEW)
        self.assertTrue(host.PENDING.exists())
        self.assertIn(host.GATE.name, (host.UNITS / (host.PRODUCT_SERVICES[0] + '.service')).read_text())
        source.SERVICES = host.LEGACY_SERVICES
        self.manually_fetch_archive_mock.reset_mock()
        host.main(['--recover'])
        self.manually_fetch_archive_mock.assert_not_called()
        self.assertFalse(host.PENDING.exists())
        self.assert_preserved()

    def test_alias_layout_is_refused_before_service_stop(self):
        self.migration_fixture()
        path = host.UNITS / (host.LEGACY_SERVICES[0] + '.service')
        path.write_text(path.read_text() + 'Alias=external.service\n')
        with self.assertRaisesRegex(RuntimeError, 'aliases require'): host.deploy(NEW)
        self.backup_mock.assert_not_called()
        self.assertFalse(host.PENDING.exists())
        self.assert_preserved()

    def test_unavailable_systemd_is_not_mistaken_for_absent_service(self):
        with mock.patch.object(source, 'run', side_effect=subprocess.CalledProcessError(1, ['systemctl'], output='')):
            with self.assertRaisesRegex(RuntimeError, 'cannot determine backend'): host.stop()


class BackupTests(unittest.TestCase):
    def test_backup_round_trip_preserves_busy_symlinks_metadata_and_original_wires(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root); directory = base/'state'; directory.mkdir()
            (directory/'wire.json').write_bytes(b'{"wire":"original"}')
            (directory/'order.busy').write_bytes(b'original lock'); (directory/'order.busy').chmod(0o600)
            (directory/'link').symlink_to('wire.json')
            expected = host.inventory([directory])
            archive = base/'backup.tar'
            host.create_backup(archive, expected)
            host.verify_backup(archive, expected)
            (directory/'order.busy').write_bytes(b'tampered')
            with self.assertRaisesRegex(RuntimeError, 'backup differs'):
                host.verify_backup(archive, host.inventory([directory]))

    def test_unverified_tar_bytes_do_not_count_as_backup(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'bad.tar'; path.write_bytes(b'broken')
            with self.assertRaises(tarfile.ReadError): host.verify_backup(path, {})


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.resource = self.root/'resource.env'
        self.resource.write_text('SAC006_BEARER_TOKEN=' + 'f'*64 + '\n')
        patch = mock.patch.object(host, 'PRIVATE', self.root)
        patch.start(); self.addCleanup(patch.stop)

    def test_missing_token_is_provisioned_once_without_changing_existing_env_or_keys(self):
        original = self.resource.read_bytes()
        (self.root/'key').write_bytes(b'original key')
        self.assertTrue(host.provision_merchant())
        env = self.root/'merchant.env'; token = env.read_bytes()
        self.assertEqual(env.stat().st_mode & 0o777, 0o600)
        self.assertTrue(host.provision_merchant())
        self.assertEqual(env.read_bytes(), token)
        self.assertEqual(self.resource.read_bytes(), original)
        self.assertEqual((self.root/'key').read_bytes(), b'original key')
        self.assertNotIn(b'f'*64, token)

    def test_existing_independent_token_is_preserved(self):
        self.resource.write_text(self.resource.read_text() + 'SAC006_MERCHANT_TOKEN=' + 'm'*64 + '\n')
        self.assertFalse(host.provision_merchant())
        self.assertFalse((self.root/'merchant.env').exists())

    def test_reusing_facilitator_authority_is_rejected(self):
        self.resource.write_text(self.resource.read_text() + 'SAC006_MERCHANT_TOKEN=' + 'f'*64 + '\n')
        with self.assertRaisesRegex(RuntimeError, 'independent'): host.provision_merchant()
        self.assertFalse((self.root/'merchant.env').exists())

    def test_symlinked_private_token_is_rejected(self):
        (self.root/'merchant.env').symlink_to(self.resource)
        with self.assertRaisesRegex(RuntimeError, 'symlink'): host.provision_merchant()



class RetryTests(unittest.TestCase):
    def test_delayed_startup_and_network_errors_are_retried(self):
        with (mock.patch.object(host, 'health', side_effect=[ConnectionRefusedError(), RuntimeError('unprovisioned'), None]) as health,
              mock.patch.object(host.time, 'sleep') as sleep):
            host.ready({'sha': OLD})
        self.assertEqual(health.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_rollback_readiness_deadline_is_bounded(self):
        with (mock.patch.object(host, 'health', side_effect=RuntimeError('still booting')),
              mock.patch.object(host.time, 'monotonic', side_effect=[0, 91]), mock.patch.object(host.time, 'sleep') as sleep):
            with self.assertRaisesRegex(RuntimeError, 'readiness exhausted'): host.ready({'sha': OLD})
        sleep.assert_not_called()


class AcceptanceTests(PolicyFixture):
    def test_owner_and_stale_head_cannot_approve(self):
        for login, revision in [('starPaw', OLD), ('gwinpin', NEW), ('independent', NEW)]:
            self.reviews = [self.review(login, revision)]
            with mock.patch.object(source, 'run', side_effect=self.gh):
                with self.assertRaisesRegex(RuntimeError, 'eligible exact-head'): launcher.require_acceptance(NEW)

    def test_gwinpin_agent_approval_on_exact_head_is_eligible(self):
        with mock.patch.object(source, 'run', side_effect=self.gh):
            self.assertEqual(launcher.require_acceptance(NEW)['reviewer'], 'gwinpin')

    def test_latest_gwinpin_changes_requested_blocks_deploy(self):
        self.reviews += [self.review('gwinpin', OLD, 'CHANGES_REQUESTED')]
        with mock.patch.object(source, 'run', side_effect=self.gh):
            with self.assertRaisesRegex(RuntimeError, 'eligible exact-head'): launcher.require_acceptance(NEW)

    def test_accepted_merge_must_preserve_reviewed_tree(self):
        self.reviewed_tree = 'different'
        with mock.patch.object(source, 'run', side_effect=self.gh):
            with self.assertRaisesRegex(RuntimeError, 'merged tree differs'): launcher.require_acceptance(NEW)


class MerchantReadinessTests(unittest.TestCase):
    def test_enabled_merchant_requires_real_application_authentication_rejection(self):
        with mock.patch.object(source, 'response', return_value=(401, b'{"error":"missing bearer token"}', {})) as response:
            host.merchant_boundary('https://capture402.xyz', required=True)
        self.assertEqual(response.call_args.kwargs['headers'], {'Origin':'https://capture402.xyz'})
        with mock.patch.object(source, 'response', return_value=(503, b'{"error":"merchant operations disabled"}', {})):
            with self.assertRaisesRegex(RuntimeError, 'authentication boundary'): host.merchant_boundary('https://capture402.xyz', required=True)

    def test_nginx_status_or_order_lookup_cannot_substitute_for_authentication(self):
        for status, body in [(401, b'<html>nginx</html>'), (409, b'{"error":"order unavailable"}')]:
            with mock.patch.object(source, 'response', return_value=(status, body, {})):
                with self.assertRaises((RuntimeError, ValueError)):
                    host.merchant_boundary('https://capture402.xyz', required=True)



class LauncherRecoveryTests(unittest.TestCase):
    def test_offline_recovery_runs_before_any_github_fetch(self):
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            if args == ('git', 'remote', 'get-url', 'origin'):
                return 'https://github.com/starPaw/svm-auth-capture.git'
            if args == ('git', 'status', '--porcelain'): return ''
            raise RuntimeError('network unavailable')
        with (mock.patch.object(source, 'run', side_effect=run),
              mock.patch.object(launcher.sys, 'argv', ['deploy.sh']),
              mock.patch.object(launcher.subprocess, 'run', return_value=type('Result', (), {'stdout':'RECOVERED'})()) as remote):
            with self.assertRaisesRegex(RuntimeError, 'recovered offline'): launcher.main()
        self.assertEqual(len(calls), 2)
        self.assertIn('capture402-recovery.service', remote.call_args.args[0][-1])

    def test_disconnect_does_not_request_pipe_or_remote_payment_execution(self):
        self.assertNotIn('--pipe', launcher.INSTALLER)
        self.assertIn('RuntimeMaxSec=900', launcher.INSTALLER)
        self.assertIn('OnFailure=capture402-recovery.service', launcher.INSTALLER)
        self.assertNotIn('SOLANA_RPC_URL', launcher.INSTALLER)



if __name__ == '__main__': unittest.main()
