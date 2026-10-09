"""Synthetic operator evidence failure/crash tests. No live services or stores."""
from contextlib import redirect_stdout, redirect_stderr, nullcontext
from concurrent.futures import ThreadPoolExecutor
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import deploy_dev as dev
import test_deploy_dev as fixtures

SECRET = 'https://private.invalid/?api-key=SECRET_WIRE_CAPABILITY'


class AttemptTests(fixtures.TransactionTests):
    def setUp(self):
        super().setUp()
        self.prod = self.stack.enter_context(mock.patch.object(dev, 'production', return_value='f' * 64))

    def test_stale_already_current_with_original_unknown_closes_gate_and_reports_new_attempt(self):
        self.write(dev.BASE / 'last-result.json', {'verdict': 'ALREADY_CURRENT', 'sha': fixtures.OLD})
        self.write(self.journal / 'original.json', {**dict.fromkeys(('messageHash', 'transactionBase64', 'blockhash', 'payment', 'payer', 'expectedHeld', 'expectedRefundable'), 'synthetic-original'), 'signature': 'original', 'operation': 'authorize', 'attempts': [{'outcome': {'result': 'unresolved'}}]})
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, '^unresolved dev submission$'): dev.deploy(fixtures.NEW, object())
        latest = dev.latest_attempt()
        self.assertEqual(latest['gate'], 'PAYMENT_JOURNALS')
        self.assertEqual(latest['outcome'], 'FAILED')
        self.assertEqual(latest['production']['classification'], 'unchanged')
        self.assertEqual(dev.safe_last_result()['verdict'], 'ALREADY_CURRENT')
        self.assertEqual(dev.current(), fixtures.OLD)
        self.assert_preserved(before)
        self.assertNotIn('stop', self.calls)
        self.assertNotIn('freeze', self.calls)
        self.assertIn('Payment journals', dev.failure_summary())

    def test_every_preflight_gate_persists_safe_failure(self):
        for target, gate in [('units', 'UNITS'), ('health', 'HEALTH'), ('production', 'PRODUCTION'),
                             ('clean_operations', 'PAYMENT_JOURNALS'), ('rpc', 'RPC'), ('stage', 'STAGING'),
                             ('install_gate', 'GATE')]:
            with self.subTest(target=target), mock.patch.object(dev, target, side_effect=OSError(SECRET)):
                with self.assertRaises(OSError): dev.deploy(fixtures.NEW, object())
                latest = dev.latest_attempt()
                self.assertEqual(latest['gate'], gate)
                self.assertEqual(latest['outcome'], 'FAILED')
                self.assertNotIn('SECRET', json.dumps(latest))
        self.assertNotIn('stop', self.calls)

    def test_launch_failure_is_attributable_and_primary_cli_safe(self):
        out, err = io.StringIO(), io.StringIO()
        a = dev.Attempt.create(fixtures.NEW)
        with mock.patch.object(dev, 'locked', side_effect=nullcontext), mock.patch.object(dev.Attempt, 'create', return_value=a), mock.patch.object(dev.os, 'geteuid', return_value=0), mock.patch.object(dev.subprocess, 'run', side_effect=OSError(SECRET)), redirect_stdout(out), redirect_stderr(err):
            with self.assertRaisesRegex(RuntimeError, 'gate=LAUNCH'):
                fixtures.cli.main(['dev', 'deploy', fixtures.NEW])
        r = dev.latest_attempt()
        self.assertEqual(r['outcome'], 'FAILED')
        self.assertEqual(r['unit'], dev.RELEASE_UNIT_PREFIX + r['id'])
        self.assertNotIn('SECRET', out.getvalue() + err.getvalue())
        self.assertNotIn('stop', self.calls)

    def test_worker_payment_gate_is_not_overwritten_by_dispatch(self):
        def worker(args, **kwargs):
            a = dev.Attempt.load(args[-1], fixtures.NEW)
            a.step('payment', invocation='e' * 32)
            a.finish('FAILED')
            return subprocess.CompletedProcess(args, 1, stdout=SECRET, stderr=SECRET)
        out, err = io.StringIO(), io.StringIO()
        a = dev.Attempt.create(fixtures.NEW)
        with mock.patch.object(dev, 'locked', side_effect=nullcontext), mock.patch.object(dev.Attempt, 'create', return_value=a), mock.patch.object(dev.os, 'geteuid', return_value=0), mock.patch.object(dev.subprocess, 'run', side_effect=worker), redirect_stdout(out), redirect_stderr(err):
            with self.assertRaisesRegex(dev.OperationBlocked, 'Payment journals'): dev.dispatch(['deploy', fixtures.NEW])
        self.assertEqual(dev.latest_attempt()['gate'], 'PAYMENT_JOURNALS')
        self.assertEqual(dev.latest_attempt()['invocation'], 'e' * 32)
        self.assertNotIn('SECRET', out.getvalue() + err.getvalue())

    def test_waiter_loss_does_not_overwrite_running_worker_checkpoint(self):
        a = dev.Attempt.create(fixtures.NEW)
        def lost_waiter(args, **kwargs):
            worker = dev.Attempt.load(args[-1], fixtures.NEW)
            worker.step('payment', invocation='e' * 32)
            raise KeyboardInterrupt()
        with mock.patch.object(dev, 'locked', side_effect=nullcontext), mock.patch.object(dev.Attempt, 'create', return_value=a), mock.patch.object(dev.os, 'geteuid', return_value=0), mock.patch.object(dev.subprocess, 'run', side_effect=lost_waiter), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(dev.OperationBlocked, 'INTERRUPTED_UNKNOWN'): dev.dispatch(['deploy', fixtures.NEW])
        self.assertEqual(dev.read_attempt(a.record['id'])['outcome'], 'INCOMPLETE')
        self.assertEqual(dev.latest_attempt()['gate'], 'PAYMENT_JOURNALS')
        worker = dev.Attempt.load(a.record['id']); worker.finish('FAILED')
        self.assertEqual(dev.latest_attempt()['outcome'], 'FAILED')

    def test_semantically_corrupt_success_is_not_presented_as_success(self):
        a = dev.Attempt.create(fixtures.NEW)
        a.record.update(outcome='DEPLOYED', endedNs=a.record['startedNs'] + 1)
        a.save()
        self.assertEqual(dev.latest_attempt()['outcome'], 'INCOMPLETE')

    def test_lock_contention_retains_separate_attempt_without_effects(self):
        with dev.locked():
            with self.assertRaises(BlockingIOError): dev.deploy(fixtures.NEW, object())
        self.assertEqual(dev.latest_attempt()['gate'], 'LOCK')
        self.assertEqual(dev.latest_attempt()['outcome'], 'FAILED')
        self.assertNotIn('stop', self.calls)

    def test_parallel_and_same_sha_allocation_never_cross_associate(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            attempts = list(pool.map(lambda _: dev.Attempt.create(fixtures.NEW), range(24)))
        self.assertEqual(len({a.record['id'] for a in attempts}), 24)
        newest = max(attempts, key=lambda a: a.record['id'])
        for a in sorted(attempts, key=lambda a: a.record['id'], reverse=True):
            a.step('payment'); a.finish('FAILED')
            self.assertEqual(dev.read_attempt(a.record['id'])['id'], a.record['id'])
        self.assertEqual(dev.latest_attempt()['id'], newest.record['id'])

    def test_prior_failure_then_later_success_latest_is_new(self):
        a = dev.Attempt.create(fixtures.NEW); a.step('payment'); a.finish('FAILED')
        dev.deploy(fixtures.NEW, object())
        self.assertEqual(dev.latest_attempt()['outcome'], 'DEPLOYED')
        self.assertEqual(dev.read_attempt(a.record['id'])['outcome'], 'FAILED')
        dev.deploy(fixtures.NEW, object())
        self.assertEqual(dev.latest_attempt()['outcome'], 'ALREADY_CURRENT')

    def test_initial_record_disk_full_permission_replace_and_fsync_fail_before_effects(self):
        for operation in ('atomic_bytes',):
            for error in (OSError(28, SECRET), PermissionError(SECRET)):
                with self.subTest(error=type(error).__name__), mock.patch.object(dev.host, operation, side_effect=error):
                    with self.assertRaises(OSError): dev.deploy(fixtures.NEW, object())
                    self.assertEqual(dev.latest_attempt()['outcome'], 'INCOMPLETE')
        for target in ('replace', 'fsync'):
            with self.subTest(target=target), mock.patch.object(dev.os, target, side_effect=OSError(SECRET)):
                with self.assertRaises(OSError): dev.deploy(fixtures.NEW, object())
        self.assertNotIn('stop', self.calls); self.assertNotIn('freeze', self.calls)

    def test_partial_atomic_write_replace_and_directory_fsync_are_incomplete(self):
        for failure_call in (1, 2):
            a = dev.Attempt.create(fixtures.NEW)
            original = dev.os.fsync
            calls = []
            def fsync(fd):
                calls.append(fd)
                if len(calls) == failure_call: raise OSError(28, SECRET)
                return original(fd)
            with mock.patch.object(dev.os, 'fsync', side_effect=fsync):
                with self.assertRaises(OSError): a.step('launch')
            self.assertEqual(dev.latest_attempt()['outcome'], 'INTERRUPTED_UNKNOWN')
        a = dev.Attempt.create(fixtures.NEW)
        with mock.patch.object(dev.os, 'replace', side_effect=PermissionError(SECRET)):
            with self.assertRaises(PermissionError): a.step('launch')
        self.assertEqual(dev.read_attempt(a.record['id'])['phase'], 'allocated')

    def test_reporting_failure_after_stop_does_not_prevent_rollback(self):
        original = dev.Attempt.save
        def save(a):
            if 'stop' in self.calls: raise OSError(SECRET)
            return original(a)
        with mock.patch.object(dev.Attempt, 'save', save), mock.patch.object(dev, 'start', side_effect=lambda sha: (_ for _ in ()).throw(RuntimeError(SECRET)) if sha == fixtures.NEW else self.start_pair(sha)):
            with self.assertRaisesRegex(RuntimeError, 'previous code restored'): dev.deploy(fixtures.NEW, object())
        self.assertEqual(dev.current(), fixtures.OLD)
        self.assertFalse(dev.PENDING.exists())
        self.assertEqual(dev.latest_attempt()['outcome'], 'INTERRUPTED_UNKNOWN')

    def test_failed_last_failure_reporting_cannot_hide_rollback_or_original_gate(self):
        original = dev.source.write_json
        def write(path, value):
            if path.name in ('last-failure.json', 'last-result.json'): raise OSError(SECRET)
            return original(path, value)
        with mock.patch.object(dev.source, 'write_json', side_effect=write), mock.patch.object(dev, 'start', side_effect=lambda sha: (_ for _ in ()).throw(RuntimeError(SECRET)) if sha == fixtures.NEW else self.start_pair(sha)):
            with self.assertRaisesRegex(RuntimeError, 'previous code restored'): dev.deploy(fixtures.NEW, object())
        self.assertEqual(dev.latest_attempt()['outcome'], 'ROLLED_BACK')
        self.assertEqual(dev.latest_attempt()['gate'], 'START')
        self.assertEqual(dev.current(), fixtures.OLD)

    def test_cutover_and_freeze_crash_boundaries_are_explicit(self):
        for phase in ('freeze', 'stop', 'switch', 'start'):
            with self.subTest(phase=phase), mock.patch.object(dev, phase, side_effect=RuntimeError(SECRET)):
                with self.assertRaises(RuntimeError): dev.deploy(fixtures.NEW, object())
                self.assertIn(dev.latest_attempt()['outcome'], ('FAILED', 'ROLLED_BACK', 'ROLLBACK_UNVERIFIED'))
                self.assertNotIn('SECRET', json.dumps(dev.latest_attempt()))
            if dev.PENDING.exists():
                dev.recover()

    def test_crash_after_freeze_stop_switch_start_preserves_recovery_order(self):
        for phase in ('freeze', 'stop', 'switch', 'start'):
            original = getattr(dev, phase)
            def crash(*args, **kwargs):
                original(*args, **kwargs)
                # Fail only the candidate transition; rollback of previous code works.
                if phase != 'start' or args[0] == fixtures.NEW:
                    raise SystemExit(77)
            before = self.snapshot()
            with self.subTest(phase=phase), mock.patch.object(dev, phase, side_effect=crash):
                with self.assertRaises(BaseException): dev.deploy(fixtures.NEW, object())
            if dev.PENDING.exists(): dev.recover()
            self.assertEqual(dev.current(), fixtures.OLD)
            self.assert_preserved(before)
            self.assertFalse(dev.PENDING.exists())

    def test_unknown_busy_and_orphan_reservation_still_block_with_safe_attempt(self):
        for path in (self.orders / 'id.json.busy', self.journal / 'unknown.json', dev.STATE / 'restaurant/reclaim/orphan.lock'):
            with self.subTest(path=path.name):
                path.write_text('{}')
                before = self.snapshot()
                with self.assertRaises(Exception): dev.deploy(fixtures.NEW, object())
                self.assertEqual(dev.latest_attempt()['gate'], 'PAYMENT_JOURNALS')
                self.assert_preserved(before)
                self.assertNotIn('stop', self.calls)
                path.unlink()

    def test_offline_recovery_survives_all_operator_reporting_failure(self):
        a = dev.Attempt.create(fixtures.NEW)
        self.write(dev.PENDING, {'previous': fixtures.OLD, 'target': fixtures.NEW, 'production': 'f' * 64,
                                'stage': 'freezing', 'attemptId': a.record['id']})
        with mock.patch.object(dev.Attempt, 'save', side_effect=OSError(SECRET)), mock.patch.object(dev, 'report_json', return_value=False):
            self.assertTrue(dev.recover())
        self.assertFalse(dev.PENDING.exists())
        self.policy.assert_not_called()

    def test_unverified_rollback_can_later_be_reported_recovered(self):
        a = dev.Attempt.create(fixtures.NEW); a.finish('ROLLBACK_UNVERIFIED')
        self.write(dev.PENDING, {'previous': fixtures.OLD, 'target': fixtures.NEW, 'production': 'f' * 64,
                                'stage': 'freezing', 'attemptId': a.record['id']})
        self.assertTrue(dev.recover())
        self.assertEqual(dev.latest_attempt()['outcome'], 'RECOVERED')

    def test_corrupt_partial_oversized_and_secret_records_are_never_success(self):
        for data in (b'{', b'null', b'x' * 32769):
            a = dev.Attempt.create(fixtures.NEW); a.path.write_bytes(data)
            self.assertEqual(dev.latest_attempt()['outcome'], 'INCOMPLETE')
        a = dev.Attempt.create(fixtures.NEW)
        for field in ('unit', 'requestedSha', 'gate', 'outcome', 'production'):
            bad = dict(a.record); bad[field] = SECRET
            a.path.write_text(json.dumps(bad))
            self.assertNotIn('SECRET', json.dumps(dev.latest_attempt()))
            self.assertEqual(dev.latest_attempt()['outcome'], 'INCOMPLETE')
        self.assertFalse(dev.PENDING.exists())

    def test_unavailable_evidence_cannot_smuggle_secret_fields(self):
        a = dev.Attempt.create(fixtures.NEW)
        a.record['production']['before'] = {'scope': 'production-config-state-current-routing-services-v1',
            'collectedNs': 1, 'state': 'unavailable', 'sha256': SECRET}
        a.save()
        self.assertEqual(dev.latest_attempt()['outcome'], 'INCOMPLETE')
        self.assertNotIn('SECRET', json.dumps(dev.latest_attempt()))

    def test_symlink_record_and_traversal_rejected(self):
        a = dev.Attempt.create(fixtures.NEW); a.path.unlink(); a.path.symlink_to(self.journal / 'secret')
        with self.assertRaises(Exception): a.save()
        self.assertEqual(dev.latest_attempt()['outcome'], 'INCOMPLETE')
        with self.assertRaises(RuntimeError): dev.Attempt.load('../private')

    def test_permissions_and_retention_are_bounded_without_deletion(self):
        a = dev.Attempt.create(fixtures.NEW)
        self.assertEqual(a.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(a.path.parent.stat().st_mode & 0o777, 0o700)
        root = a.path.parent.parent
        for n in range(4095): (root / (f'{n:020d}-' + 'a' * 32)).mkdir()
        with self.assertRaisesRegex(RuntimeError, 'retention capacity'): dev.Attempt.create(fixtures.NEW)
        self.assertTrue(a.path.exists())

    def test_missing_baseline_and_changed_production_remain_explicit_noncausal(self):
        a = dev.Attempt.create(fixtures.NEW)
        self.prod.side_effect = OSError(SECRET)
        a.finish('FAILED')
        self.assertEqual(dev.latest_attempt()['production']['classification'], 'unavailable')
        self.prod.side_effect = None
        a = dev.Attempt.create(fixtures.NEW); a.record['production']['before'] = dev.observation()
        self.prod.return_value = 'e' * 64; a.finish('FAILED')
        r = dev.latest_attempt()['production']
        self.assertEqual(r['classification'], 'changed')
        self.assertEqual(r['causality'], 'not-established')

    def test_sigkill_keeps_durable_incomplete_with_no_payment_effects(self):
        script = '''import sys, time, os
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import deploy_dev as d
d.BASE=Path(sys.argv[2])
d.trusted=lambda *args: None  # Synthetic non-root storage fixture only.
a=d.Attempt.create('b'*40)
a.step('payment')
print(a.record['id'], flush=True)
time.sleep(60)
'''
        child = subprocess.Popen([sys.executable, '-B', '-c', script, str(Path(dev.__file__).parent), str(dev.BASE)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ident = child.stdout.readline().strip()
            self.assertRegex(ident, dev.ATTEMPT_RE)
            child.kill(); child.communicate(timeout=5)
            self.assertEqual(dev.latest_attempt()['outcome'], 'INTERRUPTED_UNKNOWN')
            self.assertEqual(dev.latest_attempt()['gate'], 'PAYMENT_JOURNALS')
        finally:
            if child.poll() is None: child.kill()
            child.communicate(timeout=5)

    def test_old_status_safe_and_corrupt_last_result_unknown(self):
        self.write(dev.BASE / 'last-result.json', {'verdict': 'ALREADY_CURRENT', 'sha': fixtures.OLD, 'extra': SECRET})
        self.assertEqual(dev.safe_last_result(), {'verdict': 'ALREADY_CURRENT', 'sha': fixtures.OLD})
        (dev.BASE / 'last-result.json').write_text('{')
        self.assertEqual(dev.safe_last_result(), {'verdict': 'UNAVAILABLE'})


class ProductionObservationTests(fixtures.DevFixture):
    def test_process_cwd_entrypoint_and_routing_are_sanitized_and_scoped(self):
        def run(*args, **kwargs):
            field = args[args.index('-p') + 1]
            return {'MainPID': '123', 'ActiveState': 'active', 'FragmentPath': '',
                    'InvocationID': 'e' * 32, 'ExecStart': SECRET,
                    'WorkingDirectory': str(dev.source.RELEASES / fixtures.OLD / 'integration')}[field]
        with mock.patch.object(dev.source, 'run', side_effect=run), mock.patch.object(dev.host, 'inventory', return_value={SECRET: ['file', 'f' * 64]}), mock.patch.object(dev.os, 'readlink', return_value=str(dev.source.RELEASES / fixtures.OLD / 'integration')), mock.patch.object(dev.Path, 'read_bytes', return_value=SECRET.encode()):
            r = dev.observation()
        self.assertEqual(r['state'], 'available')
        self.assertNotIn('SECRET', json.dumps(r))
        self.assertEqual(set(r['processes']), set((*dev.host.LEGACY_SERVICES, *dev.host.PRODUCT_SERVICES)))
        for item in r['processes'].values():
            self.assertEqual(item['applicationSha'], fixtures.OLD)
            self.assertEqual(item['cwd'], 'release-integration')
            self.assertRegex(item['entrypointSha256'], '[a-f0-9]{64}')
        a = dev.Attempt.create(fixtures.NEW)
        a.record['production']['before'] = r
        with mock.patch.object(dev, 'observation', return_value=r): a.finish('FAILED')
        self.assertEqual(dev.latest_attempt()['production']['classification'], 'unchanged')

    def test_legacy_transaction_production_digest_contract_is_unchanged(self):
        names = (*dev.host.LEGACY_SERVICES, *dev.host.PRODUCT_SERVICES)
        services = {name: {'MainPID': '123', 'ActiveState': 'active', 'FragmentPath': ''} for name in names}
        files = {'synthetic-root': ('file', 'f' * 64, 0o600, 0, 0)}
        expected = hashlib.sha256(json.dumps({'services': services, 'files': files}, sort_keys=True).encode()).hexdigest()
        def run(*args, **kwargs):
            return services[args[-1]][args[args.index('-p') + 1]]
        with mock.patch.object(dev.source, 'run', side_effect=run), mock.patch.object(dev.host, 'inventory', return_value=files), mock.patch.object(dev.os, 'readlink', side_effect=AssertionError('reporting must not affect legacy gate')):
            self.assertEqual(dev.production(), expected)

    def test_unavailable_process_inventory_has_no_raw_exception(self):
        with mock.patch.object(dev.source, 'run', side_effect=RuntimeError(SECRET)):
            r = dev.observation()
        self.assertEqual(r['state'], 'unavailable')
        self.assertNotIn('SECRET', json.dumps(r))


def load_tests(loader, tests, pattern):
    # Reuse fixtures, without rerunning inherited tests from the existing suite.
    return unittest.TestSuite(cls(name) for cls in (AttemptTests, ProductionObservationTests)
                              for name in cls.__dict__ if name.startswith('test_'))
