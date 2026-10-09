"""Dev deployment failures, original-state preservation, and eligibility attacks."""
from contextlib import ExitStack
import gzip
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import deploy_dev as dev
import deploy_demo as source
import host_cli as cli
import release_policy as policy
from test_deploy_policy import PolicyFixture, OLD, NEW


class DevPolicyTests(PolicyFixture):
    def setUp(self):
        super().setUp()
        self.main = OLD
        self.pull.update(state='open', merged_at=None, mergeable=True, merge_commit_sha='c' * 40,
                         head={'sha': NEW, 'ref': 'codex/app', 'repo': {'full_name': policy.REPOSITORY}},
                         base={'ref': 'main', 'sha': OLD, 'repo': {'full_name': policy.REPOSITORY}})
        self.reviews = [self.review('gwinpin', NEW)]
        self.run.update(event='pull_request', pull_requests=[{'number': 1}])

    def api(self, route):
        if '/git/ref/heads/codex' in route: return {'object': {'sha': NEW}}
        if '/compare/' in route: return {'status': 'ahead', 'behind_by': 0}
        if route.endswith('/pulls/1'): return self.pull
        if '/git/commits/' in route: return {'tree': {'sha': 'tree'}}
        return super().api(route)

    def test_exact_reviewed_branch_is_eligible(self):
        receipt = policy.verify_dev(NEW, self.api)
        self.assertEqual((receipt['branch'], receipt['sha'], receipt['ciRun']), ('codex/app', NEW, 3))

    def test_main_uses_existing_gate(self):
        with mock.patch.object(policy, 'verify', return_value={'sha': OLD}) as verify:
            self.assertEqual(policy.verify_dev(OLD, self.api)['branch'], 'main')
            verify.assert_called_once_with(OLD, self.api)

    def test_stale_owner_or_requested_change_blocks_dev(self):
        for reviews in ([self.review('gwinpin', OLD)], [self.review('starPaw', NEW)],
                        [self.review('gwinpin', NEW, 'DISMISSED')],
                        [self.review('gwinpin', NEW), self.review('other', OLD, 'CHANGES_REQUESTED')]):
            self.reviews = reviews
            with self.assertRaisesRegex(RuntimeError, 'approval'): policy.verify_dev(NEW, self.api)

    def test_foreign_fork_or_closed_pr_blocks_dev(self):
        for value in ('foreign/repo', None):
            self.pull['head']['repo']['full_name'] = value
            with self.assertRaisesRegex(RuntimeError, 'same-repository'): policy.verify_dev(NEW, self.api)
        self.pull['head']['repo']['full_name'] = policy.REPOSITORY
        self.pull['state'] = 'closed'
        with self.assertRaises(RuntimeError): policy.verify_dev(NEW, self.api)

    def test_ci_failure_skips_duplicates_and_wrong_pr_block(self):
        for jobs in ([self.jobs[0]], self.jobs + [self.jobs[0]], [{**j, 'conclusion': 'skipped'} for j in self.jobs]):
            original = self.jobs; self.jobs = jobs
            with self.assertRaises(RuntimeError): policy.verify_dev(NEW, self.api)
            self.jobs = original
        for change in ({'conclusion': 'failure'}, {'pull_requests': []}, {'event': 'push'}, {'head_sha': OLD}):
            original = dict(self.run); self.run.update(change)
            with self.assertRaises(RuntimeError): policy.verify_dev(NEW, self.api)
            self.run = original

    def test_moved_main_branch_or_different_merge_tree_blocks(self):
        api = self.api
        for suffix, value in (('/compare/', {'status': 'diverged', 'behind_by': 1}),
                              ('/git/ref/heads/codex', {'object': {'sha': OLD}}),
                              ('/git/commits/' + 'c' * 40, {'tree': {'sha': 'different'}})):
            def changed(route): return value if suffix in route else api(route)
            with self.assertRaises(RuntimeError): policy.verify_dev(NEW, changed)


class DevFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for name, value in {'BASE': self.root, 'RELEASES': self.root / 'releases', 'CURRENT': self.root / 'current',
                            'PENDING': self.root / 'transaction.json', 'PRIVATE': self.root / 'private',
                            'STATE': self.root / 'state', 'PERMIT': self.root / 'permit', 'UNITS': self.root / 'units',
                            'CGROUP': self.root / 'cgroups'}.items():
            self.stack.enter_context(mock.patch.object(dev, name, value))
        for directory in (dev.RELEASES, dev.PRIVATE, dev.STATE, dev.UNITS): directory.mkdir()
        for sha in (OLD, NEW):
            (dev.RELEASES / sha).mkdir()
            record = dev.RELEASES / sha / source.RECORD
            record.parent.mkdir(parents=True)
            record.write_text('{"network":{"genesis_hash":"devnet"},"program":{"program_id":"program"}}')
        dev.CURRENT.symlink_to(dev.RELEASES / OLD)
        for role, values in {
            'facilitator': {'SAC006_FACILITATOR_JOURNAL_DIR': dev.STATE / 'facilitator/journal'},
            'restaurant': {'SAC006_STORE_DIR': dev.STATE / 'restaurant/operation-store',
                           'SAC006_RECLAIM_JOURNAL_DIR': dev.STATE / 'restaurant/reclaim'}}.items():
            (dev.PRIVATE / (role + '.env')).write_text(''.join(k + '=' + str(v) + '\n' for k, v in values.items()))
            for path in values.values(): path.mkdir(parents=True)
        (dev.STATE / 'restaurant/operation-store-restaurant').mkdir()
        self.stack.enter_context(mock.patch.object(dev, 'trusted'))
        self.journal = dev.STATE / 'facilitator/journal'
        self.orders = dev.STATE / 'restaurant/operation-store-restaurant'

    def write(self, path, value): path.write_text(json.dumps(value))

    def snapshot(self): return dev.host.inventory([dev.PRIVATE, dev.STATE])


class JournalTests(DevFixture):
    def test_finalized_journals_and_completed_stores_are_read_only(self):
        self.write(self.journal / 'sig.json', {**dict.fromkeys(('messageHash', 'transactionBase64', 'blockhash', 'payment', 'payer', 'expectedHeld', 'expectedRefundable'), 'original'), 'signature': 'sig', 'operation': 'authorize', 'attempts': [{'outcome': {'result': 'finalized-succeeded'}}]})
        self.write(dev.STATE / 'restaurant/operation-store/fp.json', {'status': 'completed'})
        self.write(self.orders / 'id.json', {'status': 'active', 'events': [{'action': 'authorize', 'status': 'finalized', 'transactionBase64': 'original'}]})
        self.write(self.orders / 'id.json.authorize.lock', {'action': 'authorize', 'status': 'prepared', 'transactionBase64': 'original'})
        before = self.snapshot(); dev.clean_operations()
        self.assertEqual(before, self.snapshot())

    def test_terminal_outcome_without_original_wire_is_malformed(self):
        self.write(self.journal / 'sig.json', {'attempts': [{'outcome': {'result': 'finalized-succeeded'}}]})
        with self.assertRaisesRegex(RuntimeError, 'malformed'): dev.clean_operations()

    def test_missing_unknown_malformed_and_unresolved_are_never_empty(self):
        for value in ({}, {'attempts': []}, {'attempts': [{'outcome': {'result': 'submit-threw'}}]},
                      {'attempts': [{'outcome': {'result': 'unresolved'}}]}, {'attempts': [{}]}):
            self.write(self.journal / 'sig.json', value)
            with self.assertRaises(RuntimeError): dev.clean_operations()
        (self.journal / 'sig.json').write_text('partial')
        with self.assertRaises(ValueError): dev.clean_operations()
        (self.journal / 'sig.json').unlink(); self.journal.rmdir()
        with self.assertRaises(RuntimeError): dev.clean_operations()

    def test_busy_temp_or_orphan_lock_blocks(self):
        for filename in ('id.json.busy', 'id.json.tmp-write', 'id.json.authorize.lock'):
            path = self.orders / filename; path.write_text('{}')
            with self.assertRaises((RuntimeError, KeyError, FileNotFoundError)): dev.clean_operations()
            path.unlink()

    def test_unknown_store_status_or_pending_order_blocks(self):
        for status in ('reserved', 'authorizing', 'authorized', 'handler-started', 'terminal-pending', 'unknown'):
            self.write(dev.STATE / 'restaurant/operation-store/fp.json', {'status': status})
            with self.assertRaises(RuntimeError): dev.clean_operations()
        (dev.STATE / 'restaurant/operation-store/fp.json').unlink()
        self.write(self.orders / 'id.json', {'status': 'pending', 'events': []})
        with self.assertRaises(RuntimeError): dev.clean_operations()

    def test_journal_symlink_does_not_read_outside_state(self):
        (self.journal / 'sig.json').symlink_to('/etc/passwd')
        with self.assertRaises(RuntimeError): dev.clean_operations()


class TransactionTests(DevFixture):
    def setUp(self):
        super().setUp()
        self.calls = []
        self.running = set(dev.SERVICES)
        self.acceptance = {'sha': NEW, 'tree': 'tree', 'branch': 'codex/app', 'reviewedHead': NEW, 'ciRun': 3}
        for name in ('units', 'health', 'rpc', 'install_gate', 'freeze', 'thaw'):
            self.stack.enter_context(mock.patch.object(dev, name, side_effect=lambda *args, n=name, **kw: self.calls.append(n)))
        self.stage = self.stack.enter_context(mock.patch.object(dev, 'stage'))
        self.policy = self.stack.enter_context(mock.patch.object(policy, 'verify_dev', return_value=self.acceptance))
        self.stack.enter_context(mock.patch.object(cli, 'GitHub'))
        self.stack.enter_context(mock.patch.object(dev, 'production', return_value='original-prod'))
        self.stop = self.stack.enter_context(mock.patch.object(dev, 'stop', side_effect=self.stop_pair))
        self.start = self.stack.enter_context(mock.patch.object(dev, 'start', side_effect=self.start_pair))
        def run(*args, **kw):
            if args[:2] == ('systemctl', 'show'): return '1' if args[-1] in self.running else '0'
            if args[:2] == ('systemctl', 'stop'): self.running.discard(args[-1])
            self.calls.append(args)
            return ''
        self.stack.enter_context(mock.patch.object(source, 'run', side_effect=run))

    def stop_pair(self, names=None): self.calls.append('stop'); self.running.clear()
    def start_pair(self, sha): self.calls.append(('start', sha)); self.running.update(dev.SERVICES)
    def assert_preserved(self, before):
        self.assertEqual(before, self.snapshot())
        for call in self.calls:
            if isinstance(call, tuple) and call[0] == 'systemctl':
                self.assertTrue(all('capture402-dev-' in n for n in call[2:] if n.startswith('capture402')))

    def test_new_sha_and_same_sha_preserve_state_and_second_run_does_not_restart(self):
        before = self.snapshot(); dev.deploy(NEW, object())
        self.assertEqual(dev.current(), NEW); self.assertFalse(dev.PENDING.exists())
        self.assertEqual(json.loads((dev.BASE / 'last-result.json').read_text())['verdict'], 'DEPLOYED')
        self.calls.clear(); dev.deploy(NEW, object())
        self.assertNotIn('stop', self.calls); self.assertNotIn('freeze', self.calls)
        self.assertEqual(json.loads((dev.BASE / 'last-result.json').read_text())['verdict'], 'ALREADY_CURRENT')
        self.assert_preserved(before)

    def test_install_ci_dns_rpc_failure_keeps_running_release(self):
        for target in ('stage', 'health', 'rpc'):
            with mock.patch.object(dev, target, side_effect=RuntimeError('injected')):
                with self.assertRaises(RuntimeError): dev.deploy(NEW, object())
            self.assertEqual(dev.current(), OLD); self.assertNotIn('stop', self.calls)
            self.assertFalse(dev.PENDING.exists())
        with mock.patch.object(policy, 'verify_dev', side_effect=RuntimeError('CI unavailable')):
            with self.assertRaises(RuntimeError): dev.deploy(NEW, object())
        self.assertNotIn('stop', self.calls)

    def test_operation_arriving_before_freeze_is_detected_then_thawed(self):
        def freeze():
            self.calls.append('freeze')
            self.write(self.journal / 'new.json', {'attempts': [{}]})
        with mock.patch.object(dev, 'freeze', side_effect=freeze):
            with self.assertRaisesRegex(RuntimeError, 'unresolved'): dev.deploy(NEW, object())
        self.assertIn('thaw', self.calls); self.assertNotIn('stop', self.calls)
        self.assertEqual(dev.current(), OLD); self.assertFalse(dev.PENDING.exists())

    def test_switch_failure_restores_code_only(self):
        before = self.snapshot(); real = dev.switch
        def switch(sha):
            real(sha)
            if sha == NEW: raise OSError('injected after replace')
        with mock.patch.object(dev, 'switch', side_effect=switch):
            with self.assertRaisesRegex(RuntimeError, 'previous code restored'): dev.deploy(NEW, object())
        self.assertEqual(dev.current(), OLD); self.assertFalse(dev.PENDING.exists()); self.assert_preserved(before)

    def test_start_failure_and_failed_rollback_retain_evidence(self):
        def start(sha):
            if sha == NEW: raise RuntimeError('candidate fails before process starts')
            self.start_pair(sha)
        with mock.patch.object(dev, 'start', side_effect=start):
            with self.assertRaisesRegex(RuntimeError, 'previous code restored'): dev.deploy(NEW, object())
        self.assertEqual(dev.current(), OLD); self.assertFalse(dev.PENDING.exists())
        with mock.patch.object(dev, 'start', side_effect=RuntimeError('all starts fail')):
            with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_UNVERIFIED'): dev.deploy(NEW, object())
        self.assertTrue(dev.PENDING.exists()); self.assertTrue((dev.BASE / 'last-failure.json').exists())

    def test_offline_recovery_precedes_metadata_and_requires_explicit_retry(self):
        self.write(dev.PENDING, {'previous': OLD, 'target': NEW, 'production': 'original-prod', 'stage': 'freezing'})
        self.policy.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'recovered offline'): dev.deploy(NEW, object())
        self.policy.assert_not_called(); self.assertTrue(any(isinstance(c, tuple) and c[:2] == ('systemctl', 'thaw') for c in self.calls))

    def test_pre_stop_reboot_recovers_original_code_without_metadata(self):
        self.running.clear()
        self.write(dev.PENDING, {'previous': OLD, 'target': NEW, 'production': 'original-prod', 'stage': 'freezing'})
        self.policy.reset_mock()
        self.assertTrue(dev.recover())
        self.assertIn(('start', OLD), self.calls); self.assertFalse(dev.PENDING.exists())
        self.policy.assert_not_called()

    def test_unresolved_candidate_prevents_rollback_without_stopping_or_replaying(self):
        dev.switch(NEW)
        self.write(self.journal / 'sig.json', {'attempts': [{}]})
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'unresolved'):
            dev.rollback({'previous': OLD, 'target': NEW, 'production': 'original-prod'})
        self.assertNotIn('stop', self.calls); self.assertEqual(dev.current(), NEW)
        self.assert_preserved(before)

    def test_boot_gate_blocks_pending_without_root_permit(self):
        self.write(dev.PENDING, {'stage': 'stopping'})
        with self.assertRaises(FileNotFoundError): dev.gate()
        dev.PERMIT.write_text(NEW)
        with self.assertRaises(RuntimeError): dev.gate()
        dev.PERMIT.write_text(OLD); dev.gate()

    def test_lock_excludes_a_second_deployer(self):
        with dev.locked():
            with self.assertRaises(BlockingIOError):
                with dev.locked(): pass


class CgroupTests(DevFixture):
    def setUp(self):
        super().setUp()
        for name in dev.SERVICES:
            root = dev.CGROUP / dev.group_path(name).lstrip('/')
            root.mkdir(parents=True)
            (root / 'cgroup.events').write_text('populated 0\nfrozen 1\n')
            (root / 'cgroup.kill').write_text('')
        def run(*args, **kwargs):
            if 'ControlGroup' in args: return dev.group_path(args[-1])
            if 'MainPID' in args: return '0'
            return ''
        self.run = self.stack.enter_context(mock.patch.object(source, 'run', side_effect=run))

    def test_stop_kills_frozen_dev_cgroups_before_systemd_stop(self):
        dev.freeze(); dev.stop()
        for name in dev.SERVICES:
            self.assertEqual((dev.CGROUP / dev.group_path(name).lstrip('/') / 'cgroup.kill').read_text(), '1')
        self.assertFalse(any(c.args[:2] == ('systemctl', 'thaw') for c in self.run.call_args_list))

    def test_reaped_cgroup_is_empty(self):
        self.assertFalse(dev.populated(self.root / 'already-reaped'))

    def test_unfrozen_or_foreign_cgroup_cannot_be_killed(self):
        root = dev.CGROUP / dev.group_path(dev.SERVICES[1]).lstrip('/')
        (root / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
        with self.assertRaisesRegex(RuntimeError, 'unfrozen'): dev.stop()
        self.assertEqual((root / 'cgroup.kill').read_text(), '')
        self.run.side_effect = lambda *args, **kw: '/system.slice/capture402-restaurant.service'
        with self.assertRaisesRegex(RuntimeError, 'unexpected dev cgroup'): dev.stop()


class DispatcherTests(unittest.TestCase):
    def test_dev_dispatch_never_calls_production_recovery_or_controllers(self):
        with (mock.patch.object(source.os, 'geteuid', return_value=0), mock.patch.object(dev, 'dispatch') as dispatch,
              mock.patch.object(cli, 'recover_first') as recover, mock.patch.object(cli, 'controllers') as controllers):
            cli.main(['dev', 'deploy', NEW])
        dispatch.assert_called_once_with(['deploy', NEW]); recover.assert_not_called(); controllers.assert_not_called()

    def test_dev_exception_cannot_expose_rpc_url_or_private_content(self):
        with (mock.patch.object(source.os, 'geteuid', return_value=0),
              mock.patch.object(dev, 'dispatch', side_effect=RuntimeError('SECRET_RPC_TOKEN'))):
            with self.assertRaisesRegex(RuntimeError, '^dev deployment blocked;') as caught:
                cli.main(['dev', 'deploy', NEW])
        self.assertNotIn('SECRET', str(caught.exception))


class StageTests(DevFixture):
    def setUp(self):
        super().setUp()
        from test_deploy_demo import FILES, tar
        shutil = __import__('shutil')
        shutil.rmtree(dev.RELEASES / NEW)
        (dev.BASE / 'manifests').mkdir()
        files = {**FILES, source.RECORD: (dev.RELEASES / OLD / source.RECORD).read_bytes()}
        self.tar = tar(files, compressed=False)
        self.acceptance = {'branch': 'codex/app', 'tree': 'tree'}
        user = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir='/tmp', pw_name='capture402-deploy', pw_shell='/usr/sbin/nologin')
        self.stack.enter_context(mock.patch.object(dev.pwd, 'getpwnam', return_value=user))
        self.stack.enter_context(mock.patch.object(source, 'source_ssh_command', return_value='ssh pinned'))
        self.stack.enter_context(mock.patch.object(source, 'git_archive', return_value=self.tar))
        self.stack.enter_context(mock.patch.object(source, 'chown_tree'))
        self.stack.enter_context(mock.patch.object(dev, 'seal'))
        self.stack.enter_context(mock.patch.object(dev, 'release_inventory', return_value='sealed'))
        def run(*args, **kw):
            if 'HEAD' in args: return NEW
            if 'HEAD^{tree}' in args: return 'tree'
            return ''
        self.run = self.stack.enter_context(mock.patch.object(source, 'run', side_effect=run))
        import hashlib
        self.metadata = {'sha': 'tree', 'truncated': False, 'tree': [
            {'path': path, 'type': 'blob', 'mode': '100644',
             'sha': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}
            for path, data in files.items()]}

    def api(self, route): return self.metadata

    def test_sealed_release_is_reused_with_manifest_integrity(self):
        before = self.snapshot()
        dev.stage(NEW, self.acceptance, self.api)
        self.assertTrue((dev.RELEASES / NEW / 'integration/package-lock.json').is_file())
        calls = [c for c in self.run.call_args_list if c.args[0] == 'systemd-run']
        self.assertEqual(len(calls), 1)
        args = calls[0].args
        self.assertIn('User=capture402-deploy', args); self.assertIn('--ignore-scripts', args)
        self.assertIn('ProtectSystem=strict', args); self.assertIn('--omit=dev', args)
        dev.stage(NEW, self.acceptance, self.api)
        self.assertEqual(len([c for c in self.run.call_args_list if c.args[0] == 'systemd-run']), 1)
        self.assertEqual(before, self.snapshot())
        with mock.patch.object(dev, 'release_inventory', return_value='changed'):
            with self.assertRaisesRegex(RuntimeError, 'immutable'): dev.stage(NEW, self.acceptance, self.api)

    def test_interactive_source_account_cannot_build(self):
        user = dev.pwd.getpwnam('capture402-deploy')
        user.pw_shell = '/bin/bash'
        with self.assertRaisesRegex(RuntimeError, 'noninteractive'): dev.stage(NEW, self.acceptance, self.api)
        self.assertFalse(any(c.args[0] == 'systemd-run' for c in self.run.call_args_list))

    def test_failed_dependency_install_does_not_publish_release(self):
        original = self.run.side_effect
        def failed(*args, **kw):
            if args[0] == 'systemd-run': raise RuntimeError('npm failed')
            return original(*args, **kw)
        self.run.side_effect = failed
        with self.assertRaises(RuntimeError): dev.stage(NEW, self.acceptance, self.api)
        self.assertEqual(dev.current(), OLD); self.assertFalse((dev.RELEASES / NEW).exists())
        self.assertFalse(list(dev.RELEASES.glob('.candidate-*')))

    def test_source_substitution_and_truncated_tree_never_reach_build(self):
        for bad in ({**self.metadata, 'truncated': True}, {**self.metadata, 'tree': []}):
            with self.assertRaises(RuntimeError): dev.stage(NEW, self.acceptance, lambda _: bad)
        self.metadata['tree'][0]['sha'] = 'forged'
        with self.assertRaises(RuntimeError): dev.stage(NEW, self.acceptance, self.api)
        self.assertFalse(any(c.args[0] == 'systemd-run' for c in self.run.call_args_list))
