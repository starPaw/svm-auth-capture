"""Release eligibility and on-host command trust boundaries, offline."""
import json
import io
import tarfile
import contextlib
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import deploy_demo as source
import host_cli as cli
import launch_deploy as launcher
import release_policy as policy

OLD, NEW = 'a' * 40, 'b' * 40


class PolicyFixture(unittest.TestCase):
    def setUp(self):
        self.main = NEW
        self.reviewed_tree = 'tree'
        self.reviews = [self.review('gwinpin', OLD)]
        self.run = {'id': 3, 'head_sha': NEW, 'event': 'push', 'status': 'completed', 'conclusion': 'success'}
        self.jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success'} for name in policy.REQUIRED_JOBS]
        self.pull = {'number': 1, 'merged_at': 'date', 'merge_commit_sha': NEW, 'base': {'ref': 'main'}, 'head': {'sha': OLD}}

    def review(self, login, revision, state='APPROVED'):
        return {'id': 7, 'user': {'login': login, 'type': 'User'}, 'state': state, 'commit_id': revision}

    def api(self, route):
        if '/git/ref/' in route: return {'object': {'sha': self.main}}
        if '/actions/workflows/' in route: return {'workflow_runs': [self.run]}
        if '/jobs?' in route: return {'total_count': len(self.jobs), 'jobs': self.jobs}
        if '/pulls?' in route: return [self.pull]
        if '/reviews?' in route: return self.reviews
        if '/git/commits/' in route: return {'tree': {'sha': self.reviewed_tree if route.endswith(OLD) else 'tree'}}
        raise AssertionError(route)

    def gh(self, *args, **kwargs):
        assert args[:2] == ('gh', 'api')
        return json.dumps(self.api(args[2]))


class ReleasePolicyTests(PolicyFixture):
    def test_verified_release_records_exact_review_and_ci(self):
        receipt = policy.verify(NEW, self.api)
        self.assertEqual((receipt['sha'], receipt['reviewedHead'], receipt['reviewer'], receipt['ciRun']), (NEW, OLD, 'gwinpin', 3))

    def test_missing_merge_identity_cannot_be_replaced_by_green_ci_and_review(self):
        for value in (None, OLD):
            self.pull['merge_commit_sha'] = value
            with self.assertRaisesRegex(RuntimeError, 'unambiguous merged PR'):
                policy.verify(NEW, self.api)
        self.pull.pop('merge_commit_sha')
        with self.assertRaisesRegex(RuntimeError, 'unambiguous merged PR'):
            policy.verify(NEW, self.api)

    def test_successful_workflow_cannot_hide_skipped_or_missing_job(self):
        for jobs in ([self.jobs[0]], [{**j, 'conclusion': 'skipped'} for j in self.jobs], self.jobs + [self.jobs[0]]):
            original = self.jobs
            self.jobs = jobs
            with self.assertRaisesRegex(RuntimeError, 'required CI job'): policy.verify(NEW, self.api)
            self.jobs = original

    def test_nonmain_and_main_change_are_refused(self):
        self.main = OLD
        with self.assertRaisesRegex(RuntimeError, 'current main'): policy.verify(NEW, self.api)
        self.main = NEW
        api = self.api
        calls = 0
        def changed(route):
            nonlocal calls
            if '/git/ref/' in route:
                calls += 1
                if calls > 1: return {'object': {'sha': OLD}}
            return api(route)
        with self.assertRaisesRegex(RuntimeError, 'main changed'): policy.verify(NEW, changed)

    def test_pull_request_ci_cannot_authorize_main_deployment(self):
        self.run['event'] = 'pull_request'
        with self.assertRaisesRegex(RuntimeError, 'push CI'): policy.verify(NEW, self.api)

    def test_stale_owner_and_dismissed_approvals_are_refused(self):
        for review in (self.review('starPaw', OLD), self.review('gwinpin', NEW), self.review('gwinpin', OLD, 'DISMISSED')):
            self.reviews = [review]
            with self.assertRaisesRegex(RuntimeError, 'reviewer approval'): policy.verify(NEW, self.api)


class HostCommandTests(unittest.TestCase):
    def test_bootstrap_installs_reviewed_files_without_starting_systemd_job(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            for name in cli.FILES:
                member = tarfile.TarInfo('ops/' + name)
                member.size = 5
                archive.addfile(member, io.BytesIO(b'pass\n'))
        with tempfile.TemporaryDirectory() as temporary:
            program = launcher.INSTALLER.replace('/opt/capture402/controllers', temporary + '/controllers')
            with (mock.patch.object(cli.sys, 'argv', ['installer', NEW, '--install-cli']),
                  mock.patch.object(cli.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(data.getvalue()))),
                  mock.patch.object(cli.sys, 'path', list(cli.sys.path)),
                  mock.patch.object(cli, 'install_controllers') as install,
                  mock.patch.object(cli.subprocess, 'run') as job, contextlib.redirect_stdout(io.StringIO())):
                with self.assertRaises(SystemExit) as result: exec(program, {})
            self.assertEqual(result.exception.code, 0)
            self.assertEqual(set(install.call_args.args[1]), set(cli.FILES))
            job.assert_not_called()

    def test_legacy_command_delegates_to_same_gated_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with (mock.patch.object(source, 'BASE', base), mock.patch.object(cli, 'COMMAND', base / 'capture402'),
                  mock.patch.object(cli, 'OLD_COMMAND', base / 'capture402-deploy')):
                cli.install_controllers(NEW, {name: b'pass\n' for name in cli.FILES})
                old = cli.OLD_COMMAND.read_text()
                self.assertIn('exec /usr/local/sbin/capture402 deploy "$2"', old)
                self.assertNotIn('deploy_demo.py', old)
                self.assertEqual(cli.COMMAND.stat().st_mode & 0o777, 0o755)

    def test_status_uses_live_process_metadata_without_github(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = io.StringIO()
            with (mock.patch.object(source, 'BASE', Path(temporary)), mock.patch.object(source, 'CURRENT', Path(temporary) / 'current'),
                  mock.patch.object(source.os, 'geteuid', return_value=0),
                  mock.patch.object(source, 'run', side_effect=lambda *args: 'inactive' if 'ActiveState' in args else '0'),
                  mock.patch.object(cli, 'GitHub') as api, contextlib.redirect_stdout(out)):
                cli.main(['status'])
            result = json.loads(out.getvalue())
            self.assertFalse(result['pending'])
            self.assertIsNone(result['lastResult'])
            self.assertEqual(len(result['services']), 4)
            api.assert_not_called()

    def test_rejected_release_does_not_install_or_start_anything(self):
        with (mock.patch.object(source.os, 'geteuid', return_value=0),
              mock.patch.object(cli, 'recover_first', return_value=False),
              mock.patch.object(cli, 'GitHub'), mock.patch.object(policy, 'verify', side_effect=RuntimeError('CI failed')),
              mock.patch.object(cli, 'controllers') as install, mock.patch.object(cli.subprocess, 'run') as job):
            with self.assertRaisesRegex(RuntimeError, 'CI failed'): cli.main(['deploy', NEW])
        install.assert_not_called(); job.assert_not_called()

    def test_public_or_symlinked_api_credentials_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            token = parent / 'token'
            token.write_text('fixture-token'); token.chmod(0o644)
            original = Path.lstat
            def root_info(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0)
            with mock.patch.object(cli, 'TOKEN', token), mock.patch.object(Path, 'lstat', root_info):
                with self.assertRaisesRegex(RuntimeError, 'private'): cli.GitHub()
                token.unlink(); token.symlink_to(parent / 'absent')
                with self.assertRaisesRegex(RuntimeError, 'symlink'): cli.GitHub()

    def test_api_token_is_only_in_header_and_response_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / 'token'
            token.write_text('fixture-token'); token.chmod(0o600)
            original = Path.lstat
            def root_info(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0)
            opener = mock.MagicMock()
            opener.open.side_effect = cli.urllib.error.HTTPError('https://api.github.com', 403, 'fixture-token', {}, None)
            with (mock.patch.object(cli, 'TOKEN', token), mock.patch.object(Path, 'lstat', root_info),
                  mock.patch.object(cli.urllib.request, 'build_opener', return_value=opener)):
                client = cli.GitHub()
                with self.assertRaisesRegex(RuntimeError, '^release API HTTP 403$'):
                    client('repos/starPaw/svm-auth-capture/git/ref/heads/main')
            request = opener.open.call_args.args[0]
            self.assertNotIn('fixture-token', request.full_url)
            self.assertEqual(request.get_header('Authorization'), 'Bearer fixture-token')
            self.assertEqual(request.get_header('X-github-api-version'), '2022-11-28')

    def test_pending_recovery_precedes_credentials_and_network(self):
        with mock.patch.object(source.os, 'geteuid', return_value=0), mock.patch.object(cli, 'recover_first', return_value=True), mock.patch.object(cli, 'GitHub') as api:
            with self.assertRaisesRegex(RuntimeError, 'recovered offline'): cli.main(['deploy', NEW])
        api.assert_not_called()

    def test_nonroot_or_bad_revision_cannot_start_job(self):
        with mock.patch.object(source.os, 'geteuid', return_value=5), mock.patch.object(cli.subprocess, 'run') as job:
            with self.assertRaisesRegex(RuntimeError, 'sudo'): cli.main(['deploy', NEW])
        job.assert_not_called()
        with mock.patch.object(source.os, 'geteuid', return_value=0), mock.patch.object(cli, 'GitHub') as api:
            with self.assertRaisesRegex(RuntimeError, 'usage'): cli.main(['deploy', '--latest'])
        api.assert_not_called()

    def test_controller_blob_substitution_is_refused_before_install(self):
        payload = b'pass\n'
        item = {'path': 'ops/deploy_demo.py', 'encoding': 'base64', 'content': 'cGFzcwo=', 'sha': '0' * 40}
        with mock.patch.object(cli, 'install_controllers') as install:
            with self.assertRaisesRegex(RuntimeError, 'Git blob mismatch'): cli.controllers(NEW, lambda route: item)
        install.assert_not_called()

    def test_operator_command_does_not_follow_controller_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / 'controllers').symlink_to(base, target_is_directory=True)
            with mock.patch.object(source, 'BASE', base):
                with self.assertRaisesRegex(RuntimeError, 'directory is symlink'):
                    cli.install_controllers(NEW, {name: b'pass\n' for name in cli.FILES})

    def test_api_client_refuses_redirects_and_does_not_put_token_in_url(self):
        self.assertIsNone(cli.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.invalid/'))


if __name__ == '__main__': unittest.main()
