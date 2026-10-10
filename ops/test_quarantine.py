"""Synthetic durability/schema tests. Run as root in a disposable Linux VM.

Ownership is deliberately real; non-root skips are NOT acceptance evidence.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import quarantine as q


class FakeHost:
    def __init__(self, e):
        self.e, self.calls = e, []

    def verify(self, stopped=False):
        self.calls.append(('verify', stopped))

    def close(self):
        self.calls.append(('close',))

    def fence(self):
        self.calls.append(('fence',))

    def stop(self):
        self.calls.append(('stop',))

    def select(self, sha):
        self.calls.append(('select', sha))

    def start_view(self):
        self.calls.append(('view',))

    def prepare_projection(self, raw):
        q.exclusive(Path(self.e['viewerRoot']) / 'projection.json', raw, 0o400)


@unittest.skipUnless(os.geteuid() == 0 and __import__('sys').platform == 'linux', 'NOT RUN: disposable Linux root required')
class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='b2-test-', dir='/opt')
        self.root = Path(self.tmp.name)
        self.admission = self.root / 'admission'
        self.admission.mkdir(mode=0o700)
        state = self.root / 'state'
        state.mkdir(mode=0o700)
        paths = []
        for role in q.ROLES:
            directory = state / role
            directory.mkdir(mode=0o700)
            q.exclusive(directory / 'retained.json', b'{"retained":"UNKNOWN"}\n')
            paths.append(directory)
        view = self.root / 'view'
        view.mkdir()
        self.e = {'guardSha256': 'e' * 64, 'tuple': {'candidate': 'c' * 40, 'previous': 'a' * 40}, 'viewerRoot': str(view)}
        self.host = FakeHost(self.e)
        self.patches = [patch.object(q, 'STATE', state), patch.object(q, 'STORE_PATHS', tuple(paths)), patch.object(q, 'ROOT', self.admission)]
        for p in self.patches:
            p.start()
        self.projector = lambda stores, inv: b'{"mode":"READ_ONLY_QUARANTINE","retained":"UNKNOWN"}\n'
        self.t = q.Transition(self.admission, self.host, self.e, self.projector)
        self.before = q.inventory()[0]

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_ordered_attestations_and_immutable_baseline(self):
        self.t.enter()
        self.assertEqual([r['phase'] for r in q.journal_phase(self.admission)], list(q.PHASES))
        self.assertEqual(q.inventory()[0], self.before)
        self.assertLess(self.host.calls.index(('stop',)), self.host.calls.index(('select', 'c' * 40)))
        with self.assertRaises(RuntimeError):
            self.t.enter()
        self.assertEqual(q.inventory()[0], self.before)

    def test_every_phase_crash_before_and_after_durable_write(self):
        # Each case has its own durable fixture, never overwrites a failed transition.
        for phase in q.PHASES:
            for after in (False, True):
                with self.subTest(phase=phase, after=after):
                    case = self.admission / (phase + str(after))
                    case.mkdir()
                    view = case / 'view'
                    view.mkdir()
                    e = dict(self.e, viewerRoot=str(view))
                    h = FakeHost(e)
                    t = q.Transition(case, h, e, self.projector)
                    real = q.exclusive
                    def crash(path, data, mode=0o600):
                        if path.name.endswith('-' + phase + '.json'):
                            if after:
                                real(path, data, mode)
                            raise OSError('synthetic crash')
                        return real(path, data, mode)
                    with patch.object(q, 'exclusive', crash), self.assertRaises(OSError):
                        t.enter()
                    self.assertTrue((case / 'ECONOMICS_DENIED').exists())
                    pre_calls = len(h.calls)
                    r = t.recover()
                    self.assertEqual(r['viewer'], 'STOPPED')
                    self.assertNotIn(('view',), h.calls[pre_calls:])
                    self.assertFalse(any(c[0] == 'thaw' for c in h.calls))
                    self.assertEqual(q.inventory()[0], self.before)

    def test_fsync_failure_keeps_denial_and_incomplete_record(self):
        with patch.object(q.os, 'fsync', side_effect=OSError('fsync trap')), self.assertRaises(OSError):
            self.t.enter()
        self.assertTrue((self.admission / 'ECONOMICS_DENIED').exists())
        self.assertFalse(any(c[0] in ('select', 'view') for c in self.host.calls))
        self.t.recover()
        self.assertEqual(q.inventory()[0], self.before)

    def test_effect_boundary_crashes_never_resume_or_restore(self):
        for method in ('close', 'fence', 'stop', 'prepare_projection', 'select', 'start_view'):
            for after in (False, True):
                with self.subTest(method=method, after=after):
                    case = self.admission / (method + str(after)); case.mkdir()
                    view = case / 'view'; view.mkdir()
                    e = dict(self.e, viewerRoot=str(view)); h = FakeHost(e)
                    t = q.Transition(case, h, e, self.projector); effect = getattr(h, method)
                    def crash(*args):
                        if after: effect(*args)
                        raise OSError('synthetic effect cut')
                    with patch.object(h, method, crash), self.assertRaises(OSError): t.enter()
                    self.assertTrue((case / 'ECONOMICS_DENIED').exists())
                    n = len(h.calls); t.recover()
                    self.assertNotIn(('view',), h.calls[n:]); self.assertEqual(q.inventory()[0], self.before)

    def test_rollback_is_code_only_never_starts_p_or_restores_evidence(self):
        self.t.enter()
        n = len(self.host.calls)
        self.t.rollback()
        self.assertEqual(self.host.calls[-1], ('select', 'a' * 40))
        self.assertNotIn(('view',), self.host.calls[n:])
        self.assertEqual(q.inventory()[0], self.before)

    def test_late_injected_local_result_is_detected_not_applied(self):
        self.t.enter()
        p = q.STORE_PATHS[0] / 'retained.json'
        p.write_bytes(b'{"retained":"finalized"}\n')
        with self.assertRaises(RuntimeError):
            self.t.recover()
        self.assertFalse(any(c[0] == 'thaw' for c in self.host.calls))

    def test_guard_denies_missing_corrupt_sentinel_and_valid_legacy_permit(self):
        for value in (b'valid', b'', b'{', b'unsupported-v999'):
            p = self.admission / 'ECONOMICS_DENIED'
            p.write_bytes(value)
            with self.assertRaises(RuntimeError):
                q.ordinary_allowed()
        (self.admission / 'ECONOMICS_DENIED').unlink()
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            q.ordinary_allowed()  # Transition deletion/absent enrollment does not unenroll.

    def test_corrupt_gap_or_unsupported_phase_never_recovers_by_thaw(self):
        self.t.enter()
        (self.admission / '1-FENCED.json').unlink()
        with self.assertRaises(RuntimeError):
            self.t.recover()
        self.assertNotIn(('thaw',), self.host.calls)

    def test_inventory_rejects_symlink_hardlink_tmp_directory_and_drift(self):
        p = q.STORE_PATHS[0] / 'extra.json'
        mutations = [lambda: p.symlink_to(q.STORE_PATHS[0] / 'retained.json'),
                     lambda: os.link(q.STORE_PATHS[0] / 'retained.json', p), lambda: p.mkdir()]
        for mutation in mutations:
            mutation()
            with self.assertRaises(RuntimeError):
                q.inventory()
            p.rmdir() if p.is_dir() and not p.is_symlink() else p.unlink()
        (q.STORE_PATHS[0] / 'record.tmp-1').write_text('pending')
        with self.assertRaises(RuntimeError):
            q.inventory()
        (q.STORE_PATHS[0] / 'record.tmp-1').unlink()
        self.assertNotEqual(q.inventory()[0], self.before)  # Directory/file ctime drift remains visible.

    def test_duplicate_json_unknown_versions_and_bom_rejected(self):
        for b in (b'{"version":1,"version":2}', b'\xef\xbb\xbf{}', b'{"value":NaN}', b'\xff'):
            with self.assertRaises((RuntimeError, ValueError, UnicodeDecodeError)):
                q.strict_json(b)

    def test_pending_bootstrap_preserves_A_but_never_entered_denial(self):
        guard = self.root / 'guard'
        with patch.object(q, 'GUARD', guard):
            q.exclusive(self.admission / 'BOOTSTRAP_PENDING', q.encoded(dict(version=1, candidate='c' * 40, guardSha256=q.digest(b'guard'))))
            q.ordinary_allowed()
            q.exclusive(guard, b'guard')
            q.ordinary_allowed()
            q.exclusive(self.admission / 'ECONOMICS_DENIED', b'denial')
            with self.assertRaises(RuntimeError): q.ordinary_allowed()
            (self.admission / 'ECONOMICS_DENIED').unlink()
            q.exclusive(self.admission / 'BOOTSTRAP_COMMITTED', b'B2_ENROLLED v1\n')
            with self.assertRaises(FileNotFoundError): q.ordinary_allowed()

    def test_candidate_no_raw_credential_network_or_ipc_capabilities_in_unit(self):
        unit = q.viewer_unit(self.e)
        for value in ('RootDirectory=', 'PrivateNetwork=yes', 'SystemCallFilter=~connect', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=\n', 'EnvironmentFile=\n', 'ReadWritePaths=\n', 'RestrictNamespaces=yes'):
            self.assertIn(value, unit)
        self.assertNotIn('restaurant-server.ts', unit)
        self.assertNotIn('SOLANA_RPC_URL', unit)


if __name__ == '__main__':
    unittest.main()
