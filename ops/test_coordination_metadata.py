"""Exact metadata compatibility and real byte/identity inventory accounting, no live stores."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import quarantine as q
from test_deploy_dev import DevFixture
import deploy_dev as dev


def records(paths):
    for p in paths.values():
        lock = p / q.COORDINATION_FILE
        if not lock.exists(): lock.touch(mode=0o600)
    members = [dict(role=r, path=str(paths[r]), device=str(paths[r].stat().st_dev), inode=str(paths[r].stat().st_ino), lockDevice=str((paths[r] / q.COORDINATION_FILE).stat().st_dev), lockInode=str((paths[r] / q.COORDINATION_FILE).stat().st_ino)) for r in q.COORDINATION_ROLES]
    return {r: dict(version=1, protocol='flock-v1', domain='a' * 32, role=r, members=members, writers=['facilitator', 'payer', 'resource', 'restaurant']) for r in q.COORDINATION_ROLES}


def save(paths, values):
    for role, v in values.items():
        p = paths[role] / q.COORDINATION_FILE
        p.write_bytes(json.dumps(v, separators=(',', ':')).encode()); p.chmod(0o600)


class PreflightCoordinationTests(DevFixture):
    def test_exact_metadata_passes_and_unknown_partial_corrupt_members_refuse(self):
        paths = dict(zip(q.ROLES, dev.state_paths()))
        save(paths, records(paths)); before = self.snapshot(); dev.clean_operations()
        self.assertEqual(before, self.snapshot())
        for bad in ('extra', 'writer', 'identity', 'mode', 'missing', 'symlink', 'unknown-file'):
            with self.subTest(bad=bad):
                save(paths, records(paths)); p = paths['orders'] / q.COORDINATION_FILE
                if bad in ('extra', 'writer', 'identity'):
                    v = json.loads(p.read_bytes())
                    if bad == 'extra': v['extra'] = True
                    if bad == 'writer': v['writers'].pop()
                    if bad == 'identity': v['members'][0]['inode'] = '1'
                    p.write_bytes(json.dumps(v, separators=(',', ':')).encode())
                if bad == 'mode': p.chmod(0o644)
                if bad == 'missing': p.unlink()
                if bad == 'symlink': p.unlink(); p.symlink_to(paths['facilitator'] / q.COORDINATION_FILE)
                if bad == 'unknown-file': (paths['orders'] / '.coordination-unknown.lock').write_text('{}')
                with self.assertRaises((RuntimeError, ValueError, KeyError, FileNotFoundError)): dev.clean_operations()
                if p.is_symlink(): p.unlink()
                if bad == 'unknown-file': (paths['orders'] / '.coordination-unknown.lock').unlink()


class InventoryCoordinationTests(unittest.TestCase):
    def test_inventory_accounts_for_exact_lock_bytes_identity_and_drift(self):
        # Use the repository's trusted local ancestry, not a world-writable temporary ancestor.
        with tempfile.TemporaryDirectory(prefix='.coordination-test-', dir=Path(__file__).resolve().parent) as root:
            paths = {r: Path(root) / r for r in q.COORDINATION_ROLES}
            for p in paths.values(): p.mkdir(mode=0o700)
            save(paths, records(paths))
            with mock.patch.object(q, 'STATE', Path(root)), mock.patch.object(q.os, 'listxattr', return_value=[], create=True):
                # macOS Python lacks listxattr; xattr enforcement itself is covered by Linux #57 tests.
                inv, stores = q.inventory([paths[r] for r in q.ROLES])
                self.assertEqual(len(inv), 8)
                for role in q.ROLES:
                    key = role + '/' + q.COORDINATION_FILE
                    self.assertEqual(inv[key]['sha256'], q.digest((paths[role] / q.COORDINATION_FILE).read_bytes()))
                    self.assertEqual(inv[key]['inode'], (paths[role] / q.COORDINATION_FILE).stat().st_ino)
                    self.assertEqual([m['name'] for m in stores[role]], [q.COORDINATION_FILE])
                p = paths['orders'] / q.COORDINATION_FILE
                raw = p.read_bytes(); p.rename(paths['orders'] / 'old'); p.write_bytes(raw); p.chmod(0o600)
                # Extra member and replacement inode are visible, never silently dropped.
                with self.assertRaises(RuntimeError): q.inventory([paths[r] for r in q.ROLES])
