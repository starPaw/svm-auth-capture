"""Offline failure, trust-boundary, and rollback tests for the Devnet CD helper."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest import mock

import deploy_demo as cd

OLD = "a" * 40
NEW = "b" * 40
FILES = {
    "integration/package.json": b"{}",
    "integration/package-lock.json": b"{}",
    "integration/src/restaurant-server.ts": b"restaurant",
    "integration/src/devnet-server.ts": b"facilitator",
    "integration/web/index.html": b"html",
    cd.RECORD: b'{"network":{"caip2":"solana:test"},"program":{"program_id":"program"}}',
}


def tar(files: dict[str, bytes], *, link: bool = False, compressed: bool = True) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz" if compressed else "w") as archive:
        for path, content in files.items():
            entry = tarfile.TarInfo(path)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
        if link:
            entry = tarfile.TarInfo("integration/bad-link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/sac006/keys"
            archive.addfile(entry)
    return data.getvalue()


class ArchiveTests(unittest.TestCase):
    def test_accepted_runtime_extracts_without_keys(self):
        with tempfile.TemporaryDirectory() as root:
            cd.unpack_archive(tar(FILES), Path(root))
            for path, contents in FILES.items():
                self.assertEqual((Path(root) / path).read_bytes(), contents)

    def test_reject_symlink_to_secret(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError, "links/devices"):
                cd.unpack_archive(tar(FILES, link=True), Path(root))

    def test_reject_path_traversal(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError, "unsafe archive path"):
                cd.unpack_archive(tar({**FILES, "integration/../../etc/sac006/key": b"x"}),
                                  Path(root))

    def test_reject_unexpected_paths(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError, "unexpected release path"):
                cd.unpack_archive(tar({**FILES, ".github/workflows/x.yml": b"x"}),
                                  Path(root))

    def test_reject_missing_server(self):
        with tempfile.TemporaryDirectory() as root:
            files = {k: v for k, v in FILES.items()
                     if k != "integration/src/restaurant-server.ts"}
            with self.assertRaisesRegex(RuntimeError, "required app file missing"):
                cd.unpack_archive(tar(files), Path(root))

    def test_reject_duplicate_names(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            for _ in range(2):
                entry = tarfile.TarInfo("integration/package.json")
                entry.size = 1
                archive.addfile(entry, io.BytesIO(b"x"))
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError, "duplicate archive entry"):
                cd.unpack_archive(data.getvalue(), Path(root))

    def test_git_tree_fingerprints_are_byte_exact(self):
        self.assertEqual(cd.archive_fingerprints(tar(FILES), "r:gz"),
                         cd.archive_fingerprints(tar(FILES, compressed=False), "r:"))
        changed = {**FILES, "integration/src/devnet-server.ts": b"attacker"}
        self.assertNotEqual(cd.archive_fingerprints(tar(FILES), "r:gz"),
                            cd.archive_fingerprints(tar(changed, compressed=False), "r:"))


class SwitchingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.releases = self.base / "releases"
        self.releases.mkdir()
        self.manifests = self.base / "manifests"
        self.manifests.mkdir()
        for sha in (OLD, NEW):
            (self.releases / sha).mkdir()
        (self.base / "current").symlink_to(self.releases / OLD)
        self.patches = [
            mock.patch.object(cd, "BASE", self.base),
            mock.patch.object(cd, "RELEASES", self.releases),
            mock.patch.object(cd, "CURRENT", self.base / "current"),
            mock.patch.object(cd, "PENDING", self.base / "pending.json"),
            mock.patch.object(cd, "MANIFESTS", self.manifests),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_atomic_switch_and_rollback(self):
        self.assertEqual(cd.current_sha(), OLD)
        cd.switch_to(NEW)
        self.assertEqual(cd.current_sha(), NEW)
        cd.switch_to(OLD)
        self.assertEqual(cd.current_sha(), OLD)

    def test_reject_non_versioned_current(self):
        (self.base / "current").unlink()
        (self.base / "current").symlink_to(self.base)
        with self.assertRaisesRegex(RuntimeError, "escapes releases"):
            cd.current_sha()

    def test_failed_activation_restores_old_version(self):
        payload = b"test compressed archive"
        digest = hashlib.sha256(payload).hexdigest()
        stdin = types.SimpleNamespace(buffer=io.BytesIO(payload))
        with (mock.patch.object(cd.os, "geteuid", return_value=0),
              mock.patch.object(cd, "check_unit_layout"),
              mock.patch.object(cd, "verify_source_against_main"),
              mock.patch.object(cd, "prepare_release"),
              mock.patch.object(cd, "restart"),
              mock.patch.object(cd, "run", return_value=""),
              mock.patch.object(cd, "ready",
                                side_effect=[RuntimeError("resource unhealthy"), None]),
              mock.patch.object(cd.sys, "stdin", stdin)):
            with self.assertRaisesRegex(RuntimeError, "resource unhealthy"):
                cd.deploy(NEW, digest)
        self.assertEqual(cd.current_sha(), OLD)
        self.assertFalse(cd.PENDING.exists())

    def test_interrupted_activation_is_reverted_before_new_release(self):
        cd.switch_to(NEW)
        cd.write_json(cd.PENDING, {"previous": OLD, "target": NEW})
        with mock.patch.object(cd, "restart"), mock.patch.object(cd, "ready"):
            with self.assertRaisesRegex(RuntimeError, "retry to deploy"):
                cd.recover_pending()
        self.assertEqual(cd.current_sha(), OLD)
        self.assertFalse(cd.PENDING.exists())

    def test_duplicate_exact_sha_no_restart(self):
        payload = b"test archive"
        digest = hashlib.sha256(payload).hexdigest()
        stdin = types.SimpleNamespace(buffer=io.BytesIO(payload))
        with (mock.patch.object(cd.os, "geteuid", return_value=0),
              mock.patch.object(cd, "check_unit_layout"),
              mock.patch.object(cd, "verify_source_against_main"),
              mock.patch.object(cd, "prepare_release"),
              mock.patch.object(cd, "restart") as restart,
              mock.patch.object(cd, "ready"),
              mock.patch.object(cd.sys, "stdin", stdin)):
            cd.deploy(OLD, digest)
        restart.assert_not_called()
        self.assertEqual(cd.current_sha(), OLD)

    def test_failed_recovery_leaves_pending_evidence(self):
        cd.switch_to(NEW)
        cd.write_json(cd.PENDING, {"previous": OLD, "target": NEW})
        with mock.patch.object(cd, "restart", side_effect=RuntimeError("service failed")):
            with self.assertRaisesRegex(RuntimeError, "service failed"):
                cd.recover_pending()
        self.assertTrue(cd.PENDING.exists())


if __name__ == "__main__":
    unittest.main()
