"""Offline failure, trust-boundary, and rollback tests for the Devnet CD helper."""
from __future__ import annotations

import hashlib
import io
import json
import os
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


    def test_archive_member_limit_stops_streaming_in_both_paths(self):
        payload = tar({f"integration/item-{n}": b"x" for n in range(25)})
        original_next = tarfile.TarFile.next
        for operation in ("fingerprint", "unpack"):
            parsed = 0

            def tracked_next(archive):
                nonlocal parsed
                parsed += 1
                return original_next(archive)

            with tempfile.TemporaryDirectory() as root:
                with (mock.patch.object(cd, "MAX_MEMBERS", 2),
                      mock.patch.object(tarfile.TarFile, "next", tracked_next)):
                    with self.assertRaisesRegex(RuntimeError, "too many entries"):
                        if operation == "fingerprint":
                            cd.archive_fingerprints(payload, "r:gz")
                        else:
                            cd.unpack_archive(payload, Path(root))
            self.assertLessEqual(parsed, 4, "parser inspected rejected trailing entries")

    def test_decompressed_tar_is_bounded_in_both_paths(self):
        payload = tar({"integration/large": b"x" * 20000})
        with mock.patch.object(cd, "MAX_TAR_STREAM", 2048):
            with self.assertRaisesRegex(RuntimeError, "decompressed tar stream exceeds limit"):
                cd.archive_fingerprints(payload, "r:gz")
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaisesRegex(RuntimeError, "decompressed tar stream exceeds limit"):
                    cd.unpack_archive(payload, Path(root))



class PrivateSourceTests(unittest.TestCase):
    """GitHub source authenticity and VPS-only SSH credential constraints."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.key = root / "read-key"
        self.hosts = root / "known-hosts"
        self.key.write_text("private fixture")
        self.hosts.write_text("github.com ssh-ed25519 fixture\n")
        self.key.chmod(0o600)
        self.hosts.chmod(0o644)
        for name, path in [("SOURCE_KEY", self.key),
                           ("SOURCE_KNOWN_HOSTS", self.hosts),
                           ("RELEASES", root)]:
            patch = mock.patch.object(cd, name, path)
            patch.start()
            self.addCleanup(patch.stop)
        self.user = types.SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(root))

    def config(self):
        return cd.source_ssh_command(self.user, hosts_owner_uid=os.getuid())

    def test_pinned_host_and_read_only_identity(self):
        ssh = self.config()
        self.assertIn(f"-i {self.key}", ssh)
        self.assertIn(f"UserKnownHostsFile={self.hosts}", ssh)
        self.assertIn("StrictHostKeyChecking=yes", ssh)
        self.assertIn("IdentityAgent=none", ssh)
        self.assertIn("GlobalKnownHostsFile=/dev/null", ssh)
        self.assertIn("ForwardAgent=no", ssh)

    def test_missing_key_fails_before_clone(self):
        self.key.unlink()
        with self.assertRaisesRegex(RuntimeError, "source deploy key missing"):
            self.config()

    def test_group_readable_key_is_rejected(self):
        self.key.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError, "private"):
            self.config()

    def test_writable_host_pin_is_rejected(self):
        self.hosts.chmod(0o664)
        with self.assertRaisesRegex(RuntimeError, "not writable"):
            self.config()

    def test_symlinked_host_pin_is_rejected(self):
        real = self.hosts.with_name("real-hosts")
        self.hosts.rename(real)
        self.hosts.symlink_to(real)
        with self.assertRaisesRegex(RuntimeError, "pin.*unsafe"):
            self.config()

    def test_empty_host_pin_is_rejected(self):
        self.hosts.write_text("")
        with self.assertRaisesRegex(RuntimeError, "empty GitHub host"):
            self.config()

    def test_private_git_clone_uses_exact_sha_and_byte_comparison(self):
        commands = []

        def run_stub(*args, **kwargs):
            commands.append(args)
            return NEW if args[-3:] == ("git", "rev-parse", "HEAD") else ""

        with (mock.patch.object(cd.pwd, "getpwnam", return_value=self.user),
              mock.patch.object(cd, "source_ssh_command", return_value="ssh pinned"),
              mock.patch.object(cd.os, "chown"),
              mock.patch.object(cd, "run", side_effect=run_stub),
              mock.patch.object(cd.subprocess, "run",
                                return_value=types.SimpleNamespace(
                                    stdout=tar(FILES, compressed=False)))):
            cd.verify_source_against_main(NEW, tar(FILES))
        self.assertEqual(commands[0][:6], ("runuser", "-u", "capture402-deploy",
                                          "--", "/usr/bin/env", "-i"))
        self.assertIn("GIT_TERMINAL_PROMPT=0", commands[0])
        self.assertIn("core.sshCommand=ssh pinned", commands[0])
        self.assertIn(cd.SOURCE_REMOTE, commands[0])
        self.assertNotIn("https://github.com/starPaw/svm-auth-capture.git", commands[0])

    def test_mutated_source_archive_is_rejected(self):
        with (mock.patch.object(cd.pwd, "getpwnam", return_value=self.user),
              mock.patch.object(cd, "source_ssh_command", return_value="ssh pinned"),
              mock.patch.object(cd.os, "chown"),
              mock.patch.object(cd, "run", side_effect=["", NEW]),
              mock.patch.object(cd.subprocess, "run", return_value=types.SimpleNamespace(
                  stdout=tar(FILES, compressed=False)))):
            with self.assertRaisesRegex(RuntimeError, "differs from exact GitHub"):
                cd.verify_source_against_main(
                    NEW, tar({**FILES, "integration/src/devnet-server.ts": b"tamper"}))

    def test_stale_main_sha_fails_before_source_archive(self):
        with (mock.patch.object(cd.pwd, "getpwnam", return_value=self.user),
              mock.patch.object(cd, "source_ssh_command", return_value="ssh pinned"),
              mock.patch.object(cd.os, "chown"),
              mock.patch.object(cd, "run", side_effect=["", OLD]),
              mock.patch.object(cd.subprocess, "run") as run_archive):
            with self.assertRaisesRegex(RuntimeError, "does not match approved SHA"):
                cd.verify_source_against_main(NEW, tar(FILES))
            run_archive.assert_not_called()


class HealthTests(unittest.TestCase):
    def test_html_nginx_403_is_not_a_healthy_post_route(self):
        with mock.patch.object(cd, "response", return_value=(
            403, b"<html>nginx denied</html>", {"Content-Type": "text/html"}
        )):
            with self.assertRaisesRegex(RuntimeError, "application JSON"):
                cd.check_order_routes()

    def test_both_local_and_public_routes_return_application_error(self):
        requested = []

        def fake_response(url, method="GET", data=None):
            requested.append((url, method, data))
            return (403, b'{"error":"same-origin demo action required"}',
                    {"Content-Type": "application/json; charset=UTF-8"})

        with mock.patch.object(cd, "response", side_effect=fake_response):
            cd.check_order_routes()
        self.assertEqual(requested, [
            ("http://127.0.0.1:8788/api/orders", "POST", b"{}"),
            ("https://capture402.xyz/api/orders", "POST", b"{}"),
        ])

    def test_json_proxy_403_with_wrong_body_is_rejected(self):
        with mock.patch.object(cd, "response", return_value=(
            403, b'{"error":"nginx policy"}', {"Content-Type": "application/json"}
        )):
            with self.assertRaisesRegex(RuntimeError, "Origin guard"):
                cd.check_order_routes()


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


    def test_failed_nginx_preflight_does_not_touch_current_services(self):
        payload = b"test archive"
        digest = hashlib.sha256(payload).hexdigest()
        stdin = types.SimpleNamespace(buffer=io.BytesIO(payload))
        with (mock.patch.object(cd.os, "geteuid", return_value=0),
              mock.patch.object(cd, "check_unit_layout"),
              mock.patch.object(cd, "verify_source_against_main"),
              mock.patch.object(cd, "prepare_release"),
              mock.patch.object(cd, "restart") as restart,
              mock.patch.object(cd, "run", side_effect=RuntimeError("nginx -t failed")),
              mock.patch.object(cd.sys, "stdin", stdin)):
            with self.assertRaisesRegex(RuntimeError, "nginx -t failed"):
                cd.deploy(NEW, digest)
        restart.assert_not_called()
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
