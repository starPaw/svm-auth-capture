"""Privacy checks must inspect index blobs and compressed evidence, not just text."""
import gzip
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from check_local_paths import check, has_local_path, violations


class LocalPathTests(unittest.TestCase):
    def test_personal_roots_and_encoded_forms(self):
        for parts in [('Users', 'fixture', 'file'), ('Volumes', 'fixture', 'file'),
                      ('private', 'tmp', 'fixture'), ('private', 'var', 'fixture'),
                      ('var', 'folders', 'fixture')]:
            path = ('/' + '/'.join(parts)).encode()
            for data in (path, b'file://' + path, path.replace(b'/', b'\\/'),
                         path.replace(b'/', b'%2F'), b'\x00' + path + b'\x00'):
                with self.subTest(parts=parts, data_format=len(data)):
                    self.assertTrue(has_local_path(data))

    def test_portable_and_server_paths(self):
        for data in (b'integration/src/client.ts', b'<REPO>/integration',
                     b'<OWNER_HOME>/.config', b'/usr/bin/node', b'/home/service/app',
                     b'https://api.github.com/users/fixture'):
            self.assertFalse(has_local_path(data))

    def test_compressed_logs_and_tar_members(self):
        private = ('/' + '/'.join(('Users', 'fixture', 'file'))).encode()
        self.assertTrue(violations('log.gz', gzip.compress(private)))
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as output:
            member = tarfile.TarInfo('log.txt')
            member.size = len(private)
            output.addfile(member, io.BytesIO(private))
        self.assertTrue(violations('history.tgz', archive.getvalue()))

    def test_changed_or_differently_named_binary_is_not_exempt(self):
        private = ('/' + '/'.join(('Users', 'fixture', 'file'))).encode()
        self.assertTrue(violations('docs/evidence/sac-007/build-candidate/svm_auth_capture.so', private))
        self.assertTrue(violations('other.so', private))

    def test_corrupt_compressed_evidence_fails(self):
        self.assertTrue(violations('log.gz', b'\x1f\x8bcorrupt'))

    def test_staged_leak_is_found_after_working_copy_is_cleaned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            path = root / 'evidence.log'
            private = '/' + '/'.join(('Users', 'fixture', 'file'))
            path.write_text(private)
            subprocess.run(['git', 'add', 'evidence.log'], cwd=root, check=True)
            path.write_text('<REPO>/file')
            self.assertEqual(check(root), ([], 1))
            errors, count = check(root, staged=True)
            self.assertEqual(count, 1)
            self.assertEqual(len(errors), 1)
            self.assertNotIn(private, errors[0])


if __name__ == '__main__':
    unittest.main()
