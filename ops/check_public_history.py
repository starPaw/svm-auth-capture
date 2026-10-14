#!/usr/bin/env python3
"""Reject private filenames, workstation paths and non-public commit identities."""
import gzip
import io
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile
from check_local_paths import has_local_path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PREFIXES = ('docs/evidence/', 'integration/evidence/', 'tasks/', 'ops/remote/', '.agents/', '.codex/')
PRIVATE_NAMES = {'agent.md', 'agents.md', 'docs/decisions.md', 'docs/workflow.md', 'docs/roadmap.md'}


def inspect(data, depth=0):
    if has_local_path(data):
        return False
    if depth >= 4:
        return not data.startswith((b'\x1f\x8b', b'PK\x03\x04'))
    try:
        if data.startswith(b'\x1f\x8b'):
            return inspect(gzip.decompress(data), depth + 1)
        if data.startswith(b'PK\x03\x04'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return all(not has_local_path(e.filename.encode()) and inspect(archive.read(e), depth + 1)
                           for e in archive.infolist() if not e.is_dir())
        if len(data) > 262 and data[257:262] == b'ustar':
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                return all(not has_local_path(e.name.encode()) and not has_local_path(e.linkname.encode())
                           and (not e.isfile() or inspect(archive.extractfile(e).read(), depth + 1)) for e in archive)
    except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile):
        return False
    return True


def main():
    rows = subprocess.check_output(['git', 'rev-list', '--objects', '--all'], cwd=ROOT).splitlines()
    errors = 0
    blobs = commits = 0
    proc = subprocess.Popen(['git', 'cat-file', '--batch'], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    for row in rows:
        oid, _, name = row.partition(b' ')
        label = name.decode(errors='replace')
        lower = label.lower()
        if has_local_path(name) or lower in PRIVATE_NAMES or lower.startswith(PRIVATE_PREFIXES) or any(p in ('agent.md', 'agents.md', '.agents', '.codex') for p in lower.split('/')):
            errors += 1
        proc.stdin.write(oid + b'\n'); proc.stdin.flush()
        _, kind, size = proc.stdout.readline().split()
        data = proc.stdout.read(int(size))
        if proc.stdout.read(1) != b'\n':
            raise RuntimeError('Invalid Git object framing')
        if kind == b'blob':
            blobs += 1
            if not inspect(data): errors += 1
        elif kind in (b'commit', b'tag'):
            commits += kind == b'commit'
            if not inspect(data): errors += 1
            for email in re.findall(rb'^(?:author|committer|tagger) .* <([^>]+)>', data, re.M):
                if email != b'noreply@github.com' and not email.endswith(b'@users.noreply.github.com'):
                    errors += 1
    proc.stdin.close()
    if proc.wait() != 0: errors += 1
    print(f'{commits} commits and {blobs} blobs checked; {errors} privacy violations')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
