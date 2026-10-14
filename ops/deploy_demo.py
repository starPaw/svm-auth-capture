#!/usr/bin/env python3
"""Shared release-source utilities and retained old-format rollback reader.

Forward deployment is owned by host_cli.py and deploy_vps.py. This module has
no activation CLI: direct invocation refuses without network or live mutation.
The pending.json recovery reader remains necessary for interrupted old releases.
"""
from __future__ import annotations

from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

BASE = Path("/opt/capture402")
RELEASES = BASE / "releases"
CURRENT = BASE / "current"
PENDING = BASE / "pending.json"
MANIFESTS = BASE / "manifests"
RECORD = "docs/evidence/sac-007/deployment-identity.v1.json"
SERVICES = ("sac006-facilitator", "sac006-resource")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARCHIVE = 75 * 1024 * 1024
MAX_UNPACKED = 180 * 1024 * 1024
MAX_MEMBERS = 14000
MAX_TAR_STREAM = 256 * 1024 * 1024

# A repository-scoped READ-ONLY GitHub deploy key, held on the VPS only.
# This key is unrelated to Actions -> VPS SSH or Solana economic authorities.
SOURCE_KEY = Path("/home/capture402-deploy/.ssh/github-source-readonly")
SOURCE_KNOWN_HOSTS = Path("/etc/capture402/github_known_hosts")
SOURCE_REMOTE = "ssh://git@github.com/starPaw/capture402.git"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(*args: str, cwd: Path | None = None, timeout: int = 90) -> str:
    result = subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                            text=True, timeout=timeout)
    return result.stdout.strip()


def write_json(path: Path, value: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def release_name(path: Path) -> str:
    real = path.resolve(strict=True)
    require(real.parent == RELEASES.resolve(strict=True), "current release escapes releases/")
    require(bool(SHA_RE.fullmatch(real.name)), "current release has no exact SHA name")
    return real.name


def current_sha() -> str:
    require(CURRENT.is_symlink(), "current is not a symlink; manual migration is required")
    return release_name(CURRENT)


def switch_to(sha: str) -> None:
    require(bool(SHA_RE.fullmatch(sha)), "invalid release SHA")
    require((RELEASES / sha).is_dir(), "release missing")
    link = BASE / (".current-" + str(os.getpid()))
    link.symlink_to(RELEASES / sha, target_is_directory=True)
    try:
        os.replace(link, CURRENT)
    finally:
        link.unlink(missing_ok=True)


def check_unit_layout() -> None:
    for service in SERVICES:
        cwd = run("systemctl", "show", "-p", "WorkingDirectory", "--value", service)
        require(cwd == str(CURRENT / "integration"),
                f"{service}: expected versioned-release WorkingDirectory override")


def response(url: str, method: str = "GET", data: bytes | None = None,
             headers: dict | None = None) -> tuple[int, bytes, dict]:
    request = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=5) as answer:
            return answer.status, answer.read(32 * 1024), dict(answer.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(32 * 1024), dict(error.headers)


def check_order_routes() -> None:
    # A missing Origin fails in application middleware before mutable work.
    # Insist on that JSON response, never only a proxy-supplied status.
    for url in ("http://127.0.0.1:8788/api/orders",
                "https://capture402.xyz/api/orders"):
        status, body, headers = response(url, method="POST", data=b"{}")
        content_type = next((v for k, v in headers.items()
                             if k.lower() == "content-type"), "")
        require(status == 403, f"order POST routing HTTP {status}: {url}")
        require(content_type.split(";", 1)[0].strip().lower() == "application/json",
                f"order POST did not return application JSON: {url}")
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError) as error:
            raise RuntimeError(f"order POST returned invalid JSON: {url}") from error
        require(payload == {"error": "same-origin demo action required"},
                f"order POST did not reach the application's Origin guard: {url}")


class BoundedTarReader:
    """Bound decompressed bytes, including tar/PAX metadata and padding."""

    def __init__(self, stream):
        self.stream = stream
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        require(size >= 0, "unbounded tar read not permitted")
        chunk = self.stream.read(min(size, MAX_TAR_STREAM - self.total + 1))
        self.total += len(chunk)
        require(self.total <= MAX_TAR_STREAM, "decompressed tar stream exceeds limit")
        return chunk


@contextmanager
def bounded_tar(blob: bytes, mode: str):
    require(mode in ("r:gz", "r:"), "unsupported archive read mode")
    source = (gzip.GzipFile(fileobj=io.BytesIO(blob), mode="rb")
              if mode == "r:gz" else io.BytesIO(blob))
    with source:
        # Streaming mode does not pre-scan all archive entries.
        with tarfile.open(fileobj=BoundedTarReader(source), mode="r|") as archive:
            yield archive


def check_health(sha: str) -> None:
    expected_release = (RELEASES / sha).resolve(strict=True)
    for service in SERVICES:
        require(run("systemctl", "is-active", service) == "active",
                f"{service} inactive")
        pid = run("systemctl", "show", "-p", "MainPID", "--value", service)
        require(pid.isdecimal() and int(pid) > 0, f"{service}: missing MainPID")
        require(Path(os.readlink(f"/proc/{pid}/cwd")).resolve() == expected_release / "integration",
                f"{service}: process does not execute approved release {sha}")

    status, body, _ = response("http://127.0.0.1:8788/api/config")
    require(status == 200, f"local /api/config HTTP {status}")
    config = json.loads(body)
    record = json.loads((expected_release / RECORD).read_text())
    require(config.get("configured") is True, "resource is unprovisioned")
    require(config.get("cluster") == "devnet", "unexpected cluster")
    require(config.get("programId") == record["program"]["program_id"], "program identity mismatch")
    require(config.get("network") == record["network"]["caip2"], "network mismatch")
    require(bool(config.get("mint")) and bool(config.get("merchant"))
            and bool(config.get("sponsor")), "missing authenticated runtime identities")

    local_status, _, local_headers = response("http://127.0.0.1:8788/resource")
    require(local_status == 402 and any(k.lower() == "payment-required" for k in local_headers),
            "local resource is not an x402 payment challenge")
    remote_status, _, remote_headers = response("https://capture402.xyz/resource")
    require(remote_status == 402 and any(k.lower() == "payment-required" for k in remote_headers),
            "public resource routing is not an x402 payment challenge")
    check_order_routes()


def ready(sha: str, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    last: Exception | None = None
    while True:
        try:
            check_health(sha)
            return
        except (RuntimeError, OSError, ValueError, KeyError, subprocess.CalledProcessError,
                urllib.error.URLError, json.JSONDecodeError) as exc:
            last = exc
        if time.monotonic() >= deadline:
            raise RuntimeError(f"readiness failed: {last}") from last
        time.sleep(2)


def restart() -> None:
    run("systemctl", "restart", SERVICES[0], timeout=30)
    run("systemctl", "restart", SERVICES[1], timeout=30)


def recover_pending() -> None:
    if not PENDING.exists():
        return
    pending = json.loads(PENDING.read_text())
    previous = pending["previous"]
    require(bool(SHA_RE.fullmatch(previous)), "invalid pending rollback target")
    print(f"Recovering interrupted switch back to {previous}", flush=True)
    switch_to(previous)
    restart()
    ready(previous)
    PENDING.unlink()
    print("Interrupted switch recovered; retry deployment explicitly", flush=True)
    raise RuntimeError("previous interrupted deployment rolled back; retry to deploy")


def unpack_archive(blob: bytes, destination: Path) -> None:
    total = 0
    seen: set[str] = set()
    with bounded_tar(blob, "r:gz") as archive:
        for count, member in enumerate(archive, 1):
            require(count <= MAX_MEMBERS, "archive contains too many entries")
            raw = member.name.rstrip("/")
            parts = PurePosixPath(raw).parts
            require(bool(parts) and not raw.startswith("/")
                    and all(p not in ("", ".", "..") for p in parts),
                    "unsafe archive path")
            allowed = (parts[0] == "integration"
                       or raw in ("docs", "docs/evidence", "docs/evidence/sac-007", RECORD))
            require(allowed, f"unexpected release path: {raw}")
            require(member.isdir() or member.isfile(), f"links/devices not allowed: {raw}")
            require(raw not in seen, f"duplicate archive entry: {raw}")
            seen.add(raw)
            total += member.size
            require(total <= MAX_UNPACKED, "extracted archive too large")
            path = destination.joinpath(*parts)
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if member.isdir():
                path.mkdir(mode=0o755, exist_ok=True)
            else:
                require(not path.exists(), "archive file already exists")
                stream = archive.extractfile(member)
                require(stream is not None, "missing archive file bytes")
                with path.open("xb") as output:
                    shutil.copyfileobj(stream, output)
                path.chmod(0o644)

    for relative in ("integration/package.json", "integration/package-lock.json",
                     "integration/src/restaurant-server.ts",
                     "integration/src/devnet-server.ts", "integration/web/index.html", RECORD):
        require((destination / relative).is_file(),
                f"required app file missing: {relative}")



def archive_fingerprints(blob: bytes, mode: str) -> dict[str, tuple[str, str]]:
    """Match the reviewed Git tree, not merely a digest claimed by the SSH key."""
    output: dict[str, tuple[str, str]] = {}
    with bounded_tar(blob, mode) as archive:
        total = 0
        for count, member in enumerate(archive, 1):
            require(count <= MAX_MEMBERS, "too many entries for source verification")
            path = member.name.rstrip("/")
            require(path not in output, "duplicate source path")
            require(member.isdir() or member.isfile(), "unsupported Git object type")
            total += member.size
            require(total <= MAX_UNPACKED, "source content too large")
            if member.isdir():
                output[path] = ("dir", "")
            else:
                payload = archive.extractfile(member)
                require(payload is not None, "missing source bytes")
                digest = hashlib.sha256()
                while True:
                    chunk = payload.read(128 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                output[path] = ("file", digest.hexdigest())
    return output


def source_ssh_command(user: pwd.struct_passwd, *, hosts_owner_uid: int = 0) -> str:
    """Use exactly one repository-scoped key and independently pinned GitHub host.

    Fail closed if a secret is absent, world-readable, substituted by a
    symlink, or if the trusted host pin is writable by the deploy user.
    """
    require(SOURCE_KEY.is_file() and not SOURCE_KEY.is_symlink(),
            "private GitHub source deploy key missing or unsafe")
    key_info = SOURCE_KEY.lstat()
    require(stat.S_ISREG(key_info.st_mode) and key_info.st_uid == user.pw_uid
            and (key_info.st_mode & 0o077) == 0,
            "source deploy key must be owned by deploy user and private (0600)")
    require(SOURCE_KNOWN_HOSTS.is_file() and not SOURCE_KNOWN_HOSTS.is_symlink(),
            "root-pinned GitHub known_hosts missing or unsafe")
    hosts_info = SOURCE_KNOWN_HOSTS.lstat()
    require(stat.S_ISREG(hosts_info.st_mode)
            and hosts_info.st_uid == hosts_owner_uid
            and (hosts_info.st_mode & 0o022) == 0,
            "GitHub host key pin must be root-owned and not writable by deploy user")
    require(bool(SOURCE_KNOWN_HOSTS.read_text().strip()),
            "empty GitHub host key pin")
    return (
        "ssh -F /dev/null"
        f" -i {SOURCE_KEY}"
        " -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none"
        " -o StrictHostKeyChecking=yes"
        f" -o UserKnownHostsFile={SOURCE_KNOWN_HOSTS}"
        " -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no"
        " -o ForwardAgent=no -o ClearAllForwardings=yes"
        " -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
        " -o ConnectTimeout=10"
    )


def clone_main(sha: str, root: Path, user: pwd.struct_passwd) -> Path:
    """Resolve only the current private main, with an isolated SSH identity."""
    require(bool(SHA_RE.fullmatch(sha)), "invalid canonical main SHA")
    ssh_command = source_ssh_command(user)
    repo = root / "repository"
    run("runuser", "-u", "capture402-deploy", "--", "/usr/bin/env", "-i",
        f"HOME={user.pw_dir}", "PATH=/usr/bin:/bin", "GIT_TERMINAL_PROMPT=0",
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
        "/usr/bin/git", "-c", "credential.helper=",
        "-c", f"core.sshCommand={ssh_command}", "clone", "--depth=1",
        "--single-branch", "--branch=main", "--no-checkout",
        SOURCE_REMOTE, str(repo), timeout=180)
    live = run("runuser", "-u", "capture402-deploy", "--", "/usr/bin/env", "-i",
               f"HOME={user.pw_dir}", "PATH=/usr/bin:/bin",
               "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
               "git", "rev-parse", "HEAD", cwd=repo)
    require(live == sha, "remote canonical main does not match approved SHA")
    return repo


def require_current_main(sha: str) -> None:
    """Refresh canonical identity after staging and immediately before cutover."""
    user = pwd.getpwnam('capture402-deploy')
    ssh_command = source_ssh_command(user)
    remote = run('runuser', '-u', 'capture402-deploy', '--', '/usr/bin/env', '-i',
                 f'HOME={user.pw_dir}', 'PATH=/usr/bin:/bin', 'GIT_TERMINAL_PROMPT=0',
                 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                 'git', '-c', 'credential.helper=', '-c', f'core.sshCommand={ssh_command}',
                 'ls-remote', '--exit-code', SOURCE_REMOTE, 'refs/heads/main', timeout=20)
    require(remote == sha + '\trefs/heads/main', 'canonical main changed before cutover')


def git_archive(repo: Path, sha: str) -> bytes:
    """An archive of the exact commit, excluding workflow code and any secrets."""
    return subprocess.run(
        ["runuser", "-u", "capture402-deploy", "--", "/usr/bin/env", "-i",
         f"HOME={pwd.getpwnam('capture402-deploy').pw_dir}", "PATH=/usr/bin:/bin",
         "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
         "git", "archive", "--format=tar", sha, "integration", RECORD],
        cwd=repo, capture_output=True, check=True, timeout=90,
    ).stdout


def manually_fetch_archive(sha: str) -> bytes:
    """Run on VPS only after independent human approval of the exact green SHA."""
    require(os.geteuid() == 0, "manual release requires authorized local sudo")
    require(bool(SHA_RE.fullmatch(sha)), "exact lowercase main SHA required")
    require(RELEASES.is_dir(), "release directory not provisioned")
    user = pwd.getpwnam("capture402-deploy")
    with tempfile.TemporaryDirectory(prefix=".manual-", dir=RELEASES) as path:
        temp = Path(path)
        os.chown(temp, user.pw_uid, user.pw_gid)
        repo = clone_main(sha, temp, user)
        tar = git_archive(repo, sha)
        require(0 < len(tar) <= MAX_TAR_STREAM, "source tar over limit")
        # git archive must contain supported regular files/directories only.
        archive_fingerprints(tar, "r:")
        blob = gzip.compress(tar, compresslevel=9, mtime=0)
        require(0 < len(blob) <= MAX_ARCHIVE, "compressed source archive over limit")
        return blob


def verify_source_against_main(sha: str, blob: bytes) -> None:
    """An independently fetched Git tree must match the locally staged archive.

    Even in manual deployment, a compromised checkout or substituted artifact
    cannot bypass current main-SHA and byte-exact content verification.
    """
    user = pwd.getpwnam("capture402-deploy")
    with tempfile.TemporaryDirectory(prefix=".verify-", dir=RELEASES) as path:
        temp = Path(path)
        os.chown(temp, user.pw_uid, user.pw_gid)
        repo = clone_main(sha, temp, user)
        archived = git_archive(repo, sha)
        require(archive_fingerprints(blob, "r:gz")
                == archive_fingerprints(archived, "r:"),
                "received artifact differs from exact GitHub main tree")


def chown_tree(root: Path, uid: int, gid: int) -> None:
    # Never follow npm-created .bin symlinks. Root is owner after final sealing.
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            os.chown(path, uid, gid, follow_symlinks=False)
        os.chown(parent, uid, gid, follow_symlinks=False)


def seal_runtime_permissions(root: Path) -> None:
    """Make sealed application bytes readable by sac006 under private UMask.

    Source and dependencies contain no private configuration. Keep only owner
    write access, preserve executable files, and never follow npm symlinks.
    """
    require(root.is_dir() and not root.is_symlink(), "unsafe runtime root")
    for parent, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(parent), *(Path(parent) / n for n in dirs + files)]:
            info = path.lstat()
            require(info.st_uid == os.geteuid(), "runtime is not owned by deployment user")
            if stat.S_ISLNK(info.st_mode):
                continue
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                    "unsupported runtime file type")
            path.chmod(0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o100 else 0o644)


def prepare_release(sha: str, digest: str, blob: bytes) -> None:
    target = RELEASES / sha
    manifest = MANIFESTS / f"{sha}.json"
    if target.exists():
        require(manifest.exists(), "existing release lacks sealed manifest")
        data = json.loads(manifest.read_text())
        require(data["archiveSha256"] == digest and data["sha"] == sha,
                "same SHA has a different archive digest")
        seal_runtime_permissions(target)
        return

    stage = Path(tempfile.mkdtemp(prefix=".candidate-", dir=RELEASES))
    try:
        unpack_archive(blob, stage)
        user = pwd.getpwnam("capture402-deploy")
        chown_tree(stage, user.pw_uid, user.pw_gid)
        # No lifecycle hooks; installation cannot execute arbitrary package scripts as root.
        run("runuser", "-u", "capture402-deploy", "--", "/usr/bin/env", "npm", "ci",
            "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund",
            cwd=stage / "integration", timeout=240)
        chown_tree(stage, 0, 0)
        seal_runtime_permissions(stage)
        write_json(manifest, {"sha": sha, "archiveSha256": digest, "status": "prepared"})
        os.rename(stage, target)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    raise SystemExit("Retired deployment entrypoint; use sudo capture402 deploy <40-hex-main-sha>")
