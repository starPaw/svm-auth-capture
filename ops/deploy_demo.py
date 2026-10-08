#!/usr/bin/env python3
"""Root-owned, manually provisioned Capture402 Devnet release activator.

Called ONLY through the forced-command SSH key and a narrowly scoped sudo rule.
stdin: a gzip-compressed git archive of the exact, CI-approved main commit.
No Solana program upgrade, secret mutation, journal modification or payment submission.
"""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import subprocess
import sys
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


def response(url: str, method: str = "GET", data: bytes | None = None) -> tuple[int, bytes, dict]:
    request = urllib.request.Request(url, method=method, data=data)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=5) as answer:
            return answer.status, answer.read(32 * 1024), dict(answer.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(32 * 1024), dict(error.headers)


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
    require(local_status == 402 and "PAYMENT-REQUIRED" in local_headers,
            "local resource is not an x402 payment challenge")
    remote_status, _, remote_headers = response("https://capture402.xyz/resource")
    require(remote_status == 402 and "PAYMENT-REQUIRED" in remote_headers,
            "public resource routing is not an x402 payment challenge")
    order_status, _, _ = response("https://capture402.xyz/api/orders",
                                  method="POST", data=b"{}")
    require(order_status in (400, 401, 403, 415, 422),
            f"order POST routing/origin guard unexpected HTTP {order_status}")


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
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        members = archive.getmembers()
        require(len(members) <= MAX_MEMBERS, "archive contains too many entries")
        for member in members:
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


def chown_tree(root: Path, uid: int, gid: int) -> None:
    # Never follow npm-created .bin symlinks. Root is owner after final sealing.
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            os.chown(path, uid, gid, follow_symlinks=False)
        os.chown(parent, uid, gid, follow_symlinks=False)


def prepare_release(sha: str, digest: str, blob: bytes) -> None:
    target = RELEASES / sha
    manifest = MANIFESTS / f"{sha}.json"
    if target.exists():
        require(manifest.exists(), "existing release lacks sealed manifest")
        data = json.loads(manifest.read_text())
        require(data["archiveSha256"] == digest and data["sha"] == sha,
                "same SHA has a different archive digest")
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
        stage.chmod(0o755)
        os.rename(stage, target)
        write_json(manifest, {"sha": sha, "archiveSha256": digest, "status": "prepared"})
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def deploy(sha: str, digest: str) -> None:
    require(os.geteuid() == 0, "root-owned helper must be invoked via restricted sudo")
    require(bool(SHA_RE.fullmatch(sha)) and bool(HASH_RE.fullmatch(digest)),
            "expected exact 40-hex Git SHA and 64-hex SHA-256")
    require(BASE.is_dir() and RELEASES.is_dir() and MANIFESTS.is_dir(),
            "versioned release directories not provisioned")
    lock = os.open(BASE / "deploy.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_unit_layout()
        recover_pending()
        previous = current_sha()
        blob = sys.stdin.buffer.read(MAX_ARCHIVE + 1)
        require(len(blob) <= MAX_ARCHIVE and len(blob) > 0, "archive empty or over limit")
        require(hashlib.sha256(blob).hexdigest() == digest, "release archive SHA-256 mismatch")

        prepare_release(sha, digest, blob)
        if previous == sha:
            ready(sha)
            print(f"ALREADY_ACTIVE {sha}", flush=True)
            return

        write_json(PENDING, {"previous": previous, "target": sha,
                             "archiveSha256": digest})
        try:
            run("nginx", "-t")
            switch_to(sha)
            restart()
            ready(sha)
            write_json(MANIFESTS / f"{sha}.json",
                       {"sha": sha, "archiveSha256": digest, "status": "deployed"})
            PENDING.unlink()
            print(f"DEPLOYED {sha}; previous={previous}", flush=True)
        except Exception as original:
            print(f"Release failed; restoring {previous}: {original}", file=sys.stderr,
                  flush=True)
            try:
                switch_to(previous)
                restart()
                ready(previous)
                PENDING.unlink()
                print(f"ROLLED_BACK {previous}", file=sys.stderr, flush=True)
            except Exception as recovery:
                raise RuntimeError(
                    f"ROLLBACK_UNVERIFIED previous={previous}: {recovery}") from original
            raise
    finally:
        os.close(lock)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: deploy_demo.py <40-hex-main-sha> <64-hex-archive-sha256>")
    try:
        deploy(sys.argv[1], sys.argv[2])
    except Exception as error:
        print(f"DEPLOY_BLOCKED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1) from error
