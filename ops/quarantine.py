#!/usr/bin/env python3
"""Independent dev admission + offline quarantine controller. No exit/unquarantine.

The installed copy lives OUTSIDE versioned controllers. Missing or corrupt enrolled
metadata denies startup. No payment bytes are written, migrated or restored here.
"""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import shlex
import socket
import stat
import subprocess
import sys
import time

ROOT = Path('/etc/capture402-dev-admission')
GUARD = Path('/usr/local/libexec/capture402-dev-admission.py')
BASE = Path('/opt/capture402-dev')
STATE = Path('/var/lib/capture402-dev')
PRIVATE = Path('/etc/capture402-dev')
CGROUP = Path('/sys/fs/cgroup/capture402.slice/capture402-dev.slice')
UNITS = Path('/etc/systemd/system')
VIEW_PERMIT = Path('/run/capture402-dev-view-permit')
SERVICES = ('capture402-dev-facilitator', 'capture402-dev-restaurant')
PHASES = ('DENY_INTENT', 'FENCED', 'STOPPED', 'SNAPSHOT_SEALED', 'CODE_SELECTED', 'VIEW_RUNNING')
ROLES = ('facilitator', 'operations', 'reclaim', 'orders')
STORE_PATHS = (STATE / 'facilitator/journal', STATE / 'restaurant/operation-store',
               STATE / 'restaurant/reclaim', STATE / 'restaurant/operation-store-restaurant')


def require(ok):
    if not ok:
        raise RuntimeError('QUARANTINE_REFUSED')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result)
            result[k] = v
        return result
    require(not raw.startswith(b'\xef\xbb\xbf'))
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False))


def shape(v, keys):
    require(isinstance(v, dict) and set(v) == set(keys))


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def identity(s):
    return dict(device=s.st_dev, inode=s.st_ino, type=stat.S_IFMT(s.st_mode),
                uid=s.st_uid, gid=s.st_gid, mode=stat.S_IMODE(s.st_mode), links=s.st_nlink,
                size=s.st_size, mtimeNs=s.st_mtime_ns, ctimeNs=s.st_ctime_ns)


def parents(path):
    for p in [path.parent, *path.parent.parents]:
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode) and not s.st_mode & 0o022)


def read(path, limit=32 * 1024 * 1024, owner=None, allow_empty=False):
    parents(path)
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and (0 if allow_empty else 1) <= s.st_size <= limit)
    if owner is not None:
        require(s.st_uid == owner and not s.st_mode & 0o022)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(identity(before) == identity(s))
        chunks, size = [], 0
        while size <= limit:
            b = os.read(fd, min(65536, limit + 1 - size))
            if not b:
                break
            chunks.append(b)
            size += len(b)
        raw = b''.join(chunks)
        require(len(raw) == s.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()))
        return raw, identity(s)
    finally:
        os.close(fd)


def exclusive(path, data, mode=0o600):
    # An incomplete file is deliberately retained and will fail admission.
    parents(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as f:
            f.write(data)
            f.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(path.parent)


def exists(path):
    return os.path.lexists(path)


def caller_identity(pid):
    require(type(pid) is int and pid > 0)
    root = Path('/proc') / str(pid)
    ids = next(s.split()[1:] for s in (root / 'status').read_text().splitlines() if s.startswith('Uid:'))
    require(all(n == '0' for n in ids))
    return {'pid': pid, 'startTicks': (root / 'stat').read_text().rsplit(')', 1)[1].split()[19], 'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def ordinary_allowed():
    if not exists(ROOT):
        require(not exists(GUARD))
        return  # Unenrolled ordinary A keeps its existing gates.
    s = ROOT.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700)
    # Any marker, including a corrupt/symlink/incomplete one, is denial.
    require(not exists(ROOT / 'ECONOMICS_DENIED'))
    require(not list(ROOT.glob('*-*.json')) and not exists(ROOT / 'projection.json') and not exists(BASE / 'read-only-maintenance'))
    if exists(ROOT / 'BOOTSTRAP_PENDING') and not exists(ROOT / 'BOOTSTRAP_COMMITTED'):
        pending = strict_json(read(ROOT / 'BOOTSTRAP_PENDING', owner=0)[0])
        shape(pending, ('version', 'candidate', 'guardSha256'))
        require(pending['version'] == 1 and re.fullmatch('[a-f0-9]{40}', pending['candidate']) and re.fullmatch('[a-f0-9]{64}', pending['guardSha256']))
        require(not exists(GUARD) or digest(read(GUARD, owner=0)[0]) == pending['guardSha256'])
        return  # No exception exists until verified enrollment is durably committed.
    enrollment()  # Deletion/corruption does not implicitly unenroll.


def enrollment():
    require(read(ROOT / 'BOOTSTRAP_COMMITTED', owner=0)[0] == b'B2_ENROLLED v1\n')
    e = strict_json(read(ROOT / 'enrollment.json', owner=0)[0])
    shape(e, ('version', 'uids', 'guardSha256', 'activation', 'tuple', 'selected', 'public', 'viewerRoot', 'viewerInventory', 'ownerDisposition'))
    require(e['version'] == 1 and e['ownerDisposition'] == 'ACCEPTED_CONTINUED_OUTAGE_AND_INERT_ROLLBACK')
    require(isinstance(e['uids'], list) and e['uids'] and len(set(e['uids'])) == len(e['uids']) and all(type(n) is int and n > 0 for n in e['uids']))
    require(e['guardSha256'] == digest(read(GUARD, owner=0)[0]))
    shape(e['tuple'], ('candidate', 'previous', 'controllerRevision', 'controller', 'guard', 'validator', 'codecs', 'dependencies', 'build', 'unit', 'routing', 'projectionRuntime', 'configuration'))
    for k, v in e['tuple'].items():
        require(isinstance(v, str) and re.fullmatch(r'[a-f0-9]{40}' if k in ('candidate', 'previous', 'controllerRevision') else r'[a-f0-9]{64}', v))
    require(e['tuple']['guard'] == e['guardSha256'])
    shape(e['selected'], ('signature', 'messageHash', 'wireSha256', 'journalSha256'))
    require(isinstance(e['selected']['signature'], str) and re.fullmatch('[1-9A-HJ-NP-Za-km-z]{80,90}', e['selected']['signature']))
    require(all(re.fullmatch('[a-f0-9]{64}', e['selected'][k]) for k in ('messageHash', 'wireSha256', 'journalSha256')))
    shape(e['public'], ('network', 'genesisHash', 'programId'))
    require(re.fullmatch(r'solana:[a-zA-Z0-9-]+', e['public']['network']) and all(re.fullmatch('[1-9A-HJ-NP-Za-km-z]{32,44}', e['public'][k]) for k in ('genesisHash', 'programId')))
    require(Path(e['viewerRoot']) == BASE / 'views' / e['tuple']['candidate'])
    require(isinstance(e['activation'], dict) and e['activation'] and all(str(Path(k)) == k and Path(k).is_absolute() and re.fullmatch('[a-f0-9]{64}', v) for k, v in e['activation'].items()))
    return e


def inventory(paths=None):
    paths = STORE_PATHS if paths is None else paths
    result, stores, inodes = {}, {}, set()
    for role, directory in zip(ROLES, paths):
        parents(directory / 'unused')
        ds = directory.lstat()
        require(stat.S_ISDIR(ds.st_mode) and not directory.is_symlink() and ds.st_dev == STATE.stat().st_dev)
        if sys.platform == 'linux':
            mounts = [line.split()[4].replace('\\040', ' ') for line in Path('/proc/self/mountinfo').read_text().splitlines()]
            require(not any(Path(m) == directory or Path(m).is_relative_to(directory) for m in mounts))
        names = sorted(os.listdir(directory))
        require(len(names) <= 4096)
        members = []
        for name in names:
            require(re.fullmatch('[a-zA-Z0-9.-]+', name) and '.tmp-' not in name)
            p = directory / name
            raw, meta = read(p, 4 * 1024 * 1024 - 1)
            require(meta['device'] == ds.st_dev and (meta['device'], meta['inode']) not in inodes)
            inodes.add((meta['device'], meta['inode']))
            # Reject unmodelled ACLs/xattrs; never silently ignore extra capability semantics.
            require(not os.listxattr(p, follow_symlinks=False))
            if name.endswith('.json') or role == 'orders' and name.endswith('.lock'):
                strict_json(raw)
            result[role + '/' + name] = dict(meta, sha256=digest(raw))
            members.append(dict(name=name, rawBase64=base64.b64encode(raw).decode()))
        require(names == sorted(os.listdir(directory)) and identity(ds) == identity(directory.lstat()) and not os.listxattr(directory, follow_symlinks=False))
        result[role + '/'] = identity(ds)
        stores[role] = members
    return result, stores


def tree(root):
    require(root.is_dir() and not root.is_symlink())
    result = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        require(len(result) < 20000)
        for n in dirs + names:
            p = Path(directory) / n
            s = p.lstat()
            require(s.st_uid == 0 and not s.st_mode & 0o022 and not stat.S_ISLNK(s.st_mode) and s.st_dev == root.stat().st_dev)
            if stat.S_ISREG(s.st_mode):
                require(s.st_nlink == 1)
                parents(p)
                require(s.st_size <= 128 * 1024 * 1024)
                fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    with os.fdopen(fd, 'rb', closefd=False) as stream:
                        require(identity(os.fstat(fd)) == identity(s))
                        result[str(p.relative_to(root))] = hashlib.file_digest(stream, 'sha256').hexdigest()
                        require(identity(os.fstat(fd)) == identity(s) == identity(p.lstat()))
                finally:
                    os.close(fd)
            else:
                require(stat.S_ISDIR(s.st_mode))
    return result


def static_view_tree(root):
    return {k: v for k, v in tree(root).items() if k not in ('app/projection.json', 'app/manifest.json')}


def run(*argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                       env={'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C'})
    require(r.returncode == 0)
    return r.stdout.strip()


def events():
    if not CGROUP.exists():
        return {'populated': 0, 'frozen': 1}  # Only STOPPED can accept a reaped slice.
    return {k: int(v) for k, v in (line.split() for line in (CGROUP / 'cgroup.events').read_text().splitlines())}


def uid_processes(uids):
    result = {}
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():
            continue
        try:
            status = (p / 'status').read_text()
            ids = next(s.split()[1:] for s in status.splitlines() if s.startswith('Uid:'))
            if any(int(n) in uids for n in ids):
                cgroups = (p / 'cgroup').read_text().splitlines()
                require(len(cgroups) == 1 and cgroups[0].startswith('0::'))
                result[int(p.name)] = cgroups[0][3:]
        except FileNotFoundError:
            continue
    return result


def private_capabilities(uids):
    """No unenrolled UID may acquire a private file or retained open descriptor.

    Root and prior exfiltration are explicit trust exclusions. Group-readable key
    or env files are unsupported, even when nginx shares the ingress group.
    """
    for directory, dirs, files in os.walk(PRIVATE, followlinks=False):
        for name in dirs + files:
            p = Path(directory) / name; s = p.lstat()
            require(s.st_uid in {0, *uids} and not stat.S_ISLNK(s.st_mode))
            require(s.st_dev == PRIVATE.stat().st_dev and not os.listxattr(p, follow_symlinks=False))
            if stat.S_ISREG(s.st_mode):
                require(s.st_nlink == 1 and not s.st_mode & 0o077)
            else:
                require(stat.S_ISDIR(s.st_mode) and not s.st_mode & 0o027)
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            ids = next(s.split()[1:] for s in (process / 'status').read_text().splitlines() if s.startswith('Uid:'))
            if any(int(n) in {0, *uids} for n in ids):
                continue
            for fd in (process / 'fd').iterdir():
                try:
                    target = os.readlink(fd).removesuffix(' (deleted)')
                    require(not any(target == str(p) or target.startswith(str(p) + '/') for p in (PRIVATE, STATE)))
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            continue


def configuration():
    import deploy_dev
    require(tuple(deploy_dev.state_paths()) == STORE_PATHS)
    shared = {'SOLANA_RPC_URL', 'SAC006_BEARER_TOKEN', 'SAC006_DEPLOYMENT_RECORD_PATH', 'SAC006_HOST'}
    allowed = [shared | {'SAC006_FACILITATOR_KEYPAIR_PATH', 'SAC006_FACILITATOR_JOURNAL_DIR', 'SAC006_ALLOWLIST_MERCHANT', 'SAC006_ALLOWLIST_MINT', 'SAC006_PORT', 'SAC006_SPONSOR_MAX_ATTEMPTS', 'SAC006_SPONSOR_MIN_LAMPORTS'},
               shared | {'SAC006_MERCHANT_TOKEN', 'SAC006_FACILITATOR_URL', 'SAC006_FEE_PAYER', 'SAC006_SERVER_KEYPAIR_PATH', 'SAC006_STORE_DIR', 'SAC006_RECLAIM_JOURNAL_DIR', 'SAC006_ASSET_MINT', 'SAC006_PUBLIC_ORIGIN', 'SAC006_RESOURCE_PORT'}]
    hashes = {}
    for role, supported, key_name, key_file in zip(('facilitator', 'restaurant'), allowed, ('SAC006_FACILITATOR_KEYPAIR_PATH', 'SAC006_SERVER_KEYPAIR_PATH'), ('sponsor.json', 'merchant.json')):
        raw, meta = read(PRIVATE / (role + '.env'), owner=0); require(meta['mode'] == 0o600)
        assignments = {}
        for line in raw.decode().splitlines():
            if not line.strip() or line.lstrip().startswith('#'): continue
            parts = shlex.split(line, comments=True); require(len(parts) == 1 and '=' in parts[0])
            k, v = parts[0].split('=', 1); require(k in supported and k not in assignments and v); assignments[k] = v
        require(set(assignments) == supported)
        require(assignments[key_name] == str(PRIVATE / 'keys' / key_file) and assignments['SAC006_HOST'] == '127.0.0.1' and assignments['SAC006_DEPLOYMENT_RECORD_PATH'] == str(BASE / 'current/docs/evidence/sac-007/deployment-identity.v1.json'))
        if role == 'restaurant': require(assignments['SAC006_FACILITATOR_URL'] == 'http://127.0.0.1:18887' and assignments['SAC006_RESOURCE_PORT'] == '18888')
        else: require(assignments['SAC006_PORT'] == '18887')
        key = PRIVATE / 'keys' / key_file; _, key_meta = read(key)
        require(key_meta['uid'] == pwd.getpwnam('capture402-dev-' + role).pw_uid and key_meta['mode'] == 0o600)
        hashes[role] = digest(raw)
    return digest(encoded(hashes))


class LinuxHost:
    def __init__(self, e):
        self.e = e

    def verify(self, stopped=False):
        require(sys.platform == 'linux' and os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd')
        require(not exists(BASE / 'transaction.json') and not exists(BASE / 'pending.json'))
        # Activation set is an exact root-owned host inventory, not command-name allowlisting.
        require(self.e['activation'] == activation_inventory(self.e))
        for uid in self.e['uids']:
            user = pwd.getpwuid(uid)
            require(user.pw_shell in ('/usr/sbin/nologin', '/bin/false') and user.pw_name.startswith(('capture402-dev-', 'capture402-deploy')))
            require(not (Path('/var/lib/systemd/linger') / user.pw_name).exists())
        expected_uids = {pwd.getpwnam(n).pw_uid for n in ('capture402-dev-setup', *SERVICES, 'capture402-deploy')}
        require(expected_uids == set(self.e['uids']))
        private_capabilities(set(self.e['uids']))
        require(configuration() == self.e['tuple']['configuration'])
        processes = uid_processes(self.e['uids'])
        prefix = '/' + str(CGROUP.relative_to('/sys/fs/cgroup'))
        require(all(v == prefix or v.startswith(prefix + '/') for v in processes.values()))
        if stopped:
            require(not processes and events()['populated'] == 0)
        else:
            require(CGROUP.is_dir() and (CGROUP / 'cgroup.kill').is_file())
        require(static_view_tree(Path(self.e['viewerRoot'])) == self.e['viewerInventory'])
        # Hooks independent of whichever versioned controller happens to be selected.
        for n in SERVICES:
            require(run('systemctl', 'show', '-p', 'ExecCondition', '--value', n).find(str(GUARD)) >= 0)

    def close(self):
        # Close ingress before revocation/fencing. This does not claim sends cancelled.
        exclusive(BASE / 'read-only-maintenance', b'ECONOMICS_DENIED\n') if not exists(BASE / 'read-only-maintenance') else None
        self.stop_view()
        routing = read(ROOT / 'routing.conf', owner=0)[0]
        require(digest(routing) == self.e['tuple']['routing'])
        target = PRIVATE / 'nginx-routes.conf'
        if read(target, owner=0)[0] != routing:
            tmp = PRIVATE / '.b2-routing'
            exclusive(tmp, routing, 0o600)
            os.replace(tmp, target)
            fsync_dir(PRIVATE)
        run('nginx', '-t')
        run('systemctl', 'reload', 'nginx')
        for p in (PRIVATE, STATE):
            require(p.is_dir() and not p.is_symlink())
            os.chown(p, 0, 0)
            os.chmod(p, 0o700)  # Outside four-store membership; members retain identities/modes.
            fsync_dir(p)
            fsync_dir(p.parent)

    def fence(self):
        if not CGROUP.exists():
            require(not uid_processes(self.e['uids']))
            return
        (CGROUP / 'cgroup.freeze').write_text('1')
        deadline = time.monotonic() + 10
        while events()['frozen'] != 1:
            require(time.monotonic() < deadline)
            time.sleep(.02)
        self.verify()

    def stop(self):
        if CGROUP.exists():
            require(events()['frozen'] == 1)
            (CGROUP / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 10
        while events()['populated'] or uid_processes(self.e['uids']):
            require(time.monotonic() < deadline)
            time.sleep(.02)
        for n in SERVICES:
            run('systemctl', 'stop', n)
        # Recovery owns the controller lock. Retire a crashed caller's ephemeral
        # startup lease only after all enrolled processes have ceased; denial stays.
        if exists(VIEW_PERMIT):
            require(VIEW_PERMIT.is_file() and not VIEW_PERMIT.is_symlink() and VIEW_PERMIT.stat().st_uid == 0)
            VIEW_PERMIT.unlink()
            fsync_dir(VIEW_PERMIT.parent)
        self.verify(stopped=True)

    def stop_view(self):
        group = run('systemctl', 'show', '-p', 'ControlGroup', '--value', SERVICES[1])
        if group and group != '/' + str(CGROUP.relative_to('/sys/fs/cgroup')) + '/' + SERVICES[1] + '.service':
            require(group == '/capture402.slice/capture402-view.slice/' + SERVICES[1] + '.service')
            profile = UNITS / (SERVICES[1] + '.service.d') / '99-quarantine.conf'
            require(read(profile, owner=0)[0] == viewer_unit(self.e).encode())
            path = Path('/sys/fs/cgroup') / group.lstrip('/')
            (path / 'cgroup.freeze').write_text('1')
            deadline = time.monotonic() + 10
            while 'frozen 1' not in (path / 'cgroup.events').read_text():
                require(time.monotonic() < deadline)
                time.sleep(.02)
            (path / 'cgroup.kill').write_text('1')
            run('systemctl', 'stop', SERVICES[1])

    def prepare_projection(self, raw):
        root = Path(self.e['viewerRoot']) / 'app'
        exclusive(root / 'projection.json', raw, 0o444)
        manifest = {'version': 1, 'projectionSha256': digest(raw),
                    'authSha256': digest(read(root / 'auth.json', owner=0)[0]),
                    'assets': {'/assets/' + n: digest(read(root / n, owner=0)[0])
                               for n in ('quarantine.css', 'quarantine.js')}}
        exclusive(root / 'manifest.json', encoded(manifest), 0o444)

    def open_view_ingress(self):
        require(run('systemctl', 'is-active', SERVICES[1]) == 'active')
        pid = run('systemctl', 'show', '-p', 'MainPID', '--value', SERVICES[1])
        require(pid.isdecimal() and int(pid) > 0)
        actual_root = os.stat('/proc/' + pid + '/root')
        sealed_root = Path(self.e['viewerRoot']).stat()
        require((actual_root.st_dev, actual_root.st_ino) == (sealed_root.st_dev, sealed_root.st_ino))
        require(uid_processes(self.e['uids']) == {int(pid): '/capture402.slice/capture402-view.slice/' + SERVICES[1] + '.service'})
        require(inventory()[0] == journal_phase(ROOT)[2]['attestation']['inventory'])
        (BASE / 'read-only-maintenance').unlink()
        fsync_dir(BASE)

    def select(self, sha):
        require(sha in (self.e['tuple']['candidate'], self.e['tuple']['previous']))
        target = BASE / 'releases' / sha
        require(target.is_dir() and not target.is_symlink())
        tmp = BASE / '.quarantine-current'
        require(not exists(tmp))
        tmp.symlink_to(target)
        os.replace(tmp, BASE / 'current')
        fsync_dir(BASE)

    def start_view(self):
        # Replace only the dev restaurant unit's serving profile; never start its old reader.
        unit = viewer_unit(self.e).encode()
        require(digest(unit) == self.e['tuple']['unit'])
        profile = UNITS / (SERVICES[1] + '.service.d') / '99-quarantine.conf'
        if not exists(profile):
            exclusive(profile, unit, 0o644)
        else:
            require(read(profile, owner=0)[0] == unit)
        sock = Path('/run/capture402-dev-view/view.sock')
        if exists(sock):
            require(stat.S_ISSOCK(sock.lstat().st_mode) and sock.lstat().st_uid == pwd.getpwnam(SERVICES[1]).pw_uid)
            sock.unlink()
        run('systemctl', 'daemon-reload')
        require(not exists(VIEW_PERMIT))
        exclusive(VIEW_PERMIT, encoded({'candidate': self.e['tuple']['candidate'], 'tupleSha256': digest(encoded(self.e['tuple'])), 'caller': caller_identity(os.getpid())}), 0o600)
        try:
            run('systemctl', 'start', SERVICES[1])
        finally:
            VIEW_PERMIT.unlink()
            fsync_dir(VIEW_PERMIT.parent)
        require(run('systemctl', 'is-active', SERVICES[1]) == 'active')
        # Type=simple reports active before Node has bound the socket. Open ingress
        # only after the sealed read-only profile answers with its exact identity.
        deadline = time.monotonic() + 10
        while True:
            connection = http.client.HTTPConnection('localhost', timeout=1)
            try:
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(1)
                connection.sock.connect('/run/capture402-dev-view/view.sock')
                connection.request('GET', '/api/config')
                response = connection.getresponse()
                config = strict_json(response.read(65536))
                require(response.status == 200 and config['mode'] == 'READ_ONLY_QUARANTINE' and config['viewerSha'] == self.e['tuple']['candidate'] and all(v is False for v in config['capabilities'].values()))
                break
            except (OSError, http.client.HTTPException):
                require(time.monotonic() < deadline)
                time.sleep(.05)
            finally:
                connection.close()


def effective_activation(e, names):
    # Resolve loaded instances and installed aliases through systemd, rather than
    # trusting literal template text (User=%i) or enabled symlink filenames.
    names.update(line.split()[0] for line in run('systemctl', 'list-units', '--all', '--no-legend', '--no-pager', '--plain', '--type=service').splitlines() if line.strip())
    names = sorted(n for n in names if n.endswith('.service') and '@.' not in n)
    props = ('Id', 'Names', 'User', 'Group', 'LoadCredential', 'LoadCredentialEncrypted', 'ImportCredential', 'OpenFile', 'EnvironmentFiles')
    raw = run('systemctl', 'show', '--property=' + ','.join(props), *names)
    enrolled_names = {pwd.getpwuid(uid).pw_name for uid in e['uids']}
    enrolled_ids = set(map(str, e['uids']))
    group = pwd.getpwnam(SERVICES[0]).pw_gid
    for block in raw.strip().split('\n\n'):
        values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        name = values.get('Id', '')
        if name in {n + '.service' for n in SERVICES}:
            require(set(values.get('Names', '').split()) == {name})
            continue
        require(values.get('User', '') not in enrolled_names | enrolled_ids)
        require(values.get('Group', '') not in {'capture402-dev-runtime', str(group)})
        # Specifiers in an instantiated identity must already be resolved. Unknown
        # credential/path sources are unsupported, including aliases to private dirs.
        require('%' not in values.get('User', '') and '%' not in values.get('Group', ''))
        for prop in props[4:]:
            for token in shlex.split(values.get(prop, '')):
                source = token.split(':', 1)[-1].lstrip('-')
                if source.startswith('/'):
                    require('%' not in source)
                    path = Path(source).resolve()
                    require(not any(path == root or path.is_relative_to(root) for root in (PRIVATE, STATE, BASE)))


def activation_inventory(e=None):
    # Hash the complete launch/configuration surface. Any new source is unsupported.
    roots = [Path('/etc/systemd/system'), Path('/run/systemd/system'), Path('/run/systemd/transient'),
             Path('/run/systemd/generator'), Path('/run/systemd/generator.early'), Path('/run/systemd/generator.late'),
             Path('/etc/tmpfiles.d'), Path('/run/tmpfiles.d'),
             Path('/etc/cron.d'), Path('/var/spool/cron'), Path('/var/lib/systemd/linger'),
             Path('/etc/sudoers.d'), Path('/etc/ssh'), Path('/etc/nginx'),
             Path('/usr/lib/systemd/system'), Path('/usr/lib/systemd/user'), Path('/etc/systemd/user'),
             *(Path('/etc/cron.' + n) for n in ('hourly', 'daily', 'weekly', 'monthly')), Path('/var/spool/at')]
    result = {}; unit_names = set()
    for root in roots:
        if not root.exists():
            result[str(root)] = digest(b'ABSENT')
            continue
        # Unit enablement/masks legitimately contain symlinks, hash targets without following.
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in sorted(dirs + files):
                p = Path(directory) / name
                if name.endswith('.service'): unit_names.add(name)
                s = p.lstat()
                # Ubuntu's root-owned sticky crontab spool is writable only via its
                # setgid crontab helper. Its membership/content are still inventoried.
                spool = p == Path('/var/spool/cron/crontabs') and stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o1730
                require(s.st_uid == 0 and (stat.S_ISLNK(s.st_mode) or not s.st_mode & 0o022 or spool))
                if p.is_symlink():
                    result[str(p)] = digest(('LINK:' + os.readlink(p)).encode())
                elif p.is_file():
                    data = read(p, 4 * 1024 * 1024, owner=0, allow_empty=True)[0]
                    source_text = data.decode('utf-8', errors='replace')
                    primary = p in {UNITS / (n + '.service') for n in SERVICES}
                    approved_dropin = p.parent in {UNITS / (n + '.service.d') for n in SERVICES} and p.name in ('10-deploy-gate.conf', '95-independent-admission.conf', '99-quarantine.conf')
                    ingress_tmpfiles = p.parent == Path('/etc/tmpfiles.d') and re.fullmatch(r'd /run/capture402-dev-view 0750 capture402-dev-restaurant capture402-dev-runtime -\n', source_text)
                    if p.is_relative_to('/etc/nginx'):
                        # The only private dev reference admitted in an ingress
                        # server is the pinned routing include, never a key/env.
                        source_text = source_text.replace('include /etc/capture402-dev/nginx-routes.conf;', '')
                    if primary or approved_dropin:
                        if approved_dropin and p.name == '99-quarantine.conf':
                            require(e and data == viewer_unit(e).encode())
                            continue
                        # These are the only supported capable launch sources.
                        # Descriptor/credential/namespace inheritance is unsupported.
                        require(not re.search(r'^\s*(?:LoadCredential(?:Encrypted)?|SetCredential(?:Encrypted)?|ImportCredential|OpenFile|Sockets|NetworkNamespacePath|JoinsNamespaceOf|PAMName)\s*=', source_text, re.M))
                        if p.name != '99-quarantine.conf':
                            require(not re.search(r'^\s*(?:ExecStartPre|ExecStartPost|ExecStopPost|ExecReload|RootDirectory|RootImage|BindPaths|BindReadOnlyPaths|MountImages|ExtensionImages|ExtensionDirectories)\s*=', source_text, re.M))
                    elif not ingress_tmpfiles:
                        # Hashing an idle timer/cron/credential unit is not fencing.
                        # Refuse every additional source referring to dev capabilities,
                        # including numeric enrolled UIDs and root launch wrappers.
                        require(not re.search(r'capture402-dev-|capture402-deploy|/etc/capture402-dev(?:/|\s)|/var/lib/capture402-dev(?:/|\s)|/opt/capture402-dev(?:/|\s)|capture402\s+dev', source_text))
                        if e: require(not re.search(r'^\s*User\s*=\s*(?:' + '|'.join(map(str, e['uids'])) + r')\s*$', source_text, re.M))
                        # systemd 255 renders structured LoadCredential properties
                        # as [unprintable]. Resolve source paths from every pinned
                        # fragment too; an innocent spelling may alias a dev key.
                        for value in re.findall(r'^\s*(?:LoadCredential(?:Encrypted)?|OpenFile|EnvironmentFile|Bind(?:ReadOnly)?Paths)\s*=(.*)$', source_text, re.M):
                            for token in shlex.split(value):
                                source = token.split(':', 1)[-1].lstrip('-+')
                                if source.startswith('/'):
                                    require('%' not in source)
                                    target = Path(source).resolve()
                                    require(not any(target == root or target.is_relative_to(root) for root in (PRIVATE, STATE, BASE)))
                    if e and p.parent == Path('/run/systemd/transient') and re.fullmatch(r'session-[0-9]+\.scope', p.name):
                        # Logind scopes have volatile IDs on every SSH login/boot.
                        # They cannot be economic launch sources: no enrolled UID
                        # may inhabit their user slice, now or at admission.
                        group = run('systemctl', 'show', '-p', 'ControlGroup', '--value', p.name)
                        match = re.fullmatch(r'/user.slice/user-([0-9]+)\.slice/session-[0-9]+\.scope', group)
                        require(match and int(match[1]) not in e['uids'] or not group and not p.exists())
                        continue
                    if e and p == UNITS / (SERVICES[1] + '.service.d') / '99-quarantine.conf':
                        require(data == viewer_unit(e).encode())
                        continue
                    result[str(p)] = digest(data)
    for p in (Path('/etc/passwd'), Path('/etc/group'), Path('/etc/shadow'), Path('/etc/sudoers'), Path('/etc/crontab'), Path('/etc/rc.local')):
        result[str(p)] = digest(read(p, owner=0)[0]) if p.exists() else digest(b'ABSENT')
    if e: effective_activation(e, unit_names)
    return result


def viewer_unit(e):
    root = e['viewerRoot']
    return f'''[Unit]
Requires=
Wants=
BindsTo=
PartOf=
After=
ConditionPathExists=
JoinsNamespaceOf=
[Service]
ExecStart=
ExecStartPre=
ExecStartPost=
ExecStop=
ExecStopPost=
ExecReload=
ExecCondition=
ExecCondition=+/usr/bin/python3 -I -B {GUARD} viewer
ExecStart=/usr/bin/env -i PATH=/usr/bin LANG=C /usr/bin/node --experimental-strip-types /app/quarantine-server.ts
Environment=
EnvironmentFile=
ReadWritePaths=
ReadOnlyPaths=
InaccessiblePaths=
BindPaths=
BindReadOnlyPaths=
LoadCredential=
LoadCredentialEncrypted=
SetCredential=
SetCredentialEncrypted=
ImportCredential=
OpenFile=
Sockets=
NetworkNamespacePath=
PAMName=
RootImage=
MountImages=
ExtensionImages=
ExtensionDirectories=
TemporaryFileSystem=
RuntimeDirectory=
StateDirectory=
CacheDirectory=
LogsDirectory=
ConfigurationDirectory=
User=capture402-dev-restaurant
Group=capture402-dev-runtime
SupplementaryGroups=
RootDirectory={root}
RootDirectoryStartOnly=yes
WorkingDirectory=/app
Slice=capture402-view.slice
Restart=no
StandardInput=null
StandardOutput=null
StandardError=null
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=~connect sendto sendmsg sendmmsg @mount @privileged @reboot @raw-io
SystemCallErrorNumber=EPERM
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
DevicePolicy=closed
PrivateDevices=yes
PrivateTmp=yes
MountAPIVFS=no
BindPaths=/run/capture402-dev-view:/run/ingress
ReadWritePaths=/run/ingress
UMask=0077
FileDescriptorStoreMax=0
SocketBindDeny=any
MemoryMax=256M
TasksMax=16
'''


def journal_phase(root):
    history = []
    for i, phase in enumerate(PHASES):
        p = root / f'{i}-{phase}.json'
        if not exists(p):
            break
        r = strict_json(read(p, owner=0)[0])
        shape(r, ('version', 'phase', 'attestation'))
        require(r['version'] == 1 and r['phase'] == phase and isinstance(r['attestation'], dict))
        history.append(r)
    require(set(p.name for p in root.glob('*-*.json')) == {f'{i}-{PHASES[i]}.json' for i in range(len(history))})
    return history


class Transition:
    """Effects follow fsynced attestations. Reentry revalidates actual host state."""
    def __init__(self, root, host, e, projector):
        self.root, self.host, self.e, self.projector = root, host, e, projector

    def record(self, phase, attestation):
        exclusive(self.root / f'{PHASES.index(phase)}-{phase}.json', encoded(dict(version=1, phase=phase, attestation=attestation)))

    def enter(self):
        self.host.verify()
        initial_inv, initial_stores = inventory()
        self.projector(initial_stores, initial_inv)  # Authenticate before DENY intent too.
        history = journal_phase(self.root)
        require(not history and not exists(self.root / 'ECONOMICS_DENIED'))
        # This marker is never deleted. Even failure to fsync leaves startup denied.
        exclusive(self.root / 'ECONOMICS_DENIED', b'ECONOMICS_DENIED v1\n')
        self.record('DENY_INTENT', {'guardSha256': self.e['guardSha256'], 'tupleSha256': digest(encoded(self.e['tuple'])), 'entryInventorySha256': digest(encoded(initial_inv)), 'entryInventory': initial_inv})
        self.host.close()
        self.host.fence()
        fenced_inv, _ = inventory()
        self.record('FENCED', {'verified': True, 'inventory': fenced_inv})
        self.host.stop()
        inv, stores = inventory()
        require(inv == fenced_inv)
        self.record('STOPPED', {'inventory': inv, 'zeroNewEffectsFrom': 'verified-fence-and-cessation', 'preFenceInventoryChanged': inv != initial_inv})
        self.complete(inv, stores)

    def complete(self, inv, stores):
        self.host.verify(stopped=True)
        require(inventory()[0] == inv)
        p = self.projector(stores, inv)
        require(inventory()[0] == inv)
        path = self.root / 'projection.json'
        exclusive(path, p, 0o400)
        self.host.prepare_projection(p)
        self.record('SNAPSHOT_SEALED', {'projectionSha256': digest(p), 'inventorySha256': digest(encoded(inv)), 'viewerInventory': tree(Path(self.e['viewerRoot']))})
        self.host.select(self.e['tuple']['candidate'])
        self.record('CODE_SELECTED', {'sha': self.e['tuple']['candidate']})
        self.host.start_view()
        require(inventory()[0] == inv)
        self.record('VIEW_RUNNING', {'viewerSha': self.e['tuple']['candidate'], 'economics': 'DENIED'})

    def recover(self):
        require(exists(self.root / 'ECONOMICS_DENIED'))
        # Never trust phase completion without checking the kernel. Never thaw/start.
        self.host.close()
        self.host.fence()
        self.host.stop()
        history = journal_phase(self.root)
        if len(history) >= 3:
            require(inventory()[0] == history[2]['attestation']['inventory'])
        return {'mode': 'ECONOMICS_DENIED', 'phase': history[-1]['phase'] if history else 'INCOMPLETE', 'viewer': 'STOPPED', 'automaticResume': False}

    def rollback(self):
        self.recover()
        history = journal_phase(self.root)
        require(len(history) >= 3)
        self.host.select(self.e['tuple']['previous'])
        # No old application startup, health, permit, restoration or thaw.
        require(inventory()[0] == history[2]['attestation']['inventory'])
        return {'mode': 'ECONOMICS_DENIED', 'selected': self.e['tuple']['previous'], 'viewer': 'STOPPED'}


def viewer_allowed():
    require(exists(ROOT / 'ECONOMICS_DENIED'))
    e = enrollment()
    permit = strict_json(read(VIEW_PERMIT, owner=0)[0]); shape(permit, ('candidate', 'tupleSha256', 'caller'))
    require(permit == {'candidate': e['tuple']['candidate'], 'tupleSha256': digest(encoded(e['tuple'])), 'caller': caller_identity(permit['caller']['pid'])} and stat.S_IMODE(VIEW_PERMIT.stat().st_mode) == 0o600)
    h = journal_phase(ROOT)
    require(len(h) >= 5 and h[4]['attestation'] == {'sha': e['tuple']['candidate']})
    require((BASE / 'current').is_symlink() and (BASE / 'current').resolve() == BASE / 'releases' / e['tuple']['candidate'])
    require(inventory()[0] == h[2]['attestation']['inventory'])
    require(tree(Path(e['viewerRoot'])) == h[3]['attestation']['viewerInventory'])
    require(static_view_tree(Path(e['viewerRoot'])) == e['viewerInventory'])
    require(e['activation'] == activation_inventory(e))
    require(read(ROOT / 'projection.json', owner=0)[0] == read(Path(e['viewerRoot']) / 'app/projection.json', owner=0)[0])
    require(events()['populated'] == 0 and not uid_processes(e['uids']))


def emergency_stop():
    """Best-effort containment on invalid admission; never trust metadata paths.

    This does not certify completion or repair state. Errors remain errors and
    subsequent startup is still denied by the independent guard.
    """
    require(sys.platform == 'linux' and os.geteuid() == 0)
    failures = []
    try:
        if not exists(BASE / 'read-only-maintenance'):
            exclusive(BASE / 'read-only-maintenance', b'ADMISSION_DENIED\n')
    except Exception:
        failures.append('ingress')
    for group in (CGROUP, Path('/sys/fs/cgroup/capture402.slice/capture402-view.slice')):
        try:
            if group.exists():
                (group / 'cgroup.freeze').write_text('1')
                deadline = time.monotonic() + 10
                while 'frozen 1' not in (group / 'cgroup.events').read_text():
                    require(time.monotonic() < deadline); time.sleep(.02)
                (group / 'cgroup.kill').write_text('1')
        except Exception:
            failures.append('cessation')
    for name in SERVICES:
        try: run('systemctl', 'stop', name)
        except Exception: failures.append('stop')
    require(not failures)


@contextmanager
def locked():
    require(ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_uid == 0)
    fd = os.open(ROOT / 'controller.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        require(os.geteuid() == 0)
        if sys.argv[1:] == ['economic']:
            ordinary_allowed()
        elif sys.argv[1:] == ['viewer']:
            if not exists(VIEW_PERMIT) and not exists(BASE / 'read-only-maintenance'):
                exclusive(BASE / 'read-only-maintenance', b'EXPLICIT_VIEW_START_REQUIRED\n')
            viewer_allowed()
        else:
            require(False)
    except BaseException:
        print('ADMISSION_DENIED', file=sys.stderr)
        sys.exit(1)
