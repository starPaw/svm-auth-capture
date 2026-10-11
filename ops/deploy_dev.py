#!/usr/bin/env python3
"""Dev-only code deployment. Never restores state, signs, or broadcasts payments."""
from contextlib import contextmanager
import base64
import fcntl
import gzip
import hashlib
import http.client
import json
import os
import re
from pathlib import Path
import pwd
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

import quarantine

import deploy_demo as source
import deploy_vps as host
import release_policy as policy

BASE = Path('/opt/capture402-dev')
RELEASES = BASE / 'releases'
CURRENT = BASE / 'current'
PENDING = BASE / 'transaction.json'
PRIVATE = Path('/etc/capture402-dev')
STATE = Path('/var/lib/capture402-dev')
PERMIT = Path('/run/capture402-dev-deploy-permit')
RECONCILED = BASE / 'reconciled'
SERVICES = ('capture402-dev-facilitator', 'capture402-dev-restaurant')
CGROUP = Path('/sys/fs/cgroup')
SLICE = 'capture402-dev.slice'
UNITS = Path('/etc/systemd/system')
ORIGIN = 'https://dev.capture402.xyz'


def trusted(path, directory=False):
    info = path.lstat()
    source.require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                   and info.st_uid == 0 and info.st_mode & 0o022 == 0, 'unsafe dev operator path')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# Operator evidence is never read by a release/payment eligibility gate.
RELEASE_UNIT_PREFIX = 'capture402-dev-release-'
ATTEMPT_RE = re.compile(r'[0-9]{20}-[a-f0-9]{32}')
PHASES = {'allocated', 'launch', 'lock', 'recovery', 'current', 'units', 'health',
          'production', 'payment', 'private', 'rpc', 'release', 'staging', 'assets',
          'acceptance', 'gate', 'freeze', 'stop', 'switch', 'start',
          'rollback', 'complete', 'quarantine'}
OUTCOMES = {'INCOMPLETE', 'FAILED', 'DEPLOYED', 'ALREADY_CURRENT', 'ROLLED_BACK',
            'ROLLBACK_UNVERIFIED', 'RECOVERED', 'INTERRUPTED_UNKNOWN', 'QUARANTINED'}
GATES = {phase: phase.upper() for phase in PHASES}
GATES['payment'] = 'PAYMENT_JOURNALS'
GATE_LABELS = {'PAYMENT_JOURNALS': 'Payment journals'}


def stable_bytes(path, limit):
    """Bounded no-follow read; detect inode replacement and in-place writes."""
    source.require(stat.S_ISREG(path.lstat().st_mode), 'unsafe observation file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        source.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
                       'unsafe observation file')
        data = b''
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        after = os.fstat(fd)
        identity = lambda i: (i.st_dev, i.st_ino, i.st_size, i.st_mtime_ns, i.st_ctime_ns)
        source.require(len(data) <= limit and identity(before) == identity(after) == identity(path.lstat()),
                       'observation changed during read')
        return data, dict(zip(('device', 'inode', 'size', 'mtimeNs', 'ctimeNs'), identity(after)))
    finally:
        os.close(fd)


def safe_current():
    try:
        return current()
    except Exception:
        return None


def observation():
    result = {'collectedNs': time.time_ns(), 'scope': 'production-config-state-current-routing-services-v1'}
    try:
        value = production(with_scope=True)
        result.update(state='available', **(value if isinstance(value, dict) else {'sha256': value}))
    except Exception:
        result['state'] = 'unavailable'
    return result


def evidence_pair(before, after):
    return {'before': before, 'after': after, 'classification':
            ('unavailable' if not before or before.get('state') != 'available' or after.get('state') != 'available'
             else 'unchanged' if before['sha256'] == after['sha256'] else 'changed'),
            'causality': 'not-established'}


class Attempt:
    def __init__(self, record):
        self.record = record
        self.path = BASE / 'attempts' / record['id'] / 'record.json'

    @classmethod
    def create(cls, sha):
        source.require(bool(source.SHA_RE.fullmatch(sha)), 'invalid attempt target')
        trusted(BASE, True)
        root = BASE / 'attempts'
        root.mkdir(mode=0o700, exist_ok=True)
        trusted(root, True)
        source.require(root.stat().st_mode & 0o077 == 0, 'unsafe attempt directory')
        # Serialized allocation defines latest by allocation order, never completion order.
        fd = os.open(root / 'allocation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            source.require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'unsafe allocation lock')
            fcntl.flock(fd, fcntl.LOCK_EX)
            source.require(sum(1 for p in root.iterdir() if ATTEMPT_RE.fullmatch(p.name)) < 4096,
                           'attempt retention capacity reached')
            allocated = [int(p.name[:20]) for p in root.iterdir() if ATTEMPT_RE.fullmatch(p.name)]
            ident = f'{max(time.time_ns(), max(allocated, default=0) + 1):020d}-' + uuid.uuid4().hex
            directory = root / ident
            directory.mkdir(mode=0o700)
            sync(root)
            record = {'version': 1, 'id': ident, 'requestedSha': sha, 'previousSha': None,
                      'currentSha': None, 'controllerSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      'startedNs': time.time_ns(), 'endedNs': None, 'phase': 'allocated',
                      'gate': 'ALLOCATED', 'outcome': 'INCOMPLETE', 'unit': None, 'invocation': None,
                      'production': {'before': None, 'after': None, 'classification': 'unavailable',
                                     'causality': 'not-established'}}
            attempt = cls(record)
            attempt.save()  # Required durability BEFORE recovery/preflight/launch.
            sync(BASE)
            return attempt
        finally:
            os.close(fd)

    @classmethod
    def load(cls, ident, sha=None):
        source.require(bool(ATTEMPT_RE.fullmatch(ident)), 'invalid attempt identity')
        record = read_attempt(ident)
        source.require(record['outcome'] == 'INCOMPLETE' and
                       (sha is None or record['requestedSha'] == sha), 'attempt cannot be resumed')
        return cls(record)

    def save(self):
        trusted(self.path.parent, True)
        source.require(not self.path.is_symlink(), 'unsafe attempt record')
        host.atomic_bytes(self.path, (json.dumps(self.record, sort_keys=True) + '\n').encode(), 0o600)

    def step(self, phase, required=True, **values):
        self.record.update(values, phase=phase, gate=GATES[phase])
        try:
            self.save()
        except Exception:
            if required:
                self.record['gate'] = 'REPORTING'
                raise
            return False
        return True

    def finish(self, outcome):
        self.record.update(outcome=outcome, endedNs=time.time_ns(), currentSha=safe_current())
        self.record['production'] = evidence_pair(self.record['production']['before'], observation())
        try:
            self.save()
        except Exception:
            pass  # Durable previous checkpoint remains explicitly incomplete.


def read_attempt(ident):
    source.require(bool(ATTEMPT_RE.fullmatch(ident)), 'invalid attempt identity')
    root = BASE / 'attempts'
    trusted(root, True)
    trusted(root / ident, True)
    path = root / ident / 'record.json'
    trusted(path)
    source.require(path.stat().st_mode & 0o077 == 0, 'unsafe attempt permissions')
    raw, _ = stable_bytes(path, 32768)
    r = json.loads(raw)
    # Reject the WHOLE record instead of forwarding arbitrary fields to public status.
    expected = {'version', 'id', 'requestedSha', 'previousSha', 'currentSha', 'controllerSha256',
                'startedNs', 'endedNs', 'phase', 'gate', 'outcome', 'unit', 'invocation', 'production'}
    source.require(isinstance(r, dict) and set(r) == expected and r['version'] == 1 and r['id'] == ident,
                   'invalid attempt schema')
    for key in ('requestedSha', 'controllerSha256'):
        source.require(isinstance(r[key], str) and re.fullmatch('[a-f0-9]{' + ('40' if key == 'requestedSha' else '64') + '}', r[key]), 'invalid attempt digest')
    for key in ('previousSha', 'currentSha'):
        source.require(r[key] is None or isinstance(r[key], str) and source.SHA_RE.fullmatch(r[key]), 'invalid app identity')
    source.require(r['phase'] in PHASES and r['gate'] in {GATES[r['phase']], 'REPORTING'} and r['outcome'] in OUTCOMES,
                   'invalid attempt codes')
    source.require(type(r['startedNs']) is int and r['startedNs'] > 0 and
                   (r['endedNs'] is None or type(r['endedNs']) is int and r['endedNs'] >= r['startedNs']), 'invalid attempt time')
    source.require((r['outcome'] == 'INCOMPLETE') == (r['endedNs'] is None), 'incomplete terminal record')
    source.require(r['unit'] is None or r['unit'] == RELEASE_UNIT_PREFIX + ident, 'invalid job correlation')
    source.require(r['invocation'] is None or isinstance(r['invocation'], str) and re.fullmatch('[a-f0-9]{32}', r['invocation']), 'invalid invocation')
    if r['outcome'] in ('DEPLOYED', 'ALREADY_CURRENT'):
        source.require(r['phase'] == 'complete' and r['currentSha'] == r['requestedSha'], 'invalid success record')
    prod = r['production']
    source.require(isinstance(prod, dict) and set(prod) == {'before', 'after', 'classification', 'causality'} and
                   prod['classification'] in ('unavailable', 'changed', 'unchanged') and prod['causality'] == 'not-established', 'invalid production evidence')
    for value in (prod['before'], prod['after']):
        if value is None:
            continue
        source.require(isinstance(value, dict) and set(value) in ({'collectedNs', 'scope', 'state'}, {'collectedNs', 'scope', 'state', 'sha256'}, {'collectedNs', 'scope', 'state', 'sha256', 'processes', 'routingSha256'}) and
                       type(value['collectedNs']) is int and value['scope'] == 'production-config-state-current-routing-services-v1' and
                       value['state'] in ('available', 'unavailable') and
                       ((value['state'] == 'unavailable' and set(value) == {'collectedNs', 'scope', 'state'}) or
                        (value['state'] == 'available' and re.fullmatch('[a-f0-9]{64}', value.get('sha256', '')))), 'invalid observation')
        if 'processes' in value:
            source.require(re.fullmatch('[a-f0-9]{64}', value['routingSha256']) and
                           isinstance(value['processes'], dict) and set(value['processes']) == set((*host.LEGACY_SERVICES, *host.PRODUCT_SERVICES)), 'invalid process coverage')
            for item in value['processes'].values():
                source.require(isinstance(item, dict) and set(item) == {'pid', 'applicationSha', 'cwd', 'entrypointSha256', 'serviceIdentitySha256'} and
                               (item['pid'] is None or type(item['pid']) is int and item['pid'] >= 0) and
                               (item['applicationSha'] is None or isinstance(item['applicationSha'], str) and source.SHA_RE.fullmatch(item['applicationSha'])) and
                               item['cwd'] in ('release-integration', 'unverified') and
                               (item['entrypointSha256'] is None or re.fullmatch('[a-f0-9]{64}', item['entrypointSha256'])) and
                               re.fullmatch('[a-f0-9]{64}', item['serviceIdentitySha256']), 'invalid process identity')
    source.require(prod == evidence_pair(prod['before'], prod['after']) if prod['after'] else prod['classification'] == 'unavailable', 'inconsistent production classification')
    return r


def latest_attempt():
    root = BASE / 'attempts'
    if not root.exists() and not root.is_symlink():
        return None
    try:
        trusted(root, True)
        ids = sorted(p.name for p in root.iterdir() if ATTEMPT_RE.fullmatch(p.name))
        if not ids:
            return None
        ident = ids[-1]
        r = read_attempt(ident)
        if r['outcome'] == 'INCOMPLETE':
            # No automatic reconciliation/retry. A retained transaction remains authoritative.
            r = dict(r, outcome='INTERRUPTED_UNKNOWN')
        return r
    except Exception:
        return {'outcome': 'INCOMPLETE', 'gate': 'REPORT_UNAVAILABLE'}


def safe_last_result():
    try:
        path = BASE / 'last-result.json'
        if not path.exists() and not path.is_symlink():
            return None
        trusted(path)
        raw, _ = stable_bytes(path, 32768)
        value = json.loads(raw)
        source.require(isinstance(value, dict) and value.get('verdict') in
                       {'DEPLOYED', 'ALREADY_CURRENT', 'ROLLED_BACK', 'RECOVERED_PRE_STOP'}, 'invalid legacy result')
        result = {'verdict': value['verdict']}
        for key in ('sha', 'previous', 'target'):
            if key in value:
                source.require(isinstance(value[key], str) and source.SHA_RE.fullmatch(value[key]), 'invalid result sha')
                result[key] = value[key]
        for key in ('productionUnchanged', 'ciRun'):
            if key in value:
                source.require(type(value[key]) is (bool if key == 'productionUnchanged' else int), 'invalid result field')
                result[key] = value[key]
        return result
    except Exception:
        return {'verdict': 'UNAVAILABLE'}


def failure_summary(attempt=None):
    r = attempt.record if attempt else latest_attempt()
    if not r:
        return 'dev deployment blocked; reporting unavailable'
    gate = r.get('gate', 'REPORT_UNAVAILABLE')
    return ('dev deployment blocked; gate=' + GATE_LABELS.get(gate, gate) +
            '; attempt=' + r.get('id', 'unavailable') + '; outcome=' + ('INTERRUPTED_UNKNOWN' if r['outcome'] == 'INCOMPLETE' else r['outcome']) +
            '; job=' + (r.get('unit') or 'not-launched'))


def current():
    source.require(CURRENT.is_symlink(), 'dev current must be a release symlink')
    root = CURRENT.resolve(strict=True)
    source.require(root.parent == RELEASES and source.SHA_RE.fullmatch(root.name), 'dev current escapes releases')
    trusted(root, True)
    return root.name


def switch(sha):
    source.require(bool(source.SHA_RE.fullmatch(sha)), 'invalid dev release SHA')
    trusted(RELEASES / sha, True)
    link = BASE / ('.current-' + str(os.getpid()))
    link.symlink_to(RELEASES / sha)
    try:
        os.replace(link, CURRENT)
        sync(BASE)
    finally:
        link.unlink(missing_ok=True)


def group_path(name):
    # systemd hyphenated slice names form a hierarchy, not a root-level cgroup.
    parts = SLICE.removesuffix('.slice').split('-')
    slices = ['-'.join(parts[:n]) + '.slice' for n in range(1, len(parts) + 1)]
    return '/' + '/'.join(slices) + '/' + name + '.service'


def units():
    for name, entry in zip(SERVICES, ('devnet-server.ts', 'restaurant-server.ts')):
        get = lambda key: source.run('systemctl', 'show', '-p', key, '--value', name)
        source.require(get('User') == name and get('WorkingDirectory') == str(CURRENT / 'integration')
                       and get('Restart') == 'no' and get('Slice') == SLICE, 'unexpected dev service layout')
        for key in ('Requires', 'Wants', 'Conflicts', 'BindsTo', 'PartOf', 'PropagatesStopTo'):
            source.require(not any(unit.startswith(('sac006-', 'capture402-facilitator.', 'capture402-restaurant.')) for unit in get(key).split()), 'dev dependency touches production')
        command = get('ExecStart')
        source.require('src/' + entry in command and 'capture402-facilitator.service' not in get('Requires')
                       and 'capture402-restaurant.service' not in get('Requires'), 'unsafe dev unit command/dependencies')
        group = get('ControlGroup')
        source.require(group == group_path(name),
                       'dev unit must use isolated cgroup')
        root = CGROUP / group.lstrip('/')
        source.require('populated ' in (root / 'cgroup.events').read_text() and (root / 'cgroup.kill').is_file(), 'cgroup v2 freeze/kill support required')


def populated(root):
    try:
        return 'populated 1' in (root / 'cgroup.events').read_text()
    except FileNotFoundError:
        # systemd may reap the cgroup immediately after its last task exits.
        return False


def stop(names=None):
    # Kill within a verified frozen cgroup, without systemd's automatic thaw before stop.
    # Every economic broadcast is preceded by a durable reservation. A clean frozen
    # snapshot cannot become dirty between inspection and killing the same cgroups.
    for name in reversed(SERVICES if names is None else names):
        group = source.run('systemctl', 'show', '-p', 'ControlGroup', '--value', name)
        source.require(group == group_path(name),
                       'unexpected dev cgroup')
        root = CGROUP / group.lstrip('/')
        source.require('frozen 1' in (root / 'cgroup.events').read_text(), 'refuse to kill an unfrozen dev unit')
        (root / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 10
        while populated(root):
            source.require(time.monotonic() < deadline, 'dev cgroup did not empty')
            time.sleep(0.05)
        source.run('systemctl', 'stop', name)
        source.require(source.run('systemctl', 'show', '-p', 'MainPID', '--value', name) == '0', 'dev unit still running')


def freeze():
    for name in SERVICES:
        source.run('systemctl', 'freeze', name)
        group = source.run('systemctl', 'show', '-p', 'ControlGroup', '--value', name)
        source.require(group == group_path(name),
                       'unexpected dev cgroup')
        source.require('frozen 1' in (CGROUP / group.lstrip('/') / 'cgroup.events').read_text(), 'dev freeze unverified')


def thaw():
    quarantine.ordinary_allowed()
    for name in SERVICES:
        source.run('systemctl', 'thaw', name)


def state_paths():
    expected = {
        ('facilitator', 'SAC006_FACILITATOR_JOURNAL_DIR'): STATE / 'facilitator/journal',
        ('restaurant', 'SAC006_STORE_DIR'): STATE / 'restaurant/operation-store',
        ('restaurant', 'SAC006_RECLAIM_JOURNAL_DIR'): STATE / 'restaurant/reclaim',
    }
    for (role, key), path in expected.items():
        trusted(PRIVATE / (role + '.env'))
        source.require(host.env_value(PRIVATE / (role + '.env'), key) == str(path), 'dev state path differs from isolated layout')
    return [*expected.values(), STATE / 'restaurant/operation-store-restaurant']


def clean_operations():
    # Fail closed on absent directories, partial writes, unknown schemas or outcomes.
    journal, operations, reclaim, orders = state_paths()
    quarantine.coordination_records(dict(facilitator=journal, operations=operations, reclaim=reclaim, orders=orders))
    for directory in (journal, operations, reclaim, orders):
        source.require(directory.is_dir() and not directory.is_symlink(), 'dev journal directory missing or unsafe')
        for path in directory.iterdir():
            source.require(path.is_file() and not path.is_symlink(), 'unsafe dev journal member')
            source.require(path.stat().st_size < 4 * 1024 * 1024, 'dev journal member too large')
            source.require('.tmp-' not in path.name and not path.name.endswith('.busy'), 'unfinished dev operation')
            if path.name == quarantine.COORDINATION_FILE:
                continue  # Validated as the exact complete metadata set above, never a wildcard.
            if path.suffix == '.json':
                original = path.read_bytes()
                record = json.loads(original)
                if directory in (journal, reclaim):
                    fields = ('signature', 'messageHash', 'transactionBase64', 'blockhash', 'operation', 'payment', 'payer', 'expectedHeld', 'expectedRefundable')
                    source.require(all(isinstance(record.get(key), str) and record[key] for key in fields)
                                   and record['signature'] == path.stem
                                   and record['operation'] in ('authorize', 'capture', 'void', 'refund', 'reclaim', 'setup'), 'unresolved or malformed dev submission')
                    attempts = record.get('attempts')
                    source.require(isinstance(attempts, list) and attempts and
                                   all(isinstance(a, dict) and
                                       (a.get('outcome') is None or isinstance(a.get('outcome'), dict))
                                       for a in attempts),
                                   'malformed dev submission attempts')
                    source.require(all((a.get('outcome') or {}).get('result') in
                                       ('not-submitted', 'finalized-succeeded', 'finalized-failed')
                                       for a in attempts) or _has_finality_proof(path, record, original),
                                   'unresolved dev submission')
                elif directory == operations:
                    source.require(record.get('status') in ('authorize-rejected', 'completed'), 'unresolved dev resource operation')
                else:
                    source.require(record.get('status') in ('draft', 'active', 'closed', 'rejected')
                                   and isinstance(record.get('events'), list)
                                   and all(e.get('status') in ('finalized', 'rejected') for e in record['events']), 'unresolved dev order')
            elif path.name.endswith('.lock'):
                if directory == orders:
                    # Immutable event locks stay prepared forever; the mutable order
                    # must contain the same action/wire and a terminal event instead.
                    event = json.loads(path.read_text())
                    order = json.loads((directory / (path.name.split('.')[0] + '.json')).read_text())
                    source.require(any(e.get('action') == event.get('action') and e.get('transactionBase64') == event.get('transactionBase64')
                                       and e.get('status') in ('finalized', 'rejected') for e in order['events']), 'orphan dev action lock')
                elif directory == reclaim:
                    signature = path.read_text()
                    source.require((directory / (signature + '.json')).is_file(), 'orphan dev reclaim lock')
                else:
                    raise RuntimeError('unexpected dev lock')
            else:
                raise RuntimeError('unknown dev journal member')


def production(with_scope=False):
    # Private values never enter the receipt: only a combined integrity digest.
    roots = [Path('/etc/sac006'), Path('/var/lib/sac006'), source.CURRENT, Path('/etc/nginx'), Path('/etc/letsencrypt')]
    services = {}
    for name in (*host.LEGACY_SERVICES, *host.PRODUCT_SERVICES):
        services[name] = {key: source.run('systemctl', 'show', '-p', key, '--value', name)
                          for key in ('MainPID', 'ActiveState', 'FragmentPath')}
        if with_scope:
            # Preserve the historical gate/transaction digest algorithm. Extra
            # process observations belong only to non-authoritative reporting.
            services[name].update({key: source.run('systemctl', 'show', '-p', key, '--value', name)
                                   for key in ('InvocationID', 'ExecStart', 'WorkingDirectory')})
            pid = services[name]['MainPID']
            if pid.isdigit() and int(pid) > 0:
                services[name]['processCwd'] = os.readlink('/proc/' + pid + '/cwd')
                services[name]['processEntrypointSha256'] = hashlib.sha256(Path('/proc/' + pid + '/cmdline').read_bytes()).hexdigest()
        fragment = services[name]['FragmentPath']
        if fragment:
            roots.append(Path(fragment))
        roots.append(UNITS / (name + '.service.d'))
    source.require(any(s['ActiveState'] == 'active' for s in services.values()), 'production baseline unavailable')
    values = {'services': services, 'files': host.inventory(roots)}
    digest = hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()
    if not with_scope:
        return digest
    identities = {}
    for name, value in services.items():
        cwd = value.get('processCwd', '')
        match = re.fullmatch(re.escape(str(source.RELEASES)) + r'/([a-f0-9]{40})/integration', cwd)
        identities[name] = {'pid': int(value['MainPID']) if value['MainPID'].isdigit() else None,
                            'applicationSha': match[1] if match else None,
                            'cwd': 'release-integration' if match else 'unverified',
                            'entrypointSha256': value.get('processEntrypointSha256'),
                            'serviceIdentitySha256': hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()}
    return {'sha256': digest, 'processes': identities,
            'routingSha256': hashlib.sha256(json.dumps(host.inventory([Path('/etc/nginx')]), sort_keys=True).encode()).hexdigest()}



def rpc():
    from host_cli import NoRedirect
    record = json.loads((RELEASES / current() / source.RECORD).read_text())
    for role in ('facilitator', 'restaurant'):
        url = host.env_value(PRIVATE / (role + '.env'), 'SOLANA_RPC_URL')
        source.require(url.startswith('https://'), 'dev RPC must use TLS')
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'getGenesisHash'}).encode()
        request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            data = response.read(65537)
        source.require(len(data) <= 65536 and json.loads(data).get('result') == record['network']['genesis_hash'], 'dev RPC identity unavailable')


def ingress_response(path):
    # The private tester allowlist admits loopback. Keep the real Host, SNI and
    # certificate verification while checking this VPS's dev nginx listener.
    socket.getaddrinfo('dev.capture402.xyz', 443, type=socket.SOCK_STREAM)
    connection = http.client.HTTPSConnection('dev.capture402.xyz', timeout=5,
                                              context=ssl.create_default_context())
    connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(
        ('127.0.0.1', address[1]), timeout, source_address)
    try:
        connection.request('GET', path)
        answer = connection.getresponse()
        return answer.status, answer.read(32 * 1024), dict(answer.getheaders())
    finally:
        connection.close()


def health(sha, public=True):
    for name, entry in zip(SERVICES, ('devnet-server.ts', 'restaurant-server.ts')):
        source.require(source.run('systemctl', 'is-active', name) == 'active', 'dev service inactive')
        pid = source.run('systemctl', 'show', '-p', 'MainPID', '--value', name)
        source.require(pid.isdecimal() and int(pid) > 0 and Path(os.readlink('/proc/' + pid + '/cwd')) == RELEASES / sha / 'integration',
                       'dev process source mismatch')
        argv = Path('/proc/' + pid + '/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        source.require(len(argv) == 3 and Path(os.fsdecode(argv[0])).name == 'node'
                       and argv[1:] == [b'--experimental-strip-types', ('src/' + entry).encode()], 'dev process entrypoint mismatch')
    paths = [('/', 200), ('/resource', 402), ('/assets/app.js', 200),
             ('/assets/style.css', 200), ('/assets/solflare.js', 200)]
    # Bootstrap releases predate the homepage. Check their actual assets so
    # preparation and code rollback can validate the previous running version.
    paths += [('/assets/' + name, 200) for name in ('homepage.css', 'homepage.js')
              if (RELEASES / sha / 'integration/web' / name).is_file()]
    for prefix in (['http://127.0.0.1:18888', ORIGIN] if public else ['http://127.0.0.1:18888']):
        response = ingress_response if prefix == ORIGIN else lambda path: source.response(prefix + path)
        for path, expected in paths:
            status, body, headers = response(path)
            source.require(status == expected and body, 'dev HTTP readiness failed')
            if path == '/resource':
                source.require(any(k.lower() == 'payment-required' for k in headers), 'dev challenge missing')
        status, body, _ = response('/api/config')
        config = json.loads(body)
        record = json.loads((RELEASES / sha / source.RECORD).read_text())
        source.require(status == 200 and config.get('configured') is True and config.get('cluster') == 'devnet'
                       and config.get('programId') == record['program']['program_id'], 'dev identity readiness failed')
        env = PRIVATE / 'restaurant.env'
        source.require(all(config.get(field) == host.env_value(env, key) for field, key in (
            ('sponsor', 'SAC006_FEE_PAYER'), ('mint', 'SAC006_ASSET_MINT'))), 'dev signer/mint changed')
        source.require(config.get('merchant') == host.env_value(PRIVATE / 'facilitator.env', 'SAC006_ALLOWLIST_MERCHANT')
                       and config.get('mint') == host.env_value(PRIVATE / 'facilitator.env', 'SAC006_ALLOWLIST_MINT'), 'dev allowlist identity mismatch')


def ready(sha):
    deadline = time.monotonic() + 60
    while True:
        try:
            health(sha)
            return
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            source.require(time.monotonic() < deadline, 'dev readiness exhausted')
            time.sleep(1)


def seal(root):
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory)] + [Path(directory) / n for n in dirs + files]:
            info = path.lstat()
            source.require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), 'special dev release member')
            if stat.S_ISLNK(info.st_mode):
                source.require(path.resolve().is_relative_to(root.resolve()), 'dev dependency symlink escapes release')
            elif stat.S_ISREG(info.st_mode):
                source.require(info.st_nlink == 1, 'dev release hardlink')
    source.chown_tree(root, 0, 0)
    source.seal_runtime_permissions(root)


def release_inventory(root):
    # No release member may be writable by the builder after publishing.
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory)] + [Path(directory) / n for n in dirs + files]:
            info = path.lstat()
            source.require(info.st_uid == 0 and (path.is_symlink() or info.st_mode & 0o022 == 0), 'unsealed dev release')
            if path.is_symlink():
                source.require(path.resolve().is_relative_to(root.resolve()), 'dev release symlink escape')
    return hashlib.sha256(json.dumps(host.inventory([root]), sort_keys=True).encode()).hexdigest()


def verify_archive(tar, tree, api):
    metadata = api('repos/' + policy.REPOSITORY + '/git/trees/' + tree + '?recursive=1')
    source.require(metadata.get('sha') == tree and metadata.get('truncated') is False, 'incomplete dev source tree')
    expected = {}
    for entry in metadata['tree']:
        path = entry['path']
        if path.startswith('integration/') or path == source.RECORD:
            if entry['type'] == 'tree':
                continue
            source.require(entry['type'] == 'blob' and entry['mode'] in ('100644', '100755'), 'unsupported dev Git member')
            expected[path] = entry['sha']
    actual = {}
    with source.bounded_tar(tar, 'r:') as archive:
        for member in archive:
            if member.isdir():
                continue
            source.require(member.isfile(), 'unsupported dev archive member')
            data = archive.extractfile(member).read()
            actual[member.name] = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    source.require(expected and actual == expected, 'dev archive differs from approved Git blobs')


def stage(sha, acceptance, api):
    user = pwd.getpwnam('capture402-deploy')
    ssh = source.source_ssh_command(user)
    with tempfile.TemporaryDirectory(prefix='.source-', dir=RELEASES) as temporary:
        work = Path(temporary)
        os.chown(work, user.pw_uid, user.pw_gid)
        repo = work / 'repository'
        command = ('runuser', '-u', user.pw_name, '--', '/usr/bin/env', '-i', 'HOME=' + user.pw_dir,
                   'PATH=/usr/bin:/bin', 'GIT_TERMINAL_PROMPT=0', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                   '/usr/bin/git', '-c', 'credential.helper=', '-c', 'core.sshCommand=' + ssh)
        source.run(*command, 'clone', '--depth=1', '--single-branch', '--no-checkout', '--branch=' + acceptance['branch'],
                   source.SOURCE_REMOTE, str(repo), timeout=180)
        source.require(source.run(*command, '-C', str(repo), 'rev-parse', 'HEAD') == sha
                       and source.run(*command, '-C', str(repo), 'rev-parse', 'HEAD^{tree}') == acceptance['tree'], 'dev Git source differs from approval')
        tar = source.git_archive(repo, sha)
        source.require(0 < len(tar) <= source.MAX_TAR_STREAM, 'dev source archive too large')
        source.archive_fingerprints(tar, 'r:')
        verify_archive(tar, acceptance['tree'], api)
        blob = gzip.compress(tar, mtime=0)
        source.require(len(blob) <= source.MAX_ARCHIVE, 'dev compressed source too large')
        digest = hashlib.sha256(blob).hexdigest()
    target = RELEASES / sha
    manifest = BASE / 'manifests' / (sha + '.json')
    if target.exists():
        trusted(target, True)
        trusted(manifest)
        receipt = json.loads(manifest.read_text())
        source.require(receipt['archiveSha256'] == digest and receipt['sha'] == sha
                       and receipt['inventory'] == release_inventory(target), 'immutable dev release changed')
        return
    build = Path(tempfile.mkdtemp(prefix='.candidate-', dir=RELEASES))
    try:
        source.unpack_archive(blob, build)
        source.require((build / source.RECORD).read_bytes() == (RELEASES / current() / source.RECORD).read_bytes(), 'dev release changes accepted program identity')
        builder = user
        source.require(builder.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'), 'dev builder must be a noninteractive deployment account')
        source.chown_tree(build, builder.pw_uid, builder.pw_gid)
        build.chmod(0o700)
        # No branch code executes as root; build cannot read either environment's secrets.
        source.run('systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                   '--unit=capture402-dev-build-' + str(time.time_ns()),
                   '-p', 'User=capture402-deploy', '-p', 'NoNewPrivileges=true', '-p', 'CapabilityBoundingSet=',
                   '-p', 'ProtectSystem=strict', '-p', 'ProtectHome=true', '-p', 'PrivateTmp=true',
                   '-p', 'InaccessiblePaths=/etc/sac006 /var/lib/sac006 /opt/capture402 /opt/svm-auth-capture /etc/capture402-dev /var/lib/capture402-dev',
                   '-p', 'ReadWritePaths=' + str(build), '-p', 'MemoryMax=512M', '-p', 'CPUQuota=50%',
                   '-p', 'TasksMax=64', '-p', 'RuntimeMaxSec=240', '-p', 'WorkingDirectory=' + str(build / 'integration'),
                   '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/tmp',
                   'npm', 'ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', timeout=270)
        seal(build)
        os.rename(build, target)
        sync(RELEASES)
        source.write_json(manifest, {'sha': sha, 'archiveSha256': digest, 'inventory': release_inventory(target)})
    finally:
        if build.exists():
            shutil.rmtree(build)


def install_gate():
    quarantine.ordinary_allowed()
    for name in SERVICES:
        directory = UNITS / (name + '.service.d')
        if not directory.exists():
            directory.mkdir(mode=0o755)
        trusted(directory, True)
        gate = directory / '90-dev-deployment.conf'
        content = b'[Service]\nExecCondition=+/usr/local/sbin/capture402 dev gate\n'
        if gate.exists():
            trusted(gate)
            source.require(gate.read_bytes() == content, 'dev boot gate differs; operator enrollment required')
        else:
            host.atomic_bytes(gate, content)
    source.run('systemctl', 'daemon-reload')


def gate():
    quarantine.ordinary_allowed()
    if not PENDING.exists():
        return
    trusted(PERMIT)
    source.require(PERMIT.read_text() == current(), 'pending dev deployment blocks service startup')


def start(sha):
    quarantine.ordinary_allowed()
    host.atomic_bytes(PERMIT, sha.encode(), 0o600)
    try:
        for name in SERVICES:
            # Inactive units can be garbage-collected; reset-failed rejects an
            # unloaded unit even though its installed fragment is valid.
            if source.run('systemctl', 'show', '-p', 'ActiveState', '--value', name) == 'failed':
                source.run('systemctl', 'reset-failed', name)
            source.run('systemctl', 'start', name)
        ready(sha)
    finally:
        host.durable_remove(PERMIT)


@contextmanager
def locked():
    trusted(BASE, True)
    trusted(RELEASES, True)
    trusted(BASE.parent, True)
    path = BASE / 'deploy.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        source.require(os.fstat(fd).st_uid == os.geteuid() and os.fstat(fd).st_mode & 0o077 == 0, 'unsafe dev lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def rollback(record):
    quarantine.ordinary_allowed()
    # A newly running candidate may have accepted a payment. Never interrupt it
    # on a blind rollback; retain the transaction and require original reconciliation.
    running = [name for name in SERVICES if source.run('systemctl', 'show', '-p', 'MainPID', '--value', name) != '0']
    if running:
        try:
            for name in running:
                source.run('systemctl', 'freeze', name)
            clean_operations()
            stop(running)
        except Exception:
            for name in running:
                source.run('systemctl', 'thaw', name)
            raise
    clean_operations()
    switch(record['previous'])
    start(record['previous'])
    source.require(production() == record['production'], 'production baseline changed')
    report_json(BASE / 'last-result.json', {'verdict': 'ROLLED_BACK', 'sha': record['previous'], 'target': record['target']})
    host.durable_remove(PENDING)


def _recover():
    quarantine.ordinary_allowed()
    if not PENDING.exists():
        return False
    trusted(PENDING)
    record = json.loads(PENDING.read_text())
    source.require(source.SHA_RE.fullmatch(record['previous']) and source.SHA_RE.fullmatch(record['target']), 'invalid dev recovery record')
    host.durable_remove(PERMIT)
    if record['stage'] == 'freezing' and current() == record['previous']:
        running = [name for name in SERVICES if source.run('systemctl', 'show', '-p', 'MainPID', '--value', name) != '0']
        for name in running:
            source.run('systemctl', 'thaw', name)
        if len(running) != len(SERVICES):
            # Reboot may have blocked both units before any deployment stop.
            # Start the same old code; existing journals still block payment replay.
            start(record['previous'])
        report_json(BASE / 'last-result.json', {'verdict': 'RECOVERED_PRE_STOP', 'sha': record['previous'], 'target': record['target']})
        host.durable_remove(PENDING)
    else:
        rollback(record)
    return True


def recover():
    attempt = None
    try:
        if PENDING.exists():
            record = json.loads(PENDING.read_text())
            ident = record.get('attemptId')
            if ident:
                attempt = Attempt(read_attempt(ident))
                attempt.step('recovery', required=False)
    except Exception:
        pass  # Bad/missing reporting does not inhibit authoritative recovery.
    try:
        result = _recover()
    except BaseException:
        if attempt:
            attempt.finish('ROLLBACK_UNVERIFIED')
        raise
    if attempt and result:
        attempt.finish('RECOVERED')
    return result


def deploy(sha, api, attempt=None):
    quarantine.ordinary_allowed()
    attempt = attempt or Attempt.create(sha)
    try:
        application = safe_current()
        attempt.record.update(previousSha=application, currentSha=application)
        if attempt.record['production']['before'] is None:
            attempt.record['production']['before'] = observation()
        attempt.step('lock')
        with locked():
            attempt.step('recovery')
            if recover():
                raise RuntimeError('dev recovered offline; explicitly invoke deploy again')
            _deploy(sha, api, attempt)
    except BaseException:
        if attempt.record['outcome'] == 'INCOMPLETE':
            attempt.finish('FAILED')
        raise


def _deploy(sha, api, attempt):
    def check(phase, action):
        attempt.step(phase)
        return action()
    previous = check('current', current)
    attempt.record.update(previousSha=previous, currentSha=previous)
    # Capture before any fallible preflight, including units/health/payment refusal.
    if attempt.record['production']['before'] is None:
        attempt.record['production']['before'] = observation()
    check('units', units)
    check('health', lambda: health(previous))
    baseline = check('production', production)
    check('payment', clean_operations)
    private_digest = check('private', lambda: hashlib.sha256(json.dumps(host.inventory([PRIVATE]), sort_keys=True).encode()).hexdigest())
    check('rpc', rpc)
    acceptance = check('release', lambda: policy.verify_dev(sha, api))
    for directory in (BASE / 'manifests',):
        if not directory.exists():
            directory.mkdir(mode=0o755)
        trusted(directory, True)
    check('staging', lambda: stage(sha, acceptance, api))
    check('assets', lambda: source.require(all((RELEASES / sha / 'integration/web' / name).is_file()
                       for name in ('homepage.css', 'homepage.js')), 'candidate homepage assets missing'))
    from host_cli import GitHub
    fresh = check('acceptance', lambda: policy.verify_dev(sha, GitHub()))
    source.require(all(fresh[k] == acceptance[k] for k in ('sha', 'tree', 'branch', 'reviewedHead')), 'dev acceptance changed')
    check('rpc', rpc)
    check('health', lambda: health(previous))
    check('production', lambda: source.require(production() == baseline, 'production changed during preparation'))
    check('private', lambda: source.require(hashlib.sha256(json.dumps(host.inventory([PRIVATE]), sort_keys=True).encode()).hexdigest() == private_digest, 'dev configuration changed during preparation'))
    source.write_json(BASE / 'manifests' / (sha + '.approval.json'), fresh)
    if previous == sha:
        report_json(BASE / 'last-result.json', {'verdict': 'ALREADY_CURRENT', 'sha': sha, 'productionUnchanged': True})
        attempt.step('complete', required=False)
        attempt.finish('ALREADY_CURRENT')
        return
    check('gate', install_gate)
    attempt.step('freeze')  # Required reporting before effects; existing transaction remains authority.
    record = {'previous': previous, 'target': sha, 'production': baseline, 'stage': 'freezing',
              'attemptId': attempt.record['id']}
    source.write_json(PENDING, record)
    try:
        freeze()
        attempt.step('payment', required=False)
        clean_operations()
    except BaseException:
        thaw()
        host.durable_remove(PENDING)
        raise
    record['stage'] = 'stopping'
    try:
        source.write_json(PENDING, record)
        attempt.step('stop', required=False)
        stop()
        attempt.step('payment', required=False)
        clean_operations()
        attempt.step('switch', required=False)
        switch(sha)
        attempt.step('start', required=False)
        start(sha)
        attempt.step('production', required=False)
        source.require(production() == baseline, 'production changed during dev cutover')
        report_json(BASE / 'last-result.json', {'verdict': 'DEPLOYED', 'sha': sha, 'previous': previous,
                                                   'productionUnchanged': True, 'ciRun': fresh['ciRun']})
        host.durable_remove(PENDING)
        attempt.step('complete', required=False)
        attempt.finish('DEPLOYED')
    except BaseException:
        # Capture the original gate before rollback changes the phase.
        report_json(BASE / 'last-failure.json', {'target': sha, 'stage': record['stage'],
                                               'gate': attempt.record['gate'], 'attemptId': attempt.record['id']})
        original_gate = attempt.record['phase']
        attempt.step('rollback', required=False)
        try:
            rollback(record)
        except BaseException:
            attempt.record.update(phase=original_gate, gate=GATES[original_gate])
            attempt.finish('ROLLBACK_UNVERIFIED')
            raise RuntimeError('DEV_ROLLBACK_UNVERIFIED: retained transaction; reconcile originals before recovery') from None
        attempt.record.update(phase=original_gate, gate=GATES[original_gate])
        attempt.finish('ROLLED_BACK')
        raise RuntimeError('DEV_DEPLOY_FAILED: previous code restored; inspect sanitized receipt') from None


def report_json(path, value):
    """Best effort non-authoritative reporting must never block cleanup."""
    try:
        source.write_json(path, value)
        return True
    except Exception:
        return False


# Read-only operator diagnostics. Never authorize, sign, replay, unlock or mutate journals.

# A terminal finality receipt is a new root-owned *append-only* proof, not an edit
# to the submission journal. Missing, mismatched or altered receipts fail closed.
def _proof_identity():
    path = RELEASES / current() / source.RECORD
    trusted(path)
    record = json.loads(path.read_text())
    return record['network']['genesis_hash'], record['program']['program_id']


def _has_finality_proof(journal_path, entry, original=None):
    if not RECONCILED.exists():
        return False
    trusted(RECONCILED, True)
    signature = entry.get('signature')
    if not isinstance(signature, str) or not re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{80,90}', signature):
        return False
    path = RECONCILED / (signature + '.json')
    if not path.exists() and not path.is_symlink():
        return False
    trusted(path)
    proof = json.loads(path.read_text())
    genesis, program = _proof_identity()
    original = journal_path.read_bytes() if original is None else original
    return isinstance(proof, dict) and proof.get('version') == 2 and proof.get('signature') == signature and (
        proof.get('verdict') in ('finalized-succeeded', 'finalized-failed')
    ) and proof.get('journalSha256') == hashlib.sha256(original).hexdigest() and (
        proof.get('genesis') == genesis and proof.get('programId') == program
    ) and proof.get('operation') == entry.get('operation') and proof.get('payment') == entry.get('payment') and (
        proof.get('payer') == entry.get('payer') and proof.get('wireSha256') ==
        hashlib.sha256(base64.b64decode(entry['transactionBase64'], validate=True)).hexdigest()
    ) and (
        type(proof.get('slot')) is int and proof['slot'] >= 0
    )


# Reuse the installed client's pinned codec and accepted ABI, rather than maintaining
# a second partial Solana/Ed25519/PDA implementation in Python. The sealed release
# is read by an unprivileged child with a clean environment; no keys or RPC URLs
# are passed to it. This code has no chain reader, signer, or journal writer.
_WIRE_VALIDATOR = r'''
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const root = process.argv[1];
const kit = createRequire(join(root, 'package.json'))('@solana/kit');
const abi = await import(pathToFileURL(join(root, 'src/program.ts')));
const check = (ok) => { if (!ok) throw new Error('original wire authentication failed'); };
let input = '';
for await (const chunk of process.stdin) { input += chunk; check(input.length <= 8192); }
const { entry: e, program } = JSON.parse(input);
check(['authorize', 'capture', 'void', 'refund'].includes(e.operation));
check(typeof e.transactionBase64 === 'string' && e.transactionBase64.length <= 1644);
const raw = Buffer.from(e.transactionBase64, 'base64');
check(raw.length > 0 && raw.length <= 1232 && raw.toString('base64') === e.transactionBase64);
const tx = kit.getTransactionDecoder().decode(raw);
const bytes = Buffer.from(tx.messageBytes);
const [m, end] = kit.getCompiledTransactionMessageDecoder().read(bytes, 0);
check(m.version === 'legacy' && end === bytes.length);
check(Buffer.from(kit.getCompiledTransactionMessageEncoder().encode(m)).equals(bytes));
check(kit.getBase64EncodedWireTransaction(tx) === e.transactionBase64);
check(createHash('sha256').update(bytes).digest('hex') === e.messageHash);
check(kit.getSignatureFromTransaction(tx) === e.signature && m.lifetimeToken === e.blockhash);
const keys = m.staticAccounts, h = m.header;
check(keys.length <= 256 && new Set(keys).size === keys.length);
check(h.numSignerAccounts === 2 && h.numReadonlySignerAccounts < 2 &&
      h.numReadonlyNonSignerAccounts <= keys.length - 2);
for (const signer of keys.slice(0, h.numSignerAccounts)) {
    const sig = tx.signatures[signer];
    check(sig && await kit.verifySignature(await kit.getPublicKeyFromAddress(signer), sig, bytes));
}
let ix;
const computeTags = new Set();
for (const i of m.instructions) {
    check(i.programAddressIndex >= h.numSignerAccounts && i.programAddressIndex < keys.length);
    check((i.accountIndices ?? []).every(n => n < keys.length));
    if (keys[i.programAddressIndex] === program) { check(!ix); ix = i; continue; }
    const data = Buffer.from(i.data ?? []), tag = data[0];
    check(keys[i.programAddressIndex] === 'ComputeBudget111111111111111111111111111111' &&
          !(i.accountIndices ?? []).length && (tag === 2 || tag === 3) &&
          data.length === (tag === 2 ? 5 : 9) && !computeTags.has(tag));
    computeTags.add(tag);
}
check(ix);
const op = abi.decodeInstructionData(new Uint8Array(ix.data ?? []));
check(op && op.op === e.operation);
const indices = ix.accountIndices ?? [], accounts = indices.map(n => keys[n]);
const authorize = op.op === 'authorize';
const server = accounts[authorize ? 1 : 0], mint = accounts[authorize ? 3 : 2];
check(accounts[0] === keys[1] && accounts[authorize ? 2 : 1] === e.payment && e.payer !== server);
const payerAta = await abi.ata(e.payer, mint);
const common = { payer: e.payer, server, payment: e.payment, mint, source: payerAta, payerAta,
    vault: await abi.ata(e.payment, mint), serverAta: await abi.ata(server, mint), funder: keys[0] };
const slots = authorize ? abi.authorizeAccounts(common) : op.op === 'capture' ? abi.captureAccounts(common) :
    op.op === 'void' ? abi.voidAccounts(common) : abi.refundAccounts(common);
check(indices.length === slots.length && indices.every((n, i) => {
    const s = slots[i], signer = n < h.numSignerAccounts;
    const writable = signer ? n < h.numSignerAccounts - h.numReadonlySignerAccounts :
        n < keys.length - h.numReadonlyNonSignerAccounts;
    return keys[n] === s.address && signer === s.signer && writable === s.writable;
}));
if (authorize) {
    check(e.payer === keys[1] && await abi.paymentAddress(program, e.payer, op.salt) === e.payment);
    check(e.expectedHeld === '0' && e.expectedRefundable === '0');
} else {
    check(e.expectedHeld === op.expectedHeld.toString() && e.expectedRefundable === op.expectedRefundable.toString());
}
process.stdout.write(createHash('sha256').update(raw).digest('hex'));
'''


def _wire_runtime():
    return RELEASES / current() / 'integration'


def _validate_original_wire(entry, signature):
    genesis, program = _proof_identity()
    source.require(entry['signature'] == signature and entry['operation'] in ('authorize', 'capture', 'void', 'refund'),
                   'unsupported original operation: setup/reclaim require separate evidence')
    fields = ('signature', 'messageHash', 'transactionBase64', 'blockhash', 'operation',
              'payment', 'payer', 'expectedHeld', 'expectedRefundable')
    payload = json.dumps({'entry': {k: entry[k] for k in fields}, 'program': program})
    source.require(len(payload) <= 8192, 'original wire input too large')
    result = subprocess.run([
        'runuser', '-u', 'capture402-deploy', '--', '/usr/bin/env', '-i',
        'PATH=/usr/local/bin:/usr/bin:/bin', 'node', '--experimental-strip-types',
        '--input-type=module', '--eval', _WIRE_VALIDATOR, str(_wire_runtime())],
        input=payload, capture_output=True, text=True, timeout=15)
    # Never surface the child error body or original wire in operator output.
    source.require(result.returncode == 0 and bool(re.fullmatch(r'[a-f0-9]{64}', result.stdout)),
                   'original wire authentication failed')
    return result.stdout, genesis, program


def reconcile_original(signature, record=False):
    quarantine.ordinary_allowed()
    # Reconciliation can only make a sidecar if the original *signed bytes*
    # are bound to an actually finalized transaction on the pinned network.
    # Missing history, an invalid blockhash and an absent PDA do NOT qualify.
    source.require(bool(re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{80,90}', signature)), 'invalid signature')
    journal = state_paths()[0]
    source.require(journal.is_dir() and not journal.is_symlink(), 'invalid journal directory')
    path = journal / (signature + '.json')
    info = path.lstat()
    source.require(stat.S_ISREG(info.st_mode) and 0 < info.st_size < 4 * 1024 * 1024, 'unsafe journal file')
    initial = path.read_bytes()
    entry = json.loads(initial)
    source.require(isinstance(entry, dict) and entry.get('signature') == signature and path.stem == signature,
                   'journal signature mismatch')
    fields = ('messageHash', 'transactionBase64', 'blockhash', 'operation', 'payment',
              'payer', 'expectedHeld', 'expectedRefundable')
    source.require(all(isinstance(entry.get(key), str) and entry[key] for key in fields),
                   'malformed original journal')
    attempts = entry.get('attempts')
    source.require(isinstance(attempts, list) and attempts and all(
        isinstance(a, dict) and (a.get('outcome') is None or isinstance(a.get('outcome'), dict))
        for a in attempts), 'malformed original attempts')
    wire_sha, genesis, program = _validate_original_wire(entry, signature)
    rpc()  # Enforce genesis of the currently installed Devnet release.
    url = host.env_value(PRIVATE / 'facilitator.env', 'SOLANA_RPC_URL')
    response = _dev_rpc_call(url, 'getSignatureStatuses', [[signature], {'searchTransactionHistory': True}])
    source.require(isinstance(response, dict) and isinstance(response.get('value'), list) and
                   len(response['value']) == 1, 'invalid status response')
    status = response['value'][0]
    if not isinstance(status, dict) or status.get('confirmationStatus') != 'finalized' or (
        type(status.get('slot')) is not int or status['slot'] < 0
    ) or 'err' not in status:
        print('INCONCLUSIVE: original finalized status unavailable; no recovery is authorized')
        if record:
            raise RuntimeError('original finalized status unavailable; no receipt created')
        return False
    verdict = 'finalized-failed' if status['err'] is not None else 'finalized-succeeded'
    print('Original finalized:', verdict, 'slot:', status['slot'])
    if not record:
        print('READ ONLY: use --record to save an immutable finality receipt for deployment preflight')
        return True
    source.require(not PENDING.exists(), 'pending deployment prevents reconciliation')
    source.require(path.read_bytes() == initial, 'original journal changed during reconciliation')
    if not RECONCILED.exists():
        RECONCILED.mkdir(mode=0o700)
        sync(BASE)
    trusted(RECONCILED, True)
    receipt = {
        'version': 2, 'signature': signature, 'verdict': verdict, 'slot': status['slot'],
        'genesis': genesis, 'programId': program,
        'operation': entry['operation'], 'payment': entry['payment'], 'payer': entry['payer'],
        'wireSha256': wire_sha, 'journalSha256': hashlib.sha256(initial).hexdigest()
    }
    target = RECONCILED / (signature + '.json')
    # Exclusive creation: no overwrite and no following symlinks.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    # Incomplete receipts stay in place to fail closed; do not hide an error.
    with os.fdopen(fd, 'w') as writer:
        json.dump(receipt, writer, sort_keys=True)
        writer.write(chr(10))
        writer.flush()
        os.fsync(writer.fileno())
    sync(RECONCILED)
    source.require(_has_finality_proof(path, entry), 'immutable finality receipt rejected')
    print('FINALIZED RECEIPT RECORDED: original journal unchanged; rerun dev doctor before deployment')
    return True


def doctor():
    quarantine.ordinary_allowed()
    print('DEV DEPLOY DIAGNOSTICS (read-only)')
    try:
        print('Current:', current())
    except Exception:
        print('Current: BLOCKED')
    print('Pending deployment:', 'yes' if PENDING.exists() else 'no')
    checks = (
        ('Systemd units', units),
        ('Dev health', lambda: health(current())),
        ('Production isolation', production),
        ('Payment journals', clean_operations),
        ('Devnet RPC identity', rpc),
    )
    for name, check in checks:
        try:
            check()
            print('PASS:', name)
        except Exception:
            # Error bodies, RPC URLs and private fields must never reach stdout.
            print('BLOCKED:', name)
    try:
        journal = state_paths()[0]
        source.require(journal.is_dir() and not journal.is_symlink(), 'unsafe journal directory')
        count = 0
        for path in sorted(journal.iterdir()):
            if path.suffix != '.json':
                continue  # clean_operations above reports unknown/temporary files
            try:
                info = path.lstat()
                source.require(stat.S_ISREG(info.st_mode) and info.st_size < 4 * 1024 * 1024,
                               'unsafe journal member')
                entry = json.loads(path.read_text())
                attempts = entry.get('attempts')
                outcomes = [a.get('outcome', {}).get('result') if isinstance(a.get('outcome'), dict) else None
                            for a in attempts] if isinstance(attempts, list) and all(isinstance(a, dict) for a in attempts) else []
                allowed = {'not-submitted', 'finalized-succeeded', 'finalized-failed'}
                if outcomes and all(result in allowed for result in outcomes):
                    continue
                if isinstance(entry, dict) and _has_finality_proof(path, entry):
                    continue  # Root-owned finality receipt was verified against exact journal bytes.
                count += 1
                if count > 10:
                    continue
                sig = entry.get('signature')
                operation = entry.get('operation')
                # Public signatures/operations only, no transaction wire or private metadata.
                safe_sig = sig if isinstance(sig, str) and bool(re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{80,90}', sig)) and path.stem == sig else 'invalid-signature'
                safe_op = operation if operation in ('authorize', 'capture', 'void', 'refund', 'reclaim', 'setup') else 'invalid-operation'
                safe_outcomes = ','.join(result if isinstance(result, str) and result in
                                         {'unresolved', 'submit-threw', 'not-submitted', 'finalized-succeeded', 'finalized-failed'}
                                         else 'missing-or-invalid' for result in outcomes) or 'missing-or-invalid'
                print(f'  UNRESOLVED {safe_op} {safe_sig} outcome={safe_outcomes}')
            except Exception:
                count += 1
                if count <= 10:
                    print('  MALFORMED facilitator journal entry')
        if count > 10:
            print(f'  ... {count - 10} additional entries need inspection')
    except Exception:
        print('Journal detail unavailable; payment evidence must be preserved')
    print('No recovery or journal modification was performed')


def _dev_rpc_call(url, method, params):
    from host_cli import NoRedirect
    source.require(url.startswith('https://'), 'dev RPC must use TLS')
    payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    request = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
        raw = response.read(65537)
    source.require(len(raw) <= 65536, 'oversized RPC response')
    result = json.loads(raw)
    source.require(isinstance(result, dict) and 'error' not in result and 'result' in result, 'invalid RPC response')
    return result['result']


def retain_diagnostic(report):
    """Retain only the public observation, never original bytes, outside stores."""
    report['id'] = f'{time.time_ns():020d}-' + uuid.uuid4().hex
    report['retention'] = 'unavailable'
    try:
        trusted(BASE, True)
        root = BASE / 'diagnostics'
        root.mkdir(mode=0o700, exist_ok=True)
        trusted(root, True)
        source.require(root.stat().st_mode & 0o077 == 0, 'unsafe diagnostic directory')
        fd = os.open(root / 'allocation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            source.require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'unsafe diagnostic lock')
            fcntl.flock(fd, fcntl.LOCK_EX)
            source.require(sum(1 for p in root.iterdir() if ATTEMPT_RE.fullmatch(p.name)) < 4096,
                           'diagnostic retention capacity reached')
            directory = root / report['id']
            directory.mkdir(mode=0o700)
            sync(root)
            report['retention'] = 'stored'
            data = (json.dumps(report, sort_keys=True) + '\n').encode()
            source.require(len(data) <= 32768, 'diagnostic report too large')
            host.atomic_bytes(directory / 'record.json', data, 0o600)
            sync(BASE)
        finally:
            os.close(fd)
    except Exception:
        report['retention'] = 'unavailable'
        # Read-only observations remain usable with an explicit retention gap.


def inspect_tx(signature):
    quarantine.ordinary_allowed()
    source.require(bool(re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{80,90}', signature)), 'invalid signature format')
    journal = state_paths()[0]
    source.require(journal.is_dir() and not journal.is_symlink(), 'invalid journal directory')
    path = journal / (signature + '.json')
    initial, identity = stable_bytes(path, 4 * 1024 * 1024 - 1)
    report = {'version': 1, 'signature': signature, 'sourceRevision': safe_current(),
              'controllerSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'before': {'sha256': hashlib.sha256(initial).hexdigest(), 'identity': identity},
              'after': None, 'consistency': 'unavailable', 'authentication': 'unavailable',
              'rpcSlots': {}, 'rawBytes': 'not-retained; public report cannot reproduce private original bytes'}
    try:
        entry = json.loads(initial)
        source.require(isinstance(entry, dict) and entry.get('signature') == signature and
                       entry.get('operation') in ('authorize', 'capture', 'void', 'refund', 'reclaim', 'setup'),
                       'journal signature/operation mismatch')
        try:
            _validate_original_wire(entry, signature)
            report['authentication'] = 'authenticated'
        except Exception:
            report['authentication'] = 'failed-or-unavailable'
        _inspect_tx(signature, entry, report)
    except Exception:
        print('Original diagnostic: UNAVAILABLE or invalid; no recovery is authorized')
    finally:
        try:
            final, final_identity = stable_bytes(path, 4 * 1024 * 1024 - 1)
            report['after'] = {'sha256': hashlib.sha256(final).hexdigest(), 'identity': final_identity}
            report['consistency'] = 'unchanged' if initial == final and identity == final_identity else 'changed'
            if report['sourceRevision'] != safe_current():
                report['consistency'] = 'inconsistent'
        except Exception:
            report['consistency'] = 'inconsistent'
        retain_diagnostic(report)
        print('Original byte evidence:', json.dumps(report, sort_keys=True))
        if report['consistency'] != 'unchanged':
            print('INCONSISTENT original observation; no frozen global snapshot or recovery is established')
        print('No broadcast, journal write or recovery was performed')
    return report


def _inspect_tx(signature, entry, report):
    blockhash = entry.get('blockhash')
    payment = entry.get('payment')
    source.require(isinstance(blockhash, str) and bool(re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{32,44}', blockhash))
                   and isinstance(payment, str) and bool(re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{32,44}', payment)),
                   'journal has invalid public identifiers')
    attempts = entry.get('attempts')
    outcomes = [(a.get('outcome') or {}).get('result', 'missing')
                for a in attempts] if isinstance(attempts, list) and all(isinstance(a, dict) and isinstance(a.get('outcome'), (dict, type(None))) for a in attempts) else []
    safe_outcomes = [x if x in ('unresolved', 'submit-threw', 'not-submitted', 'finalized-succeeded', 'finalized-failed') else 'invalid'
                     for x in outcomes[:32]]
    print('Operation:', entry['operation'])
    print('Signature:', signature)
    print('Journal:', ', '.join(safe_outcomes) if safe_outcomes else 'missing-or-invalid')
    try:
        rpc()  # Verify RPC genesis against the pinned Devnet deployment record.
        url = host.env_value(PRIVATE / 'facilitator.env', 'SOLANA_RPC_URL')
        status_result = _dev_rpc_call(url, 'getSignatureStatuses', [[signature], {'searchTransactionHistory': True}])
        source.require(isinstance(status_result, dict) and
                       isinstance(status_result.get('value'), list) and len(status_result['value']) == 1,
                       'malformed signature status')
        report['rpcSlots']['signatureContext'] = _safe_slot(status_result.get('context', {}).get('slot'))
        status = status_result['value'][0]
        report['rpcSlots']['signature'] = _safe_slot(status.get('slot')) if isinstance(status, dict) else None
        if status is None:
            print('Chain signature: NOT FOUND (not proof of no execution)')
        else:
            source.require(isinstance(status, dict), 'malformed signature status')
            commitment = status.get('confirmationStatus')
            print('Chain signature:', commitment if commitment in ('processed', 'confirmed', 'finalized') else 'unknown',
                  'execution=' + ('failed' if status.get('err') is not None else 'succeeded'))
            print('Signature slot:', _safe_slot(status.get('slot')) or 'unknown')
        validity = _dev_rpc_call(url, 'isBlockhashValid', [blockhash, {'commitment': 'finalized'}])
        source.require(isinstance(validity, dict) and isinstance(validity.get('value'), bool)
                       and isinstance(validity.get('context'), dict), 'malformed blockhash status')
        report['rpcSlots']['blockhash'] = _safe_slot(validity['context'].get('slot'))
        print('Blockhash valid at finalized bank:', validity['value'], 'slot:', _safe_slot(validity['context'].get('slot')))
        account = _dev_rpc_call(url, 'getAccountInfo', [payment, {'commitment': 'finalized', 'encoding': 'base64'}])
        source.require(isinstance(account, dict) and isinstance(account.get('context'), dict) and 'value' in account,
                       'malformed account response')
        report['rpcSlots']['account'] = _safe_slot(account['context'].get('slot'))
        print('Payment account:', 'ABSENT' if account['value'] is None else 'PRESENT (identity not validated)',
              'slot:', _safe_slot(account['context'].get('slot')))
        print('Blockhash origin slot:', entry.get('blockhashSlot') if
              isinstance(entry.get('blockhashSlot'), str) and re.fullmatch('[0-9]{1,20}', entry['blockhashSlot']) else 'NOT RECORDED')
        print('Last valid block height:', entry.get('lastValidBlockHeight') if
              isinstance(entry.get('lastValidBlockHeight'), str) and re.fullmatch('[0-9]{1,20}', entry['lastValidBlockHeight']) else 'NOT RECORDED')
        if status is not None and status.get('confirmationStatus') == 'finalized':
            print('Verdict: RPC signature finalized; verify original binding/account evidence before any recovery')
        else:
            print('Verdict: INCONCLUSIVE; missing history and invalid blockhash alone are not proof of no effect')
    except Exception:
        print('RPC evidence: UNAVAILABLE or invalid; preserve the original journal')


def _safe_slot(value):
    return value if type(value) is int and value >= 0 else None


class OperationBlocked(RuntimeError):
    pass


def dispatch(argv):
    if not (argv and argv[0] == 'quarantine') and argv != ['status']:
        quarantine.ordinary_allowed()
    source.require(os.geteuid() == 0, 'dev deployment requires authorized local sudo')
    if len(argv) == 2 and argv[0] == 'deploy' and source.SHA_RE.fullmatch(argv[1]):
        attempt = None
        launched = False
        launch_refused = False
        try:
            attempt = Attempt.create(argv[1])
            application = safe_current()
            attempt.record.update(previousSha=application, currentSha=application)
            attempt.record['production']['before'] = observation()
            attempt.step('lock')
            with locked():
                attempt.step('recovery')
                if recover():
                    raise RuntimeError('dev recovered offline; explicitly invoke deploy again')
            controller = str(Path(__file__).resolve())
            unit = RELEASE_UNIT_PREFIX + attempt.record['id']
            attempt.step('launch', unit=unit)
            print('Dev deployment attempt: ' + attempt.record['id'] + '; job: ' + unit, flush=True)
            launched = True
            try:
                result = subprocess.run(['systemd-run', '--unit=' + unit, '--wait', '--property=Type=exec',
                    '--property=UMask=0077', '--property=RuntimeMaxSec=900',
                    '--property=ExecStopPost=/usr/bin/python3 -B ' + controller + ' recover',
                    '/usr/bin/python3', '-B', controller, *argv, attempt.record['id']],
                    capture_output=True, text=True)
            except OSError:
                launch_refused = True  # Local exec failure, before systemd-run could launch a job.
                raise
            # Never print systemd/subprocess bodies or infer that an unreported job ended.
            # A lost waiter/DBus connection can leave the worker running. Do not overwrite it.
            worker = read_attempt(attempt.record['id'])
            attempt.record = worker
            source.require(result.returncode == 0 and worker['outcome'] in ('DEPLOYED', 'ALREADY_CURRENT'), 'job failed')
        except BaseException:
            if attempt and attempt.record['outcome'] == 'INCOMPLETE':
                # Reload so a completed worker is never overwritten by the dispatcher.
                try:
                    attempt.record = read_attempt(attempt.record['id'])
                except Exception:
                    pass
                if attempt.record['outcome'] == 'INCOMPLETE' and (not launched or launch_refused):
                    attempt.finish('FAILED')
            summary = failure_summary(attempt) if attempt else 'dev deployment blocked; gate=REPORTING; attempt=unavailable; outcome=INCOMPLETE; job=not-launched'
            print(summary, file=sys.stderr)
            raise OperationBlocked(summary) from None
    else:
        main(argv)

def main(argv):
    source.require(os.geteuid() == 0, 'dev deployment requires authorized local sudo')
    if argv and argv[0] == 'quarantine':
        import quarantine_prepare
        print(json.dumps(quarantine_prepare.control(argv[1:])))
        return
    if argv == ['gate']:
        gate()
        return
    if argv == ['recover']:
        with locked():
            print('RECOVERED' if recover() else 'NO_PENDING')
        return
    if argv == ['doctor']:
        doctor()
        return
    if len(argv) == 2 and argv[0] == 'tx':
        inspect_tx(argv[1])
        return
    if len(argv) in (2, 3) and argv[0] == 'reconcile':
        source.require(len(argv) == 2 or argv[2] == '--record', 'usage: dev reconcile <signature> [--record]')
        with locked():
            reconcile_original(argv[1], record=len(argv) == 3)
        return
    if argv == ['status']:
        print(json.dumps({'current': current(), 'pending': PENDING.exists(),
                          'lastResult': safe_last_result(), 'latestAttempt': latest_attempt()}))
        return
    source.require(len(argv) in (2, 3) and argv[0] == 'deploy' and source.SHA_RE.fullmatch(argv[1]), 'usage: capture402 dev deploy <40-hex-sha>|status|doctor|tx <signature>|reconcile <signature> [--record]|recover')
    attempt = Attempt.load(argv[2], argv[1]) if len(argv) == 3 else Attempt.create(argv[1])
    try:
        application = safe_current()
        attempt.record.update(previousSha=application, currentSha=application)
        if attempt.record['production']['before'] is None:
            attempt.record['production']['before'] = observation()
        attempt.step('lock')
        invocation = os.environ.get('INVOCATION_ID')
        if invocation and re.fullmatch('[a-f0-9]{32}', invocation):
            attempt.step('lock', invocation=invocation)
        # No metadata access before retained offline recovery.
        attempt.step('recovery')
        with locked():
            if recover():
                raise RuntimeError('dev recovered offline; explicitly invoke deploy again')
        from host_cli import GitHub
        attempt.step('release')
        deploy(argv[1], GitHub(), attempt)
    except BaseException:
        if attempt.record['outcome'] == 'INCOMPLETE':
            attempt.finish('FAILED')
        print(failure_summary(attempt), file=sys.stderr)
        raise


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except BaseException:
        # RPC URLs, subprocess output and private journal content stay private.
        print('DEV_DEPLOY_BLOCKED: inspect dev receipts and retained transaction', file=sys.stderr)
        sys.exit(1)
