#!/usr/bin/env python3
"""Pre-import source closure verification. Inputs must be installed by the trusted operator."""
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import stat
import sys

def protected(p, mode=None):
    p=Path(p)
    for x in [p,*p.parents]:
        s=x.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022 or not (stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)):
            raise RuntimeError('untrusted root input')
        if x==p and (mode is not None and stat.S_IMODE(s.st_mode)!=mode or stat.S_ISREG(s.st_mode) and s.st_nlink!=1):
            raise RuntimeError('unsafe input metadata')

def digest(p):
    with open(p,'rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()

def verify(root, approval_path='/etc/capture402-e2e/provision-approved.json', network_path='/etc/capture402-e2e/p2-network.json', hosts_path='/etc/capture402-e2e/p2-hosts', action=None):
    root=Path(root);protected(root);protected(approval_path,0o600);protected(network_path,0o600);protected(hosts_path,0o600)
    approved=json.loads(Path(approval_path).read_text());manifest=root/'snapshot-manifest.json';protected(manifest,0o444)
    if approved['snapshotPath']!=str(root) or approved['snapshotManifestSha256']!=digest(manifest):raise RuntimeError('snapshot approval mismatch')
    entries=json.loads(manifest.read_text())['entries']
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_symlink() or not p.is_dir()}
    if actual!=set(entries)|{'snapshot-manifest.json'}:raise RuntimeError('snapshot closure changed')
    for name,entry in entries.items():
        p=root/name
        if p.is_symlink():
            if entry.get('link')!=os.readlink(p) or not p.resolve().is_relative_to(root) or p.lstat().st_uid!=0:raise RuntimeError('untrusted snapshot symlink')
        else:
            protected(p,entry['mode'])
            if digest(p)!=entry['sha256']:raise RuntimeError('snapshot bytes changed')
    if digest(root/'node/bin/node')!='23a5637c2470fde09fcc1acc77c1b92e04e3d7e3e6e80ff7df6f5831958d1477':raise RuntimeError('interpreter authenticity mismatch')
    network=json.loads(Path(network_path).read_text())
    addresses=network['addresses']
    if network['host']!='api.devnet.solana.com' or not addresses or len(set(addresses))!=len(addresses):raise RuntimeError('fixed RPC host required')
    for value in addresses:
        if not ipaddress.ip_address(value).is_global:raise RuntimeError('public approved RPC address required')
    expected=''.join(f'{v} api.devnet.solana.com\n' for v in addresses)
    if Path(hosts_path).read_text()!=expected or approved['networkSha256']!=digest(network_path) or approved['hostsSha256']!=digest(hosts_path):raise RuntimeError('network approval changed')
    if action is not None and (action not in ['init-budget','budget-status','accept-funding','observe-funding','plan-assets','assets','observe-assets','continue-assets-presigner-stop'] or not isinstance(approved.get('actions',{}).get(action),str) or not approved['actions'][action].strip()):raise RuntimeError('exact operator action approval missing before credentials')
    if action=='continue-assets-presigner-stop':
        stop_path=Path('/etc/capture402-e2e/p2-presigner-stop.json');protected(stop_path,0o600)
        if approved.get('preSignerStopSha256')!=digest(stop_path):raise RuntimeError('specific pre-signer stop approval missing')
        stop=json.loads(stop_path.read_text())
        expected={'schema':1,'reason':'B206_SYSTEMD_SERVICE_SUFFIX_REJECTED_BEFORE_SDK_SIGNER','stoppedSourceRevision':'b2062584b488adfa3e34e43918fddaafd7e0dc37','stoppedEntrypointSha256':'2d4ac36d064410b834b7eecf13127c4c9818fcb19dcee4dc1a2716c5f13cf4f8','stoppedManifestSha256':'dda6fa6162d0ddd4199b38e023ec602f178c364715196510650ea78de5c39301'}
        if any(stop.get(k)!=v for k,v in expected.items()) or not re.fullmatch(r'/run/credentials/capture402-e2e-p2-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.service',stop.get('observedCredentialDirectory','')):raise RuntimeError('unknown stop cannot receive signer credentials')
        intent=Path('/var/lib/capture402-e2e/setup/assets-intent.json');protected(intent,0o600)
        if digest(intent)!=stop.get('originalIntentSha256') or json.loads(intent.read_text()).get('planHash')!=stop.get('originalPlanHash'):raise RuntimeError('original intent drift')
        if any(os.path.lexists(intent.parent/('assets-'+s+'.json')) for s in ['signed','broadcast','response','receipt','continuation-intent']):raise RuntimeError('existing signed/continuation state must remain frozen')
        state_path=Path('/var/lib/capture402-e2e/facilitator/campaign-budget/state.json');ss=state_path.lstat()
        if not stat.S_ISREG(ss.st_mode) or ss.st_uid!=0 or ss.st_nlink!=1 or stat.S_IMODE(ss.st_mode)!=0o600:raise RuntimeError('unsafe campaign state')
        state=json.loads(state_path.read_text())
        if not isinstance(state.get('entries'),dict) or 'assets' in state['entries']:raise RuntimeError('existing budget admission cannot be continued')
    if action in ['assets','continue-assets-presigner-stop']:
        for role,uid,gid in [('sponsor',989,986),('mint',0,0)]:
            key=Path('/etc/capture402-e2e/keys')/(role+'.json');protected(key.parent)
            s=key.lstat()
            if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=uid or s.st_gid!=gid or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('signer custody drift')
    return True

if __name__=='__main__':
    try:verify(sys.argv[1],action=sys.argv[2] if len(sys.argv)>2 else None)
    except Exception:sys.exit('P2 snapshot/network verification failed before imports')
