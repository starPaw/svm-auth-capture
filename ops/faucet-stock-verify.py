#!/usr/bin/env python3
"""Root pre-import verification; never read or print key bytes."""
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

PUBLIC = '/etc/capture402-e2e/faucet-stock-approved.json'
BUDGET = Path('/var/lib/capture402-e2e/facilitator/campaign-budget')
ADMISSION = Path('/var/lib/capture402-e2e/facilitator/b3-admission')
STOCK = Path('/var/lib/capture402-e2e/facilitator/faucet-stock-setup')

def digest(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def private(path, uid, gid, mode):
    s = path.lstat()
    if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)) or s.st_uid != uid or s.st_gid != gid or stat.S_IMODE(s.st_mode) != mode or stat.S_ISREG(s.st_mode) and s.st_nlink != 1:
        raise RuntimeError('stock custody drift')

def validate_approval(a, source, action):
    expected = {'schema':1, 'sourceRevision':source, 'sponsor':'5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX',
        'mint':'91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp', 'browser':'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74',
        'genesisHash':'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
        'campaignReference':'owner-policy-2026-10-12-existing-10-sol-spend-cap-1-sol',
        'amount':'100000000000', 'maximumSpend':'2139280', 'admissionMaximum':600}
    if not re.fullmatch('[a-f0-9]{40}', source) or any(a.get(k) != v for k,v in expected.items()) or action not in ('quote','issue','observe') or not isinstance(a.get('actions',{}).get(action),str) or not a['actions'][action].strip() or not isinstance(a.get('issueApprovalReference'),str) or not a['issueApprovalReference'].strip():
        raise RuntimeError('fixed stock scope/action approval required before credentials')

def require_stopped_writers():
    # This UID preserves native journal custody. Its running application must not
    # coexist with ephemeral mint credentials under the same UID.
    for name in ('capture402-e2e-facilitator','capture402-e2e-restaurant'):
        # systemctl sorts property output; parse explicit keys to avoid order assumptions.
        result = subprocess.run(['systemctl','show','--property=ActiveState,MainPID,ControlPID',name],check=True,capture_output=True,text=True,timeout=10)
        fields = dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        if fields.get('ActiveState') not in ('inactive','failed') or fields.get('MainPID')!='0' or fields.get('ControlPID')!='0':
            raise RuntimeError('E2E writers must be stopped before mint credential delivery')
    for process in Path('/proc').iterdir():
        if process.name.isdigit():
            try:
                status = (process/'status').read_text()
                ids = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status,re.M)
                if ids is None: raise RuntimeError('process UID inventory unavailable')
                if '989' in ids.groups(): raise RuntimeError('remaining E2E UID process blocks mint credential delivery')
            except FileNotFoundError:
                pass

def verify(root, action):
    root = Path(root)
    spec = importlib.util.spec_from_file_location('p2_verifier', root/'ops/p2-verify.py')
    p2 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(p2)
    # The verifier itself must be externally authenticated before this entry point runs.
    p2.verify(root, approval_path=PUBLIC)  # Same approved full closure, interpreter and fixed network.
    approved = json.loads(Path(PUBLIC).read_text())
    validate_approval(approved,json.loads((root/'snapshot-manifest.json').read_text())['sourceRevision'],action)
    for directory, prefix in [(BUDGET,'budget'),(ADMISSION,'admission')]:
        private(directory,989,986,0o700)
        for name in ('policy.json','state.json','.lock'):
            private(directory/name,989,986,0o600)
        if digest(directory/'policy.json') != approved.get(prefix+'PolicySha256'):
            raise RuntimeError('original native policy changed')
        lock = (directory/'.lock').stat()
        if approved.get(prefix+'Lock') != {'device':lock.st_dev,'inode':lock.st_ino}:
            raise RuntimeError('original native lock replaced')
    private(STOCK,989,986,0o700)
    for parent in STOCK.parents:
        if parent == STOCK.parent: private(parent,989,986,0o700)
        else: p2.protected(parent)
    for receipt,field in [('/etc/capture402-e2e/b1-complete.json','b1ReceiptSha256'),('/etc/capture402-e2e/identities.json','identitiesSha256'),('/var/lib/capture402-e2e/setup/external-funding-receipt.json','fundingReceiptSha256')]:
        p2.protected(receipt,0o600)
        if digest(receipt) != approved.get(field): raise RuntimeError('accepted original custody/funding receipt changed')
    if action == 'issue':
        require_stopped_writers()
        if any(STOCK.iterdir()): raise RuntimeError('existing or partial stock action remains frozen')
        if 'faucet-stock' in json.loads((BUDGET/'state.json').read_text()).get('entries',{}):
            raise RuntimeError('original stock budget reservation remains frozen')
        for role,uid,gid in [('sponsor',989,986),('mint',0,0)]:
            key = Path('/etc/capture402-e2e/keys')/(role+'.json')
            p2.protected(key.parent)
            private(key,uid,gid,0o600)
    return True

if __name__ == '__main__':
    try:
        if len(sys.argv) != 3: raise RuntimeError('exact stock action required')
        verify(sys.argv[1],sys.argv[2])
    except Exception:
        sys.exit('Stock snapshot/network/action/custody verification failed before credentials or Node imports')
