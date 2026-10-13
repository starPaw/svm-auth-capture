#!/usr/bin/env python3
"""Marked disposable VM ONLY. Exact wrapper properties, synthetic Node probe.

Usage: python3 -B faucet_stock_linux_test.py <sealed-stock-snapshot>
Never run on the VPS. No original economic key, public RPC or transaction is used.
"""
import hashlib
import http.server
import json
import os
import pwd
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading

if socket.gethostname()!='capture402-p2-disposable' or Path('/etc/capture402-p2-disposable').read_text().strip()!='DISPOSABLE_SYNTHETIC_P2_TEST_ONLY':
    sys.exit('marked synthetic disposable VM required; never run on VPS')
root=Path(sys.argv[1]);private=Path('/etc/capture402-e2e');facilitator=Path('/var/lib/capture402-e2e/facilitator')
budget=facilitator/'campaign-budget';admission=facilitator/'b3-admission';stock=facilitator/'faucet-stock-setup'
results=[]
def run(args,ok=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=90)
    if ok and p.returncode: raise RuntimeError(p.stderr[-1500:])
    return p
def digest(p):
    with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,value,mode=0o600,uid=0,gid=0):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value);p.chmod(mode);os.chown(p,uid,gid)
def require(value):
    if not value:raise RuntimeError('synthetic assertion failed')
def check(name,fn):
    fn();results.append({'name':name,'result':'PASS'});print('PASS '+name,flush=True)
def owner_directory(p,uid=0,gid=0):
    p.mkdir(parents=True,exist_ok=True);p.chmod(0o700);os.chown(p,uid,gid)
for p in [private,private/'keys',facilitator]:owner_directory(p,989 if p==facilitator else 0,986 if p==facilitator else 0)
for p in [budget,admission,stock]:
    if p.exists():shutil.rmtree(p)  # Synthetic overlay only; never live history.
    owner_directory(p,989,986)
run(['groupadd','--gid','986','stock-fixture'],ok=False)
try:username=pwd.getpwuid(989).pw_name
except KeyError:
    run(['useradd','--uid','989','--gid','986','--no-create-home','--shell','/usr/sbin/nologin','stock-fixture']);username='stock-fixture'
require(run(['id','-u',username]).stdout.strip()=='989')
plan={'schema':1,'sourceRevision':json.loads((root/'snapshot-manifest.json').read_text())['sourceRevision'],
    'sponsor':'5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX','mint':'91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp',
    'browser':'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74','genesisHash':'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
    'campaignReference':'owner-policy-2026-10-12-existing-10-sol-spend-cap-1-sol',
    'amount':'100000000000','maximumSpend':'2139280','admissionMaximum':600,'issueApprovalReference':'SYNTHETIC_NO_LIVE_PERMISSION'}
for name in ['sponsor','mint','merchant','payer']:write(private/f'keys/{name}.json','SYNTHETIC_SECRET_MARKER_NOT_A_KEY',uid=989 if name=='sponsor' else 0,gid=986 if name=='sponsor' else 0)
for name in ['facilitator.env','restaurant.env']:write(private/name,'SYNTHETIC_PRIVATE_ENV')
old=['/etc/sac006','/var/lib/sac006','/opt/capture402','/opt/svm-auth-capture','/etc/capture402-dev','/var/lib/capture402-dev','/opt/capture402-dev','/home/capture402-dev']
for p in old:write(Path(p)/'stock-marker','SYNTHETIC_OLD_SECRET')
for path,field in [(private/'b1-complete.json','b1ReceiptSha256'),(private/'identities.json','identitiesSha256'),(Path('/var/lib/capture402-e2e/setup/external-funding-receipt.json'),'fundingReceiptSha256')]:
    write(path,json.dumps({'SYNTHETIC_ONLY':True}));plan[field]=digest(path)
write(private/'p2-network.json',json.dumps({'host':'api.devnet.solana.com','addresses':['1.1.1.1']}))
write(private/'p2-hosts','1.1.1.1 api.devnet.solana.com\n')
run(['ip','address','add','1.1.1.1/32','dev','lo'],ok=False)
server=http.server.ThreadingHTTPServer(('1.1.1.1',19443),http.server.SimpleHTTPRequestHandler)
threading.Thread(target=server.serve_forever,daemon=True).start()
names=['capture402-e2e-facilitator','capture402-e2e-restaurant']
# Ubuntu's synthetic image may assign UID989 to polkit; it must not coexist
# with the fixed-UID fixture. This stop occurs only inside the marked overlay.
run(['systemctl','stop','polkit.service'],ok=False)
run(['systemctl','stop',*names],ok=False)
for name in names:write(Path('/etc/systemd/system')/(name+'.service'),'[Service]\nUser=989\nGroup=986\nExecStart=/usr/bin/sleep infinity\n',0o644)
run(['systemctl','daemon-reload'])
initialization="""import {CampaignBudget} from './integration/src/campaign-budget.ts';import {AdmissionJournal} from './integration/src/admission-journal.ts';
CampaignBudget.initialize('/var/lib/capture402-e2e/facilitator/campaign-budget',{schema:1,reference:'owner-policy-2026-10-12-existing-10-sol-spend-cap-1-sol',genesisHash:'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',sponsor:'5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX',browser:'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74',spendLimit:'1000000000'});
AdmissionJournal.initialize('/var/lib/capture402-e2e/facilitator/b3-admission',{schema:1,kind:'relay-attempts',reference:'synthetic-stock',maximum:600,carryForward:43,historicalActual:null,sourceSha256:'a'.repeat(64)});"""
subprocess.run(['setpriv','--reuid=989','--regid=986','--clear-groups',str(root/'node/bin/node'),'--experimental-strip-types','--input-type=module','-e',initialization],cwd=root,check=True)
for directory,prefix in [(budget,'budget'),(admission,'admission')]:
    plan[prefix+'PolicySha256']=digest(directory/'policy.json');s=(directory/'.lock').stat();plan[prefix+'Lock']={'device':s.st_dev,'inode':s.st_ino}
probe=r"""import fs from 'node:fs';import net from 'node:net';import dns from 'node:dns/promises';import assert from 'node:assert/strict';
import {CampaignBudget} from './integration/src/campaign-budget.ts';import {AdmissionJournal} from './integration/src/admission-journal.ts';
import {stockCredentialDirectory,validateStockCredential} from './integration/operators/faucet-stock-operator.ts';
const action=process.argv[2],b='/var/lib/capture402-e2e/facilitator/campaign-budget',a='/var/lib/capture402-e2e/facilitator/b3-admission',s='/var/lib/capture402-e2e/facilitator/faucet-stock-setup';
assert.equal(process.getuid(),989);assert.equal(process.getgid(),986);assert.match(fs.readFileSync('/proc/self/status','utf8'),/^CapEff:\s+0+$/m);
const credentials=stockCredentialDirectory(process.env.CREDENTIALS_DIRECTORY);validateStockCredential(fs.lstatSync(credentials+'/stock-approval'));
for(const name of ['sponsor-key','mint-key']){if(action==='issue'){assert.match(fs.readFileSync(credentials+'/'+name,'utf8'),/^SYNTHETIC_/);validateStockCredential(fs.lstatSync(credentials+'/'+name));}else assert.throws(()=>fs.readFileSync(credentials+'/'+name));}
const old=JSON.parse(process.env.STOCK_OLD_ROOTS??'[]');
for(const p of ['/etc/sac006/stock-marker','/var/lib/sac006/stock-marker','/opt/capture402/stock-marker','/opt/svm-auth-capture/stock-marker','/etc/capture402-dev/stock-marker','/var/lib/capture402-dev/stock-marker','/opt/capture402-dev/stock-marker','/home/capture402-dev/stock-marker','/etc/capture402-e2e/keys/sponsor.json','/etc/capture402-e2e/keys/mint.json','/etc/capture402-e2e/keys/merchant.json','/etc/capture402-e2e/facilitator.env','/etc/capture402-e2e/restaurant.env'])assert.throws(()=>fs.readFileSync(p));
for(const p of ['/tmp/stock-write','/var/tmp/stock-write','/etc/stock-write',new URL('./integration/operators/faucet-stock.ts',import.meta.url)])assert.throws(()=>fs.writeFileSync(p,'forbidden'));
assert.throws(()=>process.setuid(0));assert.equal((await dns.lookup('api.devnet.solana.com')).address,'1.1.1.1');
function connection(options){return new Promise((resolve,reject)=>{const socket=net.createConnection(options);socket.setTimeout(1500,()=>socket.destroy(new Error('timeout')));socket.once('connect',()=>{socket.destroy();resolve();});socket.once('error',reject);});}
await connection({host:'1.1.1.1',port:19443});await assert.rejects(connection({host:'127.0.0.1',port:19443}));await assert.rejects(connection({host:'1.0.0.1',port:19443}));await assert.rejects(connection({path:'/run/dbus/system_bus_socket'}));
await assert.rejects(new Promise((resolve,reject)=>{const server=net.createServer();server.once('error',reject);server.listen(19444,'0.0.0.0',()=>{server.close();resolve();});}));
const budget=new CampaignBudget(b,JSON.parse(fs.readFileSync(b+'/policy.json','utf8'))),admission=new AdmissionJournal(a,'relay-attempts',600);
if(action==='issue'){budget.reserve('synthetic-stock-probe','sponsorship','b'.repeat(64),{fees:10000n,rent:0n,browserAllocation:0n});admission.reserve();}
assert.equal(fs.statSync(b+'/state.json').uid,989);assert.equal(fs.statSync(a+'/state.json').uid,989);assert.equal(fs.statSync(b+'/state.json').mode&511,384);
fs.writeFileSync(s+'/probe-'+action,'SYNTHETIC_BOUNDARIES_PASS',{mode:384});console.log('STOCK_EFFECTIVE_BOUNDARIES_PASS '+action);
"""
write(root/'stock-probe.mjs',probe,0o444)
source=(root/'ops/faucet-stock-compartment.sh').read_text()
needle='"$snapshot/node/bin/node" --experimental-strip-types "$snapshot/integration/operators/faucet-stock-operator.ts" "$1" --profile e2e'
require(needle in source)
write(root/'ops/stock-probe.sh',source.replace(needle,'"$snapshot/node/bin/node" --experimental-strip-types "$snapshot/stock-probe.mjs" "$1"'),0o555)
manifest=json.loads((root/'snapshot-manifest.json').read_text())
for name in ['stock-probe.mjs','ops/stock-probe.sh']:manifest['entries'][name]={'sha256':digest(root/name),'mode':(root/name).stat().st_mode&511}
write(root/'snapshot-manifest.json',json.dumps(manifest,sort_keys=True),0o444)
plan.update(snapshotPath=str(root),snapshotManifestSha256=digest(root/'snapshot-manifest.json'),networkSha256=digest(private/'p2-network.json'),hostsSha256=digest(private/'p2-hosts'),actions={'quote':'SYNTHETIC_QUOTE_ONLY'})
def approval():write(private/'faucet-stock-approved.json',json.dumps(plan))
approval();wrapper=root/'ops/stock-probe.sh'
check('complete authenticated Node/source closure and native original custody before credentials',lambda:run(['python3','-I','-B',str(root/'ops/faucet-stock-verify.py'),str(root),'quote']))
check('quote receives no signer; actual UID/caps/native flock/ownership, IP allow/deny, DNS, hidden secrets and write/service/bind bounds',lambda:require('STOCK_EFFECTIVE_BOUNDARIES_PASS' in run([str(wrapper),'quote','--profile','e2e']).stdout))
(stock/'probe-quote').unlink()
check('quote-only approval cannot deliver issuance credentials',lambda:require(run([str(wrapper),'issue','--profile','e2e'],ok=False).returncode!=0 and not any(stock.iterdir())))
plan['actions']['issue']='SYNTHETIC_PROBE_ONLY';approval();run(['systemctl','start',names[0]])
check('live E2E writer blocks mint credentials before any stock probe',lambda:require(run([str(wrapper),'issue','--profile','e2e'],ok=False).returncode!=0 and not any(stock.iterdir())))
run(['systemctl','stop',names[0]])
check('stopped-writer issuance delivers scoped credentials and preserves replaced native journal UID/mode/inodes',lambda:require('STOCK_EFFECTIVE_BOUNDARIES_PASS issue' in run([str(wrapper),'issue','--profile','e2e']).stdout))
plan['actions']['observe']='SYNTHETIC_OBSERVE_ONLY';approval()
check('observation receives no signer credentials after retained stock probe',lambda:require('STOCK_EFFECTIVE_BOUNDARIES_PASS observe' in run([str(wrapper),'observe','--profile','e2e']).stdout))
check('retained partial stock blocks any further credential delivery',lambda:require(run([str(wrapper),'issue','--profile','e2e'],ok=False).returncode!=0))
original=(root/'integration/operators/faucet-stock.ts').read_bytes();(root/'integration/operators/faucet-stock.ts').write_bytes(original+b'\n// SYNTHETIC_TAMPER\n')
check('changed transitive operator source refused before Node imports',lambda:require(run([str(wrapper),'observe','--profile','e2e'],ok=False).returncode!=0));(root/'integration/operators/faucet-stock.ts').write_bytes(original)
original=(private/'p2-hosts').read_text();(private/'p2-hosts').write_text('1.0.0.1 api.devnet.solana.com\n')
check('changed approved DNS refused before Node imports',lambda:require(run([str(wrapper),'observe','--profile','e2e'],ok=False).returncode!=0));(private/'p2-hosts').write_text(original)
server.shutdown()
output={'scope':'DISPOSABLE_SYNTHETIC_EXACT_WRAPPER_PROPERTIES_FINAL_EXECUTABLE_SUBSTITUTED_ONLY','sourceRevision':manifest['sourceRevision'],
    'wrapperSha256':digest(root/'ops/faucet-stock-compartment.sh'),'verifierSha256':digest(root/'ops/faucet-stock-verify.py'),
    'nodeSha256':digest(root/'node/bin/node'),'systemd':run(['systemctl','--version']).stdout.splitlines()[0],
    'tests':results,'counts':{'PASS':len(results),'FAIL':0},'liveStockOrIngress':'NOT RUN'}
write('/root/stock-linux-result.json',json.dumps(output,indent=2)+'\n')
print(json.dumps(output),flush=True)
