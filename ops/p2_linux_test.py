#!/usr/bin/env python3
"""Synthetic P2 checks on a marked disposable VM ONLY. Never run on the VPS."""
import hashlib,json,os,shutil,socket,subprocess,sys,tarfile,threading,http.server
from pathlib import Path
if Path('/etc/capture402-p2-disposable').read_text().strip()!='DISPOSABLE_SYNTHETIC_P2_TEST_ONLY' or socket.gethostname()!='capture402-p2-disposable':sys.exit('disposable VM marker/hostname required')
S=Path('/opt/capture402-e2e/p2/test');D=Path('/etc/capture402-e2e');B=Path('/var/lib/capture402-e2e/facilitator/campaign-budget');SETUP=Path('/var/lib/capture402-e2e/setup');R=Path('/opt/capture402-e2e/releases/3ddb204d16f10cf6826a3fa4fd831275333a13f5');OUT=Path('/root/p2-results.json');tests=[]
def run(args,ok=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=120)
 if ok and p.returncode:raise RuntimeError(p.stderr[-1500:])
 return p

def digest(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,value,mode=0o600):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value);p.chmod(mode)
def check(name,fn):
 try:fn();tests.append({'name':name,'result':'PASS'})
 except Exception:tests.append({'name':name,'result':'FAIL'});save();raise
 save();print('PASS '+name,flush=True)
def require(v):
 if not v:raise RuntimeError('assertion failed')
def save():
 OUT.write_text(json.dumps({'scope':'DISPOSABLE_SYNTHETIC_ONLY_NOT_VPS', 'harnessSha256':digest(__file__),'wrapperSha256':digest(S/'ops/p2-compartment.sh') if S.exists() else None,'nodeSha256':digest(S/'node/bin/node') if (S/'node/bin/node').exists() else None,'systemd':run(['systemctl','--version']).stdout.splitlines()[0],'tests':tests,'counts':{'PASS':sum(t['result']=='PASS' for t in tests),'FAIL':sum(t['result']=='FAIL' for t in tests)}},indent=2)+'\n')
S.mkdir(parents=True);shutil.copytree('/root/p2-source/integration',S/'integration');shutil.copytree('/root/p2-source/ops',S/'ops')
# Archives were staged separately from authenticated B1 inputs; only this disposable harness extracts them.
with tarfile.open('/root/node.tar.xz') as t:t.extractall('/opt',filter='data')
shutil.copytree('/opt/node-v24.20.0-linux-arm64',S/'node')
with tarfile.open('/root/installed-deps.tar.gz') as t:t.extractall(S/'integration',filter='data')
# archive stores integration/node_modules (assert the known native Linux dependency exists).
require((S/'integration/node_modules/fs-ext/build/Release/fs_ext.node').exists())
R.mkdir(parents=True)
with tarfile.open('/root/release.tar') as t:t.extractall(R,filter='data')
for p in [D,D/'keys',B,SETUP]:p.mkdir(parents=True,exist_ok=True);p.chmod(0o700)
ids={'sponsor':'5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX','merchant':'CbSG1T25CHcKqPGgu5nrd2b62yVdXMp2GK6UhWYocA1t','payer':'Aka3W4dNW8rSqdmLBUPkTftSn69kBsqn2KMzy9n3fKXb','mint':'91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp'}
write(D/'identities.json',json.dumps(ids));write(D/'b1-complete.json',json.dumps({'release':R.name,'status':'OFFLINE_B1_VERIFIED_B2_B3_NOT_RUN','public_ids':ids}))
for name in ['sponsor','mint','merchant','payer']:write(D/f'keys/{name}.json','SYNTHETIC_SECRET_MARKER_NOT_A_KEY')
os.chown(D/'keys/sponsor.json',989,986)
for name in ['facilitator.env','restaurant.env']:write(D/name,'SYNTHETIC_CREDENTIAL')
old=['/etc/sac006','/var/lib/sac006','/opt/capture402','/opt/svm-auth-capture','/etc/capture402-dev','/var/lib/capture402-dev','/opt/capture402-dev','/home/capture402-dev']
for p in old:write(Path(p)/'marker','SYNTHETIC_OLD_SECRET')
write(D/'p2-network.json',json.dumps({'host':'api.devnet.solana.com','addresses':['1.1.1.1']}));write(D/'p2-hosts','1.1.1.1 api.devnet.solana.com\n')
# A globally shaped IP is routed to a VM-local fixture, never the public chain.
run(['ip','address','add','1.1.1.1/32','dev','lo'])
denied_server=http.server.ThreadingHTTPServer(('127.0.0.1',19443),http.server.SimpleHTTPRequestHandler);threading.Thread(target=denied_server.serve_forever,daemon=True).start()
server=http.server.ThreadingHTTPServer(('1.1.1.1',19443),http.server.SimpleHTTPRequestHandler);threading.Thread(target=server.serve_forever,daemon=True).start()
probe='''import os,socket,pathlib,json
S=pathlib.Path('/var/lib/capture402-e2e/setup');B=pathlib.Path('/var/lib/capture402-e2e/facilitator/campaign-budget')
for p in [S/'probe-write',B/'probe-write']:p.write_text('allowed')
for name in ['sponsor-key','mint-key']:assert (pathlib.Path(os.environ['CREDENTIALS_DIRECTORY'])/name).read_text().startswith('SYNTHETIC_')
for p in %s+['/etc/capture402-e2e/keys/merchant.json','/etc/capture402-e2e/keys/payer.json','/etc/capture402-e2e/facilitator.env','/etc/capture402-e2e/restaurant.env']:
 try:pathlib.Path(p).read_text();raise AssertionError('secret readable')
 except OSError:pass
for p in %s:
 try:pathlib.Path(p).write_text('forbidden');raise AssertionError('write allowed')
 except OSError:pass
assert socket.gethostbyname('api.devnet.solana.com')=='1.1.1.1'
socket.create_connection(('1.1.1.1',19443),timeout=2).close()
for ip in ['127.0.0.1','1.0.0.1']:
 try:socket.create_connection((ip,19443),timeout=1);raise AssertionError('unapproved address allowed')
 except OSError:pass
try:socket.socket(socket.AF_UNIX);raise AssertionError('service-control socket family allowed')
except OSError:pass
try:s=socket.socket();s.bind(('0.0.0.0',19444));raise AssertionError('ingress bind allowed')
except OSError:pass
status=pathlib.Path('/proc/self/status').read_text();assert 'CapEff:\\t0000000000000000' in status
print('P2_EFFECTIVE_BOUNDARIES_PASS')
'''%(repr([p+'/marker' for p in old]),repr([str(S/'integration/operators/e2e-provision.ts'),str(S/'node/bin/node'),str(R/'README.md'),'/tmp/p2-write','/etc/p2-write']))
write(S/'probe.py',probe,0o444)
# Every file and directory is sealed; preserve executable bits only.
for p in S.rglob('*'):
 if not p.is_symlink():p.chmod(0o555 if p.is_dir() or p.stat().st_mode&0o111 else 0o444)
S.chmod(0o555)
entries={}
for p in S.rglob('*'):
 if p.is_symlink():entries[str(p.relative_to(S))]={'link':os.readlink(p)}
 elif p.is_file():entries[str(p.relative_to(S))]={'sha256':digest(p),'mode':p.stat().st_mode&0o777}
write(S/'snapshot-manifest.json',json.dumps({'entries':entries},sort_keys=True),0o444)
approved={'applicationRelease':R.name,'campaignReference':'synthetic-p2','browser':'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74','spendLimit':'1000000000','assetsMaximumSpend':'15640160','snapshotPath':str(S),'snapshotManifestSha256':digest(S/'snapshot-manifest.json'),'networkSha256':digest(D/'p2-network.json'),'hostsSha256':digest(D/'p2-hosts'),'b1ReceiptSha256':digest(D/'b1-complete.json'),'identitiesSha256':digest(D/'identities.json'),'entrypointSha256':digest(S/'integration/operators/e2e-provision.ts'),'coreSha256':digest(S/'integration/operators/e2e-provisioning.ts'),'actions':{'init-budget':'synthetic','budget-status':'synthetic','assets':'synthetic-probe-only'}}
write(D/'provision-approved.json',json.dumps(approved))
wrapper=S/'ops/p2-compartment.sh'
check('complete sealed source/dependency/interpreter pre-import verification',lambda:run(['python3','-I','-B',str(S/'ops/p2-verify.py'),str(S)]))
check('explicit profile and funding ban',lambda:require(all(run([str(wrapper),*a],ok=False).returncode!=0 for a in [[],['fund','--profile','e2e'],['init-budget','--profile','dev']])))
# Use EXACT wrapper properties with only the last command substituted by this marked VM probe.
source=wrapper.read_text();needle='"$snapshot/node/bin/node" --experimental-strip-types "$snapshot/integration/operators/e2e-provision.ts" "$1" --profile e2e'
require(needle in source)
probe_wrapper=S/'ops/p2-probe.sh';write(probe_wrapper,source.replace(needle,'/usr/bin/python3 -I -B "$snapshot/probe.py"'),0o555)
# Test-only wrapper adds an entry to the fixture manifest; production source remains unchanged.
entries['ops/p2-probe.sh']={'sha256':digest(probe_wrapper),'mode':0o555};write(S/'snapshot-manifest.json',json.dumps({'entries':entries},sort_keys=True),0o444);approved['snapshotManifestSha256']=digest(S/'snapshot-manifest.json');write(D/'provision-approved.json',json.dumps(approved))
check('actual IP allow and deny, DNS pinning, custody and write bounds, capabilities, no ingress/service control',lambda:require('P2_EFFECTIVE_BOUNDARIES_PASS' in run([str(probe_wrapper),'assets','--profile','e2e']).stdout))
saved=approved['actions'].pop('assets');write(D/'provision-approved.json',json.dumps(approved))
check('missing assets approval refuses before ephemeral credential delivery',lambda:require(run([str(probe_wrapper),'assets','--profile','e2e'],ok=False).returncode!=0))
approved['actions']['assets']=saved;write(D/'provision-approved.json',json.dumps(approved))
check('native Node CLI initialization in actual compartment (synthetic public metadata only)',lambda:run([str(wrapper),'init-budget','--profile','e2e']))
check('restart persistent state/native Linux flock in actual compartment',lambda:require('"available":"1000000000"' in run([str(wrapper),'budget-status','--profile','e2e']).stdout))
check('init intent prevents budget reset/reinitialization',lambda:require(run([str(wrapper),'init-budget','--profile','e2e'],ok=False).returncode!=0))
original=(S/'integration/src/campaign-budget.ts').read_bytes();(S/'integration/src/campaign-budget.ts').write_bytes(original+b'\n// tampered fixture\n')
check('changed transitive source denied before imports',lambda:require(run([str(wrapper),'budget-status','--profile','e2e'],ok=False).returncode!=0))
(S/'integration/src/campaign-budget.ts').write_bytes(original)
(D/'p2-hosts').write_text('1.0.0.1 api.devnet.solana.com\n')
check('changed hosts pin denied before imports',lambda:require(run([str(wrapper),'budget-status','--profile','e2e'],ok=False).returncode!=0))
(D/'p2-hosts').write_text('1.1.1.1 api.devnet.solana.com\n')
# An invalid mandatory namespace setup must fail before the probe writes.
for p in [SETUP/'probe-write',B/'probe-write']:p.unlink()
bad=source.replace(needle,'/usr/bin/python3 -I -B "$snapshot/probe.py"').replace(' --property=Type=exec',' --property=BindReadOnlyPaths=/p2-missing-required-source:/p2-test-target --property=Type=exec')
write(S/'ops/p2-probe.sh',bad,0o555);entries['ops/p2-probe.sh']['sha256']=digest(probe_wrapper);write(S/'snapshot-manifest.json',json.dumps({'entries':entries},sort_keys=True),0o444);approved['snapshotManifestSha256']=digest(S/'snapshot-manifest.json');write(D/'provision-approved.json',json.dumps(approved))
check('mandatory sandbox setup failure executes no probe',lambda:require(run([str(probe_wrapper),'assets','--profile','e2e'],ok=False).returncode!=0 and not (SETUP/'probe-write').exists()))
server.shutdown();denied_server.shutdown();print('P2 SYNTHETIC COMPLETE')
