#!/usr/bin/env python3
"""Credential-path and pre-import continuation checks on the marked synthetic VM only."""
import hashlib,json,os,socket,subprocess,shutil
from pathlib import Path
assert Path('/etc/capture402-p2-disposable').read_text().strip()=='DISPOSABLE_SYNTHETIC_P2_TEST_ONLY'
assert socket.gethostname()=='capture402-p2-disposable'
assert os.geteuid()==0
SOURCE=Path('/root/p2-stop-source');S=Path('/opt/capture402-e2e/p2/credential-stop-fixture');D=Path('/etc/capture402-e2e');SETUP=Path('/var/lib/capture402-e2e/setup');B=Path('/var/lib/capture402-e2e/facilitator/campaign-budget')
for role in ['sponsor','mint']:assert (D/'keys'/f'{role}.json').read_text().startswith('SYNTHETIC_')
S.mkdir();(S/'ops').mkdir();(S/'node/bin').mkdir(parents=True)
def write(p,data,mode=0o600):p.write_text(data);p.chmod(mode)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args):return subprocess.run(args,capture_output=True,text=True,timeout=90)
def require(ok):
 if not ok:raise RuntimeError('synthetic pre-signer assertion failed')
for name in ['p2-verify.py','p2-compartment.sh']:shutil.copyfile(SOURCE/name,S/'ops'/name)
shutil.copyfile(SOURCE/'p2-presigner-stop.ts',S/'p2-presigner-stop.ts')
shutil.copyfile('/opt/capture402-e2e/p2/b2062584b488adfa3e34e43918fddaafd7e0dc37/node/bin/node',S/'node/bin/node');(S/'node/bin/node').chmod(0o555)
helper="""import {credentialDirectory} from './p2-presigner-stop.ts';import {readFileSync,writeFileSync,statSync} from 'node:fs';
const d=credentialDirectory(process.env.CREDENTIALS_DIRECTORY);if(!d.endsWith('.service'))throw Error('suffix');
for(const role of ['sponsor','mint']){const p=d+'/'+role+'-key';if((statSync(p).mode&0o777)!==0o400||!readFileSync(p,'utf8').startsWith('SYNTHETIC_'))throw Error('synthetic custody');}
if(!/^CapEff:\\s+0+$/m.test(readFileSync('/proc/self/status','utf8')))throw Error('capabilities');
writeFileSync('/var/lib/capture402-e2e/setup/synthetic-stop-probe-ran','SYNTHETIC_ONLY');console.log('NATIVE_SYSTEMD_CREDENTIAL_GUARD_PASS');
"""
write(S/'native-probe.mjs',helper)
wrapper=(S/'ops/p2-compartment.sh').read_text();needle='"$snapshot/node/bin/node" --experimental-strip-types "$snapshot/integration/operators/e2e-provision.ts" "$1" --profile e2e';assert needle in wrapper
wrapper=wrapper.replace('--property="WorkingDirectory=$snapshot/integration"','--property="WorkingDirectory=$snapshot"').replace(needle,'"$snapshot/node/bin/node" --experimental-strip-types "$snapshot/native-probe.mjs"')
write(S/'ops/p2-compartment.sh',wrapper,0o555)
entries={}
for p in S.rglob('*'):
 if p.is_file():p.chmod(0o555 if p.stat().st_mode&0o111 else 0o444);entries[str(p.relative_to(S))]={'mode':p.stat().st_mode&0o777,'sha256':digest(p)}
 elif p.is_dir():p.chmod(0o555)
write(S/'snapshot-manifest.json',json.dumps({'entries':entries}),0o444);S.chmod(0o555)
intent=SETUP/'assets-intent.json';require(not intent.exists());write(intent,json.dumps({'planHash':'a'*64}))
stop={'schema':1,'reason':'B206_SYSTEMD_SERVICE_SUFFIX_REJECTED_BEFORE_SDK_SIGNER','stoppedSourceRevision':'b2062584b488adfa3e34e43918fddaafd7e0dc37','stoppedEntrypointSha256':'2d4ac36d064410b834b7eecf13127c4c9818fcb19dcee4dc1a2716c5f13cf4f8','stoppedManifestSha256':'dda6fa6162d0ddd4199b38e023ec602f178c364715196510650ea78de5c39301','originalIntentSha256':digest(intent),'originalPlanHash':'a'*64,'observedCredentialDirectory':'/run/credentials/capture402-e2e-p2-57070b79-1663-4cff-b39b-12c5c765a625.service'}
write(D/'p2-presigner-stop.json',json.dumps(stop))
a={'snapshotPath':str(S),'snapshotManifestSha256':digest(S/'snapshot-manifest.json'),'networkSha256':digest(D/'p2-network.json'),'hostsSha256':digest(D/'p2-hosts'),'actions':{'continue-assets-presigner-stop':'SYNTHETIC_EXPLICIT_NEW_APPROVAL'},'preSignerStopSha256':digest(D/'p2-presigner-stop.json')}
write(D/'provision-approved.json',json.dumps(a));tests=[]
def check(name,ok):require(ok);tests.append({'name':name,'result':'PASS'})
def verify():return run(['/usr/bin/python3','-I','-B',str(S/'ops/p2-verify.py'),str(S),'continue-assets-presigner-stop'])
check('valid pinned stop pre-import verification',verify().returncode==0)
for key in ['reason','stoppedSourceRevision','originalIntentSha256','observedCredentialDirectory']:
 saved=stop[key];stop[key]='UNKNOWN';write(D/'p2-presigner-stop.json',json.dumps(stop));a['preSignerStopSha256']=digest(D/'p2-presigner-stop.json');write(D/'provision-approved.json',json.dumps(a));check('invalid '+key+' fails before credentials',verify().returncode!=0);stop[key]=saved
write(D/'p2-presigner-stop.json',json.dumps(stop));a['preSignerStopSha256']=digest(D/'p2-presigner-stop.json');write(D/'provision-approved.json',json.dumps(a))
for name in ['signed','broadcast','response','receipt','continuation-intent']:
 p=SETUP/('assets-'+name+'.json');p.symlink_to('/synthetic-missing-original');check('dangling '+name+' refuses before credentials',verify().returncode!=0);p.unlink()
state=(B/'state.json').read_text();modified=json.loads(state);modified['entries']['assets']={};write(B/'state.json',json.dumps(modified));check('existing assets budget entry refuses before credentials',verify().returncode!=0);write(B/'state.json',state)
saved=a['actions'].pop('continue-assets-presigner-stop');write(D/'provision-approved.json',json.dumps(a));check('old/missing continuation authorization refuses before credentials',verify().returncode!=0);a['actions']['continue-assets-presigner-stop']=saved;write(D/'provision-approved.json',json.dumps(a))
p=run([str(S/'ops/p2-compartment.sh'),'continue-assets-presigner-stop','--profile','e2e']);require(p.returncode==0);check('native Node guard accepts actual systemd .service credentials, synthetic only, zero capabilities','NATIVE_SYSTEMD_CREDENTIAL_GUARD_PASS' in p.stdout)
result={'scope':'DISPOSABLE_SYNTHETIC_GUARD_AND_PREIMPORT_ONLY_NOT_VPS_CONTINUATION','sourceHashes':{p.name:digest(p) for p in SOURCE.iterdir()},'tests':tests,'counts':{'PASS':len(tests),'FAIL':0},'economicOperations':0}
write(Path('/root/p2-stop-results.json'),json.dumps(result,indent=2)+'\n');print(json.dumps(result))
