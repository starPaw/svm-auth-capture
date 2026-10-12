#!/usr/bin/env python3
"""Prepare an uninstalled P2 snapshot from an exact Git revision and authenticated B1 archives."""
import gzip,hashlib,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path
NODE_ARCHIVE='5f4ddab610c1ab2016b3c227cebdbf6d9495161487e4739c7b90090595f465f7'
DEPS_ARCHIVE='14bcc27a87b5c3a74b69952b373c2a15eb268e9d0c471c0958632fff673069f2'
INVENTORY='b0ac624226c71ddf687f21eb0743b62f23c019728da67d3dbfe042132c5fc2f9'
NODE_BINARY='23a5637c2470fde09fcc1acc77c1b92e04e3d7e3e6e80ff7df6f5831958d1477'
def digest(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def unpack(t,root):
 root=Path(root)
 for m in t.getmembers():
  p=root/m.name
  if m.name.startswith('/') or '..' in Path(m.name).parts or not (m.isfile() or m.isdir() or m.issym()):raise RuntimeError('unsafe archive entry')
  if m.issym() and (os.path.isabs(m.linkname) or not (p.parent/m.linkname).resolve().is_relative_to(root.resolve())):raise RuntimeError('escaping archive link')
 for m in t.getmembers():
  p=root/m.name
  if m.isdir():p.mkdir(parents=True,exist_ok=True)
  elif m.issym():p.parent.mkdir(parents=True,exist_ok=True);p.symlink_to(m.linkname)
  else:
   p.parent.mkdir(parents=True,exist_ok=True)
   with t.extractfile(m) as src,p.open('xb') as dst:shutil.copyfileobj(src,dst)
   p.chmod(0o755 if m.mode&0o111 else 0o644)

def main():
 if len(sys.argv)!=7:sys.exit('expected: repo revision node.tar.xz installed-deps.tar.gz installed-inventory.json new-output-directory')
 repo,ref,node,deps,inventory,out=sys.argv[1:];root=Path(out)
 sha=subprocess.check_output(['git','-C',repo,'rev-parse',ref+'^{commit}'],text=True).strip()
 if len(sha)!=40:raise RuntimeError('exact commit required')
 for p,expected in [(node,NODE_ARCHIVE),(deps,DEPS_ARCHIVE),(inventory,INVENTORY)]:
  if digest(p)!=expected:raise RuntimeError('authenticated B1 archive/inventory mismatch')
 root.mkdir(mode=0o700)
 paths=['integration/src','integration/evidence','integration/package.json','integration/package-lock.json','ops/p2-compartment.sh','ops/p2-verify.py','ops/p2-operator-parent.conf']
 archive=subprocess.check_output(['git','-C',repo,'archive',sha,*paths])
 with tarfile.open(fileobj=io.BytesIO(archive)) as t:unpack(t,root)
 with tarfile.open(deps) as t:unpack(t,root/'integration')
 node_tmp=root/'node-stage';node_tmp.mkdir()
 with tarfile.open(node) as t:unpack(t,node_tmp)
 (node_tmp/'node-v24.20.0-linux-arm64').rename(root/'node');node_tmp.rmdir()
 if digest(root/'node/bin/node')!=NODE_BINARY:raise RuntimeError('interpreter mismatch')
 expected={e['path'].removeprefix('integration/'):e for e in json.loads(Path(inventory).read_text())['entries'] if e['path'].startswith('integration/node_modules/') and e['kind']=='file'}
 actual={str(p.relative_to(root/'integration')):p for p in (root/'integration/node_modules').rglob('*') if p.is_file() and not p.is_symlink()}
 if set(expected)!=set(actual) or any(digest(actual[n])!=e['sha256'] for n,e in expected.items()):raise RuntimeError('accepted dependency bytes mismatch')
 entries={}
 for p in sorted(root.rglob('*')):
  if p.is_symlink():entries[str(p.relative_to(root))]={'link':os.readlink(p)}
  elif p.is_file():
   mode=0o555 if p.stat().st_mode&0o111 else 0o444;p.chmod(mode);entries[str(p.relative_to(root))]={'sha256':digest(p),'mode':mode}
  elif p.is_dir():p.chmod(0o555)
 manifest={'schema':1,'sourceRevision':sha,'nodeArchiveSha256':NODE_ARCHIVE,'dependencyArchiveSha256':DEPS_ARCHIVE,'acceptedInventorySha256':INVENTORY,'dependencyFiles':len(expected),'entries':entries}
 (root/'snapshot-manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n');(root/'snapshot-manifest.json').chmod(0o444);root.chmod(0o555)
 # Archive uses root ownership and normalized time; no live installation is performed.
 bundle=root.parent/(root.name+'.tar.gz')
 with bundle.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w') as t:
  for p in [root,*sorted(root.rglob('*'))]:
   info=t.gettarinfo(str(p),arcname='.' if p==root else str(p.relative_to(root)));info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=0
   if info.isfile():
    with p.open('rb') as f:t.addfile(info,f)
   else:t.addfile(info)
 print(json.dumps({'status':'PREPARED_NOT_INSTALLED','sourceRevision':sha,'snapshotManifestSha256':digest(root/'snapshot-manifest.json'),'bundleSha256':digest(bundle),'bundlePath':str(bundle),'entries':len(entries),'dependencyFiles':len(expected)},indent=2))
if __name__=='__main__':main()
