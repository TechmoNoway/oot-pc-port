"""Fetch only the pinned standalone compiler dependency, preserving its notices."""
import argparse,hashlib,json,os,stat,urllib.request,zipfile
from pathlib import Path,PurePosixPath
from input_formats import require
ROOT=Path(__file__).resolve().parents[1]

def fetch(destination,lock_path=ROOT/'config/dependencies/shader-compiler.json'):
    destination=Path(destination).resolve()
    require(destination.is_relative_to(ROOT/'toolchain')and not destination.is_symlink(),'shader dependency must stay under toolchain/')
    lock=json.loads(Path(lock_path).read_text());commit=lock['commit']
    require(lock['repository']in('https://github.com/t0masz407/Hookshot','https://github.com/KhronosGroup/SPIRV-Headers')and len(commit)==40 and
        all(c in'0123456789abcdef'for c in commit),'invalid pinned shader source')
    records=lock['files'];require(0<len(records)<=2048,'invalid compiler source census');seen=set()
    for r in records:
        p=PurePosixPath(r['path'])
        require(p.parts and p.as_posix()==r['path'] and not p.is_absolute()and'..'not in p.parts and '\\'not in r['path'] and
            all(':'not in part and part.rstrip(' .')==part for part in p.parts) and
            r['path'].casefold()not in seen and type(r['bytes'])is int and 0<=r['bytes']<=8*1024*1024 and
            len(r['git_sha1'])==40 and all(c in'0123456789abcdef'for c in r['git_sha1']),
            'invalid compiler source path/size')
        seen.add(r['path'].casefold())
    require('license'in seen,'compiler source lock omits its root license')
    def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    needed=[]
    for r in records:
        target=destination/r['path'];require(target.resolve().is_relative_to(destination),'compiler source escapes destination')
        if not target.is_file()or target.stat().st_size!=r['bytes']or blob(target.read_bytes())!=r['git_sha1']:needed.append(r)
    destination.mkdir(parents=True,exist_ok=True)
    repo=lock['repository'].removeprefix('https://github.com/')
    archive=destination.parent/(repo.split('/')[-1]+'-'+commit+'.zip')
    if needed:
        if not archive.exists():
            temporary=archive.with_suffix('.zip.part')
            request=urllib.request.Request('https://codeload.github.com/'+repo+'/zip/'+commit,headers={'User-Agent':'oot-pc-port-dependency-fetch'})
            with urllib.request.urlopen(request,timeout=90)as source,temporary.open('wb')as out:
                size=0
                while data:=source.read(1024*1024):
                    size+=len(data);require(size<=128*1024*1024,'compiler source archive exceeds limit');out.write(data)
            os.replace(temporary,archive)
        with zipfile.ZipFile(archive)as source:
            roots={n.split('/')[0]for n in source.namelist()};require(len(roots)==1,'compiler archive has multiple roots')
            prefix=next(iter(roots))+'/'
            for r in needed:
                info=source.getinfo(prefix+r['path'])
                require(info.file_size==r['bytes']and not stat.S_ISLNK(info.external_attr>>16),'compiler source size/type differs')
                raw=source.read(info);require(blob(raw)==r['git_sha1'],'compiler source Git object differs: '+r['path'])
                target=destination/r['path'];target.parent.mkdir(parents=True,exist_ok=True)
                import tempfile
                with tempfile.NamedTemporaryFile(dir=target.parent,prefix=target.name+'.',suffix='.part',delete=False)as out:
                    temporary=Path(out.name);out.write(raw)
                os.replace(temporary,target)
    manifest=dict(repository=lock['repository'],commit=commit,scope=lock.get('scope','Standalone compiler headers and notices only'),files=[])
    for r in records:
        raw=(destination/r['path']).read_bytes();require(len(raw)==r['bytes']and blob(raw)==r['git_sha1'],'compiler dependency changed after fetch')
        manifest['files'].append(dict(r,sha256=hashlib.sha256(raw).hexdigest()))
    path=destination.parent/(destination.name+'-manifest.json');path.write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'toolchain/shader-compiler/vendor')
    p.add_argument('--lock',type=Path,default=ROOT/'config/dependencies/shader-compiler.json')
    a=p.parse_args();r=fetch(a.output,a.lock);print('Verified',len(r['files']),'compiler dependency files at',r['commit'])
