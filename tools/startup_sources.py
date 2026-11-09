"""Owned generated translation units, exact source seals and stable cache paths."""
import hashlib
import json
import re
from pathlib import Path
from input_formats import require


def write_sources(folder,sources):
    records=[]
    for name,source in sorted(sources.items()):
        require(re.fullmatch(r'(?:startup|lift_[0-9a-f]+)\.c',name),'invalid generated unit name')
        data=source.encode('utf-8')
        (folder/name).write_bytes(data)
        records.append(dict(path=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
    manifest=dict(format='oot-startup-sources',schema_version=1,files=records)
    (folder/'sources.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    return manifest


def cached_sources(bundle,cache):
    manifest_path=bundle/'sources.json'
    if not manifest_path.exists():return [bundle/'startup.c'],False
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    require(manifest.get('format')=='oot-startup-sources' and manifest.get('schema_version')==1,'invalid source manifest')
    records=manifest.get('files',[])
    require(0<len(records)<=4096 and len({r['path'] for r in records})==len(records) and
            any(r['path']=='startup.c' for r in records),'invalid source unit set')
    verified=[]
    for record in records:
        name=record['path']
        require(re.fullmatch(r'(?:startup|lift_[0-9a-f]+)\.c',name),'source path escapes bundle')
        source=bundle/name
        require(source.resolve().is_relative_to(bundle.resolve()),'source link escapes bundle')
        data=source.read_bytes()
        require(len(data)==record['bytes'] and hashlib.sha256(data).hexdigest()==record['sha256'],'generated source checksum mismatch')
        verified.append((name,data))
    target=cache/'sources';target.mkdir(parents=True,exist_ok=True)
    result=[]
    for name,data in verified:
        path=target/name
        require(path.resolve().is_relative_to(target.resolve()),'cached source escapes cache')
        if not path.exists() or path.read_bytes()!=data:path.write_bytes(data)
        result.append(path.resolve())
    return result,True
