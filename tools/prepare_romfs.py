"""Verify NUP RomFS content and prepare a private read-only native index.

Raw bytes remain in the original NUP. Only zstd entries need a decoded cache.
No guest code, filesystem service or original SDK object is executed/created.
"""
import argparse,hashlib,json,os,shutil,struct,tempfile,time
from pathlib import Path
from input_formats import InputError,NupCatalog,inspect_npdm,require
from link_exefs import build_destination,load_prepared

HEADER=struct.Struct('<8sIIQQQQIIQII32s32sII16s')
RECORD=struct.Struct('<QIIQQ32s')
MAGIC=b'OOTRFS1\0'
PACK_MAGIC=b'OOTRFSD1'
MAX_FILES=1000000
MAX_NAME_BYTES=128*1024*1024
MAX_FILE_BYTES=4*1024**3
MAX_TOTAL_BYTES=128*1024**3
CHUNK=1024*1024

def path_bytes(parts):
    require(parts and all(part and part not in ('.','..') and not any(c in part for c in '\\/:\0') for part in parts),
            'invalid virtual RomFS path')
    name='/'.join(parts).encode('utf-8')
    require(len(name)<=4096,'RomFS path exceeds its finite native limit')
    return name

def directory_names(catalog,root):
    pending=[(root,())];seen=set();names=set()
    while pending:
        index,parts=pending.pop()
        require(index<catalog.directory_count and index not in seen,'invalid RomFS directory graph')
        seen.add(index)
        if parts:
            name=path_bytes(parts);require(name not in names,'duplicate RomFS directory path');names.add(name)
        _,_,first,count,_=struct.unpack_from('<IIIIQ',catalog.toc,catalog.directory_offset+index*24)
        require(0<=first<=catalog.child_count and count<=catalog.child_count-first,'RomFS directory child table exceeds catalog')
        for slot in range(first,first+count):
            child=struct.unpack_from('<I',catalog.toc,catalog.child_offset+slot*4)[0]
            if child<catalog.directory_count:
                offset,size=struct.unpack_from('<II',catalog.toc,catalog.directory_offset+child*24)
                pending.append((child,parts+(catalog.name(offset,size),)))
    return names

def copy_payload(source,record,cache=None):
    size,offset,stored,expected,codec=record
    require(0<=size<=MAX_FILE_BYTES and 0<=stored<=MAX_FILE_BYTES,'RomFS file exceeds size bound')
    source.seek(offset);digest=hashlib.sha256();produced=0
    def consume(data):
        nonlocal produced
        produced+=len(data);require(produced<=size,'RomFS decompression exceeds declared output size')
        digest.update(data)
        if cache is not None:cache.write(data)
    if codec==0:
        require(size==stored,'raw RomFS extent size differs')
        left=stored
        while left:
            block=source.read(min(CHUNK,left));require(block,'truncated raw RomFS content')
            left-=len(block);consume(block)
    else:
        require(codec==1,'unsupported RomFS compression')
        try:
            from compression.zstd import ZstdDecompressor,DecompressionParameter,ZstdError
        except ImportError as error:raise InputError('streaming RomFS preparation requires Python 3.14 zstd') from error
        decoder=ZstdDecompressor(options={DecompressionParameter.window_log_max:27});left=stored
        try:
            while True:
                if decoder.needs_input:
                    require(left>0,'truncated compressed RomFS frame')
                    block=source.read(min(CHUNK,left));require(block,'truncated compressed RomFS content');left-=len(block)
                else:block=b''
                consume(decoder.decompress(block,max_length=min(CHUNK,size-produced+1)))
                if decoder.eof:
                    require(not decoder.unused_data and left==0,'RomFS compressed entry has trailing frames or bytes')
                    break
        except ZstdError as error:raise InputError(f'RomFS zstd decoding failed: {error}') from error
    require(produced==size and digest.digest()==expected,'RomFS payload size/SHA-256 mismatch')

def prepare(prepared,output):
    started=time.perf_counter();output=build_destination(Path(output));prepared=Path(prepared).resolve()
    require(not output.exists(),'choose a fresh RomFS output directory')
    require(not output.is_relative_to(prepared) and not prepared.is_relative_to(output),'RomFS output overlaps prepared modules')
    manifest=json.loads((prepared/'manifest.json').read_text(encoding='utf-8'))
    require(manifest.get('format')=='prepared-exefs' and manifest.get('schema_version')==1,'RomFS needs verified prepared ExeFS')
    load_prepared(prepared) # Recheck the supplied normalized input and its seals.
    source_path=Path(manifest['source']['path']).resolve()
    require(not source_path.is_relative_to(output),'RomFS output contains its source')
    catalog=NupCatalog(source_path)
    selected=manifest['source']['package']['index']
    require(0<=selected<len(catalog.packages) and catalog.packages[selected]==manifest['source']['package'],
            'RomFS source package differs from prepared metadata')
    package=catalog.packages[selected]
    require(package['romfs_directory']!=0xffffffff,'selected package has no RomFS directory')
    exefs={}
    for parts,record in catalog.files_in(package['exefs_directory']):
        name='/'.join(parts);require(name not in exefs,'duplicate ExeFS source path');exefs[name]=record[3].hex()
    require(exefs=={r['name']:r['source_sha256'] for r in manifest['files']},'RomFS catalog ExeFS hashes differ from prepared originals')
    npdm=(prepared/'main.npdm').read_bytes();npdm_record=next(r for r in manifest['files'] if r['name']=='main.npdm')
    require(hashlib.sha256(npdm).hexdigest()==npdm_record['sha256'],'prepared NPDM checksum differs')
    program_id=int(inspect_npdm(npdm)['program_id'],16)
    require(program_id==int(package['title_id'],16),'RomFS source title and program identity differ')
    directories=directory_names(catalog,package['romfs_directory'])
    records=[];seen=set(directories);total=cached=0;name_size=sum(map(len,directories))
    for parts,record in catalog.files_in(package['romfs_directory']):
        name=path_bytes(parts);require(name not in seen,'duplicate RomFS virtual path');seen.add(name)
        size,offset,stored,_,codec=record
        require(max(size,stored)<=MAX_FILE_BYTES,'RomFS file exceeds finite size limit')
        total+=size;cached+=size if codec else 0;name_size+=len(name)
        records.append((name,record))
        require(len(records)+len(directories)<=MAX_FILES and total<=MAX_TOTAL_BYTES and name_size<=MAX_NAME_BYTES,'RomFS index/output limits exceeded')
    output.parent.mkdir(parents=True,exist_ok=True)
    require(shutil.disk_usage(output.parent).free>=cached+name_size+len(records)*64+64*1024*1024,'insufficient free space for decoded RomFS cache')
    staging=Path(tempfile.mkdtemp(prefix='.romfs-',dir=output.parent))
    require(staging.resolve().is_relative_to(output.parent.resolve()),'RomFS staging escaped its owned parent')
    with source_path.open('rb') as source:
        source_header=source.read(128);source_header_hash=hashlib.sha256(source_header).digest()
        original_stat=os.fstat(source.fileno());resolved={}
        with (staging/'romfs.data').open('xb') as cache:
            cache.write(PACK_MAGIC+source_header_hash+struct.pack('<QQQ',catalog.file_size,program_id,0))
            for number,(name,record) in enumerate(sorted(records,key=lambda row:row[1][1])):
                size,offset,_,digest,codec=record
                if codec:
                    cache.write(bytes((-cache.tell())%16));position=cache.tell();copy_payload(source,record,cache)
                else:position=offset;copy_payload(source,record)
                resolved[name]=(codec,size,position,digest)
                if (number+1)%10000==0:print(f'Verified RomFS files: {number+1}/{len(records)}',flush=True)
            cache_size=cache.tell()
        final_stat=os.fstat(source.fileno())
        require((original_stat.st_size,original_stat.st_mtime_ns)==(final_stat.st_size,final_stat.st_mtime_ns),
                'NUP source changed during RomFS verification')
    source_name=str(source_path).encode('utf-8');cache_name=b'romfs.data'
    require(0<len(source_name)<=32768 and b'\0' not in source_name,'invalid original NUP path')
    names=bytearray();table=bytearray()
    resolved.update({name:(2,0,0,bytes(32)) for name in directories})
    for name in sorted(resolved):
        codec,size,position,digest=resolved[name]
        table+=RECORD.pack(len(names),len(name),codec,size,position,digest);names+=name
    body=source_name+cache_name+table+names
    header=HEADER.pack(MAGIC,1,HEADER.size,HEADER.size+len(body),program_id,catalog.file_size,cache_size,
        len(resolved),RECORD.size,len(names),len(source_name),len(cache_name),source_header_hash,hashlib.sha256(body).digest(),len(directories),1,bytes(16))
    index=header+body;(staging/'romfs.index').write_bytes(index)
    report=dict(format='oot-prepared-romfs',schema_version=1,program_id=f'{program_id:016x}',files=len(records),directories=len(directories),
        decoded_bytes=total,cached_bytes=cache_size,raw_payloads_retained_in_nup=True,
        payload_hashes_verified=True,exefs_catalog_matches_prepared=True,catalog_sha256=hashlib.sha256(catalog.toc).hexdigest(),
        source_header_sha256=source_header_hash.hex(),index_sha256=hashlib.sha256(index).hexdigest(),seconds=time.perf_counter()-started,
        guest_code_executed=False,original_sdk_objects_created=False,source=str(source_path))
    (staging/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    require(not output.exists(),'RomFS destination appeared during preparation');staging.rename(output)
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('prepared',type=Path);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args()
    try:print(json.dumps(prepare(a.prepared,a.output)));return 0
    except (InputError,OSError,ValueError,EOFError) as error:parser.exit(1,f'RomFS preparation failed: {error}\n')
if __name__=='__main__':raise SystemExit(main())
