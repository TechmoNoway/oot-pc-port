"""Independent synthetic NUP directories, source binding and streamed payloads."""
import hashlib,io,json,struct,sys,tempfile,unittest
from pathlib import Path
from compression import zstd
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from input_formats import InputError,NupCatalog
from prepare_exefs import prepare as prepare_exefs
from prepare_romfs import prepare,copy_payload,HEADER,RECORD
from test_arm64_analysis import synthetic_module
from test_input_inspection import make_npdm

PROGRAM_ID=0x123456789abcdef0
ASSETS=(('raw.bin',b'raw\0original bytes',False),('dir/data.bin',b'compressed\0bytes'*10000,True),('dir/empty.bin',b'',False))

def make_romfs_nup(assets=ASSETS,empty_dirs=('vacant',)):
    directories=[['',[]],['exefs',[]],['romfs',[]]];directories[0][1]=[('d',1),('d',2)]
    paths={():2};files=[('main',synthetic_module(),False),('main.npdm',bytes(make_npdm()),False)]
    directories[1][1]=[('f',0),('f',1)]
    def directory(parts):
        for number in range(1,len(parts)+1):
            key=tuple(parts[:number])
            if key not in paths:
                parent=paths[key[:-1]];paths[key]=len(directories);directories[parent][1].append(('d',len(directories)))
                directories.append([key[-1],[]])
        return paths[tuple(parts)]
    for name in empty_dirs:directory(name.split('/'))
    for name,data,compressed in assets:
        parts=name.split('/');parent=directory(parts[:-1]);directories[parent][1].append(('f',len(files)))
        files.append((parts[-1],data,compressed))
    strings=bytearray();dir_names=[];file_names=[]
    for name,_ in directories:
        encoded=name.encode();dir_names.append((len(strings),len(encoded)));strings+=encoded
    for name,_,_ in files:
        encoded=name.encode();file_names.append((len(strings),len(encoded)));strings+=encoded
    child_count=sum(len(children)for _,children in directories)
    string_at=48+64+len(directories)*24+len(files)*80+child_count*4
    blob=(128+string_at+len(strings)+15)&~15;payload=bytearray();records=bytearray()
    for n,(_,data,compressed) in enumerate(files):
        payload+=bytes((-len(payload))%16);stored=zstd.compress(data) if compressed else data
        records+=struct.pack('<IIQQQ32sBBH12s',*file_names[n],len(data),blob+len(payload),len(stored),hashlib.sha256(data).digest(),int(compressed),0,0,bytes(12))
        payload+=stored
    toc=bytearray(struct.pack('<IIQQQQQ',0x01434f54,1,len(directories),len(files),string_at,len(strings),0))
    package=struct.pack('<QIIIIBBHIQI',PROGRAM_ID,0,1,2,1,1,1,0,0,0,0);toc+=package+bytes(64-len(package))
    children=[]
    for n,(_,entries) in enumerate(directories):
        toc+=struct.pack('<IIIIQ',*dir_names[n],len(children),len(entries),0)
        children.extend(index if kind=='d' else len(directories)+index for kind,index in entries)
    toc+=records+struct.pack('<'+'I'*len(children),*children)+strings
    header=bytearray(128);header[:4]=b'NUP\1'
    struct.pack_into('<HHQQ32sQQII',header,4,128,1,128,len(toc),hashlib.sha256(toc).digest(),blob,blob+len(payload),1,0)
    return header+toc+bytes(blob-128-len(toc))+payload

def fixture(root,assets=ASSETS,empty_dirs=('vacant',)):
    source=root/'source.nup';source.write_bytes(make_romfs_nup(assets,empty_dirs))
    prepared=root/'exefs';prepare_exefs(source,prepared)
    return source,prepared

def index_entries(path):
    raw=path.read_bytes();fields=HEADER.unpack_from(raw)
    source_len,cache_len=fields[10:12];count=fields[7]
    table=HEADER.size+source_len+cache_len;names=table+count*64;entries={}
    for n in range(count):
        offset,length,kind,size,data,digest=RECORD.unpack_from(raw,table+n*64)
        entries[raw[names+offset:names+offset+length].decode()]=(kind,size,data,digest)
    return fields,entries

class RomFsPreparationTests(unittest.TestCase):
    def test_executable_asset_identity_is_bound_to_the_original_exefs_catalog(self):
        from build_startup import validated_romfs_input
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);source,prepared=fixture(root);prepare(prepared,root/'romfs')
            index=root/'romfs/romfs.index';report=validated_romfs_input(prepared,index)
            self.assertEqual(report['index_sha256'],hashlib.sha256(index.read_bytes()).hexdigest())
            path=root/'romfs/manifest.json';original=path.read_bytes()
            for field,value in (('source',str(root/'other.nup')),('catalog_sha256','11'*32),
                ('source_header_sha256','22'*32),('program_id','0000000000000001'),
                ('payload_hashes_verified',False),('exefs_catalog_matches_prepared',False)):
                changed=json.loads(original);changed[field]=value;path.write_text(json.dumps(changed))
                with self.subTest(field=field),self.assertRaises(InputError):validated_romfs_input(prepared,index)
            path.write_bytes(original);data=bytearray(index.read_bytes());data[-1]^=1;index.write_bytes(data)
            with self.assertRaises(InputError):validated_romfs_input(prepared,index)

    def test_verified_raw_and_zstd_views_include_empty_directories_without_copying_raw(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);source,prepared=fixture(root);before=source.read_bytes()
            result=prepare(prepared,root/'romfs');fields,entries=index_entries(root/'romfs/romfs.index')
            self.assertEqual(result['files'],3);self.assertEqual(result['directories'],2)
            self.assertTrue(result['payload_hashes_verified']);self.assertFalse(result['guest_code_executed'])
            self.assertEqual(fields[4],PROGRAM_ID);self.assertEqual(fields[7],5)
            self.assertEqual(entries['vacant'],(2,0,0,bytes(32)))
            self.assertEqual(source.read_bytes(),before)
            for name,data,_ in ASSETS:
                kind,size,offset,digest=entries[name]
                blob=(root/'romfs/romfs.data').read_bytes() if kind else before
                self.assertEqual(blob[offset:offset+size],data);self.assertEqual(digest,hashlib.sha256(data).digest())
            self.assertEqual(result['index_sha256'],hashlib.sha256((root/'romfs/romfs.index').read_bytes()).hexdigest())
    def test_payload_corruption_source_binding_duplicates_and_existing_output_reject(self):
        for mutation in ('payload','binding','duplicate','traversal','exists'):
            with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
                root=Path(tmp);assets=ASSETS if mutation not in ('duplicate','traversal') else (
                    (('same',b'a',False),('same',b'b',False)) if mutation=='duplicate' else (('../outside',b'x',False),))
                source,prepared=fixture(root,assets)
                if mutation=='payload':
                    c=NupCatalog(source);_,record=next(c.files_in(c.packages[0]['romfs_directory']))
                    raw=bytearray(source.read_bytes());raw[record[1]]^=1;source.write_bytes(raw)
                if mutation=='binding':
                    p=prepared/'manifest.json';m=json.loads(p.read_text());m['files'][0]['source_sha256']='00'*32;p.write_text(json.dumps(m))
                if mutation=='exists':(root/'romfs').mkdir();(root/'romfs/keep').write_bytes(b'keep')
                with self.subTest(mutation=mutation),self.assertRaises(InputError):prepare(prepared,root/'romfs')
                if mutation=='exists':self.assertEqual((root/'romfs/keep').read_bytes(),b'keep')
                else:self.assertFalse((root/'romfs').exists())
    def test_stream_bounds_truncated_frames_hashes_and_trailing_data_reject(self):
        data=b'bounded stream'*10000;compressed=zstd.compress(data)
        for payload,size,digest in ((compressed,len(data)-1,hashlib.sha256(data).digest()),
            (compressed[:-1],len(data),hashlib.sha256(data).digest()),(compressed+b'extra',len(data),hashlib.sha256(data).digest()),
            (compressed,len(data),bytes(32))):
            target=io.BytesIO()
            with self.assertRaises(InputError):copy_payload(io.BytesIO(payload),(size,0,len(payload),digest,1),target)
