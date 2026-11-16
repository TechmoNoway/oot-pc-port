"""Bounded file protocol for the isolated shader compiler (no renderer linkage)."""
import hashlib,json,os,struct,subprocess,tempfile
from pathlib import Path
from input_formats import require

ROOT=Path(__file__).resolve().parents[1]
HEADER=struct.Struct('<20I')
MAX_CODE=65536*16+128

def digest(data):return hashlib.sha256(data).hexdigest()

def adapter_identity():
    paths=[ROOT/'tools/shader_compiler/CMakeLists.txt',ROOT/'tools/shader_compiler/main.cpp',ROOT/'tools/shader_compiler/msvc_compat.h',
        ROOT/'config/dependencies/shader-compiler.json',ROOT/'config/dependencies/spirv-headers.json']
    return {p.relative_to(ROOT).as_posix():digest(p.read_bytes())for p in paths}

def encode_request(code,*,stage,capabilities=0,viewport=0,texture_bank=0,local_memory=0,
                   shared_memory=0,workgroup=(0,0,0),spirv_version=0x10000,
                   ssbo_alignment=16,descriptor_limit=16,constants=(),textures=()):
    """All environment answers are captured inputs. No implicit texture/cbuf answers."""
    code=bytes(code);constants=list(constants);textures=list(textures)
    require(type(stage)is int and stage in(0,1,2),'unsupported shader stage')
    prefix=0 if stage==2 else 128
    require(prefix+16<=len(code)<=MAX_CODE and (len(code)-prefix)%16==0,'invalid captured shader extent')
    require(len(workgroup)==3 and all(type(n)is int and 0<=n<=1024 for n in workgroup),'invalid shader workgroup')
    if stage==2:require(all(workgroup)and workgroup[0]*workgroup[1]*workgroup[2]<=1024,'invalid compute workgroup')
    require(type(capabilities)is int and 0<=capabilities<=7 and 0<=texture_bank<32,'invalid shader capabilities/bank')
    require(0<=local_memory<=64*1024*1024 and 0<=shared_memory<=1024*1024,'shader memory exceeds bounds')
    require(spirv_version in range(0x10000,0x10700,0x100) and type(ssbo_alignment)is int and
        0<ssbo_alignment<=65536 and not(ssbo_alignment&(ssbo_alignment-1)) and
        type(descriptor_limit)is int and 0<descriptor_limit<=65536,'invalid SPIR-V host limits')
    require(len(constants)<=65536 and len(textures)<=65536,'shader query census exceeds limit')
    seen=set();parts=[]
    for row in constants:
        require(len(row)==3 and all(type(n)is int and 0<=n<1<<32 for n in row),'invalid captured constant query')
        bank,offset,_=row
        require(bank<32 and offset%4==0 and (bank,offset)not in seen,'duplicate/unaligned captured constant query')
        seen.add((bank,offset));parts.append(struct.pack('<3I',*row))
    seen=set()
    for row in textures:
        require(len(row)==4 and all(type(n)is int and 0<=n<1<<32 for n in row),'invalid captured texture query')
        handle,kind,pixel,integer=row
        require(handle not in seen and kind<9 and pixel<=101 and integer<=1,'invalid/duplicate captured texture metadata')
        seen.add(handle);parts.append(struct.pack('<4I',*row))
    values=(0x53544f4f,1,HEADER.size,stage,len(code),len(constants),len(textures),capabilities,
        viewport,texture_bank,local_memory,shared_memory,*workgroup,spirv_version,ssbo_alignment,descriptor_limit,0,0)
    require(all(type(n)is int and 0<=n<1<<32 for n in values),'shader header contains invalid values')
    return HEADER.pack(*values)+b''.join(parts)+code

def inspect_spirv(data,stage):
    """Structural check only; this is not SPIRV-Tools semantic validation."""
    require(20<=len(data)<=32*1024*1024 and len(data)%4==0,'invalid SPIR-V size')
    words=struct.unpack('<'+str(len(data)//4)+'I',data)
    require(words[0]==0x07230203 and words[1]in range(0x10000,0x10700,0x100) and
        0<words[3]<=1<<24 and words[4]==0,'invalid SPIR-V header')
    at=5;models=[]
    while at<len(words):
        count=words[at]>>16;op=words[at]&0xffff
        require(count>0 and count<=len(words)-at,'invalid SPIR-V instruction length')
        if op==15:
            require(count>=4,'truncated SPIR-V entry point');models.append(words[at+1])
        at+=count
    require(models==[{0:0,1:4,2:5}[stage]],'SPIR-V entry point stage differs')
    return dict(words=len(words),version=words[1],bound=words[3],validation='structural-only')

def translate(tool,receipt,request,output):
    """Run one private job and publish a verified result without reusing old outputs."""
    tool=Path(tool).resolve();receipt=json.loads(Path(receipt).read_text())
    require(receipt.get('schema')==1 and receipt.get('adapter')==adapter_identity() and
        receipt.get('binary_sha256')==digest(tool.read_bytes()),'shader compiler identity differs; rebuild it')
    require(len(request)>=HEADER.size,'truncated shader request')
    h=HEADER.unpack_from(request);require(h[:3]==(0x53544f4f,1,80)and h[3]<=2,'invalid shader request protocol')
    output=Path(output).resolve();require(output.is_relative_to(ROOT/'build')and not output.exists(),'choose fresh private shader output')
    output.mkdir(parents=True)
    (output/'request.bin').write_bytes(request)
    env={k:v for k,v in os.environ.items()if not k.upper().startswith(('RX_','GPU_SHADER_','EDEN_'))}
    try:
        completed=subprocess.run([str(tool),str(output/'request.bin'),str(output/'module.spv'),str(output/'reflection.json')],
            cwd=ROOT,env=env,capture_output=True,timeout=120,check=False)
        (output/'compiler.stdout').write_bytes(completed.stdout);(output/'compiler.stderr').write_bytes(completed.stderr)
        require(completed.returncode==0,'external shader translation failed; see private compiler.stderr')
        data=(output/'module.spv').read_bytes();info=inspect_spirv(data,h[3])
        meta_path=output/'reflection.json';require(meta_path.stat().st_size<=4*1024*1024,'shader reflection exceeds limit')
        reflection=json.loads(meta_path.read_text());require(reflection.get('schema')==1 and
            reflection.get('stage')==h[3]and reflection.get('words')==info['words'],'shader reflection identity differs')
        result=dict(schema=1,status='translated',request_sha256=digest(request),binary_sha256=receipt['binary_sha256'],
            spirv_sha256=digest(data),reflection_sha256=digest(meta_path.read_bytes()),**info,game_frame_proven=False)
        (output/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result
    except Exception as error:
        (output/'failure.json').write_text(json.dumps(dict(status='failed',error=str(error)))+'\n');raise
