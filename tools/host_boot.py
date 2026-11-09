"""Project-owned ARM64 boot scaffolding for a separately linked guest image."""
import hashlib,struct
from input_formats import require
from arm64_lifter import decode_instruction
from sdk_init_instructions import decode_sdk_init_instruction

class BootModule:
    name='hostboot';base=0x200000000
    ranges=((0,4096),(4096,4096),(4096,8192));bss_start=8192;bss_end=8192
    symbols=()
    def __init__(self,words):
        self.image=bytearray(8192)
        for n,word in enumerate(words):struct.pack_into('<I',self.image,n*4,word)
        self.source_sha256=hashlib.sha256(self.image).hexdigest()
    def is_code(self,offset):return 0<=offset<4096 and offset%4==0
    def read(self,offset,size):
        require(0<=offset and size<=len(self.image)-offset,'boot scaffold range invalid')
        return bytes(self.image[offset:offset+size])
    def unpack(self,fmt,offset):return struct.unpack(fmt,self.read(offset,struct.calcsize(fmt)))

def mov64(register,value):
    return [0xd2800000|((value&65535)<<5)|register]+[0xf2800000|(n<<21)|(((value>>(16*n))&65535)<<5)|register for n in range(1,4)]

def make_boot(linker,sdk_goal,initializer_audit,main_handle):
    # Bind the observed boot argument recipe before creating any replacement.
    rtld=linker.modules[0];require(rtld.name=='rtld','host boot requires a source-bound rtld mapping')
    main=next(m for m in linker.modules if m.name=='main')
    candidates=[]
    for off in range(0,rtld.ranges[0][1]-24,4):
        words=rtld.unpack('<6I',off)
        if words[0]!=0x2a1303e0 or words[3:6]!=(0xaa1403e2,0xaa1503e3,0xaa1603e4):continue
        try:i=decode_instruction(words[2],rtld.base+off+8)
        except ValueError:continue
        if i.form=='pc_relative' and i.rd==1 and i.target==rtld.base+len(rtld.image):candidates.append((off,i.target))
    require(len(candidates)==1,'host boot requires the original main-handle/unmapped-argument-area register recipe')
    call_pc=rtld.base+candidates[0][0]-24
    call=decode_instruction(rtld.unpack('<I',call_pc-rtld.base)[0],call_pc)
    require(call.form=='branch_immediate' and call.operation==1,'unrecognized original ready-callback getter call')
    getter=call.target
    getter_words=rtld.unpack('<3I',getter-rtld.base)
    require(getter_words[0]==0xd503201f and getter_words[2]==0xd65f03c0,'unrecognized original ready-callback getter')
    pointer=decode_instruction(getter_words[1],getter+4)
    require(pointer.form=='pc_relative' and pointer.rd==0,'ready callback is not an original PC-relative pointer')
    original_ready=pointer.target
    ready_words=rtld.unpack('<9I',original_ready-rtld.base)
    require(ready_words[:3]==(0xd503237f,0xaa1e03e0,0xd503201f) and
            ready_words[4:]==(0x52800021,0xb9000041,0xaa0003fe,0xd50323ff,0xd65f03c0),
            'unrecognized original loader-readiness store protocol')
    flag_instruction=decode_instruction(ready_words[3],original_ready+12)
    require(flag_instruction.form=='pc_relative' and flag_instruction.rd==2,'unrecognized readiness field producer')
    ready_flag=flag_instruction.target
    require(rtld.base+rtld.ranges[2][0]<=ready_flag and ready_flag+4<=rtld.base+rtld.bss_end,
            'loader readiness field is outside original writable backing')
    stage=sdk_goal['stages'][0]
    require(stage['symbol']=='_ZN2nn4init5StartEmmPFvvES2_S2_','host boot requires original SDK Start identity')
    boot_base=BootModule.base;ready=boot_base+0x100;inits=boot_base+0x140;fini=boot_base+0x800
    words=mov64(0,main_handle)+mov64(1,candidates[0][1])+mov64(2,ready)+mov64(3,inits)+mov64(4,fini)+mov64(16,stage['entry'])+[0xd63f0200,0xd400ffe1]
    require(len(words)*4<=0x100,'boot entry exceeds its own layout')
    words += [0xd503201f]*(0x100//4-len(words));words += mov64(16,ready_flag)+[0x52800031,0xb9000211,0xd65f03c0]
    words += [0xd503201f]*(0x140//4-len(words));words += [0xa9bf7bfd,0x910003fd]
    records={m['name']:m for m in initializer_audit['modules']};order=[]
    # Explicit host dependency order: SDK first, remaining modules in reverse load order.
    # Each original DT_INIT still performs DSO registration and its actual init_array.
    records_to_call=[]
    for m in reversed(linker.modules):
        if m.name=='rtld':continue
        init=records[m.name]['dynamic_functions']['init']
        if not init:continue
        target=init['address'];require(m.is_code(target-m.base),'DT_INIT is outside original module text')
        page=decode_sdk_init_instruction(m.unpack('<I',target-m.base+20)[0],target+20)
        load=decode_sdk_init_instruction(m.unpack('<I',target-m.base+24)[0],target+24)
        branch=decode_sdk_init_instruction(m.unpack('<I',target-m.base+28)[0],target+28)
        require(page.form=='pc_relative' and page.rd==19 and load.rn==19 and load.rd==8 and load.load and load.width==32 and
                branch.form=='compare_branch' and branch.rd==8 and branch.width==32 and branch.operation==1,
                'unrecognized original deferred-constructor entry protocol')
        flag=page.target+load.immediate
        require(any(a<=flag-m.base and flag-m.base+4<=b for a,b in (m.ranges[2],(m.bss_start,m.bss_end))),
                'constructor flag is outside original module-owned writable backing')
        data=m.read(target-m.base,364)
        require(struct.pack('<III',0xb9000260,0xb9400268,0x7100051f) in data and target+28<branch.target<target+364,
                'original constructor has no proved DSO-result/deferred-init protocol')
        pattern=data.index(struct.pack('<III',0xb9000260,0xb9400268,0x7100051f))
        eq=decode_sdk_init_instruction(m.unpack('<I',target-m.base+pattern+12)[0],target+pattern+12)
        require(eq.form=='branch_condition' and eq.operation==0 and branch.target==target+pattern+16,
                'constructor deferred-return branch is not source-bound')
        return_pc=eq.target+12
        require(m.unpack('<I',return_pc-m.base)[0]==0xd65f0fff,'constructor epilogue must authenticate its return')
        size=return_pc+4-target
        records_to_call.append(target)
        order.append(dict(module=m.name,entry=target,registration_flag=flag,body_entry=branch.target,
            return_pc=return_pc,size=size,body_sha256=hashlib.sha256(m.read(target-m.base,size)).hexdigest()))
    # Original primary-DSO registration may invoke deferred DT_INIT callbacks
    # itself. Never reenter them from the host: the dispatcher observes actual
    # body execution and authenticated returns, independently of result flags.
    for target in records_to_call:
        words+=mov64(16,target)+[0xd63f0200]
    words += [0xa8c17bfd,0xd65f03c0]
    require(len(words)*4<0x800,'module callbacks exceed host scaffold')
    words += [0xd503201f]*(0x800//4-len(words));words += [0xd400ffc1,0xd4200000]
    module=BootModule(words);nodes=[]
    for n,w in enumerate(words):
        pc=module.base+4*n
        if w==0xd4200000:
            nodes.append(dict(address=pc,word=w,semantic_supported=False,selection_stop="host scaffold boundary"));continue
        try:decode_sdk_init_instruction(w,pc)
        except ValueError:
            if w&0xffe0001f!=0xd4000001:raise
        row=dict(address=pc,word=w,semantic_supported=True)
        if w&0xffe0001f==0xd4000001:row['service_immediate']=w>>5&65535
        nodes.append(row)
    return module,nodes,dict(format='oot-host-boot',sdk_entry=stage['entry'],module_order=order,
        argument_recipe_sha256=hashlib.sha256(rtld.read(candidates[0][0],24)).hexdigest(),
        scaffold_sha256=module.source_sha256,original_rtld_execution_allowed=False,ready_flag=ready_flag,
        ready_protocol_sha256=hashlib.sha256(rtld.read(original_ready-rtld.base,36)).hexdigest(),
        finalizer_implemented=False,abi='explicit observed main-handle/unmapped-argument-area SDK Start experiment')
