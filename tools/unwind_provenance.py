"""Narrow canonical original unwind extents for separate private-entry audits.

This does not unwind frames, establish a calling convention, change the legacy
discovery parser or authorize native execution. Callers still need complete
table/relocation/consumer proofs before declaring any private guard.
"""
import hashlib,re,struct
from input_formats import require
from module_linker import MAX_SYMBOLS


def prove_extents(module,entries):
    entries=set(entries);lo,hi=module.ranges[1]
    require(all(type(entry)is int and 0<=entry<1<<64 for entry in entries)and len(entries)<=MAX_SYMBOLS,
        'invalid extent selection')
    require(isinstance(module.source_sha256,str)and re.fullmatch('[0-9a-f]{64}',module.source_sha256)is not None,
        'invalid original source identity')
    for index in (0,1):
        begin,end=module.ranges[index];segment=module.header['segments'][index]
        require(segment.get('hash_verified')is True and
            hashlib.sha256(module.read(begin,end-begin)).hexdigest()==segment.get('sha256'),
            'extent proof requires unchanged verified original text/rodata')
    def read(at,size):
        require(type(at)is int and type(size)is int and size>=0 and lo<=at<=hi and size<=hi-at,
            'unwind metadata leaves original rodata')
        return module.read(at,size)
    begin,end=module.mod0['exception_start'],module.mod0['exception_end']
    header=read(begin,end-begin)
    require(len(header)>=12 and header[:4]==b'\x01\x1b\x03\x3b','unsupported narrow unwind header')
    frame=begin+4+struct.unpack_from('<i',header,4)[0]
    count=struct.unpack_from('<I',header,8)[0]
    require(0<count<=MAX_SYMBOLS and len(header)==12+count*8,'unwind table extent differs')
    table=[];previous=-1
    for initial,delta in struct.iter_unpack('<ii',header[12:]):
        pc=begin+initial;fde=begin+delta
        require(pc%4==0 and pc>previous and module.is_code(pc),'invalid canonical unwind entry')
        read(fde,4);table.append((pc,fde));previous=pc
    selected=[(pc,fde,i)for i,(pc,fde)in enumerate(table)if module.base+pc in entries]
    require(len(selected)==len(entries),'private entry lacks a unique canonical unwind row')
    if not selected:return []
    maximum=max(fde for pc,fde,i in selected);records={};at=frame
    # A sequential walk proves record membership. An interior byte pattern is
    # never accepted merely because a table pointer was changed to point at it.
    while at<=maximum:
        require(len(records)<MAX_SYMBOLS and at%4==0,'unwind record walk exceeds bound/alignment')
        size=struct.unpack('<I',read(at,4))[0]
        require(4<=size<0xfffffff0 and size%4==0,'unsupported/truncated DWARF32 record')
        data=read(at,size+4)
        require(at+len(data)<=begin or at>=end,'frame record overlaps unwind header')
        records[at]=data;at+=len(data)
    result=[]
    for pc,fde,index in selected:
        require(fde in records,'unwind FDE is not a record boundary')
        raw=records[fde];require(len(raw)>=20,'truncated selected FDE')
        distance=struct.unpack_from('<I',raw,4)[0];cie=fde+4-distance
        require(distance>0 and cie<fde and cie in records,'invalid canonical CIE reference')
        common=records[cie]
        require(len(common)>=20 and common[4:9]==b'\0\0\0\0\1','unsupported CIE identity/version')
        zero=common.find(b'\0',9)
        require(zero>=0 and common[9:zero]in(b'zR',b'zRB'),'unsupported CIE augmentation')
        require(common[zero+1:zero+6]==b'\1\x7c\x1e\1\x1b','unsupported CIE factors/pointer encoding')
        tail=common[zero+6:]
        require(tail[:3]==b'\x0c\x1f\0'and not any(tail[3:]),'unsupported initial CIE frame declaration')
        target=fde+8+struct.unpack_from('<i',raw,8)[0];size=struct.unpack_from('<i',raw,12)[0]
        require(target==pc and size>0 and size%4==0 and module.is_code(pc+size-4),
            'FDE start/extent differs from canonical table/text')
        require(index+1==len(table)or pc+size<=table[index+1][0],'FDE overlaps next canonical entry')
        require(raw[16]==0,'selected FDE has unsupported augmentation payload')
        result.append(dict(source_kind='canonical-unwind-private-entry',entry=module.base+pc,size=size,
            body_sha256=hashlib.sha256(module.read(pc,size)).hexdigest(),source_sha256=module.source_sha256,
            fde_offset=fde,cie_offset=cie,fde_sha256=hashlib.sha256(raw).hexdigest(),
            cie_sha256=hashlib.sha256(common).hexdigest(),table_sha256=hashlib.sha256(header).hexdigest(),
            b_key_marker=common[9:zero]==b'zRB',runtime_capability=False))
    return result
