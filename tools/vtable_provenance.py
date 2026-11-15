"""Static original vtable/relocation/extents proof, without runtime authority.

The pristine module is retained separately from the offline-linked image. Every
table byte is reconstructed using the original RELA/RELR records. Anonymous
targets stay private entries; they are never labelled as dynamic ELF exports.
"""
from copy import copy
import hashlib,struct
from input_formats import require
from module_linker import Module,MAX_RELOCATIONS,MAX_SYMBOLS
from sdk_startup_audit import _symbol_record
from unwind_provenance import prove_extents


def _metadata(module):
    # Reparse immutable original metadata instead of trusting cached Python fields.
    fresh=copy(module)
    Module.parse_mod0(fresh);Module.parse_dynamic(fresh);Module.parse_relocations(fresh)
    require((fresh.mod0,fresh.dynamic,fresh.rela,fresh.relr)==
        (module.mod0,module.dynamic,module.rela,module.relr),'vtable parsed metadata differs from original bytes')
    counts=[]
    if 39 in fresh.dynamic:
        require(fresh.dynamic[39]%24==0,'invalid vtable symbol census extent')
        counts.append(fresh.dynamic[39]//24)
    if 4 in fresh.dynamic:counts.append(fresh.unpack('<II',fresh.dynamic[4])[1])
    if not counts and 0x6ffffef5 in fresh.dynamic:counts.append(fresh.gnu_symbol_count())
    require(counts and all(n==len(module.symbols) and 0<n<=MAX_SYMBOLS for n in counts),
        'vtable original symbol census differs')
    return [_symbol_record(module,i,s)for i,s in enumerate(module.symbols)]


def prove_vtables(pristine,linker,specifications):
    """Prove named primary tables with a caller-declared finite slot count.

    Only same-module ABS64 (zero addend) and RELR entries are admitted. This is a
    deliberately narrow source audit, not a generic C++ ABI or relocation loader.
    Returned data cannot register handlers or authorize execution by itself.
    """
    require(type(specifications)is dict and 0<len(specifications)<=16 and
        all(isinstance(name,str) and name.startswith('_ZTV') and type(count)is int and
            0<count<=4096 for name,count in specifications.items()),'invalid bounded vtable selection')
    matches=[m for m in linker.modules if m.name==pristine.name]
    require(linker.report().get('link_complete')is True and len(matches)==1,
        'vtable audit requires its completely linked module')
    module=matches[0]
    require(module is not pristine and module.source_sha256==pristine.source_sha256 and
        module.ranges==pristine.ranges and module.header==pristine.header and
        not pristine.touched,'vtable original source binding differs')
    for i,(a,b)in enumerate(pristine.ranges):
        segment=pristine.header['segments'][i]
        require(segment.get('hash_verified')is True and
            hashlib.sha256(pristine.read(a,b-a)).hexdigest()==segment['sha256'],
            'vtable audit requires unchanged verified pristine segments')
        if i<2:
            require(module.read(a,b-a)==pristine.read(a,b-a),'linked vtable text/rodata differs')
    original_metadata=_metadata(pristine);metadata=_metadata(module)
    require(original_metadata==metadata and pristine.symbols==module.symbols and
        pristine.dynamic==module.dynamic and pristine.mod0==module.mod0,
        'linked vtable metadata differs from pristine source')
    relocations={}
    def add(offset,kind,index,addend,record):
        width=4 if kind==258 else 8
        for word in range(offset//4,(offset+width+3)//4):
            require(word not in relocations,'vtable relocation records overlap')
            relocations[word]=(offset,width,kind,index,addend,record)
        require(len(relocations)<=MAX_RELOCATIONS*2,'vtable expanded relocations exceed bound')
    cursor=None
    for n,(word,)in enumerate(struct.iter_unpack('<Q',pristine.relr)):
        if word&1:
            require(cursor is not None,'vtable RELR bitmap lacks a base')
            targets=tuple(cursor+bit*8 for bit in range(63)if word&(1<<(bit+1)));cursor+=63*8
        else:targets=(word,);cursor=word+8
        for offset in targets:
            require(offset%8==0,'unaligned vtable RELR relocation')
            add(offset,'RELR',0,0,dict(table='relr',index=n,word=word))
    for label,table in pristine.rela:
        for n,(offset,info,addend)in enumerate(struct.iter_unpack('<QQq',table)):
            kind=info&0xffffffff
            if kind:add(offset,kind,info>>32,addend,dict(table=label,index=n,
                record_sha256=hashlib.sha256(table[n*24:n*24+24]).hexdigest()))
    tables=[];targets={};intervals=[]
    for name,count in sorted(specifications.items()):
        definitions=[(i,s)for i,s in enumerate(pristine.symbols)if s.name==name and s.section]
        require(len(definitions)==1,'missing or ambiguous original vtable definition')
        index,symbol=definitions[0];begin=symbol.value;end=begin+symbol.size
        require(symbol.kind==1 and symbol.binding in(1,2) and symbol.visibility in(0,3) and
            begin%8==0 and symbol.size==16+count*8 and
            pristine.ranges[2][0]<=begin<end<=pristine.ranges[2][1],
            'vtable object shape/initialized-data extent differs')
        require(all(end<=a or b<=begin for a,b in intervals),'selected vtables overlap')
        intervals.append((begin,end));expected=bytearray(pristine.read(begin,symbol.size))
        require(expected[:8]==bytes(8),'unsupported non-primary vtable offset-to-top')
        require(begin//4 not in relocations and begin//4+1 not in relocations,
            'vtable offset-to-top is relocated')
        slots=[]
        for at in range(begin+8,end,8):
            record=relocations.get(at//4)
            require(record is not None and record[:2]==(at,8) and
                relocations.get(at//4+1)==record,'vtable pointer lacks one whole original relocation')
            offset,width,kind,target_index,addend,evidence=record
            target_symbol=None
            if kind=='RELR':
                value=module.base+pristine.unpack('<Q',at)[0]
            else:
                require(kind==257 and addend==0 and 0<target_index<len(pristine.symbols),
                    'unsupported vtable pointer relocation/addend')
                target_symbol=pristine.symbols[target_index]
                require(target_symbol.section and target_symbol.kind==(1 if at==begin+8 else 2),
                    'vtable relocation symbol is not a defined object/function')
                value,owner=linker.resolve(module,target_index)
                require(owner in('local',module.name) and value==module.base+target_symbol.value,
                    'vtable pointer resolves outside its original module')
            require(0<=value<1<<39,'vtable target exceeds declared guest address space')
            struct.pack_into('<Q',expected,at-begin,value)
            relocation=dict(kind='RELR'if kind=='RELR'else 'ABS64',**evidence)
            if target_symbol is not None:relocation['symbol_metadata']=original_metadata[target_index]
            if at==begin+8:
                require(pristine.ranges[2][0]<=value-module.base<pristine.ranges[2][1],
                    'vtable RTTI is outside initialized module data')
                rtti=dict(entry=value,relocation=relocation)
            else:
                require(module.is_code(value-module.base),'vtable slot is not original aligned text')
                slot=dict(slot=(at-begin-16)//8,entry=value,relocation=relocation)
                slots.append(slot);targets.setdefault(value,[]).append(dict(table=name,slot=slot['slot']))
        linked=module.read(begin,symbol.size)
        require(linked==bytes(expected),'linked vtable bytes differ from original relocation reconstruction')
        tables.append(dict(symbol=name,symbol_metadata=original_metadata[index],entry=module.base+begin,
            size=symbol.size,source_sha256=pristine.source_sha256,rtti=rtti,slots=slots,
            original_sha256=hashlib.sha256(pristine.read(begin,symbol.size)).hexdigest(),
            linked_sha256=hashlib.sha256(linked).hexdigest()))
    proofs=prove_extents(module,set(targets))
    for proof in proofs:
        aliases=[]
        for i,symbol in enumerate(pristine.symbols):
            if symbol.section and symbol.kind==2 and module.base+symbol.value==proof['entry']:
                require(symbol.size==proof['size'],'export alias disagrees with canonical private extent')
                aliases.append(dict(symbol=symbol.name,symbol_metadata=original_metadata[i]))
        proof.update(slots=targets[proof['entry']],export_aliases=aliases)
    require(all(a['entry']+a['size']<=b['entry']for a,b in zip(proofs,proofs[1:])),
        'selected private function extents overlap')
    return dict(format='oot-static-vtable-provenance',schema_version=1,module=module.name,
        source_sha256=pristine.source_sha256,tables=tables,targets=proofs,
        slot_count=sum(specifications.values()),runtime_capability=False,guest_code_executed=False)


def main():
    import argparse,json,sys
    from copy import deepcopy
    from pathlib import Path
    from input_formats import InputError
    from link_exefs import build_destination,load_prepared
    from module_linker import Linker
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared',type=Path)
    parser.add_argument('--module',default='sdk')
    parser.add_argument('--table',action='append',required=True,help='original mangled vtable name=slot-count')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        specifications={}
        for declaration in args.table:
            name,count=declaration.rsplit('=',1)
            require(name not in specifications,'duplicate vtable declaration')
            specifications[name]=int(count)
        output=build_destination(args.output)
        require(not output.exists(),'vtable report already exists; choose a fresh output')
        linker=Linker(load_prepared(args.prepared))
        selected=[m for m in linker.modules if m.name==args.module]
        require(len(selected)==1,'vtable source module is missing')
        pristine=deepcopy(selected[0]);linker.apply()
        report=prove_vtables(pristine,linker,specifications)
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('x',encoding='utf-8')as stream:stream.write(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(output=str(output),tables=len(report['tables']),slots=report['slot_count'],
            unique_targets=len(report['targets']),runtime_capability=False,guest_code_executed=False)))
    except(InputError,OSError,ValueError)as error:
        print('Error: '+str(error),file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
