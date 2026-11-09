"""Whole-function acceleration for original linear register-only leaf proofs."""
from arm64_lifter import decode_block,body,constant
from leaf_verifier import verify_leaf
from input_formats import InputError

def emit_fast(linker,rows,units,goal,natives):
    selected={r[0] for r in rows};found={};protected=[]
    if goal:protected=goal['mandatory_stage_entries']+[goal['goal_entry']['thunk_entry'],goal['goal_entry']['entry']]
    for m in linker.modules:
      for symbol in m.symbols:
        pc=m.base+symbol.value;size=symbol.size
        if not symbol.section or symbol.kind!=2 or not 8<=size<=1024 or size%4 or pc in found:continue
        if any(pc<=a<pc+size for a in protected) or any(pc<f['entry']+f['size'] and f['entry']<pc+size for f in natives):continue
        if not all(p in selected for p in range(pc,pc+size,4)):continue
        try:
          data=m.read(symbol.value,size);proof=verify_leaf(data,pc)
          if any(row['next']!=[n+1] for n,row in enumerate(proof['control_flow'][:-1])) or proof['control_flow'][-1]['next']:continue
          found[pc]=(data,proof)
        except (InputError,ValueError):continue
    lines=[];records=[]
    for pc,(data,proof) in sorted(found.items())[:4096]:
      name=f'oot_fast_leaf_{pc:x}'
      code=[f'int {name}(OotArm64State *s,OotGuestMemory *memory,const OotPauth *pauth,uint64_t budget,uint64_t *executed) {{',
        '(void)pauth;(void)memory;*executed=0;',f'if(budget<{len(data)//4})return OOT_LIFT_BUDGET;']
      for ins in decode_block(data,pc):code += ['{',*body(ins),'}']
      code += [f'*executed={len(data)//4};return OOT_LIFT_DISPATCH;','}']
      chunk=f'lift_{pc>>16:x}.c';units[chunk]=units.get(chunk,'#include "pauth.h"\n')+'\n'.join(code)+'\n'
      lines.append(f'extern int {name}(OotArm64State *,OotGuestMemory *,const OotPauth *,uint64_t,uint64_t *);')
      digest=','.join('0x'+proof['source_sha256'][i:i+2] for i in range(0,64,2))
      records.append(f'{{{constant(pc)},{len(data)},{{{digest}}},{name}}},')
    if records:lines+=['static const OotStartupFastFunction oot_fast_functions[]={',*records,'};',f'const OotStartupFastFunction *oot_startup_compiled_fast_functions(size_t *n){{*n={len(records)};return oot_fast_functions;}}']
    else:lines+=['const OotStartupFastFunction *oot_startup_compiled_fast_functions(size_t *n){*n=0;return NULL;}']
    return lines,len(records)
