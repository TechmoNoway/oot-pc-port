"""Actual synthetic generated resource callbacks, native quota and full vectors."""
from ctypes import POINTER,byref,c_char_p,c_int,c_uint,c_uint64
from pathlib import Path
import json,os,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import test_application_boot as boot
from build_startup import build_native,execute
from startup_sources import write_sources
from lifter_validation import compile_library
from lifter_validation_types import State
from test_sdk_init_vectors import VectorState


class ApplicationResourceBootTests(unittest.TestCase):
    def test_both_getters_real_dispatch_native_quota_vectors_and_old_init_stop(self):
        compiler=os.environ.get('OOT_LIFTER_COMPILER','cmake')
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);outcomes=[]
            for app in (False,True):
                blob,sources,_=boot.package(2,app,resource=True)
                folder=root/str(app);folder.mkdir();write_sources(folder,sources)
                (folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,compiler,root/'cache')
                outcomes.append(execute(exe,folder,1000,1000,'full'))
            self.assertEqual(outcomes[0]['error'],15)
            whole=outcomes[1]
            self.assertNotIn('application_resource',outcomes[0])
            self.assertEqual(whole['application_resource'],dict(logical_process_id=1,active=1,queries=2))
            self.assertEqual((whole['error'],whole['native_calls'],whole['application_stop_arguments'][0]),(8,3,2))
            rows=[json.loads(line) for line in Path(whole['trace_file']).read_text().splitlines()]
            calls=[r for r in rows if r['event']==3];self.assertEqual(len(calls),3)
            quotas={r['retired']+delta for r in calls for delta in (-1,0,1)}
            for limit in (1000,*sorted(q for q in quotas if q>0)):
                folder=root/f'prefix-{limit}';folder.mkdir();(folder/'startup.ootmem').write_bytes(blob)
                prefix=execute(exe,folder,limit,1,'full')
                actual=[json.loads(line) for line in Path(prefix['trace_file']).read_text().splitlines()]
                self.assertEqual(actual[:-1],rows[:len(actual)-1])
                self.assertEqual(prefix['native_calls'],sum(r['event']==3 for r in actual[:-1]))
                if limit==1000:self.assertEqual(prefix['trace_sha256'],whole['trace_sha256'])
            observer=('#include <stdint.h>\nstatic uint64_t oot_test_resource_query_count;\n'+boot.SNAPSHOT_SOURCE.replace(
                '*count=used;*final=state;ok=1;',
                '*count=used;*final=state;oot_test_resource_query_count=oot_startup_context_application_resource_queries(context);ok=1;')+
                '\nOOT_LIFT_EXPORT uint64_t oot_test_resource_queries(void){return oot_test_resource_query_count;}\n')
            lib,build=compile_library([],compiler,extra_source='\n'.join([*sources.values(),observer]),startup=True)
            fn=lib.oot_test_simd_snapshot
            fn.argtypes=[c_char_p,c_uint64,c_uint64,c_uint,POINTER(VectorState),POINTER(c_uint),POINTER(State)];fn.restype=c_int
            queries=lib.oot_test_resource_queries;queries.argtypes=[];queries.restype=c_uint64
            path=Path(build['directory'])/'resource.ootmem';path.write_bytes(blob)
            snapshots=[]
            for quantum in (1000,1):
                history=(VectorState*1024)();count=c_uint();state=State()
                self.assertEqual(fn(os.fsencode(path),quantum,1000,0,history,byref(count),byref(state)),1)
                self.assertEqual((queries(),state.x[0],state.x[19]),(2,2,1))
                snapshots.append((bytes(history[count.value-1]),state.values()))
                if quantum==1:self.assertEqual(count.value,whole['retired']+whole['native_calls']+1)
            self.assertEqual(*snapshots)
            expected=[bytes(16) for _ in range(32)];expected[0]=bytes([0x5a])*16;expected[31]=bytes([0xa5])*16
            self.assertEqual(snapshots[0][0],b''.join(expected)+bytes(8))


if __name__=='__main__':unittest.main()
