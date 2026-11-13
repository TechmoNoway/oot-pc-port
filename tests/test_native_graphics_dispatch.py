"""Real generated dispatcher with a private synthetic Vulkan function table."""
from ctypes import CDLL,POINTER,byref,c_char_p,c_int,c_uint,c_uint64
import os
from pathlib import Path
import shutil,subprocess,tempfile,unittest
import test_application_boot as boot
from lifter_validation import find_cmake
from lifter_validation_types import State
from test_sdk_init_vectors import VectorState

ROOT=boot.ROOT
NAMES=('guest_memory','runtime_image','host_win32','leaf_dispatch','frame_dispatch','stack_dispatch',
    'pauth','checked_read','plt_bridge','startup_dispatch','sdk_native','native_platform','native_services',
    'native_math','startup_vector','startup_float','startup_init_atomic','application_services','native_romfs')

class GraphicsDispatchTests(unittest.TestCase):
    def test_native_boot_check_quota_and_complete_vector_bank(self):
        self.run_native()

    def run_native(self,display=False):
        blob,sources,_=boot.package(2,True,graphics=True,graphics_calls=True,display=display)
        observer=boot.SNAPSHOT_SOURCE.replace('oot_startup_dispatch_create_application',
            'oot_startup_dispatch_create_display' if display else 'oot_startup_dispatch_create_graphics')
        getter='display_get' if display else 'fake_get'
        observer=observer.replace('if(!context || !keys)goto done;',
            f'if(!context || !keys)goto done;\n    context->graphics->get_instance={getter};\n    context->graphics->destroy_instance=fake_destroy_instance;')
        self.assertIn('context->graphics->get_instance='+getter,observer)
        observer=observer.replace('*count=used;*final=state;ok=1;',
            '*count=used;*final=state;oot_graphics_snapshot(context->graphics,&last_graphics);'
            'oot_graphics_display_snapshot(context->graphics,&last_display);'
            'last_native=context->native.calls;last_retired=report.retired;ok=1;')
        fixture=('#define OOT_DISPLAY_FIXTURE_ONLY\n#define failure graphics_fixture_failure\n#include "native_display_test.c"\n#undef failure\n' if display else
            '#define main oot_test_unused_lifecycle_main\n#define failure graphics_fixture_failure\n#include "native_graphics_test.c"\n#undef main\n#undef failure\n')
        text=(fixture+'#include "startup_context.c"\nstatic OotGraphicsReport last_graphics;\nstatic OotDisplayReport last_display;\n'
            'static uint64_t last_native,last_retired;\n'+'\n'.join(sources.values())+observer+
            '\nOOT_LIFT_EXPORT void oot_test_graphics_counts(uint64_t *out){'
            'out[0]=last_native;out[1]=last_graphics.boots;out[2]=last_graphics.checks;'
            'out[3]=last_graphics.ready;out[4]=last_retired;out[5]=instance_destroys;out[6]=device_destroys;out[7]=instances;out[8]=devices;'
            'out[9]=last_display.ready;out[10]=last_display.calls;out[11]=last_display.initializations;'
            +('out[12]=classes;out[13]=windows;out[14]=surfaces;' if display else 'out[12]=0;out[13]=0;out[14]=0;')+'}\n')
        parent=ROOT/'build/graphics-dispatch-tests';parent.mkdir(parents=True,exist_ok=True)
        # Keep loaded native artifacts under ignored build, as compile_library does.
        temporary=tempfile.mkdtemp(dir=parent)
        dest=Path(temporary);source=dest/'fixture.c';source.write_text(text)
        includes=[ROOT/'src',ROOT/'tests',ROOT/'third_party/vulkan/include']
        paths=[source,*[ROOT/'src'/(n+'.c') for n in NAMES]]
        if os.environ.get('OOT_LIFTER_COMPILER','cmake')=='gcc':
            library=dest/'graphics-fixture.dll'
            commands=[[shutil.which('gcc'),'-std=c17','-O2','-Wall','-Wextra','-Wpedantic','-Werror',
                '-shared','-DOOT_MEMORY_SHARED_EXPORTS','-D_CRT_SECURE_NO_WARNINGS','-D_WIN32_WINNT=0x0A00',
                *[arg for path in includes for arg in ('-I',str(path))],*map(str,paths),'-lbcrypt','-o',str(library)]]
        else:
            (dest/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(graphics_dispatch C)\n'
                +'add_library(graphics-fixture SHARED '+' '.join('"'+p.as_posix()+'"' for p in paths)+')\n'
                +'target_include_directories(graphics-fixture PRIVATE '+' '.join('"'+p.as_posix()+'"' for p in includes)+')\n'
                +'target_link_libraries(graphics-fixture PRIVATE bcrypt)\n'
                +'target_compile_features(graphics-fixture PRIVATE c_std_17)\n'
                +'target_compile_definitions(graphics-fixture PRIVATE OOT_MEMORY_SHARED_EXPORTS _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0A00)\n'
                +'target_compile_options(graphics-fixture PRIVATE /W4 /WX)\n')
            commands=[[find_cmake(),'-S',str(dest),'-B',str(dest/'native')],
                [find_cmake(),'--build',str(dest/'native'),'--config','Release']]
            library=dest/'native/Release/graphics-fixture.dll'
        for command in commands:
            result=subprocess.run(command,capture_output=True,text=True,timeout=180)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        lib=CDLL(str(library));fn=lib.oot_test_simd_snapshot
        fn.argtypes=[c_char_p,c_uint64,c_uint64,c_uint,POINTER(VectorState),POINTER(c_uint),POINTER(State)];fn.restype=c_int
        counts=lib.oot_test_graphics_counts;counts.argtypes=[POINTER(c_uint64)];counts.restype=None
        path=dest/'graphics.ootmem';path.write_bytes(blob);snapshots=[]
        for invocation,quantum in enumerate((1,2,1000),1):
            history=(VectorState*1024)();count=c_uint();state=State();values=(c_uint64*15)()
            self.assertEqual(fn(os.fsencode(path),quantum,1000,0,history,byref(count),byref(state)),1)
            counts(values);self.assertEqual(tuple(values[:4]),(4,2,0 if display else 1,1))
            self.assertEqual(tuple(values[5:9]),(invocation,invocation,0,0))
            self.assertEqual(tuple(values[9:12]),(1,1,1) if display else (0,0,0))
            self.assertEqual(tuple(values[12:]),(0,0,0))
            self.assertEqual(bytes(history[count.value-1].q[0]),b'\x5a'*16)
            self.assertEqual(bytes(history[count.value-1].q[31]),b'\xa5'*16)
            if quantum==1:self.assertEqual(count.value,values[4]+values[0]+1)
            snapshots.append((bytes(history[count.value-1]),state.values()))
        self.assertTrue(all(s==snapshots[0] for s in snapshots))
        # Each completed invocation destroyed its private mock resources.
        # The fixture never loads the Windows Vulkan loader.

if __name__=='__main__':unittest.main()
