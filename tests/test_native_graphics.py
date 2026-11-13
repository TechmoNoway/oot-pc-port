"""Compile the private-dispatch lifecycle fixture on the selected native compiler."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from lifter_validation import find_cmake


class NativeGraphicsTests(unittest.TestCase):
    def test_lifecycle_and_failed_boot_have_no_published_effects(self):
        parent=ROOT/'build/graphics-tests';parent.mkdir(parents=True,exist_ok=True)
        dest=Path(tempfile.mkdtemp(dir=parent));source=ROOT/'tests/native_graphics_test.c'
        if os.environ.get('OOT_LIFTER_COMPILER','cmake')=='gcc':
            exe=dest/'graphics-test.exe'
            commands=[[shutil.which('gcc'),'-std=c17','-O2','-Wall','-Wextra','-Wpedantic','-Werror',
                '-D_CRT_SECURE_NO_WARNINGS','-I',str(ROOT/'third_party/vulkan/include'),
                str(source),'-o',str(exe)]]
        else:
            (dest/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(graphics_test C)\n'
                f'add_executable(graphics-test "{source.as_posix()}")\n'
                f'target_include_directories(graphics-test PRIVATE "{(ROOT/"third_party/vulkan/include").as_posix()}")\n'
                'target_compile_features(graphics-test PRIVATE c_std_17)\n'
                'target_compile_definitions(graphics-test PRIVATE _CRT_SECURE_NO_WARNINGS)\n'
                'target_compile_options(graphics-test PRIVATE /W4 /WX)\n')
            commands=[[find_cmake(),'-S',str(dest),'-B',str(dest/'native')],
                [find_cmake(),'--build',str(dest/'native'),'--config','Release']]
            exe=dest/'native/Release/graphics-test.exe'
        for command in commands:
            result=subprocess.run(command,capture_output=True,text=True,timeout=180)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('failure isolation passed',result.stdout)


if __name__=='__main__':unittest.main()
