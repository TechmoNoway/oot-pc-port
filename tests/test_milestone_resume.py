"""Interrupted evidence is reused only under the exact validated binding."""
import json,os,sys,tempfile,unittest,subprocess,time,ctypes,threading
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from run_milestone import MilestoneRun
from milestone_checkpoint import process_alive,seal_native_build,verify_native_build,execution_binding,owned_run,replace_checkpoint

@contextmanager
def deny_delete_sharing(path):
 from ctypes import wintypes as w
 kernel=ctypes.WinDLL('kernel32',use_last_error=True)
 kernel.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE]
 kernel.CreateFileW.restype=w.HANDLE;kernel.CloseHandle.argtypes=[w.HANDLE]
 handle=kernel.CreateFileW(str(path),0x80000000,3,None,3,0x80,None)
 if handle in(None,ctypes.c_void_p(-1).value):raise ctypes.WinError(ctypes.get_last_error())
 try:yield
 finally:kernel.CloseHandle(handle)

class MilestoneResumeTests(unittest.TestCase):
 def test_checkpoint_publication_waits_for_a_real_windows_reader(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp,patch('run_milestone.source_digest',return_value='fixed'):
   output=Path(tmp)/'run';run=MilestoneRun(output,'test',['work'],binding={'input':'a'})
   held=threading.Event();release=threading.Event()
   def reader():
    with deny_delete_sharing(output/'run.json'):
     held.set();release.wait(5)
   reader_thread=threading.Thread(target=reader);reader_thread.start();self.assertTrue(held.wait(5))
   timer=threading.Timer(.1,release.set);timer.start()
   try:
    run.manifest['observer_test']='published after reader release';run.save()
    self.assertEqual(json.loads((output/'run.json').read_text())['observer_test'],'published after reader release')
    self.assertFalse((output/'run.tmp').exists())
   finally:release.set();reader_thread.join();timer.join();run.close()

 def test_persistent_windows_sharing_denial_fails_without_overwriting_checkpoint(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
   folder=Path(tmp);target=folder/'run.json';source=folder/'run.tmp'
   target.write_text('last committed checkpoint');source.write_text('unpublished candidate')
   with deny_delete_sharing(target):
    with self.assertRaises(PermissionError):replace_checkpoint(source,target,timeout=.03)
   self.assertEqual(target.read_text(),'last committed checkpoint')
   self.assertEqual(source.read_text(),'unpublished candidate')
 def test_direct_replay_timeout_terminates_child_and_closes_capture(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
   ready=Path(tmp)/'ready'
   program='import os,time; from pathlib import Path; Path('+repr(str(ready))+').write_text(str(os.getpid())); print("ready",flush=True); time.sleep(20)'
   with self.assertRaises(subprocess.TimeoutExpired):
    owned_run([sys.executable,'-c',program],ROOT,os.environ.copy(),2)
   self.assertTrue(ready.exists());self.assertFalse(process_alive(int(ready.read_text())))
 def test_direct_replay_capture_and_owner_termination_cover_descendants(self):
  result=owned_run([sys.executable,'-c','import sys; print("output"); print("diagnostic",file=sys.stderr); sys.exit(3)'],
      ROOT,os.environ.copy(),10)
  self.assertEqual((result.returncode,result.stdout.strip(),result.stderr.strip()),(3,'output','diagnostic'))
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
   folder=Path(tmp);ready=folder/'ready';done=folder/'done';driver=folder/'driver.py'
   program='import os,time; from pathlib import Path; Path('+repr(str(ready))+').write_text(str(os.getpid())); time.sleep(2); Path('+repr(str(done))+').write_text("done")'
   command=[str(Path(sys.base_prefix)/'python.exe'),'-c',program]
   driver.write_text('import sys,os\nsys.path.insert(0,'+repr(str(ROOT/'tools'))+')\n'
       +'from milestone_checkpoint import owned_run\nowned_run('+repr(command)+','+repr(str(ROOT))+',os.environ.copy(),10)\n')
   child=subprocess.Popen([str(Path(sys.base_prefix)/'python.exe'),str(driver)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:
    deadline=time.monotonic()+10
    while not ready.exists()and time.monotonic()<deadline:
     if child.poll()is not None:self.fail(child.communicate()[1].decode(errors='replace'))
     time.sleep(.01)
    self.assertTrue(ready.exists());descendant=int(ready.read_text())
    child.terminate();child.communicate(timeout=10)
    while process_alive(descendant)and time.monotonic()<deadline:time.sleep(.01)
    self.assertFalse(process_alive(descendant));self.assertFalse(done.exists())
   finally:
    if child.poll()is None:child.kill();child.communicate(timeout=10)
 def test_execution_binding_detects_same_timestamp_input_content_changes(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp,patch('object_cache.SharedCompiler')as compiler:
   compiler.return_value.toolchain={'identity':'synthetic compiler'}
   folder=Path(tmp);prepared=folder/'prepared';prepared.mkdir()
   source=folder/'source.bin';source.write_bytes(b'synthetic original input')
   (prepared/'manifest.json').write_text(json.dumps({'source':{'path':str(source)}}))
   config={'prepared':prepared.relative_to(ROOT).as_posix()}
   first=execution_binding(ROOT,config,False)
   stamp=source.stat();source.write_bytes(b'modified! original input')
   os.utime(source,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
   second=execution_binding(ROOT,config,False)
   self.assertNotEqual(first,second)
   self.assertEqual(first['files'][str(source.resolve())]['bytes'],second['files'][str(source.resolve())]['bytes'])
 def test_native_build_rules_and_binaries_are_sealed_outside_run_output(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
   native=Path(tmp);exe=native/'host.exe';rules=native/'host.vcxproj'
   exe.write_bytes(b'synthetic artifact');rules.write_text('synthetic build rules')
   records=seal_native_build(ROOT,native);verify_native_build(ROOT,records)
   stamp=rules.stat();rules.write_text('modified! build rules')
   os.utime(rules,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
   with self.assertRaises(InputError):verify_native_build(ROOT,records)
   rules.write_text('synthetic build rules');exe.write_bytes(b'modified! artifact')
   with self.assertRaises(InputError):verify_native_build(ROOT,records)
 def test_resume_reuses_real_command_but_requires_post_verification(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp,patch('run_milestone.source_digest',return_value='fixed'):
   output=Path(tmp)/'run';binding={'toolchain':'one','input':'original'}
   run=MilestoneRun(output,'test',['work'],binding=binding)
   marker=output/'result.json'
   argv=[sys.executable,'-c',"from pathlib import Path; p=Path("+repr(str(marker))+"); assert not p.exists(); p.write_text('actual result')"]
   run.command('work',argv,os.environ.copy())
   with self.assertRaises(InputError):run.finish()
   run.close()
   resumed=MilestoneRun(output,'test',['work'],binding=binding,resume=True)
   try:
    resumed.command('work',argv,os.environ.copy())
    self.assertEqual(marker.read_text(),'actual result')
    with self.assertRaises(InputError):resumed.finish()
    resumed.mark_verified(['work']);resumed.finish()
   finally:resumed.close()
   self.assertEqual(json.loads((output/'run.json').read_text())['status'],'passed')

 def test_tampered_evidence_binding_source_and_live_owner_are_rejected(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp,patch('run_milestone.source_digest',return_value='fixed'):
   output=Path(tmp)/'run';binding={'input':'a'}
   run=MilestoneRun(output,'test',['audit'],binding=binding)
   try:
    with self.assertRaises(InputError):MilestoneRun(output,'test',['audit'],binding=binding,resume=True)
    result=output/'audit.json';result.write_text('original')
    run.action('audit',lambda:None);run.close()
    with self.assertRaises(InputError):MilestoneRun(output,'test',['audit'],binding={'input':'b'},resume=True)
    with patch('run_milestone.source_digest',return_value='changed'):
     with self.assertRaises(InputError):MilestoneRun(output,'test',['audit'],binding=binding,resume=True)
    stamp=result.stat();result.write_text('tampered');os.utime(result,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
    with self.assertRaises(InputError):MilestoneRun(output,'test',['audit'],binding=binding,resume=True)
   finally:run.close()

 def test_actual_interruption_preserves_partial_output_and_restarts_command(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
   base=Path(tmp);output=base/'run';folder=output/'work';driver=base/'driver.py'
   python=Path(sys.base_prefix)/'python.exe'
   program=("from pathlib import Path; import time,os; p=Path("+repr(str(folder))+"); "
       "p.mkdir(); (p/'ready').write_text(str(os.getpid())); time.sleep(1.5); (p/'done').write_text('done')")
   command=[str(python),'-c',program,'--output',str(folder)]
   driver.write_text('import sys,os\n'
       +'sys.path[:0]='+repr([str(ROOT/'tools'),str(Path(sys.prefix)/'Lib/site-packages')])+'\n'
       +'from pathlib import Path\nfrom run_milestone import MilestoneRun\n'
       +'r=MilestoneRun(Path('+repr(str(output))+'),"test",["work"],binding={"input":"test"})\n'
       +'r.command("work",'+repr(command)+',os.environ.copy())\n')
   child=subprocess.Popen([str(python),str(driver)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:
    deadline=time.monotonic()+10
    while not (folder/'ready').exists()and time.monotonic()<deadline:
     if child.poll()is not None:self.fail(child.communicate()[1].decode(errors='replace'))
     time.sleep(0.01)
    self.assertTrue((folder/'ready').exists())
    manifest=json.loads((output/'run.json').read_text());pid=manifest['stages']['work']['child_pid']
    descendant=int((folder/'ready').read_text())
    child.terminate();child.communicate(timeout=10)
    while (process_alive(pid)or process_alive(descendant))and time.monotonic()<deadline:time.sleep(0.01)
    self.assertFalse(process_alive(pid))
    self.assertFalse(process_alive(descendant))
    self.assertFalse((folder/'done').exists())
    resumed=MilestoneRun(output,'test',['work'],binding={'input':'test'},resume=True)
    try:
     self.assertTrue((output/'interrupted/attempt-2/work/ready').exists())
     resumed.command('work',command,os.environ.copy());resumed.mark_verified(['work']);resumed.finish()
    finally:resumed.close()
    self.assertEqual((folder/'done').read_text(),'done')
   finally:
    if child.poll()is None:child.kill();child.communicate(timeout=10)

 def test_still_active_recorded_command_blocks_resume(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp,patch('run_milestone.source_digest',return_value='fixed'):
   output=Path(tmp)/'run';binding={'input':'a'}
   run=MilestoneRun(output,'test',['work'],binding=binding)
   child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'])
   try:
    run.manifest['stages']['work'].update(status='running',child_pid=child.pid)
    run.save();run.close()
    with self.assertRaises(InputError):MilestoneRun(output,'test',['work'],binding=binding,resume=True)
   finally:child.kill();child.wait();run.close()

 def test_changed_command_environment_and_failed_run_cannot_resume(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp,patch('run_milestone.source_digest',return_value='fixed'):
   output=Path(tmp)/'run';binding={'input':'a'};env=os.environ.copy()
   command=[sys.executable,'-c','pass']
   run=MilestoneRun(output,'test',['work','later'],binding=binding)
   run.command('work',command,env);run.close()
   resumed=MilestoneRun(output,'test',['work','later'],binding=binding,resume=True)
   try:
    with self.assertRaises(InputError):resumed.command('work',command+['changed'],env)
    with self.assertRaises(InputError):resumed.command('work',command,dict(env,OOT_CHECKPOINT_TEST='changed'))
    resumed.mark_verified(['work'])
    self.assertFalse(resumed.manifest['stages']['later']['verified'])
    with self.assertRaises(InputError):resumed.command('later',[sys.executable,'-c','raise SystemExit(4)'],env)
   finally:resumed.close()
   with self.assertRaises(InputError):MilestoneRun(output,'test',['work','later'],binding=binding,resume=True)

 def test_same_size_same_timestamp_active_artifact_tamper_rejected_at_finish(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp,patch('run_milestone.source_digest',return_value='fixed'):
   output=Path(tmp)/'run';run=MilestoneRun(output,'test',['work'],binding={'input':'a'})
   try:
    marker=output/'result.json';marker.write_text('original')
    run.action('work',lambda:None)
    stamp=marker.stat();marker.write_text('tampered');os.utime(marker,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
    with self.assertRaises(InputError):run.finish()
   finally:run.close()

if __name__=='__main__':unittest.main()
