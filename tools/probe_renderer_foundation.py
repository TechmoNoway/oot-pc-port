"""Explicit synthetic shader and physical GPU transfer integration probes."""
import argparse,hashlib,json,os,struct
from pathlib import Path
from input_formats import require
from object_cache import SharedCompiler
from milestone_checkpoint import owned_run
from shader_tool import ROOT,encode_request,translate

def probe(tool,identity,output):
    output=Path(output).resolve();require(output.is_relative_to(ROOT/'build')and not output.exists(),'choose fresh private renderer probe output')
    output.mkdir(parents=True);shaders={};compilers={}
    for stage in(0,1,2):
        code=(bytes(128)if stage!=2 else b'')+struct.pack('<4I',0x794d,0,0x03800000,0)
        shaders[str(stage)]=translate(tool,identity,encode_request(code,stage=stage,
            workgroup=(1,1,1)if stage==2 else(0,0,0)),output/('shader-'+str(stage)))
    bad=output/'invalid';bad.mkdir();(bad/'request.bin').write_bytes(bytes(80))
    rejected=owned_run([str(Path(tool).resolve()),str(bad/'request.bin'),str(bad/'module.spv'),str(bad/'reflection.json')],ROOT,os.environ.copy(),30)
    (bad/'stderr.log').write_text(rejected.stderr)
    require(rejected.returncode==1 and not(bad/'module.spv').exists(),'shader compiler accepted an invalid request')
    for mode in('cmake','gcc'):
        folder=output/mode;folder.mkdir();compiler=SharedCompiler(mode,log=folder/'compile.log');exe=folder/'probe.exe'
        compiler.build([ROOT/'tools/probe_gpu.c',ROOT/'src/native_gpu.c',ROOT/'src/native_graphics.c'],exe,
            compiler.includes([ROOT/'src',ROOT/'third_party/vulkan/include']),libraries=['user32'])
        result=owned_run([str(exe)],ROOT,os.environ.copy(),60)
        (folder/'stdout.json').write_text(result.stdout);(folder/'stderr.log').write_text(result.stderr)
        require(result.returncode==0,'physical GPU transfer probe failed');observation=json.loads(result.stdout)
        require(observation.get('status')=='passed'and observation.get('synthetic_data_only')is True and
            observation.get('game_frame_proven')is False and
            (observation.get('copies'),observation.get('uploads'),observation.get('downloads'))==(32,16,16),
            'physical GPU transfer result differs')
        compilers[mode]=dict(executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),observation=observation)
    require(compilers['cmake']['observation']==compilers['gcc']['observation'],'physical GPU compiler observations differ')
    report=dict(format='oot-renderer-foundation-probe',shaders=shaders,invalid_request_rejected=True,compilers=compilers,
        game_code_executed=False,game_frame_proven=False,shader_validation='structural-only')
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool',type=Path,required=True)
    p.add_argument('--identity',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(probe(a.tool,a.identity,a.output),indent=2))
