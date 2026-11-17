"""Explicit two-compiler physical resource-owner probes; synthetic storage only."""
import argparse,hashlib,json,os
from pathlib import Path
from input_formats import require
from link_exefs import build_destination
from object_cache import SharedCompiler
from milestone_checkpoint import owned_run
ROOT=Path(__file__).resolve().parents[1]
def probe(output):
    output=build_destination(output);require(not output.exists(),'choose fresh resource probe output');output.mkdir(parents=True)
    observations={}
    for mode in ('cmake','gcc'):
        folder=output/mode;folder.mkdir();compiler=SharedCompiler(mode,log=folder/'build.log');exe=folder/'resources.exe'
        compiler.build([ROOT/'tools/probe_nvn_resources.c',ROOT/'src/native_gpu.c',ROOT/'src/native_graphics.c',ROOT/'src/guest_memory.c'],exe,
            compiler.includes([ROOT/'src',ROOT/'third_party/vulkan/include']),libraries=['user32'])
        result=owned_run([str(exe)],ROOT,os.environ.copy(),60);(folder/'execution.log').write_text(result.stdout+result.stderr)
        require(result.returncode==0,'physical resource probe failed');r=json.loads(result.stdout)
        require(r.get('status')=='passed' and r.get('copies')==r.get('recaptures')==r.get('readbacks')==16 and
            r.get('initializations')==r.get('finalizations')==2 and r.get('peak_descriptor_slots')==37164 and r.get('peak_samplers')==4 and r.get('sampler_registrations')==2 and r.get('sampler_anisotropy')==r.get('shader_image_gather_extended')==1 and
            r.get('descriptor_initializations')==r.get('descriptor_finalizations')==2 and r.get('synthetic_data_only')is True and
            r.get('game_frame_proven')is False,'physical resource probe observation differs')
        observations[mode]=dict(executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),observation=r)
    require(observations['cmake']['observation']==observations['gcc']['observation'],'physical resource compiler observations differ')
    report=dict(format='oot-nvn-resource-probe',compilers=observations,game_code_executed=False,game_frame_proven=False)
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();print(json.dumps(probe(a.output)))
