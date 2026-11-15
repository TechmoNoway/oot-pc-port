"""Explicit real Win32/Vulkan/DXGI host probe; never part of synthetic CI."""
import argparse,hashlib,json,os
from pathlib import Path
from input_formats import require
from link_exefs import build_destination
from milestone_checkpoint import owned_run
from object_cache import SharedCompiler
ROOT=Path(__file__).resolve().parent.parent

def run(output):
    output=build_destination(output);require(not output.exists(),'choose a fresh physical probe directory')
    output.mkdir(parents=True);reports={}
    for mode in('cmake','gcc'):
        folder=output/mode;folder.mkdir();compiler=SharedCompiler(mode,log=folder/'build.log')
        flags=compiler.includes([ROOT/'src',ROOT/'third_party/vulkan/include'])+compiler.defines({'_CRT_SECURE_NO_WARNINGS':None})
        exe=folder/'probe.exe';compiler.build([ROOT/'tests/display_peers_physical.c',ROOT/'src/native_graphics.c',
            ROOT/'src/native_vblank.c'],exe,flags,libraries=['user32','dxgi','ole32'])
        result=owned_run([str(exe)],ROOT,os.environ.copy(),30)
        (folder/'execution.log').write_text(result.stdout+result.stderr)
        require(result.returncode==0,'physical display probe failed: '+result.stdout+result.stderr)
        report=json.loads(result.stdout)
        require(report.get('client_width')==1920 and report.get('client_height')==1080 and
            report.get('visible')is True and report.get('presentation_supported')is True and
            report.get('successful_waits_and_resets')==16 and report.get('physical_edges_observed',0)>=16 and
            report.get('guest_code_executed')is False,'physical host observation differs')
        reports[mode]=dict(observation=report,executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
    fields=('monitor_width','monitor_height','refresh_field','dpi','client_width','client_height')
    require(all(reports['cmake']['observation'][k]==reports['gcc']['observation'][k]for k in fields),
        'physical compiler observations differ')
    (output/'report.json').write_text(json.dumps(dict(format='oot-physical-display-peers',compilers=reports),indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args().output)
