"""Build the separately licensed compiler tool from verified pinned sources."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
from fetch_shader_compiler import fetch
from input_formats import require
from lifter_validation import find_cmake
from shader_tool import ROOT,adapter_identity,digest

def build(output):
    output=Path(output).resolve();require(output.is_relative_to(ROOT/'build'),'shader compiler output must stay under build/')
    vendor=ROOT/'toolchain/shader-compiler/vendor';spirv=vendor.parent/'spirv'
    for target,lock in((vendor,'shader-compiler.json'),(spirv,'spirv-headers.json')):
        fetch(target,ROOT/'config/dependencies'/lock)
    output.mkdir(parents=True,exist_ok=True);cmake=find_cmake()
    commands=([str(cmake),'-S',str(ROOT/'tools/shader_compiler'),'-B',str(output),'-A','x64',
        '-DOOT_SHADER_VENDOR='+str(vendor),'-DOOT_SPIRV_HEADERS='+str(spirv)],
        [str(cmake),'--build',str(output),'--config','Release','--','/m:1','/nodeReuse:false'])
    identity=adapter_identity()
    for n,command in enumerate(commands):
        with (output/('configure.log'if n==0 else'build.log')).open('wb')as log:
            completed=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=1200,check=False)
        require(completed.returncode==0,'shader compiler build failed; see private build logs')
    require(identity==adapter_identity(),'shader adapter changed during build')
    binary=output/'Release/oot-shader-tool.exe';require(binary.is_file(),'shader compiler executable is missing')
    version=subprocess.run([str(binary),'--version'],capture_output=True,text=True,timeout=15,check=True).stdout.strip()
    result=dict(schema=1,adapter=identity,binary_sha256=digest(binary.read_bytes()),version=version,
        dependencies=[json.loads((ROOT/'config/dependencies'/p).read_text())['commit']for p in('shader-compiler.json','spirv-headers.json')],
        license_scope='Separate GPL shader compiler; preserve pinned dependency sources and notices')
    (output/'tool-identity.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'build/shader-compiler')
    a=p.parse_args();print(json.dumps(build(a.output),indent=2))
