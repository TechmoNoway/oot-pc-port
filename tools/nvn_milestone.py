"""Full original NVN diagnostic lanes, kept separate from renderer readiness."""
import hashlib,json,shutil,sys
from pathlib import Path
from input_formats import require

def validate_nvn_config(c):
    require(type(c.get('nvn_experiment',False))is bool,'invalid NVN milestone flag')
    if c.get('name')=='nvn-bootstrap':require(c.get('nvn_experiment')is True,'NVN milestone requires execution')
    if not c.get('nvn_experiment'):return
    require(c.get('refresh_experiment')is True and c.get('refresh_expected_guard')=='nvnBootstrapLoader'and
        isinstance(c.get('nvn_seed_report'),str)and c['nvn_seed_report'],'NVN requires the retained refresh loader boundary and source seed')
    require(c.get('nvn_expected_guard')=='nvnDeviceGetInteger'and type(c.get('nvn_expected_query'))is int and
        0<=c['nvn_expected_query']<=169 and c['nvn_expected_query']not in(0,1,42,90),'invalid NVN property boundary')
    require(type(c.get('nvn_min_post_entry'))is int and c['nvn_min_post_entry']>c['refresh_min_post_entry'],'invalid NVN retirement bound')
    require(all(isinstance(c.get(k),str)and c[k].startswith('build/')for k in
        ('renderer_shader_tool','renderer_shader_identity')),'NVN milestone requires the separately bound shader tool')

def run_nvn_lanes(run,c,env):
    from run_milestone import ROOT,read_json,application_evidence
    from link_exefs import build_destination
    from build_startup import execute,validated_romfs_input
    from startup_sources import cached_sources
    from nvn_progress import verify_nvn_progress_trace
    seed=read_json(build_destination(ROOT/c['nvn_seed_report']));prior=seed['iterations'][-1]
    require(seed.get('nvn_runtime')is True and seed.get('host_linked')is True,'NVN seed is not a source-selection diagnostic')
    old_seed=read_json(build_destination(Path(prior['bundle'])/'manifest.json'))
    baseline=read_json(ROOT/c['baseline_sdk_init']);audit=read_json(run.output/'nvn-audit.json')
    entropy=run.output/'process-entropy.bin';romfs=build_destination(ROOT/c['application_romfs_index'])
    romfs_input=validated_romfs_input(ROOT/c['prepared'],romfs);experiments={};proofs={}
    keys=('status','error','pc','retired','word','service','trace_sha256','trace_steps','trace_rows','native_calls','native_stats',
        'sdk_stages_completed','sdk_initialization_completed','game_entry_reached','init_stats','original_retired',
        'host_scaffold_retired','constructors_completed','application_entry_retired','post_entry_retired',
        'application_services','application_thread','application_resource','application_graphics','application_display',
        'graphics_runtime','display_runtime','objects_runtime','events_runtime','refresh_runtime','display_objects',
        'display_refresh','nvn_runtime','nvn','game_frame_proven','romfs','native_handler_stop','application_stop_arguments')
    for mode in('cmake','gcc'):
        folder=run.output/('nvn-'+mode);cache=folder/'native-cache'
        args=[sys.executable,'-B','tools/build_startup.py',ROOT/c['prepared'],'--output',folder,'--compiler',mode,
            '--sdk','--native-sdk','--sdk-init','--host-linked','--application','--graphics','--display','--objects','--events',
            '--refresh','--nvn','--fast-functions','--execute','--entropy-file',entropy,'--native-cache',cache,'--romfs-index',romfs,
            '--expand-targets','64','--limit','1000000000','--quantum','10000']
        for pc in prior['additional_entries']:args+=['--extra-entry',str(pc)]
        for pc in prior['application_entries']:args+=['--app-entry',str(pc)]
        run.command('nvn-experiment-'+mode,args,env)
        result=read_json(folder/'run.json');last=result['iterations'][-1];bundle=read_json(Path(last['bundle'])/'manifest.json')
        require(result.get('nvn_runtime')is True and bundle['native_audit']==audit and
            bundle['sdk_npdm']==old_seed['sdk_npdm']and
            result['entropy_input_sha256']==hashlib.sha256(entropy.read_bytes()).hexdigest(),'NVN source/audit/NPDM/entropy identity differs')
        cached_sources(Path(last['bundle']),folder/'source-verification')
        require(last['build']['source_manifest_sha256']==hashlib.sha256((Path(last['bundle'])/'sources.json').read_bytes()).hexdigest()and
            last['build'].get('romfs_index_sha256')==romfs_input['index_sha256']and
            last['build'].get('romfs_binding_sha256')==hashlib.sha256((cache/'romfs_binding.h').read_bytes()).hexdigest()and
            last['executable_sha256']==hashlib.sha256(Path(last['executable']).read_bytes()).hexdigest(),'NVN generated/native/content identity differs')
        e=application_evidence(result,bundle,baseline,c['sdk_init_required_stages'],c['nvn_min_post_entry'],
            c['nvn_expected_guard'],romfs_input,expected_native=461,expected_query=c['nvn_expected_query'])
        require(e.get('game_frame_proven')is False,'NVN diagnostic cannot establish a frame')
        full_dir=run.proof_directory(folder,'progress-full');full_dir.mkdir()
        shutil.copyfile(Path(last['bundle'])/'startup.ootmem',full_dir/'startup.ootmem')
        full=execute(Path(last['executable']),full_dir,1000000000,10000,'full',entropy,False,romfs_index=romfs)
        (full_dir/'report.json').write_text(json.dumps(full,indent=2)+'\n')
        require(all(e.get(k)==full.get(k)for k in keys),'NVN full/compact or accelerated/single-step evidence differs')
        old_folder=run.output/('refresh-'+mode);old=read_json(old_folder/'run.json')['iterations'][-1]
        old_full=read_json(old_folder/'progress-full/report.json');old_bundle=read_json(Path(old['bundle'])/'manifest.json')
        require(run.manifest['stages']['refresh-experiment-'+mode].get('verified')is True and
            old_full['trace_sha256']==old['execution']['trace_sha256'],'NVN preceding full refresh lane is unverified')
        proof=verify_nvn_progress_trace(Path(old_full['trace_file']),old_full,old_bundle,Path(full['trace_file']),full,bundle)
        (full_dir/'nvn-progress.json').write_text(json.dumps(proof,indent=2)+'\n');run.publish_proof(folder,'progress-full',full_dir)
        experiments[mode]=e;proofs[mode]=proof
    require(all(experiments['cmake'].get(k)==experiments['gcc'].get(k)for k in keys),'NVN compiler prefix/state agreement failed')
    run.mark_verified(['nvn-experiment-'+m for m in('cmake','gcc')])
    return dict(nvn_experiments=experiments,nvn_progress=proofs)
