#include "startup_cli.h"
#include "startup_dispatch.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#ifdef OOT_HAS_STARTUP_PROGRAM
const OotStartupProgram *oot_startup_compiled_program(void);
const OotStartupConfig *oot_startup_compiled_config(void);
const OotStartupProbe *oot_startup_compiled_probes(size_t *count);
const OotSdkConfig *oot_startup_compiled_sdk_config(void);
const OotSdkGoal *oot_startup_compiled_sdk_goal(void);
const OotNativeFunction *oot_startup_compiled_native_functions(size_t *count);
uint64_t oot_startup_compiled_original_oe_entry(void);
const OotStartupFastFunction *oot_startup_compiled_fast_functions(size_t *count);
const OotStartupConstructor *oot_startup_compiled_constructors(size_t *count);

typedef struct TraceFile {
    FILE *file;
    BCRYPT_HASH_HANDLE hash;
    uint8_t buffer[65536];
    size_t used;
    uint64_t rows, steps;
    uint64_t original_oe_entry;
    int original_oe_seen;
    int failed, compact;
} TraceFile;

static void flush_hash(TraceFile *out)
{
    if (out->used && BCryptHashData(out->hash,out->buffer,(ULONG)out->used,0)<0) out->failed=1;
    out->used=0;
}

static void write_trace(const OotStartupTrace *r, void *user)
{
    TraceFile *out = user;
    char row[256];
    int size=snprintf(row,sizeof(row),"{\"pc\":\"0x%" PRIx64 "\",\"next_pc\":\"0x%" PRIx64
        "\",\"retired\":%" PRIu64 ",\"word\":%" PRIu32 ",\"event\":%" PRIu32
        ",\"error\":%" PRIu32 ",\"service\":%" PRIu32 "}\n",
        r->pc,r->next_pc,r->retired,r->word,r->event,r->error,r->service);
    if (out->failed) return;
    if (out->original_oe_entry && r->pc==out->original_oe_entry && r->event==OOT_STARTUP_TRACE_STEP)
        out->original_oe_seen=1;
    if (size<0 || (size_t)size>=sizeof(row)) { out->failed=1; return; }
    if (out->used+(size_t)size>sizeof(out->buffer)) flush_hash(out);
    memcpy(out->buffer+out->used,row,(size_t)size);out->used+=(size_t)size;
    ++out->rows;
    if (r->event!=OOT_STARTUP_TRACE_STOP) ++out->steps;
    if ((!out->compact || out->rows<=64 || r->event!=OOT_STARTUP_TRACE_STEP || r->retired%10000==0) &&
        fwrite(row,1,(size_t)size,out->file)!=(size_t)size) out->failed=1;
}

static int parse_limit(const char *s, uint64_t *value, uint64_t maximum)
{
    char *end;
    unsigned long long n;
    if (!*s || *s=='-' || *s=='+') return 0;
    errno=0; n=strtoull(s,&end,10);
    if (errno || *end || !n || n>maximum) return 0;
    *value=(uint64_t)n; return 1;
}
#endif

int oot_startup_cli(int argc, char **argv)
{
    if (argc < 2 || strcmp(argv[1],"--boot-images")) return -1;
#ifndef OOT_HAS_STARTUP_PROGRAM
    fputs("This executable has no compiled startup selection. Use tools/build_startup.py to prepare a private raw-image build.\n",stderr);
    return 2;
#else
    const char *package=NULL, *trace_path=NULL, *entropy_path=NULL;
    uint64_t limit=1000000,quantum=1000;
    uint32_t error=0;
    char message[192];
    OotRuntimeImage *image=NULL;
    OotStartupContext *context=NULL;
    OotPauth *pauth=NULL;
    OotStartupDispatcher *dispatcher=NULL;
    OotStartupReport report={0};
    OotArm64State state;
    TraceFile trace={0};
    uint8_t digest[32]={0};
    char digest_hex[65];
    int result=1;
    size_t probe_count=0,probe_matches=0;
    const OotStartupProgram *program=oot_startup_compiled_program();
    trace.original_oe_entry=oot_startup_compiled_original_oe_entry();
    const OotSdkConfig *compiled_sdk=oot_startup_compiled_sdk_config();
    OotSdkConfig sdk={0};
    int native_stop=0,fast_functions=0;
    uint64_t maximum=compiled_sdk ? OOT_STARTUP_SDK_MAX_RETIRED : OOT_STARTUP_MAX_RETIRED;
    if (argc < 5 || strcmp(argv[3],"--trace")) goto usage;
    package=argv[2]; trace_path=argv[4];
    for (int i=5;i<argc;i+=2) {
        if (i+1==argc) goto usage;
        if (!strcmp(argv[i],"--limit")) { if (!parse_limit(argv[i+1],&limit,maximum)) goto usage; }
        else if (!strcmp(argv[i],"--quantum")) { if (!parse_limit(argv[i+1],&quantum,maximum)) goto usage; }
        else if (!strcmp(argv[i],"--entropy-file") && compiled_sdk) entropy_path=argv[i+1];
        else if (!strcmp(argv[i],"--trace-mode")) {
            if (!strcmp(argv[i+1],"compact")) trace.compact=1;
            else if (strcmp(argv[i+1],"full")) goto usage;
        }
        else if (!strcmp(argv[i],"--fast-functions") && !strcmp(argv[i+1],"1")) fast_functions=1;
        else goto usage;
    }
    image=oot_runtime_open(package,message,sizeof(message));
    if (!image) { fprintf(stderr,"Startup mapping failed: %s\n",message); goto cleanup; }
    if (compiled_sdk) {
        sdk=*compiled_sdk;
        if (entropy_path) {
            uint8_t bytes[32];
            FILE *input=fopen(entropy_path,"rb");
            if (!input) { fputs("SDK entropy input could not be opened.\n",stderr); goto cleanup; }
            size_t count=fread(bytes,1,sizeof(bytes),input);
            int extra=fgetc(input),failed=ferror(input);
            fclose(input);
            if (count!=sizeof(bytes) || extra!=EOF || failed) {
                SecureZeroMemory(bytes,sizeof(bytes));
                fputs("SDK entropy input must contain exactly 32 bytes.\n",stderr); goto cleanup;
            }
            for (unsigned i=0;i<4;++i) {
                sdk.entropy[i]=0;
                for (unsigned j=0;j<8;++j) sdk.entropy[i]|=(uint64_t)bytes[i*8+j]<<(8*j);
            }
            SecureZeroMemory(bytes,sizeof(bytes));
            sdk.flags|=OOT_SDK_EXPLICIT_ENTROPY;
        }
        context=oot_startup_context_create_sdk(image,oot_startup_compiled_config(),&sdk,&error);
        SecureZeroMemory(sdk.entropy,sizeof(sdk.entropy));
    } else context=oot_startup_context_create(image,oot_startup_compiled_config(),&error);
    if (!context) { fprintf(stderr,"Startup context rejected: %" PRIu32 "\n",error); goto cleanup; }
    pauth=oot_pauth_create(OOT_PAUTH_QARMA5_VA39,NULL);
    if (!pauth) { fputs("Startup PAC context failed.\n",stderr); goto cleanup; }
    dispatcher=(program->flags&OOT_STARTUP_HOST_LINKED) ? oot_startup_dispatch_create_host(image,context,pauth,program,limit,&error) :
        oot_startup_context_init_enabled(context) ? oot_startup_dispatch_create_init(image,context,pauth,program,limit,&error) :
        oot_startup_context_native_enabled(context) ? oot_startup_dispatch_create_native(image,context,pauth,program,limit,&error) :
        compiled_sdk ? oot_startup_dispatch_create_sdk(image,context,pauth,program,limit,&error) :
        oot_startup_dispatch_create(image,context,pauth,program,limit,&error);
    if (!dispatcher) { fprintf(stderr,"Startup selection rejected: %" PRIu32 "\n",error); goto cleanup; }
    if (oot_startup_context_native_enabled(context)) {
        size_t count=0;
        const OotNativeFunction *functions=oot_startup_compiled_native_functions(&count);
        if (!oot_startup_dispatch_set_native_functions(dispatcher,functions,count,&error)) {
            fprintf(stderr,"Native SDK bindings rejected: %" PRIu32 "\n",error); goto cleanup;
        }
    }
    if (compiled_sdk && !oot_startup_dispatch_set_sdk_goal(dispatcher,oot_startup_compiled_sdk_goal(),&error)) {
        fprintf(stderr,"SDK goal rejected: %" PRIu32 "\n",error); goto cleanup;
    }
    if(program->flags&OOT_STARTUP_HOST_LINKED){size_t n=0;const OotStartupConstructor *c=oot_startup_compiled_constructors(&n);
        if(!oot_startup_dispatch_set_constructors(dispatcher,c,n)){fputs("Constructor observers rejected.\n",stderr);goto cleanup;}
    }
    if(fast_functions){size_t n=0;const OotStartupFastFunction *f=oot_startup_compiled_fast_functions(&n);
        if(n && !oot_startup_dispatch_set_fast_functions(dispatcher,f,n)){fputs("Fast function registry rejected.\n",stderr);goto cleanup;}
        if(!oot_startup_context_init_enabled(context))goto cleanup;
    }
    if (!oot_startup_context_initial_state(context,program->entry,&state)) {
        fputs("Startup state initialization rejected.\n",stderr); goto cleanup;
    }
    (void)oot_startup_dispatch_begin(dispatcher,&state,&report);
    if (report.status != OOT_STARTUP_READY) {
        fprintf(stderr,"Startup entry rejected: %" PRIu32 "\n",report.error); goto cleanup;
    }
    /* Exclusive creation prevents accidental destruction of a package or log. */
    trace.file=fopen(trace_path,"wx");
    if (!trace.file) { fputs("Choose a fresh writable startup trace path.\n",stderr); goto cleanup; }
    if (BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE,&trace.hash,NULL,0,NULL,0,0)<0) {
        fputs("Startup trace hash initialization failed.\n",stderr);goto cleanup;
    }
    do {
        (void)oot_startup_dispatch_run(dispatcher,&state,quantum,write_trace,&trace,&report);
    } while (report.status==OOT_STARTUP_YIELDED && !trace.failed);
    flush_hash(&trace);
    if (BCryptFinishHash(trace.hash,digest,sizeof(digest),0)<0) trace.failed=1;
    for (unsigned i=0;i<32;++i) { digest_hex[2*i]="0123456789abcdef"[digest[i]>>4];digest_hex[2*i+1]="0123456789abcdef"[digest[i]&15]; }
    digest_hex[64]=0;
    if (fclose(trace.file)) trace.failed=1;
    trace.file=NULL;
    if (trace.failed) { fputs("Startup trace write failed.\n",stderr); goto cleanup; }
    {
        const OotStartupProbe *probes=oot_startup_compiled_probes(&probe_count);
        for (size_t i=0;i<probe_count;++i) {
            uint64_t value;
            if (oot_memory_load(oot_startup_context_memory(context),probes[i].address,8,&value) && value==probes[i].value)
                ++probe_matches;
        }
    }
    printf("{\"format\":\"oot-startup-run\",\"schema_version\":1,\"status\":%" PRIu32
        ",\"error\":%" PRIu32 ",\"pc\":\"0x%" PRIx64 "\",\"retired\":%" PRIu64
        ",\"word\":%" PRIu32 ",\"service\":%" PRIu32
        ",\"guest_code_executed\":%s,\"startup_completed\":false,\"process_abi\":\"experimental\""
        ",\"relative_relocation_probes\":%zu,\"relative_relocations_matching_offline_link\":%zu",
        report.status,report.error,report.pc,report.retired,report.word,report.service,
        report.retired ? "true":"false",probe_count,probe_matches);
    if (oot_startup_context_native_enabled(context)) {
        size_t count=0;
        const OotNativeFunction *functions=oot_startup_compiled_native_functions(&count);
        for (size_t i=0;i<count;++i)
            if (report.pc>=functions[i].entry && report.pc-functions[i].entry<functions[i].size &&
                report.service==functions[i].id) native_stop=1;
    }
    if (report.service==0x02 && !native_stop)
        printf(",\"memory_permission_request\":{\"address\":%" PRIu64 ",\"size\":%" PRIu64 ",\"permission\":%" PRIu32 "}",
            state.x[0],state.x[1],(uint32_t)state.x[2]);
    if (report.service==0x03 && !native_stop)
        printf(",\"memory_attribute_request\":{\"address\":%" PRIu64 ",\"size\":%" PRIu64 ",\"mask\":%" PRIu32 ",\"attribute\":%" PRIu32 "}",
            state.x[0],state.x[1],(uint32_t)state.x[2],(uint32_t)state.x[3]);
    if (report.service==0x29 && !native_stop)
        printf(",\"get_info_request\":{\"info_id\":%" PRIu64 ",\"handle\":%" PRIu32 ",\"sub_id\":%" PRIu64 "}",
            state.x[1],(uint32_t)state.x[2],state.x[3]);
    printf(",\"sdk_runtime\":%s,\"sdk_stages_completed\":%" PRIu32
        ",\"sdk_initialization_completed\":%s,\"game_entry_reached\":%s",
        compiled_sdk ? "true":"false",oot_startup_dispatch_sdk_stages_completed(dispatcher),
        report.error==OOT_STARTUP_SDK_INITIALIZED ? "true":"false",
        report.error==OOT_STARTUP_SDK_INITIALIZED ? "true":"false");
    if (compiled_sdk && report.service==0x1f && !native_stop) {
        uint8_t name[4];
        int sm=oot_memory_load_record(oot_startup_context_memory(context),state.x[1],name,sizeof(name)) &&
            !memcmp(name,"sm:",sizeof(name));
        /* Match only this known protocol name; never dump arbitrary guest bytes. */
        printf(",\"named_port\":\"%s\"",sm ? "sm:":"unrecognized");
    }
    if (oot_startup_context_native_enabled(context)) {
        const OotSdkNative *native=oot_startup_context_native(context);
        printf(",\"native_sdk\":true,\"native_handler_stop\":%s,\"original_oe_initialize_entered\":%s,\"native_calls\":%" PRIu64
            ",\"native_stats\":{\"calls\":%" PRIu64 ",\"logging_initializations\":%" PRIu64
            ",\"destination_updates\":%" PRIu64 ",\"log_records\":%" PRIu64 ",\"log_bytes\":%" PRIu64 "}",
            native_stop ? "true":"false",trace.original_oe_seen ? "true":"false",
            oot_startup_dispatch_native_calls(dispatcher),native->calls,native->logging_initializations,
            native->destination_updates,native->log_records,native->log_bytes);
    }
    if (oot_startup_context_init_enabled(context)) {
        OotStartupProtectionStats protection={0};
        (void)oot_startup_context_protection_stats(context,&protection);
        const OotNativePlatform *platform=oot_startup_context_platform(context);
        const OotNativeServices *services=oot_startup_context_services(context);
        printf(",\"sdk_init_providers\":true,\"init_stats\":{\"platform_initialized\":%u,\"platform_calls\":%" PRIu64
            ",\"platform_initializations\":%" PRIu64 ",\"cpu_boost_mode\":%u,\"service_calls\":%" PRIu64
            ",\"aoc_initialized\":%u,\"err_initialized\":%u,\"diag_initialized\":%u,\"pctl_initialized\":%u"
            ",\"fs_mode\":%u,\"local_access_log\":%u,\"result_handled\":%u,\"clock_initialized\":%u,\"heap_size\":%" PRIu64
            ",\"relro_readonly_bytes\":%" PRIu64 ",\"relro_locked_bytes\":%" PRIu64
            ",\"permission_updates\":%" PRIu64 ",\"permission_locks\":%" PRIu64 "}",
            platform->initialized,platform->calls,platform->initialization_calls,platform->cpu_boost_mode,services->calls,
            services->aoc_initialized,services->err_initialized,services->diag_initialized,services->pctl_initialized,
            services->fs_mode,services->local_access_log,services->result_handled,services->clock_initialized,
            oot_startup_context_heap_size(context),protection.readonly_bytes,protection.locked_bytes,
            protection.permission_updates,protection.permission_locks);
    }
    if(program->flags&OOT_STARTUP_HOST_LINKED)printf(",\"host_linked\":true,\"host_scaffold_retired\":%" PRIu64 ",\"original_retired\":%" PRIu64 ",\"constructors_completed\":%" PRIu32,oot_startup_dispatch_host_steps(dispatcher),report.retired-oot_startup_dispatch_host_steps(dispatcher),oot_startup_dispatch_constructors_completed(dispatcher));
    if(fast_functions)printf(",\"fast_function_calls\":%" PRIu64,oot_startup_dispatch_fast_calls(dispatcher));
    printf(",\"trace_mode\":\"%s\",\"trace_rows\":%" PRIu64 ",\"trace_steps\":%" PRIu64 ",\"trace_sha256\":\"%s\"",
        trace.compact?"compact":"full",trace.rows,trace.steps,digest_hex);
    puts("}");
    /* A diagnostic boundary is not a completed process or a successful boot. */
    result=report.status==OOT_STARTUP_STOPPED ? (report.error==OOT_STARTUP_SDK_INITIALIZED ? 0:3) : 1;
cleanup:
    if (trace.hash) BCryptDestroyHash(trace.hash);
    if (trace.file) fclose(trace.file);
    if (dispatcher) (void)oot_startup_dispatch_destroy(dispatcher);
    oot_pauth_destroy(pauth);
    oot_startup_context_destroy(context);
    oot_runtime_close(image);
    return result;
usage:
    fputs("Usage: oot-pc-port --boot-images FILE --trace NEW_FILE [--limit N] [--quantum N] [--trace-mode full|compact] [--entropy-file FILE]\n",stderr);
    return 2;
#endif
}
