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

typedef struct TraceFile {
    FILE *file;
    BCRYPT_HASH_HANDLE hash;
    uint8_t buffer[65536];
    size_t used;
    uint64_t rows, steps;
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
    if (size<0 || (size_t)size>=sizeof(row)) { out->failed=1; return; }
    if (out->used+(size_t)size>sizeof(out->buffer)) flush_hash(out);
    memcpy(out->buffer+out->used,row,(size_t)size);out->used+=(size_t)size;
    ++out->rows;
    if (r->event!=OOT_STARTUP_TRACE_STOP) ++out->steps;
    if ((!out->compact || out->rows<=64 || r->event!=OOT_STARTUP_TRACE_STEP || r->retired%10000==0) &&
        fwrite(row,1,(size_t)size,out->file)!=(size_t)size) out->failed=1;
}

static int parse_limit(const char *s, uint64_t *value)
{
    char *end;
    unsigned long long n;
    if (!*s || *s=='-' || *s=='+') return 0;
    errno=0; n=strtoull(s,&end,10);
    if (errno || *end || !n || n>OOT_STARTUP_MAX_RETIRED) return 0;
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
    const char *package=NULL, *trace_path=NULL;
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
    if (argc < 5 || strcmp(argv[3],"--trace")) goto usage;
    package=argv[2]; trace_path=argv[4];
    for (int i=5;i<argc;i+=2) {
        if (i+1==argc) goto usage;
        if (!strcmp(argv[i],"--limit")) { if (!parse_limit(argv[i+1],&limit)) goto usage; }
        else if (!strcmp(argv[i],"--quantum")) { if (!parse_limit(argv[i+1],&quantum)) goto usage; }
        else if (!strcmp(argv[i],"--trace-mode")) {
            if (!strcmp(argv[i+1],"compact")) trace.compact=1;
            else if (strcmp(argv[i+1],"full")) goto usage;
        }
        else goto usage;
    }
    image=oot_runtime_open(package,message,sizeof(message));
    if (!image) { fprintf(stderr,"Startup mapping failed: %s\n",message); goto cleanup; }
    context=oot_startup_context_create(image,oot_startup_compiled_config(),&error);
    if (!context) { fprintf(stderr,"Startup context rejected: %" PRIu32 "\n",error); goto cleanup; }
    pauth=oot_pauth_create(OOT_PAUTH_QARMA5_VA39,NULL);
    if (!pauth) { fputs("Startup PAC context failed.\n",stderr); goto cleanup; }
    dispatcher=oot_startup_dispatch_create(image,context,pauth,program,limit,&error);
    if (!dispatcher) { fprintf(stderr,"Startup selection rejected: %" PRIu32 "\n",error); goto cleanup; }
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
    if (report.service==0x29)
        printf(",\"get_info_request\":{\"info_id\":%" PRIu64 ",\"handle\":%" PRIu32 ",\"sub_id\":%" PRIu64 "}",
            state.x[1],(uint32_t)state.x[2],state.x[3]);
    printf(",\"trace_mode\":\"%s\",\"trace_rows\":%" PRIu64 ",\"trace_steps\":%" PRIu64 ",\"trace_sha256\":\"%s\"",
        trace.compact?"compact":"full",trace.rows,trace.steps,digest_hex);
    puts("}");
    /* A diagnostic boundary is not a completed process or a successful boot. */
    result=report.status==OOT_STARTUP_STOPPED ? 3 : 1;
cleanup:
    if (trace.hash) BCryptDestroyHash(trace.hash);
    if (trace.file) fclose(trace.file);
    if (dispatcher) (void)oot_startup_dispatch_destroy(dispatcher);
    oot_pauth_destroy(pauth);
    oot_startup_context_destroy(context);
    oot_runtime_close(image);
    return result;
usage:
    fputs("Usage: oot-pc-port --boot-images FILE --trace NEW_FILE [--limit N] [--quantum N] [--trace-mode full|compact]\n",stderr);
    return 2;
#endif
}
