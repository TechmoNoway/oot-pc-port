#include "startup_dispatch.h"
#include "checked_read.h"
#include "startup_init_atomic.h"
#include "native_math.h"

#include <stdlib.h>
#include <string.h>

#define STARTUP_ADDRESS_LIMIT (UINT64_C(1) << 39)

struct OotStartupDispatcher {
    OotRuntimeImage *image;
    OotStartupContext *context;
    OotPauth *pauth;
    OotStartupInstruction *instructions;
    OotStartupSpan *spans;
    size_t instruction_count, span_count;
    uint8_t body_sha256[32];
    uint64_t entry, limit, retired, stack_base, stack_top;
    OotArm64State checkpoint;
    OotStartupVectorState vector_checkpoint;
    uint32_t phase, executing, stop_error, stop_word, stop_service;
    uint32_t sdk, has_goal, stage_count, stages_completed, goal_bad_order, goal_thunk_retired;
    uint64_t goal_thunk, goal_entry, stages[OOT_STARTUP_SDK_MAX_STAGES];
    OotNativeFunction *native_functions;
    size_t native_function_count;
    uint64_t native_calls;
    uint32_t native, initialization, host_linked, application;
    uint32_t initialization_reached, application_entry_retired;
    uint64_t initialization_retired;
    uint64_t scaffold_retired;
    OotStartupFastFunction *fast;
    size_t fast_count;
    uint64_t fast_calls;
    OotStartupConstructor constructors[16];
    uint32_t constructor_count, constructor_bad, constructor_depth;
    uint32_t constructor_completed[16];
    struct { uint64_t sp, lr; uint32_t index, body; } constructor_frames[32];
};

static int same_state(const OotArm64State *a, const OotArm64State *b)
{
    return !memcmp(a->x,b->x,sizeof(a->x)) && a->sp == b->sp &&
        a->pc == b->pc && a->nzcv == b->nzcv;
}

static int same_vectors(const OotStartupDispatcher *d)
{
    const OotStartupVectorState *vectors;
    if (!d->initialization) return 1;
    vectors=oot_startup_context_vectors(d->context);
    return vectors && !memcmp(vectors,&d->vector_checkpoint,sizeof(*vectors));
}

static size_t find_instruction(const OotStartupDispatcher *d, uint64_t pc)
{
    size_t first = 0, last = d->instruction_count;
    while (first < last) {
        size_t middle = first + (last-first)/2;
        if (d->instructions[middle].pc < pc) first = middle+1;
        else last = middle;
    }
    return first < d->instruction_count && d->instructions[first].pc == pc ? first : d->instruction_count;
}

static size_t find_native_function(const OotStartupDispatcher *d, uint64_t pc)
{
    size_t first=0,last=d->native_function_count;
    while (first<last) {
        size_t middle=first+(last-first)/2;
        if (d->native_functions[middle].entry<=pc) first=middle+1;
        else last=middle;
    }
    if (first && pc-d->native_functions[first-1].entry<d->native_functions[first-1].size) return first-1;
    return d->native_function_count;
}

static int covers_goal(const OotStartupDispatcher *d, uint64_t entry, uint32_t size)
{
    for(size_t n=0;n<d->constructor_count;++n)
        if(entry<d->constructors[n].entry+d->constructors[n].size && d->constructors[n].entry<entry+size)return 1;
    if (!d->has_goal) return 0;
    if ((d->goal_entry>=entry && d->goal_entry-entry<size) ||
        (d->goal_thunk>=entry && d->goal_thunk-entry<size)) return 1;
    for (uint32_t n=0;n<d->stage_count;++n)
        if (d->stages[n]>=entry && d->stages[n]-entry<size) return 1;
    return 0;
}

static void observe_constructor(OotStartupDispatcher *d,uint64_t pc,uint64_t next_pc)
{
    if(!d->host_linked || d->constructor_bad)return;
    for(uint32_t n=0;n<d->constructor_count;++n){
        const OotStartupConstructor *c=d->constructors+n;
        if(pc==c->body_entry-4 && (uint32_t)d->checkpoint.x[8]!=1 && (uint32_t)d->checkpoint.x[8]!=2){d->constructor_bad=1;return;}
        if(pc==c->entry){
            OotArm64State original=d->checkpoint;
            if(d->constructor_depth==32 || oot_pauth_step(d->pauth,&original,UINT32_C(0xd50323ff))!=OOT_PAUTH_AUTHENTICATED ||
               original.x[30]>=STARTUP_ADDRESS_LIMIT || (original.x[30]&3)) {d->constructor_bad=1;return;}
            d->constructor_frames[d->constructor_depth].index=n;
            d->constructor_frames[d->constructor_depth].sp=original.sp;
            d->constructor_frames[d->constructor_depth].lr=original.x[30];
            d->constructor_frames[d->constructor_depth++].body=0;
        }
        if(pc==c->body_entry || pc==c->return_pc){
            if(!d->constructor_depth || d->constructor_frames[d->constructor_depth-1].index!=n){d->constructor_bad=1;return;}
            if(pc==c->body_entry)d->constructor_frames[d->constructor_depth-1].body=1;
            else{
                uint32_t at=--d->constructor_depth;
                if(d->checkpoint.sp!=d->constructor_frames[at].sp || next_pc!=d->constructor_frames[at].lr){d->constructor_bad=1;return;}
                if(d->constructor_frames[at].body && ++d->constructor_completed[n]!=1)d->constructor_bad=1;
            }
        }
    }
}

static int result(const OotStartupDispatcher *d, OotStartupReport *out,
    uint32_t status, uint32_t error, uint32_t word, uint32_t service)
{
    if (out) *out = (OotStartupReport){d ? d->checkpoint.pc : 0,d ? d->retired : 0,status,error,word,service};
    return (int)status;
}

static void trace_row(OotStartupDispatcher *d, OotStartupTraceSink sink, void *user,
    uint64_t pc, uint64_t next_pc, uint32_t word, uint32_t event, uint32_t error, uint32_t service)
{
    OotStartupTrace row = {pc,next_pc,d->retired,word,event,error,service};
    if(event==OOT_STARTUP_TRACE_STEP || event==OOT_STARTUP_TRACE_SERVICE)observe_constructor(d,pc,next_pc);
    if(d->application && d->initialization_reached && pc==d->goal_entry &&
       (event==OOT_STARTUP_TRACE_STEP || event==OOT_STARTUP_TRACE_SERVICE))d->application_entry_retired=1;
    if(d->host_linked && (event==OOT_STARTUP_TRACE_STEP || event==OOT_STARTUP_TRACE_SERVICE) &&
       pc>=d->entry && pc-d->entry<4096)++d->scaffold_retired;
    if (!sink) return;
    d->executing = 1;
    sink(&row,user);
    d->executing = 0;
}

static int stop(OotStartupDispatcher *d, OotStartupReport *out,
    OotStartupTraceSink sink, void *user, uint32_t error, uint32_t word,
    uint32_t service, uint64_t next_pc, int contract)
{
    d->phase = contract ? 3u : 2u;
    d->stop_error = error; d->stop_word = word; d->stop_service = service;
    trace_row(d,sink,user,d->checkpoint.pc,next_pc,word,OOT_STARTUP_TRACE_STOP,error,service);
    return result(d,out,contract ? OOT_STARTUP_CONTRACT_FAULT : OOT_STARTUP_STOPPED,error,word,service);
}

static int pac_word(uint32_t word)
{
    return word == UINT32_C(0xd503233f) || word == UINT32_C(0xd503237f) ||
        word == UINT32_C(0xd50323bf) || word == UINT32_C(0xd50323ff) ||
        word == UINT32_C(0xd65f0bff) || word == UINT32_C(0xd65f0fff);
}

/* This decoder checks control transfers independently of compiled callbacks.
 * Value instructions still belong to the trusted, original-word-bound emitter. */
static uint32_t word_kind(uint32_t word)
{
    uint32_t reg = word & UINT32_C(0xfffffc1f);
    if (oot_startup_init_atomic_kind(word) || oot_startup_application_atomic_kind(word)) return OOT_STARTUP_SYSTEM;
    if (oot_startup_vector_kind(word) || oot_startup_application_vector_kind(word)) return OOT_STARTUP_VECTOR;
    if (word==UINT32_C(0xd50320ff)) return OOT_STARTUP_SYSTEM;
    uint32_t system = word & UINT32_C(0xffffffe0);
    if (system == UINT32_C(0xd53bd060) || system == UINT32_C(0xd53bd040) ||
        system == UINT32_C(0xd51bd040)) return OOT_STARTUP_SYSTEM;
    if ((word & UINT32_C(0xbfa07c00)) == UINT32_C(0x88a07c00)) return OOT_STARTUP_SYSTEM;
    if ((word & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50330bf) && ((word>>8)&3u)) return OOT_STARTUP_SYSTEM;
    if ((word & UINT32_C(0xffe0001f)) == UINT32_C(0xd4000001)) return OOT_STARTUP_SVC;
    if (reg == UINT32_C(0xd61f0000) || reg == UINT32_C(0xd63f0000) ||
        reg == UINT32_C(0xd65f0000) || word == UINT32_C(0xd65f0bff) || word == UINT32_C(0xd65f0fff))
        return OOT_STARTUP_INDIRECT;
    if ((word & UINT32_C(0x7c000000)) == UINT32_C(0x14000000) ||
        (word & UINT32_C(0xff000010)) == UINT32_C(0x54000000) ||
        (word & UINT32_C(0x7e000000)) == UINT32_C(0x34000000) ||
        (word & UINT32_C(0x7e000000)) == UINT32_C(0x36000000)) return OOT_STARTUP_BRANCH;
    return OOT_STARTUP_NORMAL;
}

static int control_expected(const OotStartupDispatcher *d, const OotStartupInstruction *i,
    const OotArm64State *before, OotArm64State *after)
{
    uint32_t word = i->word, masked = word & UINT32_C(0xfffffc1f);
    uint64_t target;
    *after = *before;
    if (pac_word(word)) return oot_pauth_step(d->pauth,after,word) != OOT_PAUTH_REJECTED;
    after->pc += 4;
    if ((word & UINT32_C(0x7c000000)) == UINT32_C(0x14000000)) {
        after->pc = before->pc + (oot_arm64_sign_extend(word & UINT32_C(0x03ffffff),26) << 2);
        if (word & UINT32_C(0x80000000)) after->x[30] = before->pc+4;
    } else if ((word & UINT32_C(0xff000010)) == UINT32_C(0x54000000)) {
        if (oot_arm64_condition(before->nzcv,word & 15))
            after->pc = before->pc + (oot_arm64_sign_extend((word >> 5) & 0x7ffff,19) << 2);
    } else if ((word & UINT32_C(0x7e000000)) == UINT32_C(0x34000000)) {
        unsigned nonzero = !!(word & (1u << 24));
        if ((unsigned)!!oot_arm64_read(before,word & 31,word >> 31 ? 64 : 32,0) == nonzero)
            after->pc = before->pc + (oot_arm64_sign_extend((word >> 5) & 0x7ffff,19) << 2);
    } else if ((word & UINT32_C(0x7e000000)) == UINT32_C(0x36000000)) {
        unsigned bit = ((word >> 31) << 5) | ((word >> 19) & 31), nonzero = !!(word & (1u << 24));
        if ((unsigned)!!(oot_arm64_read(before,word & 31,64,0) & (UINT64_C(1) << bit)) == nonzero)
            after->pc = before->pc + (oot_arm64_sign_extend((word >> 5) & 0x3fff,14) << 2);
    } else if (masked == UINT32_C(0xd61f0000) || masked == UINT32_C(0xd63f0000) || masked == UINT32_C(0xd65f0000)) {
        target = oot_arm64_read(before,(word >> 5) & 31,64,0);
        if (masked == UINT32_C(0xd63f0000)) after->x[30] = before->pc+4;
        after->pc = target;
    }
    return 1;
}

static int valid_metadata(const OotStartupInstruction *i, int sdk, int initialization,int application)
{
    uint32_t kind = word_kind(i->word);
    uint64_t target = i->pc+4;
    if (i->kind == OOT_STARTUP_UNSUPPORTED)
        return !i->run && i->next_a == i->pc && i->next_b == i->pc;
    if((oot_startup_application_atomic_kind(i->word) || oot_startup_application_vector_kind(i->word)) && !application)return 0;
    if (((kind==OOT_STARTUP_VECTOR || i->word==UINT32_C(0xd50320ff) || oot_startup_init_atomic_kind(i->word)) && !initialization) ||
        (kind == OOT_STARTUP_SYSTEM && !sdk) || i->kind != kind ||
        ((kind == OOT_STARTUP_SVC || kind == OOT_STARTUP_SYSTEM || kind==OOT_STARTUP_VECTOR) ? i->run != NULL : i->run == NULL)) return 0;
    if (kind == OOT_STARTUP_INDIRECT) return !i->next_a && !i->next_b;
    if (kind == OOT_STARTUP_BRANCH) {
        if ((i->word & UINT32_C(0x7c000000)) == UINT32_C(0x14000000)) {
            target = i->pc + (oot_arm64_sign_extend(i->word & UINT32_C(0x03ffffff),26) << 2);
            return i->next_a == target && i->next_b == target;
        }
        target = i->pc + (oot_arm64_sign_extend((i->word >> 5) &
            ((i->word & UINT32_C(0x7e000000)) == UINT32_C(0x36000000) ? 0x3fffu : 0x7ffffu),
            (i->word & UINT32_C(0x7e000000)) == UINT32_C(0x36000000) ? 14 : 19) << 2);
        return i->next_a == target && i->next_b == i->pc+4;
    }
    return i->next_a == target && i->next_b == target;
}

static int valid_state(const OotStartupDispatcher *d, const OotArm64State *s)
{
    return !(s->nzcv & UINT32_C(0x0fffffff)) && !(s->sp & 15) &&
        s->sp >= d->stack_base && s->sp <= d->stack_top;
}

static void observe_retirement(OotStartupDispatcher *d, uint64_t pc, uint64_t next_pc)
{
    uint32_t n;
    if (!d->has_goal) return;
    for (n = d->stages_completed; n < d->stage_count; ++n) {
        if (pc != d->stages[n]) continue;
        if (n == d->stages_completed) ++d->stages_completed;
        else d->goal_bad_order = 1;
        break;
    }
    if (pc == d->goal_thunk && next_pc == d->goal_entry)
        d->goal_thunk_retired = 1;
}

static uint32_t check_code(const OotStartupDispatcher *d)
{
    size_t n;
    if (oot_startup_context_image(d->context) != d->image || !oot_startup_context_memory(d->context))
        return OOT_STARTUP_BAD_IMAGE;
    for (n = 0; n < d->span_count; ++n) {
        const OotStartupSpan *s = &d->spans[n];
        int error = oot_runtime_check_code(d->image,d->body_sha256,s->entry,s->size,s->sha256);
        if (error != OOT_CODE_MATCH) return error == OOT_CODE_BAD_IMAGE ? OOT_STARTUP_BAD_IMAGE : OOT_STARTUP_BAD_CODE;
    }
    for (n=0;!d->initialization && n<d->native_function_count;++n) {
        const OotNativeFunction *f=&d->native_functions[n];
        int error=oot_runtime_check_code(d->image,d->body_sha256,f->entry,f->size,f->sha256);
        if (error!=OOT_CODE_MATCH) return error==OOT_CODE_BAD_IMAGE ? OOT_STARTUP_BAD_IMAGE:OOT_STARTUP_BAD_CODE;
    }
    return OOT_STARTUP_OK;
}

int oot_startup_dispatch_destroy(OotStartupDispatcher *d)
{
    if (!d) return 1;
    if (d->executing) return 0;
    oot_pauth_destroy(d->pauth);
    oot_startup_context_destroy(d->context);
    oot_runtime_close(d->image);
    free(d->fast); free(d->instructions); free(d->spans); free(d->native_functions); free(d);
    return 1;
}

static OotStartupDispatcher *create_registry(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *p,
    uint64_t limit, uint32_t *error, int sdk, int native, int initialization, int host_linked, int application,int graphics,int display)
{
    OotStartupDispatcher *d;
    size_t n, span = 0;
    uint32_t failure = OOT_STARTUP_BAD_ARGUMENT;
    if (error) *error = failure;
    if (!image || !context || !pauth || oot_pauth_model(pauth) != OOT_PAUTH_QARMA5_VA39 || !p ||
        p->version != OOT_STARTUP_DISPATCH_VERSION || p->flags != ((host_linked ? OOT_STARTUP_HOST_LINKED:OOT_STARTUP_RAW_IMAGE) | (sdk ? OOT_STARTUP_SDK_RUNTIME : 0u) | (native ? OOT_STARTUP_NATIVE_RUNTIME:0u) | (initialization ? OOT_STARTUP_INIT_RUNTIME:0u) | (application ? OOT_STARTUP_APPLICATION:0u) | (graphics ? OOT_STARTUP_GRAPHICS:0u) | (display ? OOT_STARTUP_DISPLAY:0u)) ||
        !!oot_startup_context_sdk_enabled(context) != !!sdk ||
        (native && !oot_startup_context_native_enabled(context)) ||
        (!native && oot_startup_context_native_enabled(context)) ||
        !!oot_startup_context_init_enabled(context)!=!!initialization ||
        !!oot_startup_context_application_enabled(context)!=!!application ||
        !!oot_startup_context_graphics_enabled(context)!=!!graphics ||
        !!oot_startup_context_display_enabled(context)!=!!display ||
        !limit || limit > (sdk ? OOT_STARTUP_SDK_MAX_RETIRED : OOT_STARTUP_MAX_RETIRED) ||
        !p->instructions || !p->instruction_count ||
        p->instruction_count > (initialization ? OOT_STARTUP_INIT_MAX_INSTRUCTIONS : sdk ? OOT_STARTUP_SDK_MAX_INSTRUCTIONS : OOT_STARTUP_MAX_INSTRUCTIONS) ||
        !p->spans || !p->span_count || p->span_count > (initialization ? OOT_STARTUP_INIT_MAX_SPANS : sdk ? OOT_STARTUP_SDK_MAX_SPANS : OOT_STARTUP_MAX_SPANS))
        return NULL;
    d = calloc(1,sizeof(*d));
    if (!d) return NULL;
    d->instructions = calloc(p->instruction_count,sizeof(*d->instructions));
    d->spans = calloc(p->span_count,sizeof(*d->spans));
    failure = OOT_STARTUP_BAD_PROGRAM;
    if (!d->instructions || !d->spans) goto fail;
    memcpy(d->instructions,p->instructions,p->instruction_count*sizeof(*d->instructions));
    memcpy(d->spans,p->spans,p->span_count*sizeof(*d->spans));
    d->instruction_count = p->instruction_count; d->span_count = p->span_count;
    d->entry = p->entry; d->limit = limit; d->sdk = !!sdk; d->native=!!native;
    d->initialization=!!initialization;d->host_linked=!!host_linked;d->application=!!application;
    memcpy(d->body_sha256,p->body_sha256,sizeof(d->body_sha256));
    for (n = 0; n < d->span_count; ++n) {
        const OotStartupSpan *s = &d->spans[n];
        if (!s->size || s->size > 65536 || (s->entry & 3) || (s->size & 3) || s->entry >= STARTUP_ADDRESS_LIMIT ||
            s->size > STARTUP_ADDRESS_LIMIT-s->entry || (n && s->entry < d->spans[n-1].entry+d->spans[n-1].size)) goto fail;
    }
    for (n = 0; n < d->instruction_count; ++n) {
        const OotStartupInstruction *i = &d->instructions[n];
        if(host_linked){
            const OotGuestMemory *view=oot_runtime_memory(image);
            if(!view || !view->count || (i->pc>=view->regions[0].base && i->pc-view->regions[0].base<view->regions[0].size))goto fail;
        }
        if ((i->pc & 3) || i->pc >= STARTUP_ADDRESS_LIMIT-3 || (n && i->pc <= d->instructions[n-1].pc) || !valid_metadata(i,sdk,initialization,application)) goto fail;
        while (span < d->span_count && i->pc >= d->spans[span].entry+d->spans[span].size) ++span;
        if (span == d->span_count || i->pc < d->spans[span].entry || i->pc-d->spans[span].entry > d->spans[span].size-4) goto fail;
        if ((i->kind == OOT_STARTUP_NORMAL || i->kind == OOT_STARTUP_SVC || i->kind == OOT_STARTUP_SYSTEM || i->kind==OOT_STARTUP_VECTOR) &&
            find_instruction(d,i->pc+4) == d->instruction_count) goto fail;
    }
    if (find_instruction(d,d->entry) == d->instruction_count) goto fail;
    failure = OOT_STARTUP_BAD_IMAGE;
    if (oot_startup_context_image(context) != image || !oot_runtime_retain(image)) goto fail;
    d->image = image;
    if (!oot_startup_context_retain(context)) goto fail;
    d->context = context;
    if (!oot_pauth_retain(pauth)) goto fail;
    d->pauth = pauth;
    d->stack_base = oot_runtime_stack_base(image); d->stack_top = oot_runtime_stack_pointer(image);
    failure = check_code(d);
    if (failure) goto fail;
    for (n = 0; n < d->instruction_count; ++n) {
        uint64_t word;
        if (!oot_memory_load(oot_runtime_memory(image),d->instructions[n].pc,4,&word) || word != d->instructions[n].word) {
            failure = OOT_STARTUP_BAD_CODE; goto fail;
        }
    }
    if (error) *error = OOT_STARTUP_OK;
    return d;
fail:
    if (error) *error = failure;
    (void)oot_startup_dispatch_destroy(d);
    return NULL;
}

OotStartupDispatcher *oot_startup_dispatch_create(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *p,
    uint64_t limit, uint32_t *error)
{
    return create_registry(image,context,pauth,p,limit,error,0,0,0,0,0,0,0);
}

OotStartupDispatcher *oot_startup_dispatch_create_sdk(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *p,
    uint64_t limit, uint32_t *error)
{
    return create_registry(image,context,pauth,p,limit,error,1,0,0,0,0,0,0);
}

OotStartupDispatcher *oot_startup_dispatch_create_native(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *p,
    uint64_t limit, uint32_t *error)
{
    return create_registry(image,context,pauth,p,limit,error,1,1,0,0,0,0,0);
}

OotStartupDispatcher *oot_startup_dispatch_create_init(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *p,
    uint64_t limit, uint32_t *error)
{
    return create_registry(image,context,pauth,p,limit,error,1,1,1,0,0,0,0);
}

OotStartupDispatcher *oot_startup_dispatch_create_host(OotRuntimeImage *image,OotStartupContext *context,
    OotPauth *pauth,const OotStartupProgram *program,uint64_t limit,uint32_t *error)
{ return create_registry(image,context,pauth,program,limit,error,1,1,1,1,0,0,0); }

OotStartupDispatcher *oot_startup_dispatch_create_application(OotRuntimeImage *image,OotStartupContext *context,
    OotPauth *pauth,const OotStartupProgram *program,uint64_t limit,uint32_t *error)
{ return create_registry(image,context,pauth,program,limit,error,1,1,1,1,1,0,0); }

OotStartupDispatcher *oot_startup_dispatch_create_graphics(OotRuntimeImage *image,OotStartupContext *context,
    OotPauth *pauth,const OotStartupProgram *program,uint64_t limit,uint32_t *error)
{ return create_registry(image,context,pauth,program,limit,error,1,1,1,1,1,1,0); }

OotStartupDispatcher *oot_startup_dispatch_create_display(OotRuntimeImage *image,OotStartupContext *context,
    OotPauth *pauth,const OotStartupProgram *program,uint64_t limit,uint32_t *error)
{ return create_registry(image,context,pauth,program,limit,error,1,1,1,1,1,1,1); }

int oot_startup_dispatch_initialization_reached(const OotStartupDispatcher *d)
{ return d && d->application && d->initialization_reached; }
int oot_startup_dispatch_application_entry_retired(const OotStartupDispatcher *d)
{ return d && d->application && d->application_entry_retired; }
uint64_t oot_startup_dispatch_post_entry_retired(const OotStartupDispatcher *d)
{ return d && d->application && d->initialization_reached ? d->retired-d->initialization_retired:0; }

int oot_startup_dispatch_set_fast_functions(OotStartupDispatcher *d,const OotStartupFastFunction *functions,size_t count)
{
    OotStartupFastFunction *copy;
    if (!d || !d->initialization || d->phase || d->executing || !functions || !count || count>4096) return 0;
    copy=calloc(count,sizeof(*copy));if(!copy)return 0;
    memcpy(copy,functions,count*sizeof(*copy));
    for(size_t n=0;n<count;++n){
        const OotStartupFastFunction *f=copy+n;
        if(!f->run || f->size<8 || f->size>1024 || f->size%4 || f->entry%4 || f->entry>=STARTUP_ADDRESS_LIMIT-f->size ||
           (n && f->entry<copy[n-1].entry+copy[n-1].size) || covers_goal(d,f->entry,f->size) ||
           oot_runtime_check_code(d->image,d->body_sha256,f->entry,f->size,f->sha256)!=OOT_CODE_MATCH)goto fail;
        for(uint32_t off=0;off<f->size;off+=4){
            size_t at=find_instruction(d,f->entry+off);OotArm64State state={0};OotReadEffect effect;
            if(at==d->instruction_count || find_native_function(d,f->entry+off)!=d->native_function_count)goto fail;
            const OotStartupInstruction *i=d->instructions+at;
            if(off+4==f->size){if(i->word!=UINT32_C(0xd65f03c0))goto fail;}
            else if(i->kind!=OOT_STARTUP_NORMAL || pac_word(i->word) ||
                oot_leaf_read_decode(i->word,i->pc,&state,&effect) || oot_leaf_write_decode(i->word,i->pc,&state,&effect))goto fail;
        }
    }
    free(d->fast);d->fast=copy;d->fast_count=count;return 1;
fail:free(copy);return 0;
}
uint64_t oot_startup_dispatch_host_steps(const OotStartupDispatcher *d){return d ? d->scaffold_retired:0;}
uint64_t oot_startup_dispatch_fast_calls(const OotStartupDispatcher *d){return d ? d->fast_calls:0;}

int oot_startup_dispatch_set_constructors(OotStartupDispatcher *d,const OotStartupConstructor *c,size_t count)
{
    if(!d || !d->host_linked || d->phase || d->executing || !c || !count || count>16)return 0;
    for(size_t n=0;n<count;++n){
        size_t entry=find_instruction(d,c[n].entry),body=find_instruction(d,c[n].body_entry),ret=find_instruction(d,c[n].return_pc);
        if(entry==d->instruction_count || body==d->instruction_count || ret==d->instruction_count ||
           c[n].entry%4 || c[n].size<36 || c[n].size>4096 || c[n].size%4 || c[n].entry>=STARTUP_ADDRESS_LIMIT-c[n].size ||
           c[n].body_entry<=c[n].entry || c[n].body_entry>=c[n].return_pc || c[n].return_pc+4!=c[n].entry+c[n].size ||
           d->instructions[entry].word!=UINT32_C(0xd503237f) || d->instructions[ret].word!=UINT32_C(0xd65f0fff) ||
           covers_goal(d,c[n].entry,c[n].size) ||
           oot_runtime_check_code(d->image,d->body_sha256,c[n].entry,c[n].size,c[n].sha256)!=OOT_CODE_MATCH)return 0;
        { uint64_t cbnz,eq,store,load,cmp;
          OotGuestMemory *memory=oot_runtime_memory(d->image);
          if(!oot_memory_load(memory,c[n].entry+28,4,&cbnz) || (cbnz&UINT32_C(0xff00001f))!=UINT32_C(0x35000008) ||
             c[n].entry+28+(oot_arm64_sign_extend((cbnz>>5)&0x7ffff,19)<<2)!=c[n].body_entry ||
             !oot_memory_load(memory,c[n].body_entry-4,4,&eq) || (eq&UINT32_C(0xff00001f))!=UINT32_C(0x54000000) ||
             c[n].body_entry-4+(oot_arm64_sign_extend((eq>>5)&0x7ffff,19)<<2)!=c[n].return_pc-12 ||
             !oot_memory_load(memory,c[n].body_entry-16,4,&store) || store!=UINT32_C(0xb9000260) ||
             !oot_memory_load(memory,c[n].body_entry-12,4,&load) || load!=UINT32_C(0xb9400268) ||
             !oot_memory_load(memory,c[n].body_entry-8,4,&cmp) || cmp!=UINT32_C(0x7100051f))return 0;
        }
        for(size_t k=0;k<n;++k)if(c[n].entry<c[k].entry+c[k].size && c[k].entry<c[n].entry+c[n].size)return 0;
        for(uint32_t off=0;off<c[n].size;off+=4){
            if(find_native_function(d,c[n].entry+off)!=d->native_function_count)return 0;
            for(size_t k=0;k<d->fast_count;++k)if(c[n].entry+off>=d->fast[k].entry && c[n].entry+off-d->fast[k].entry<d->fast[k].size)return 0;
        }
    }
    if(d->constructor_count)return 0;
    memcpy(d->constructors,c,count*sizeof(*c));d->constructor_count=(uint32_t)count;return 1;
}
uint32_t oot_startup_dispatch_constructors_completed(const OotStartupDispatcher *d)
{
    uint32_t result=0;if(!d || d->constructor_bad)return 0;
    for(uint32_t n=0;n<d->constructor_count;++n)if(d->constructor_completed[n]==1)++result;
    return result;
}

int oot_startup_dispatch_set_native_functions(OotStartupDispatcher *d,
    const OotNativeFunction *functions, size_t count, uint32_t *error)
{
    OotNativeFunction *copy;
    uint32_t failure=OOT_STARTUP_BAD_NATIVE_FUNCTION;
    if (error) *error=failure;
    if (d && d->executing) { if (error) *error=OOT_STARTUP_REENTRY; return 0; }
    if (!d || !d->native || d->phase || count>(d->initialization ?
            OOT_STARTUP_INIT_MAX_NATIVE_FUNCTIONS : OOT_STARTUP_MAX_NATIVE_FUNCTIONS) ||
        !count || !functions) return 0;
    copy=calloc(count,sizeof(*copy));
    if (!copy) return 0;
    memcpy(copy,functions,count*sizeof(*copy));
    for (size_t n=0;n<count;++n) {
        const OotNativeFunction *f=&copy[n];
        if (f->version!=OOT_NATIVE_FUNCTION_VERSION || !oot_startup_context_handler_valid(d->context,f->id) ||
            (f->entry&3) || !f->size || (f->size&3) || f->size>65536 ||
            f->entry>=STARTUP_ADDRESS_LIMIT || f->size>STARTUP_ADDRESS_LIMIT-f->entry ||
            (n && f->entry<copy[n-1].entry+copy[n-1].size) ||
            (!d->initialization && find_instruction(d,f->entry)==d->instruction_count) ||
            covers_goal(d,f->entry,f->size)) goto fail;
        if(d->host_linked){const OotGuestMemory *view=oot_runtime_memory(d->image);
            if(f->entry<view->regions[0].base+view->regions[0].size && view->regions[0].base<f->entry+f->size)goto fail;}
        for(size_t fast_index=0;fast_index<d->fast_count;++fast_index)
            if(f->entry<d->fast[fast_index].entry+d->fast[fast_index].size && d->fast[fast_index].entry<f->entry+f->size)goto fail;
        failure=oot_runtime_check_code(d->image,d->body_sha256,f->entry,f->size,f->sha256)==OOT_CODE_MATCH ?
            OOT_STARTUP_BAD_NATIVE_FUNCTION:OOT_STARTUP_BAD_CODE;
        if (failure==OOT_STARTUP_BAD_CODE) goto fail;
    }
    failure=check_code(d);
    if (failure) goto fail;
    free(d->native_functions);d->native_functions=copy;d->native_function_count=count;
    if (error) *error=OOT_STARTUP_OK;
    return 1;
fail:
    free(copy);
    if (error) *error=failure;
    return 0;
}

uint64_t oot_startup_dispatch_native_calls(const OotStartupDispatcher *d)
{
    return d && d->native ? d->native_calls:0;
}

int oot_startup_dispatch_set_sdk_goal(OotStartupDispatcher *d, const OotSdkGoal *goal,
    uint32_t *error)
{
    size_t index;
    uint32_t n, m, failure = OOT_STARTUP_BAD_SDK_GOAL;
    const OotStartupInstruction *thunk;
    if (error) *error = failure;
    if (!d || !goal) return 0;
    if (d->executing) { if (error) *error = OOT_STARTUP_REENTRY; return 0; }
    if (!d->sdk || d->phase || goal->version != OOT_STARTUP_SDK_GOAL_VERSION ||
        !goal->stages || !goal->stage_count || goal->stage_count > OOT_STARTUP_SDK_MAX_STAGES ||
        goal->entry == goal->thunk || goal->entry == d->entry) return 0;
    index = find_instruction(d,goal->thunk);
    if (index == d->instruction_count || find_instruction(d,goal->entry) == d->instruction_count) return 0;
    thunk = &d->instructions[index];
    if (thunk->kind != OOT_STARTUP_BRANCH || thunk->word != goal->thunk_word ||
        (thunk->word & UINT32_C(0xfc000000)) != UINT32_C(0x14000000) ||
        thunk->next_a != goal->entry || thunk->next_b != goal->entry) return 0;
    for (n = 0; n < goal->stage_count; ++n) {
        index = find_instruction(d,goal->stages[n]);
        if (index == d->instruction_count || goal->stages[n] == goal->entry) return 0;
        for (m = 0; m < n; ++m) if (goal->stages[m] == goal->stages[n]) return 0;
    }
    for(size_t fast_index=0;fast_index<d->fast_count;++fast_index){
        const OotStartupFastFunction *f=d->fast+fast_index;
        if((goal->entry>=f->entry && goal->entry-f->entry<f->size) || (goal->thunk>=f->entry && goal->thunk-f->entry<f->size))return 0;
        for(size_t k=0;k<goal->stage_count;++k)if(goal->stages[k]>=f->entry && goal->stages[k]-f->entry<f->size)return 0;
    }
    if (find_native_function(d,goal->entry)!=d->native_function_count ||
        find_native_function(d,goal->thunk)!=d->native_function_count) return 0;
    for (n=0;n<goal->stage_count;++n)
        if (find_native_function(d,goal->stages[n])!=d->native_function_count) return 0;
    failure = check_code(d);
    if (failure) { if (error) *error = failure; return 0; }
    memcpy(d->stages,goal->stages,goal->stage_count*sizeof(*goal->stages));
    d->stage_count = goal->stage_count; d->goal_entry = goal->entry; d->goal_thunk = goal->thunk;
    d->stages_completed = d->goal_bad_order = d->goal_thunk_retired = 0;
    d->has_goal = 1;
    if (error) *error = OOT_STARTUP_OK;
    return 1;
}

uint32_t oot_startup_dispatch_sdk_stages_completed(const OotStartupDispatcher *d)
{
    return d && d->sdk && d->has_goal ? d->stages_completed : 0;
}

int oot_startup_dispatch_begin(OotStartupDispatcher *d, const OotArm64State *s, OotStartupReport *out)
{
    uint32_t error;
    if (!d || !s) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_ARGUMENT,0,0);
    if (d->executing) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_REENTRY,0,0);
    if (d->phase || s->pc != d->entry || !valid_state(d,s)) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_STATE,0,0);
    if (d->native && !d->native_function_count)
        return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_NATIVE_FUNCTION,0,0);
    if(d->host_linked && !d->constructor_count)return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_SDK_GOAL,0,0);
    if(d->application && !d->has_goal)return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_SDK_GOAL,0,0);
    error = check_code(d);
    if (error) return result(d,out,OOT_STARTUP_REJECTED,error,0,0);
    if (!oot_runtime_claim_startup(d->image))
        return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_IMAGE,0,0);
    if (d->initialization) d->vector_checkpoint=*oot_startup_context_vectors(d->context);
    d->checkpoint = *s; d->retired = 0; d->native_calls=0;d->fast_calls=0;d->scaffold_retired=0; d->phase = 1;
    d->stages_completed = d->goal_bad_order = d->goal_thunk_retired = 0;
    d->constructor_bad=d->constructor_depth=0;memset(d->constructor_completed,0,sizeof(d->constructor_completed));
    d->initialization_reached=d->application_entry_retired=0;d->initialization_retired=0;
    d->stop_error = d->stop_word = d->stop_service = 0;
    return result(d,out,OOT_STARTUP_READY,OOT_STARTUP_OK,0,0);
}

int oot_startup_dispatch_abort(OotStartupDispatcher *d)
{
    if (!d || d->executing) return 0;
    d->phase = 0; d->retired = 0; d->native_calls=0;d->fast_calls=0;d->scaffold_retired=0; d->stop_error = d->stop_word = d->stop_service = 0;
    d->stages_completed = d->goal_bad_order = d->goal_thunk_retired = 0;
    d->constructor_bad=d->constructor_depth=0;memset(d->constructor_completed,0,sizeof(d->constructor_completed));
    d->initialization_reached=d->application_entry_retired=0;d->initialization_retired=0;
    return 1;
}

int oot_startup_dispatch_run(OotStartupDispatcher *d, OotArm64State *s, uint64_t budget,
    OotStartupTraceSink sink, void *user, OotStartupReport *out)
{
    uint64_t count = 0;
    uint32_t error;
    if (!d || !s) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_ARGUMENT,0,0);
    if (d->executing) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_REENTRY,0,0);
    if (!d->phase) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_NO_ACTIVE,0,0);
    if (!same_state(s,&d->checkpoint) || !same_vectors(d)) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_STATE,0,0);
    if (d->phase != 1) return result(d,out,d->phase == 3 ? OOT_STARTUP_CONTRACT_FAULT : OOT_STARTUP_STOPPED,d->stop_error,d->stop_word,d->stop_service);
    error = check_code(d);
    if (error) return stop(d,out,sink,user,error,0,0,s->pc,0);
    while (count < budget) {
        size_t index = find_instruction(d,d->checkpoint.pc);
        size_t native_index=find_native_function(d,d->checkpoint.pc);
        const OotStartupInstruction *i;
        OotStartupInstruction native_instruction={0};
        OotArm64State expected, working = d->checkpoint;
        OotGuestMemory window, *memory;
        OotGuestRegion region;
        OotReadEffect effect = {0};
        uint8_t bytes[16] = {0}, wanted[16] = {0};
        uint64_t word, executed = UINT64_MAX, source_pc = working.pc;
        unsigned memory_kind = 0, k;
        int status, control;
        if (!same_state(s,&d->checkpoint) || !same_vectors(d)) return stop(d,out,sink,user,OOT_STARTUP_BAD_STATE,0,0,s->pc,1);
        if (native_index!=d->native_function_count && working.pc!=d->native_functions[native_index].entry)
            return stop(d,out,sink,user,OOT_STARTUP_NATIVE_INTERIOR,0,d->native_functions[native_index].id,working.pc,0);
        if (index == d->instruction_count) {
            if (!d->initialization || native_index==d->native_function_count)
                return stop(d,out,sink,user,OOT_STARTUP_UNREGISTERED_TARGET,0,0,working.pc,0);
            /* A registered whole-function entry needs no compiled callback.
             * The complete copied body hash is checked before native effects. */
            if (!oot_memory_load(oot_runtime_memory(d->image),working.pc,4,&word))
                return stop(d,out,sink,user,OOT_STARTUP_BAD_CODE,0,0,working.pc,0);
            native_instruction.pc=working.pc;
            native_instruction.word=(uint32_t)word;
            i=&native_instruction;
        } else i = &d->instructions[index];
        if (d->has_goal && working.pc == d->goal_entry && !d->initialization_reached) {
            int complete=d->stages_completed == d->stage_count &&
                !d->goal_bad_order && d->goal_thunk_retired && (!d->host_linked ||
                (!d->constructor_bad && !d->constructor_depth && oot_startup_dispatch_constructors_completed(d)==d->constructor_count));
            if(!d->application || !complete)return stop(d,out,sink,user,complete ? OOT_STARTUP_SDK_INITIALIZED:OOT_STARTUP_BAD_SDK_GOAL,i->word,0,working.pc,0);
            d->initialization_reached=1;d->initialization_retired=d->retired;
        }
        if(d->constructor_bad)return stop(d,out,sink,user,OOT_STARTUP_BAD_SDK_GOAL,i->word,0,working.pc,0);
        if (d->native_calls>=d->limit || d->retired >= d->limit-d->native_calls)
            return stop(d,out,sink,user,OOT_STARTUP_RETIREMENT_LIMIT,i->word,0,working.pc,0);
        memory = oot_startup_context_memory(d->context);
        if (!memory) return stop(d,out,sink,user,OOT_STARTUP_BAD_IMAGE,i->word,0,working.pc,0);
        if (!oot_memory_load(oot_runtime_memory(d->image),i->pc,4,&word) || word != i->word)
            return stop(d,out,sink,user,OOT_STARTUP_BAD_CODE,i->word,0,working.pc,0);
        if (native_index!=d->native_function_count) {
            const OotNativeFunction *f=&d->native_functions[native_index];
            OotSdkNativeReport native_report={0};
            uint64_t return_pc=working.x[30];
            size_t return_native=find_native_function(d,return_pc);
            size_t return_index=find_instruction(d,return_pc);
            if ((return_pc&3) || return_pc>=STARTUP_ADDRESS_LIMIT || return_pc==f->entry ||
                return_index==d->instruction_count)
                return stop(d,out,sink,user,OOT_STARTUP_UNREGISTERED_TARGET,i->word,f->id,return_pc,0);
            if (return_native!=d->native_function_count && return_pc!=d->native_functions[return_native].entry)
                return stop(d,out,sink,user,OOT_STARTUP_NATIVE_INTERIOR,i->word,f->id,return_pc,0);
            if (oot_runtime_check_code(d->image,d->body_sha256,f->entry,f->size,f->sha256)!=OOT_CODE_MATCH ||
                !oot_memory_load(oot_runtime_memory(d->image),return_pc,4,&word) ||
                word!=d->instructions[return_index].word)
                return stop(d,out,sink,user,OOT_STARTUP_BAD_CODE,i->word,f->id,return_pc,0);
            expected=working;expected.pc=return_pc;
            d->executing=1;
            status=oot_startup_context_native_call(d->context,f->id,&working,&native_report);
            d->executing=0;
            if (status!=OOT_STARTUP_SERVICE_IMPLEMENTED)
                return stop(d,out,sink,user,status==OOT_STARTUP_SERVICE_UNSUPPORTED ?
                    OOT_STARTUP_UNSUPPORTED_SERVICE:OOT_STARTUP_NATIVE_FAULT,i->word,f->id,source_pc,0);
            if (oot_startup_context_returns_value(d->context,f->id)) expected.x[0]=working.x[0];
            if (!same_state(&working,&expected) || !valid_state(d,&working))
                return stop(d,out,sink,user,OOT_STARTUP_BAD_CALLBACK,i->word,f->id,working.pc,1);
            if(d->initialization){const OotStartupVectorState *vectors=oot_startup_context_vectors(d->context);
                OotStartupVectorState allowed=d->vector_checkpoint;
                if(f->id==OOT_NATIVE_MATH_LOG)memcpy(allowed.q[0],vectors->q[0],8);
                if(memcmp(&allowed,vectors,sizeof(allowed)))return stop(d,out,sink,user,OOT_STARTUP_BAD_CALLBACK,i->word,f->id,working.pc,1);
                d->vector_checkpoint=*vectors;
            }
            d->checkpoint=working;*s=working;++count;++d->native_calls;
            trace_row(d,sink,user,source_pc,working.pc,i->word,OOT_STARTUP_TRACE_NATIVE,OOT_STARTUP_OK,f->id);
            continue;
        }
        if (i->kind == OOT_STARTUP_UNSUPPORTED) return stop(d,out,sink,user,OOT_STARTUP_UNSUPPORTED_WORD,i->word,0,working.pc,0);
        if (i->kind==OOT_STARTUP_VECTOR) {
            OotStartupVectorState vectors;
            status=oot_startup_context_vector_preview(d->context,i->word,&working,&expected,&vectors);
            if (status!=OOT_STARTUP_SERVICE_IMPLEMENTED || !valid_state(d,&expected))
                return stop(d,out,sink,user,status==OOT_STARTUP_SERVICE_UNSUPPORTED ? OOT_STARTUP_UNSUPPORTED_WORD:OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
            d->executing=1;
            status=oot_startup_context_vector_step(d->context,i->word,&working);
            d->executing=0;
            if (status!=OOT_STARTUP_SERVICE_IMPLEMENTED)
                return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
            if (!same_state(&working,&expected) ||
                memcmp(oot_startup_context_vectors(d->context),&vectors,sizeof(vectors)))
                return stop(d,out,sink,user,OOT_STARTUP_BAD_CALLBACK,i->word,0,working.pc,1);
            d->vector_checkpoint=vectors;
            d->checkpoint=working;*s=working;++count;++d->retired;
            observe_retirement(d,source_pc,working.pc);
            trace_row(d,sink,user,source_pc,working.pc,i->word,OOT_STARTUP_TRACE_STEP,OOT_STARTUP_OK,0);
            continue;
        }
        if (i->kind == OOT_STARTUP_SYSTEM) {
            uint32_t system = i->word & UINT32_C(0xffffffe0), rd = i->word & 31;
            uint64_t value = 0;
            int init_atomic=oot_startup_init_atomic_kind(i->word);
            if(!init_atomic)init_atomic=oot_startup_application_atomic_kind(i->word);
            int narrow_cas=init_atomic==OOT_STARTUP_APP_CAS_NARROW;
            int atomic = narrow_cas || (i->word & UINT32_C(0xbfa07c00)) == UINT32_C(0x88a07c00);
            expected = working; expected.pc += 4;
            if (init_atomic==OOT_STARTUP_INIT_LDADD || init_atomic==OOT_STARTUP_INIT_LDADDAL ||
                init_atomic==OOT_STARTUP_INIT_LDSET || init_atomic==OOT_STARTUP_INIT_LDCLR ||
                init_atomic==OOT_STARTUP_APP_LDADDA || init_atomic==OOT_STARTUP_APP_LDADDL) {
                unsigned rn=(i->word>>5)&31;
                unsigned size=(i->word>>30)==3 ? 8u:4u;
                uint64_t address=oot_arm64_read(&working,rn,64,1);
                if (!oot_memory_load(memory,address,size,&value))
                    return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
                oot_arm64_write(&expected,i->word&31,size*8,0,value);
            }
            else if (init_atomic==OOT_STARTUP_INIT_STLR) { /* No GPR result. */ }
            else if (i->word==UINT32_C(0xd50320ff)) {
                uint64_t mask=UINT64_C(0x0000007fffffffff);
                expected.x[30]=(working.x[30]&mask) | ((working.x[30]&(UINT64_C(1)<<55)) ? ~mask:0);
            }
            else if (atomic) {
                unsigned rn=(i->word >> 5)&31, rs=(i->word >> 16)&31;
                unsigned size=narrow_cas ? 1u<<(i->word>>30):((i->word & UINT32_C(0x40000000)) ? 8:4);
                uint64_t address=oot_arm64_read(&working,rn,64,1);
                /* This context/image has one owner thread. The snapshot is
                 * only the independent full-state expectation; the actual
                 * compare/conditional write is one locked backend transfer. */
                if (!oot_memory_load(memory,address,size,&value))
                    return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
                oot_arm64_write(&expected,rs,narrow_cas ? 32:size*8,0,value);
            }
            else if (system == UINT32_C(0xd53bd060)) value = oot_startup_context_tls_pointer(d->context);
            else if (system == UINT32_C(0xd53bd040)) value = oot_startup_context_tpidr_el0(d->context);
            else value = oot_arm64_read(&working,rd,64,0);
            if (!atomic && !init_atomic && i->word!=UINT32_C(0xd50320ff) && system != UINT32_C(0xd51bd040)) oot_arm64_write(&expected,rd,64,0,value);
            d->executing = 1;
            status = oot_startup_context_system(d->context,i->word,&working);
            d->executing = 0;
            if (status != OOT_STARTUP_SERVICE_IMPLEMENTED)
                return stop(d,out,sink,user,status == OOT_STARTUP_SERVICE_UNSUPPORTED ? OOT_STARTUP_UNSUPPORTED_WORD :
                    (atomic || init_atomic) ? OOT_STARTUP_MEMORY_FAULT : OOT_STARTUP_BAD_STATE,
                    i->word,0,source_pc,0);
            if (!same_state(&working,&expected) || !valid_state(d,&working) ||
                (!atomic && system == UINT32_C(0xd51bd040) && oot_startup_context_tpidr_el0(d->context) != value))
                return stop(d,out,sink,user,OOT_STARTUP_BAD_CALLBACK,i->word,0,working.pc,1);
            d->checkpoint = working; *s = working; ++count; ++d->retired;
            observe_retirement(d,source_pc,working.pc);
            trace_row(d,sink,user,source_pc,working.pc,i->word,OOT_STARTUP_TRACE_STEP,OOT_STARTUP_OK,0);
            continue;
        }
        if (i->kind == OOT_STARTUP_SVC) {
            OotStartupServiceReport service;
            uint32_t id = (i->word >> 5) & 65535;
            d->executing = 1;
            status = oot_startup_context_service(d->context,id,&working,&service);
            d->executing = 0;
            if (status != OOT_STARTUP_SERVICE_IMPLEMENTED)
                return stop(d,out,sink,user,status == OOT_STARTUP_SERVICE_UNSUPPORTED ? OOT_STARTUP_UNSUPPORTED_SERVICE : OOT_STARTUP_BAD_SERVICE,i->word,id,source_pc,0);
            if (working.pc != source_pc+4 || !valid_state(d,&working))
                return stop(d,out,sink,user,OOT_STARTUP_BAD_CALLBACK,i->word,id,working.pc,1);
            d->checkpoint = working; *s = working; ++count; ++d->retired;
            observe_retirement(d,source_pc,working.pc);
            trace_row(d,sink,user,source_pc,working.pc,i->word,OOT_STARTUP_TRACE_SERVICE,OOT_STARTUP_OK,id);
            continue;
        }
        if(d->fast_count){
            size_t lo=0,hi=d->fast_count;
            while(lo<hi){size_t mid=lo+(hi-lo)/2;if(d->fast[mid].entry<working.pc)lo=mid+1;else hi=mid;}
            if(lo<d->fast_count && d->fast[lo].entry==working.pc){
                const OotStartupFastFunction *f=d->fast+lo;
                uint64_t steps=f->size/4,lr=working.x[30];
                if(steps<=budget-count && steps<=d->limit-d->native_calls-d->retired &&
                   lr<STARTUP_ADDRESS_LIMIT && !(lr&3) && !(lr>=f->entry && lr-f->entry<f->size) &&
                   find_instruction(d,lr)!=d->instruction_count &&
                   (find_native_function(d,lr)==d->native_function_count || d->native_functions[find_native_function(d,lr)].entry==lr)){
                    if(oot_runtime_check_code(d->image,d->body_sha256,f->entry,f->size,f->sha256)!=OOT_CODE_MATCH)
                        return stop(d,out,sink,user,OOT_STARTUP_BAD_CODE,i->word,0,source_pc,0);
                    (void)oot_memory_init(&window,NULL,0);
                    d->executing=1;status=f->run(&working,&window,d->pauth,steps,&executed);d->executing=0;
                    if(status!=OOT_LIFT_DISPATCH || executed!=steps || working.pc!=lr || !valid_state(d,&working) ||
                       working.sp!=s->sp || memcmp(working.x+18,s->x+18,13*sizeof(uint64_t)) ||
                       !window.valid || window.count || window.regions || window.fault.reason || !same_vectors(d))
                        return stop(d,out,sink,user,OOT_STARTUP_BAD_CALLBACK,i->word,0,working.pc,1);
                    d->checkpoint=working;*s=working;++d->fast_calls;count+=steps;
                    for(uint32_t off=0;off<f->size;off+=4){
                        const OotStartupInstruction *row=d->instructions+find_instruction(d,f->entry+off);
                        ++d->retired;trace_row(d,sink,user,row->pc,off+4==f->size ? lr:row->pc+4,row->word,OOT_STARTUP_TRACE_STEP,OOT_STARTUP_OK,0);
                    }
                    continue;
                }
            }
        }
        control = i->kind != OOT_STARTUP_NORMAL || pac_word(i->word);
        if (!control_expected(d,i,&d->checkpoint,&expected))
            return stop(d,out,sink,user,OOT_STARTUP_BAD_STATE,i->word,0,working.pc,0);
        native_index=find_native_function(d,expected.pc);
        if (native_index!=d->native_function_count && expected.pc!=d->native_functions[native_index].entry)
            return stop(d,out,sink,user,OOT_STARTUP_NATIVE_INTERIOR,i->word,d->native_functions[native_index].id,expected.pc,0);
        if (find_instruction(d,expected.pc) == d->instruction_count &&
            !(d->initialization && native_index!=d->native_function_count))
            return stop(d,out,sink,user,OOT_STARTUP_UNREGISTERED_TARGET,i->word,0,expected.pc,0);
        if (oot_leaf_read_decode(i->word,i->pc,&working,&effect)) memory_kind = 1;
        else if (oot_leaf_write_decode(i->word,i->pc,&working,&effect)) memory_kind = 2;
        (void)oot_memory_init(&window,NULL,0);
        if (memory_kind) {
            expected = working;
            if (effect.sp_base && (working.sp & 15))
                return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
            if (memory_kind == 1) {
                if (!oot_leaf_read_capture(memory,&effect,bytes,&expected))
                    return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
                memcpy(wanted,bytes,effect.size);
            } else {
                if (!oot_memory_probe(memory,effect.address,effect.size,OOT_MEMORY_WRITE))
                    return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
                oot_leaf_write_expected(&effect,&working,wanted,&expected);
                for (k = 0; k < effect.size; ++k) bytes[k] = (uint8_t)~wanted[k];
            }
            region = (OotGuestRegion){effect.address,effect.size,bytes,memory_kind == 1 ? OOT_MEMORY_READ : OOT_MEMORY_WRITE};
            (void)oot_memory_init(&window,&region,1);
        }
        d->executing = 1;
        status = i->run(&working,&window,d->pauth,1,&executed);
        d->executing = 0;
        error = OOT_STARTUP_OK;
        if ((status != OOT_LIFT_BUDGET && status != OOT_LIFT_DISPATCH) || executed != 1 ||
            !valid_state(d,&working) || working.pc != expected.pc || (control && !same_state(&working,&expected)))
            error = OOT_STARTUP_BAD_CALLBACK;
        if (!error && (window.valid != 1 || window.fault.reason ||
            (memory_kind ? (window.regions != &region || window.count != 1 || region.base != effect.address ||
                region.size != effect.size || region.data != bytes || region.permissions != (uint32_t)(memory_kind == 1 ? OOT_MEMORY_READ : OOT_MEMORY_WRITE) ||
                memcmp(bytes,wanted,effect.size) || !same_state(&working,&expected)) : (window.regions || window.count))))
            error = OOT_STARTUP_BAD_CALLBACK;
        if (error) return stop(d,out,sink,user,error,i->word,0,working.pc,1);
        if (memory_kind == 2 && !oot_write_commit(memory,&effect,&d->checkpoint))
            return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
        d->checkpoint = working; *s = working; ++count; ++d->retired;
        observe_retirement(d,source_pc,working.pc);
        trace_row(d,sink,user,source_pc,working.pc,i->word,OOT_STARTUP_TRACE_STEP,OOT_STARTUP_OK,0);
    }
    if (!same_state(s,&d->checkpoint) || !same_vectors(d)) return stop(d,out,sink,user,OOT_STARTUP_BAD_STATE,0,0,s->pc,1);
    return result(d,out,OOT_STARTUP_YIELDED,OOT_STARTUP_OK,0,0);
}
