#include "startup_dispatch.h"
#include "checked_read.h"

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
    uint32_t phase, executing, stop_error, stop_word, stop_service;
    uint32_t sdk, has_goal, stage_count, stages_completed, goal_bad_order, goal_thunk_retired;
    uint64_t goal_thunk, goal_entry, stages[OOT_STARTUP_SDK_MAX_STAGES];
};

static int same_state(const OotArm64State *a, const OotArm64State *b)
{
    return !memcmp(a->x,b->x,sizeof(a->x)) && a->sp == b->sp &&
        a->pc == b->pc && a->nzcv == b->nzcv;
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
    uint32_t system = word & UINT32_C(0xffffffe0);
    if (system == UINT32_C(0xd53bd060) || system == UINT32_C(0xd53bd040) ||
        system == UINT32_C(0xd51bd040)) return OOT_STARTUP_SYSTEM;
    if ((word & UINT32_C(0xbfa07c00)) == UINT32_C(0x88a07c00)) return OOT_STARTUP_SYSTEM;
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

static int valid_metadata(const OotStartupInstruction *i, int sdk)
{
    uint32_t kind = word_kind(i->word);
    uint64_t target = i->pc+4;
    if (i->kind == OOT_STARTUP_UNSUPPORTED)
        return !i->run && i->next_a == i->pc && i->next_b == i->pc;
    if ((kind == OOT_STARTUP_SYSTEM && !sdk) || i->kind != kind ||
        ((kind == OOT_STARTUP_SVC || kind == OOT_STARTUP_SYSTEM) ? i->run != NULL : i->run == NULL)) return 0;
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
    return OOT_STARTUP_OK;
}

int oot_startup_dispatch_destroy(OotStartupDispatcher *d)
{
    if (!d) return 1;
    if (d->executing) return 0;
    oot_pauth_destroy(d->pauth);
    oot_startup_context_destroy(d->context);
    oot_runtime_close(d->image);
    free(d->instructions); free(d->spans); free(d);
    return 1;
}

static OotStartupDispatcher *create_registry(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *p,
    uint64_t limit, uint32_t *error, int sdk)
{
    OotStartupDispatcher *d;
    size_t n, span = 0;
    uint32_t failure = OOT_STARTUP_BAD_ARGUMENT;
    if (error) *error = failure;
    if (!image || !context || !pauth || oot_pauth_model(pauth) != OOT_PAUTH_QARMA5_VA39 || !p ||
        p->version != OOT_STARTUP_DISPATCH_VERSION || p->flags != (OOT_STARTUP_RAW_IMAGE | (sdk ? OOT_STARTUP_SDK_RUNTIME : 0u)) ||
        !!oot_startup_context_sdk_enabled(context) != !!sdk ||
        !limit || limit > (sdk ? OOT_STARTUP_SDK_MAX_RETIRED : OOT_STARTUP_MAX_RETIRED) ||
        !p->instructions || !p->instruction_count ||
        p->instruction_count > (sdk ? OOT_STARTUP_SDK_MAX_INSTRUCTIONS : OOT_STARTUP_MAX_INSTRUCTIONS) ||
        !p->spans || !p->span_count || p->span_count > (sdk ? OOT_STARTUP_SDK_MAX_SPANS : OOT_STARTUP_MAX_SPANS))
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
    d->entry = p->entry; d->limit = limit; d->sdk = !!sdk;
    memcpy(d->body_sha256,p->body_sha256,sizeof(d->body_sha256));
    for (n = 0; n < d->span_count; ++n) {
        const OotStartupSpan *s = &d->spans[n];
        if (!s->size || s->size > 65536 || (s->entry & 3) || (s->size & 3) || s->entry >= STARTUP_ADDRESS_LIMIT ||
            s->size > STARTUP_ADDRESS_LIMIT-s->entry || (n && s->entry < d->spans[n-1].entry+d->spans[n-1].size)) goto fail;
    }
    for (n = 0; n < d->instruction_count; ++n) {
        const OotStartupInstruction *i = &d->instructions[n];
        if ((i->pc & 3) || i->pc >= STARTUP_ADDRESS_LIMIT-3 || (n && i->pc <= d->instructions[n-1].pc) || !valid_metadata(i,sdk)) goto fail;
        while (span < d->span_count && i->pc >= d->spans[span].entry+d->spans[span].size) ++span;
        if (span == d->span_count || i->pc < d->spans[span].entry || i->pc-d->spans[span].entry > d->spans[span].size-4) goto fail;
        if ((i->kind == OOT_STARTUP_NORMAL || i->kind == OOT_STARTUP_SVC || i->kind == OOT_STARTUP_SYSTEM) &&
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
    return create_registry(image,context,pauth,p,limit,error,0);
}

OotStartupDispatcher *oot_startup_dispatch_create_sdk(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *p,
    uint64_t limit, uint32_t *error)
{
    return create_registry(image,context,pauth,p,limit,error,1);
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
    error = check_code(d);
    if (error) return result(d,out,OOT_STARTUP_REJECTED,error,0,0);
    if (!oot_runtime_claim_startup(d->image))
        return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_IMAGE,0,0);
    d->checkpoint = *s; d->retired = 0; d->phase = 1;
    d->stages_completed = d->goal_bad_order = d->goal_thunk_retired = 0;
    d->stop_error = d->stop_word = d->stop_service = 0;
    return result(d,out,OOT_STARTUP_READY,OOT_STARTUP_OK,0,0);
}

int oot_startup_dispatch_abort(OotStartupDispatcher *d)
{
    if (!d || d->executing) return 0;
    d->phase = 0; d->retired = 0; d->stop_error = d->stop_word = d->stop_service = 0;
    d->stages_completed = d->goal_bad_order = d->goal_thunk_retired = 0;
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
    if (!same_state(s,&d->checkpoint)) return result(d,out,OOT_STARTUP_REJECTED,OOT_STARTUP_BAD_STATE,0,0);
    if (d->phase != 1) return result(d,out,d->phase == 3 ? OOT_STARTUP_CONTRACT_FAULT : OOT_STARTUP_STOPPED,d->stop_error,d->stop_word,d->stop_service);
    error = check_code(d);
    if (error) return stop(d,out,sink,user,error,0,0,s->pc,0);
    while (count < budget) {
        size_t index = find_instruction(d,d->checkpoint.pc);
        const OotStartupInstruction *i;
        OotArm64State expected, working = d->checkpoint;
        OotGuestMemory window, *memory;
        OotGuestRegion region;
        OotReadEffect effect = {0};
        uint8_t bytes[16] = {0}, wanted[16] = {0};
        uint64_t word, executed = UINT64_MAX, source_pc = working.pc;
        unsigned memory_kind = 0, k;
        int status, control;
        if (!same_state(s,&d->checkpoint)) return stop(d,out,sink,user,OOT_STARTUP_BAD_STATE,0,0,s->pc,1);
        if (index == d->instruction_count) return stop(d,out,sink,user,OOT_STARTUP_UNREGISTERED_TARGET,0,0,working.pc,0);
        i = &d->instructions[index];
        if (d->has_goal && working.pc == d->goal_entry)
            return stop(d,out,sink,user,d->stages_completed == d->stage_count &&
                !d->goal_bad_order && d->goal_thunk_retired ? OOT_STARTUP_SDK_INITIALIZED : OOT_STARTUP_BAD_SDK_GOAL,
                i->word,0,working.pc,0);
        if (d->retired >= d->limit) return stop(d,out,sink,user,OOT_STARTUP_RETIREMENT_LIMIT,i->word,0,working.pc,0);
        memory = oot_startup_context_memory(d->context);
        if (!memory) return stop(d,out,sink,user,OOT_STARTUP_BAD_IMAGE,i->word,0,working.pc,0);
        if (!oot_memory_load(oot_runtime_memory(d->image),i->pc,4,&word) || word != i->word)
            return stop(d,out,sink,user,OOT_STARTUP_BAD_CODE,i->word,0,working.pc,0);
        if (i->kind == OOT_STARTUP_UNSUPPORTED) return stop(d,out,sink,user,OOT_STARTUP_UNSUPPORTED_WORD,i->word,0,working.pc,0);
        if (i->kind == OOT_STARTUP_SYSTEM) {
            uint32_t system = i->word & UINT32_C(0xffffffe0), rd = i->word & 31;
            uint64_t value = 0;
            int atomic = (i->word & UINT32_C(0xbfa07c00)) == UINT32_C(0x88a07c00);
            expected = working; expected.pc += 4;
            if (atomic) {
                unsigned rn=(i->word >> 5)&31, rs=(i->word >> 16)&31;
                unsigned size=(i->word & UINT32_C(0x40000000)) ? 8:4;
                uint64_t address=oot_arm64_read(&working,rn,64,1);
                /* This context/image has one owner thread. The snapshot is
                 * only the independent full-state expectation; the actual
                 * compare/conditional write is one locked backend transfer. */
                if (!oot_memory_load(memory,address,size,&value))
                    return stop(d,out,sink,user,OOT_STARTUP_MEMORY_FAULT,i->word,0,source_pc,0);
                oot_arm64_write(&expected,rs,size*8,0,value);
            }
            else if (system == UINT32_C(0xd53bd060)) value = oot_startup_context_tls_pointer(d->context);
            else if (system == UINT32_C(0xd53bd040)) value = oot_startup_context_tpidr_el0(d->context);
            else value = oot_arm64_read(&working,rd,64,0);
            if (!atomic && system != UINT32_C(0xd51bd040)) oot_arm64_write(&expected,rd,64,0,value);
            d->executing = 1;
            status = oot_startup_context_system(d->context,i->word,&working);
            d->executing = 0;
            if (status != OOT_STARTUP_SERVICE_IMPLEMENTED)
                return stop(d,out,sink,user,status == OOT_STARTUP_SERVICE_UNSUPPORTED ? OOT_STARTUP_UNSUPPORTED_WORD :
                    atomic ? OOT_STARTUP_MEMORY_FAULT : OOT_STARTUP_BAD_STATE,
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
        control = i->kind != OOT_STARTUP_NORMAL || pac_word(i->word);
        if (!control_expected(d,i,&d->checkpoint,&expected))
            return stop(d,out,sink,user,OOT_STARTUP_BAD_STATE,i->word,0,working.pc,0);
        if (find_instruction(d,expected.pc) == d->instruction_count)
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
    if (!same_state(s,&d->checkpoint)) return stop(d,out,sink,user,OOT_STARTUP_BAD_STATE,0,0,s->pc,1);
    return result(d,out,OOT_STARTUP_YIELDED,OOT_STARTUP_OK,0,0);
}
