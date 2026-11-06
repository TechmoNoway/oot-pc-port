#include "stack_dispatch.h"
#include "checked_read.h"
#include "plt_bridge.h"
#include <stdlib.h>
#include <string.h>

typedef struct OwnedFunction {
    OotStackFunction info;
    OotStackStep steps[OOT_STACK_MAX_WORDS];
    OotStackCfgStep flow[OOT_STACK_MAX_WORDS];
    OotStackLayoutStep states[OOT_STACK_MAX_WORDS];
    uint8_t reserved_bytes[OOT_STACK_MAX_FRAME];
    uint32_t saved_mask, locals_begin, record_offset;
    OotPauthRun pauth_run;
    uint32_t sign_word, auth_word;
    uint32_t read_words[OOT_STACK_MAX_WORDS];
    uint32_t open_word, close_word;
} OwnedFunction;
typedef struct Activation {
    size_t function;
    OotArm64State initial;
    uint64_t base, expected_return, signed_lr;
    uint8_t bytes[OOT_STACK_MAX_FRAME];
    unsigned owns;
} Activation;
typedef struct OwnedPlt {
    OotPltFunction info;
    uint64_t page;
    uint32_t target_words;
    OotCodeHash target_hash;
} OwnedPlt;
struct OotStackDispatcher {
    OotRuntimeImage *image;
    OotLeafDispatcher *leaf;
    OotPauth *pauth;
    OwnedFunction functions[OOT_STACK_MAX_FUNCTIONS];
    Activation frames[OOT_STACK_MAX_DEPTH];
    OotArm64State checkpoint;
    uint64_t returns[256], total, expected_return;
    uint8_t body_hash[32];
    size_t count, root, depth, return_count;
    OotReadRange read_ranges[OOT_STACK_MAX_READ_RANGES];
    size_t read_count;
    OotReadRange write_ranges[OOT_STACK_MAX_READ_RANGES];
    size_t write_count;
    OwnedPlt plts[OOT_STACK_MAX_PLT];
    size_t plt_count, active_plt;
    uint64_t plt_return;
    unsigned phase, executing, leaf_active, fault;
};

static int result(const OotStackDispatcher *d, const OotArm64State *s, OotLeafReport *out,
    unsigned status, unsigned error, uint64_t retired)
{
    if (out != NULL) *out = (OotLeafReport){status, error, d != NULL ? d->functions[d->root].info.entry : 0,
        s != NULL ? s->pc : 0, d != NULL ? d->expected_return : 0, retired, d != NULL ? d->total : 0};
    return (int)status;
}

static size_t find_function(const OotStackDispatcher *d, uint64_t entry)
{
    size_t i;
    for (i = 0; i < d->count && d->functions[i].info.entry != entry; ++i) { }
    return i;
}

static size_t find_plt(const OotStackDispatcher *d, uint64_t entry)
{
    size_t i;
    for (i = 0; i < d->plt_count && d->plts[i].info.entry != entry; ++i) { }
    return i;
}

static unsigned plt_check(OotStackDispatcher *d, size_t index, uint64_t *got)
{
    const OwnedPlt *o = &d->plts[index];
    const OotPltFunction *p = &o->info;
    uint64_t target;
    int code = oot_runtime_check_code(d->image,d->body_hash,p->entry,16,p->hash.bytes);
    if (code == OOT_CODE_MATCH)
        code = oot_runtime_check_code(d->image,d->body_hash,p->target,o->target_words*4,o->target_hash.bytes);
    if (code != OOT_CODE_MATCH) return code == OOT_CODE_BAD_IMAGE ? OOT_LEAF_BAD_IMAGE : OOT_LEAF_BAD_CODE;
    if (!oot_memory_load(oot_runtime_memory(d->image),p->slot,8,&target)) return OOT_STACK_BAD_MEMORY;
    if (got) *got = target;
    return target == p->target ? 0 : OOT_STACK_BAD_PLT_TARGET;
}

static unsigned code_match(const OotStackDispatcher *d, size_t index)
{
    const OotStackFunction *f = &d->functions[index].info;
    int code = oot_runtime_check_code(d->image, d->body_hash, f->entry, f->instruction_count * 4, f->hash.bytes);
    return code == OOT_CODE_MATCH ? OOT_LEAF_OK : code == OOT_CODE_BAD_IMAGE ? OOT_LEAF_BAD_IMAGE : OOT_LEAF_BAD_CODE;
}

int oot_stack_destroy(OotStackDispatcher *d)
{
    if (d == NULL) return 1;
    if (d->executing) return 0;
    (void)oot_leaf_dispatcher_destroy(d->leaf);
    oot_runtime_close(d->image);
    oot_pauth_destroy(d->pauth);
    free(d);
    return 1;
}

static int compare_pc(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static int canonical_pointer(uint64_t pointer)
{
    return (pointer >> 39) == 0 || (pointer >> 39) == (UINT64_MAX >> 39);
}

static int transfer_size(unsigned size)
{
    return size == 1 || size == 2 || size == 4 || size == 8 || size == 16;
}

static int validate_cfg_layout(OwnedFunction *owned)
{
    const OotStackFunction *f = &owned->info;
    size_t saves = 0, i, body, epilogue, head = 0, tail = 1;
    uint16_t pending[OOT_STACK_MAX_WORDS] = {0};
    uint8_t visited[OOT_STACK_MAX_WORDS] = {1};
    uint32_t mask = 0, offset = 16, restored = 0;
    while (2 + saves < f->instruction_count - 2 && f->steps[2 + saves].kind == OOT_STACK_SAVE) {
        const OotStackStep *s = &f->steps[2 + saves];
        const OotStackCfgStep *flow = &owned->flow[2 + saves];
        uint32_t bits;
        if (flow->saved_a < 19 || flow->saved_a > 28 || s->offset != offset || (s->size != 8 && s->size != 16)) return 0;
        bits = UINT32_C(1) << flow->saved_a;
        if (s->size == 16) {
            if (flow->saved_b < 19 || flow->saved_b > 28 || flow->saved_a == flow->saved_b) return 0;
            bits |= UINT32_C(1) << flow->saved_b;
        } else if (flow->saved_b != UINT16_MAX) return 0;
        if (mask & bits) return 0;
        mask |= bits; offset += s->size; ++saves;
    }
    body = 2 + saves; epilogue = f->instruction_count - 2 - saves;
    if (body > epilogue || offset > f->frame_size || owned->locals_begin != offset || owned->saved_mask != mask) return 0;
    for (i = 0; i < f->instruction_count; ++i) {
        const OotStackStep *s = &f->steps[i];
        const OotStackCfgStep *flow = &owned->flow[i];
        uint32_t writable = 0;
        if (i >= body && i < epilogue) {
            if (s->kind == OOT_STACK_SAVE || s->kind == OOT_STACK_RESTORE) return 0;
            writable = mask;
        } else if (i >= epilogue && i < f->instruction_count - 2) {
            size_t source = 2 + f->instruction_count - 3 - i;
            const OotStackStep *save = &f->steps[source];
            const OotStackCfgStep *save_flow = &owned->flow[source];
            if (s->kind != OOT_STACK_RESTORE || s->offset != save->offset || s->size != save->size ||
                flow->saved_a != save_flow->saved_a || flow->saved_b != save_flow->saved_b) return 0;
            restored |= UINT32_C(1) << flow->saved_a;
            if (flow->saved_b != UINT16_MAX) restored |= UINT32_C(1) << flow->saved_b;
            writable = mask & ~restored;
        }
        if (s->kind != OOT_STACK_SAVE && s->kind != OOT_STACK_RESTORE &&
            (flow->saved_a != UINT16_MAX || flow->saved_b != UINT16_MAX)) return 0;
        if (flow->writable_mask != writable || flow->max_steps == 0 || flow->max_steps > OOT_STACK_MAX_STEPS) return 0;
        if (s->kind == OOT_STACK_RETURN) {
            if (flow->next_a != UINT16_MAX || flow->next_b != UINT16_MAX) return 0;
        } else if (flow->next_a >= f->instruction_count || flow->next_b >= f->instruction_count) return 0;
        else if (s->kind == OOT_STACK_BRANCH) {
            if (i < body || i >= epilogue || flow->next_a < body || flow->next_a > epilogue ||
                flow->next_b < body || flow->next_b > epilogue) return 0;
        } else if (flow->next_a != i + 1 || flow->next_b != i + 1) return 0;
    }
    while (head < tail) {
        const OotStackCfgStep *flow = &owned->flow[pending[head++]];
        unsigned targets[2] = {flow->next_a, flow->next_b}, which;
        for (which = 0; which < 2; ++which) {
            unsigned target = targets[which];
            if (target != UINT16_MAX && !visited[target]) { visited[target] = 1; pending[tail++] = (uint16_t)target; }
        }
    }
    return tail == f->instruction_count;
}

static int layout_state(const OwnedFunction *o, size_t i, unsigned sp, unsigned fp, unsigned lr, unsigned owner)
{
    const OotStackLayoutStep *s = &o->states[i];
    return s->sp == sp && s->fp == fp && s->lr == lr && s->owner == owner;
}

static int reserve_slot(OwnedFunction *o, uint32_t offset, uint32_t size)
{
    unsigned i;
    if (offset % 8 || offset > o->info.frame_size || size > o->info.frame_size - offset) return 0;
    for (i = offset; i < offset + size; ++i) if (o->reserved_bytes[i]) return 0;
    for (i = offset; i < offset + size; ++i) o->reserved_bytes[i] = 1;
    return 1;
}

static int validate_offset_layout(OwnedFunction *o)
{
    const OotStackFunction *f = &o->info;
    size_t save_indices[OOT_STACK_MAX_WORDS], saves = 0, body, epilogue, i, j, start, tail, head = 0, pending_tail = 1;
    uint16_t pending[OOT_STACK_MAX_WORDS] = {0};
    uint8_t visited[OOT_STACK_MAX_WORDS] = {1};
    uint32_t mask = 0, restored = 0;
    unsigned pac = f->policy_version >= OOT_STACK_PAUTH_POLICY_VERSION;
    unsigned prefix = pac ? 1 : 0, explicit_auth = pac && (o->auth_word == 0xd50323bf || o->auth_word == 0xd50323ff);
    unsigned signed_lr = pac ? 3 : 1, fp_ready = 0, split = f->steps[prefix].kind == OOT_STACK_ALLOC;
    unsigned lr_frame = o->open_word != 0, partner = 0;
    size_t close_index = f->instruction_count - 2 - explicit_auth;
    if (lr_frame) {
        unsigned first = o->open_word & 31, second = (o->open_word >> 10) & 31;
        uint32_t variables = UINT32_C(0x003f8000) | UINT32_C(0x7c1f);
        partner = first == 30 ? second : first;
        if ((f->policy_version != OOT_STACK_CALL_POLICY_VERSION && f->policy_version != OOT_STACK_PLT_POLICY_VERSION &&
            f->policy_version != OOT_STACK_MEMORY_POLICY_VERSION && f->policy_version != OOT_STACK_MEMORY_CALLEE_POLICY_VERSION && f->policy_version != OOT_STACK_BOUNDED_CALLEE_POLICY_VERSION) || split || partner < 19 || partner > 28 ||
            (first != 30 && second != 30) || (o->open_word & ~variables) != UINT32_C(0xa98003e0) ||
            (o->close_word & ~variables) != UINT32_C(0xa8c003e0) ||
            (o->open_word & UINT32_C(0x7c1f)) != (o->close_word & UINT32_C(0x7c1f)) ||
            oot_arm64_sign_extend((o->open_word >> 15) & 127,7) * 8 != UINT64_C(0)-f->frame_size ||
            ((o->close_word >> 15) & 127) * 8 != f->frame_size) return 0;
        mask = UINT32_C(1) << partner;
    } else if (o->close_word) return 0;
    if (pac && (f->steps[0].kind != OOT_STACK_SIGN || !layout_state(o, 0, 1, 0, 3, 0) ||
        (o->sign_word != 0xd503233f && o->sign_word != 0xd503237f) ||
        (o->sign_word == 0xd503233f ? (o->auth_word != 0xd50323bf && o->auth_word != 0xd65f0bff) :
         (o->auth_word != 0xd50323ff && o->auth_word != 0xd65f0fff)))) return 0;
    if (o->locals_begin != 0 || (!split && f->steps[prefix].kind != (uint32_t)(lr_frame ? OOT_STACK_OPEN_LR : OOT_STACK_OPEN)) ||
        (!split && o->record_offset != 0) || !reserve_slot(o, o->record_offset, 16)) return 0;
    start = prefix + (split ? 2 : 1); tail = (split ? 3 : 2) + explicit_auth;
    if (f->instruction_count < start + tail + (lr_frame ? 0 : 1) ||
        !layout_state(o, prefix, 0, 0, 0, 1) || f->steps[f->instruction_count - 1].kind != OOT_STACK_RETURN ||
        f->steps[close_index].kind != (uint32_t)(split ? OOT_STACK_DEALLOC : lr_frame ? OOT_STACK_CLOSE_LR : OOT_STACK_CLOSE)) return 0;
    if (explicit_auth && (f->steps[f->instruction_count - 2].kind != OOT_STACK_AUTH ||
        !layout_state(o, f->instruction_count - 2, 1, 0, 1, 0))) return 0;
    if (split && (f->steps[prefix + 1].kind != OOT_STACK_RECORD_SAVE || !layout_state(o, prefix + 1, 0, 0, 0, 0) ||
        f->steps[close_index - 1].kind != OOT_STACK_RECORD_RESTORE)) return 0;
    for (body = start; body < f->instruction_count - tail; ++body) {
        const OotStackStep *s = &f->steps[body];
        const OotStackCfgStep *flow = &o->flow[body];
        if (s->kind == OOT_STACK_FP) {
            if (fp_ready || lr_frame) return 0;
            fp_ready = 1;
        } else if (s->kind == OOT_STACK_SAVE) {
            uint32_t bits;
            if (flow->saved_a < 19 || flow->saved_a > 28 || (s->size != 8 && s->size != 16)) return 0;
            bits = UINT32_C(1) << flow->saved_a;
            if (s->size == 16) {
                if (flow->saved_b < 19 || flow->saved_b > 28 || flow->saved_a == flow->saved_b) return 0;
                bits |= UINT32_C(1) << flow->saved_b;
            } else if (flow->saved_b != UINT16_MAX) return 0;
            if ((mask & bits) || !reserve_slot(o, s->offset, s->size)) return 0;
            mask |= bits; save_indices[saves++] = body;
        } else break;
        if (!layout_state(o, body, 0, fp_ready, 0, 0)) return 0;
    }
    if ((!fp_ready && !lr_frame) || saves + tail > f->instruction_count) return 0;
    epilogue = f->instruction_count - tail - saves;
    if (body > epilogue || mask != o->saved_mask) return 0;
    for (i = 0; i < f->instruction_count; ++i) {
        const OotStackStep *s = &f->steps[i];
        const OotStackCfgStep *flow = &o->flow[i];
        uint32_t writable = 0;
        int memory = s->kind == OOT_STACK_OPEN || s->kind == OOT_STACK_OPEN_LR || s->kind == OOT_STACK_RECORD_SAVE || s->kind == OOT_STACK_RECORD_RESTORE ||
            s->kind == OOT_STACK_SAVE || s->kind == OOT_STACK_RESTORE || s->kind == OOT_STACK_LOAD || s->kind == OOT_STACK_STORE;
        if (s->reserved || (s->kind != OOT_STACK_CALL && s->callee) || (!memory && (s->offset || s->size))) return 0;
        if (memory && (!transfer_size(s->size) || s->offset > f->frame_size || s->size > f->frame_size - s->offset)) return 0;
        if ((s->kind == OOT_STACK_OPEN || s->kind == OOT_STACK_OPEN_LR || s->kind == OOT_STACK_RECORD_SAVE || s->kind == OOT_STACK_RECORD_RESTORE) &&
            (s->offset != o->record_offset || s->size != 16)) return 0;
        if (i >= body && i < epilogue) {
            if (s->kind != OOT_STACK_NORMAL && s->kind != OOT_STACK_CALL && s->kind != OOT_STACK_BRANCH &&
                s->kind != OOT_STACK_LOAD && s->kind != OOT_STACK_STORE &&
                !(s->kind == OOT_STACK_READ && f->policy_version >= OOT_STACK_READ_POLICY_VERSION) &&
                !(s->kind == OOT_STACK_WRITE && (f->policy_version == OOT_STACK_MEMORY_POLICY_VERSION || f->policy_version == OOT_STACK_MEMORY_CALLEE_POLICY_VERSION || f->policy_version == OOT_STACK_BOUNDED_CALLEE_POLICY_VERSION))) return 0;
            if (s->kind == OOT_STACK_READ || s->kind == OOT_STACK_WRITE) {
                OotReadEffect e;
                OotArm64State empty = {0};
                uint32_t bits;
                if (!(s->kind == OOT_STACK_WRITE ? oot_write_decode : oot_read_decode)(o->read_words[i],f->entry+i*4,&empty,&e)) return 0;
                if (lr_frame && e.frame_base && !e.sp_base) return 0;
                bits = (e.rd == 31 ? 0 : UINT32_C(1) << e.rd) | (e.pair && e.rt2 != 31 ? UINT32_C(1) << e.rt2 : 0);
                if (s->kind == OOT_STACK_READ && (bits & ~(mask | UINT32_C(0x3ffff)))) return 0;
            }
            if (!layout_state(o, i, 0, !lr_frame, s->kind == OOT_STACK_CALL ? 2 : 0, 0)) return 0;
            if (s->kind == OOT_STACK_LOAD || s->kind == OOT_STACK_STORE)
                for (j = s->offset; j < s->offset + s->size; ++j) if (o->reserved_bytes[j]) return 0;
            writable = mask;
        } else if (i >= epilogue && i < f->instruction_count - tail) {
            size_t source = save_indices[f->instruction_count - tail - 1 - i];
            const OotStackStep *save = &f->steps[source];
            const OotStackCfgStep *save_flow = &o->flow[source];
            if (s->kind != OOT_STACK_RESTORE || s->offset != save->offset || s->size != save->size ||
                flow->saved_a != save_flow->saved_a || flow->saved_b != save_flow->saved_b || !layout_state(o, i, 0, !lr_frame, 0, 0)) return 0;
            restored |= UINT32_C(1) << flow->saved_a;
            if (flow->saved_b != UINT16_MAX) restored |= UINT32_C(1) << flow->saved_b;
            writable = mask & ~restored;
        } else if (i == f->instruction_count - 1) { if (!layout_state(o, i, 1, 0, pac && !explicit_auth ? 3 : 1, 0)) return 0; }
        else if (i == close_index) { if (!layout_state(o, i, 1, 0, signed_lr, 2)) return 0; }
        else if (split && i == close_index - 1) { if (!layout_state(o, i, 0, 0, signed_lr, 0)) return 0; }
        if (flow->writable_mask != writable || flow->max_steps == 0 || flow->max_steps > OOT_STACK_MAX_STEPS ||
            ((s->kind != OOT_STACK_SAVE && s->kind != OOT_STACK_RESTORE) && (flow->saved_a != UINT16_MAX || flow->saved_b != UINT16_MAX))) return 0;
        if (s->kind != OOT_STACK_READ && s->kind != OOT_STACK_WRITE && o->read_words[i]) return 0;
        if (s->kind == OOT_STACK_RETURN) {
            if (flow->next_a != UINT16_MAX || flow->next_b != UINT16_MAX) return 0;
        } else if (flow->next_a >= f->instruction_count || flow->next_b >= f->instruction_count) return 0;
        else if (s->kind == OOT_STACK_BRANCH) {
            if (flow->next_a < body || flow->next_a > epilogue || flow->next_b < body || flow->next_b > epilogue) return 0;
        } else if (flow->next_a != i + 1 || flow->next_b != i + 1) return 0;
    }
    while (head < pending_tail) {
        const OotStackCfgStep *flow = &o->flow[pending[head++]];
        unsigned targets[2] = {flow->next_a, flow->next_b}, which;
        for (which = 0; which < 2; ++which) {
            unsigned target = targets[which];
            if (target != UINT16_MAX && !visited[target]) { visited[target] = 1; pending[pending_tail++] = (uint16_t)target; }
        }
    }
    return pending_tail == f->instruction_count;
}

static OotStackDispatcher *create_registry(OotRuntimeImage *image,
    const OotStackFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error,
    const OotStackCfgFunction *cfg, const OotStackLayoutFunction *layout,
    const OotStackPauthFunction *pac, OotPauth *pauth, const OotStackReadFunction *reads,
    const OotReadRange *ranges, size_t range_count, const OotStackCallFunction *lr_calls,
    const OotPltFunction *plts, size_t plt_count, int writes,
    const OotReadRange *write_ranges, size_t write_count, const OotMemoryLeafFunction *memory_leaves, int memory_callees,
    const OotBoundedLeafFunction *bounded_leaves, int bounded_callees)
{
    OotStackDispatcher *d;
    uint64_t sites[256 + OOT_STACK_MAX_FUNCTIONS * OOT_STACK_MAX_WORDS];
    uint32_t bounds[OOT_STACK_MAX_FUNCTIONS] = {0}, depths[OOT_STACK_MAX_FUNCTIONS] = {0};
    uint8_t visited[OOT_STACK_MAX_FUNCTIONS] = {0};
    size_t pending[OOT_STACK_MAX_FUNCTIONS], i, j, k, nsites = return_count, unique = 0, pass, head = 0, tail = 1;
    if (error != NULL) *error = OOT_LEAF_BAD_ARGUMENT;
    if (image == NULL || functions == NULL || count == 0 || count > OOT_STACK_MAX_FUNCTIONS ||
        leaf_count > OOT_LEAF_MAX_FUNCTIONS || (leaf_count && (leaves == NULL || hashes == NULL)) ||
        body_hash == NULL || returns == NULL || return_count == 0 || return_count > 256 ||
        (pac && oot_pauth_model(pauth) != OOT_PAUTH_QARMA5_VA39) ||
        (plts && (!lr_calls || !leaf_count || !plt_count || plt_count > OOT_STACK_MAX_PLT)) || (!plts && plt_count) ||
        (reads && (range_count > OOT_STACK_MAX_READ_RANGES || (range_count && !ranges) || (!writes && !range_count))) ||
        (writes && (!reads || write_count > OOT_STACK_MAX_READ_RANGES || (write_count && !write_ranges))) ||
        (!writes && write_count) || (memory_callees && (!writes || (leaf_count && !memory_leaves))) || (bounded_callees && (!memory_callees || (leaf_count && !bounded_leaves)))) return NULL;
    d = calloc(1, sizeof(*d));
    if (d == NULL) { if (error != NULL) *error = OOT_LEAF_ALLOCATION_FAILED; return NULL; }
    if (error != NULL) *error = OOT_STACK_BAD_REGISTRY;
    d->count = count;
    for (i = 0; i < count; ++i) {
        const OotStackFunction *f = &functions[i];
        if (f->entry % 4 || f->instruction_count < 4 || f->instruction_count > OOT_STACK_MAX_WORDS ||
            f->entry > UINT64_MAX - (uint64_t)f->instruction_count * 4 ||
            (pac ? (f->run != NULL || pac[i].run == NULL) : f->run == NULL) || f->steps == NULL ||
            (pac && (!canonical_pointer(f->entry) || !canonical_pointer(f->entry + (uint64_t)f->instruction_count * 4 - 1))) ||
            f->abi_version != OOT_LIFT_ABI_VERSION || f->policy_version != (bounded_callees ? OOT_STACK_BOUNDED_CALLEE_POLICY_VERSION : memory_callees ? OOT_STACK_MEMORY_CALLEE_POLICY_VERSION : writes ? OOT_STACK_MEMORY_POLICY_VERSION : plts ? OOT_STACK_PLT_POLICY_VERSION : lr_calls ? OOT_STACK_CALL_POLICY_VERSION : reads ? OOT_STACK_READ_POLICY_VERSION : pac ? OOT_STACK_PAUTH_POLICY_VERSION : layout != NULL ? OOT_STACK_LAYOUT_POLICY_VERSION :
                cfg != NULL ? OOT_STACK_CFG_POLICY_VERSION : OOT_STACK_POLICY_VERSION) ||
            f->frame_size < 16 || f->frame_size > OOT_STACK_MAX_FRAME || f->frame_size % 16 ||
            (i && f->entry < functions[i - 1].entry + (uint64_t)functions[i - 1].instruction_count * 4)) goto failure;
        d->functions[i].info = *f;
        if (lr_calls) {
            d->functions[i].open_word = lr_calls[i].open_word;
            d->functions[i].close_word = lr_calls[i].close_word;
        }
        if (pac) {
            d->functions[i].pauth_run = pac[i].run;
            d->functions[i].sign_word = pac[i].sign_word;
            d->functions[i].auth_word = pac[i].auth_word;
        }
        if (reads) {
            if (!reads[i].read_words) goto failure;
            memcpy(d->functions[i].read_words,reads[i].read_words,f->instruction_count*sizeof(uint32_t));
        }
        memcpy(d->functions[i].steps, f->steps, f->instruction_count * sizeof(*f->steps));
        d->functions[i].info.steps = d->functions[i].steps;
        d->functions[i].locals_begin = 16;
        if (cfg != NULL) {
            if (cfg[i].flow == NULL) goto failure;
            memcpy(d->functions[i].flow, cfg[i].flow, f->instruction_count * sizeof(*cfg[i].flow));
            d->functions[i].saved_mask = cfg[i].saved_mask;
            d->functions[i].locals_begin = cfg[i].locals_begin;
            if (layout != NULL) {
                if (layout[i].states == NULL || layout[i].reserved) goto failure;
                memcpy(d->functions[i].states, layout[i].states, f->instruction_count * sizeof(*layout[i].states));
                d->functions[i].record_offset = layout[i].record_offset;
                if (!validate_offset_layout(&d->functions[i])) goto failure;
            } else if (!validate_cfg_layout(&d->functions[i])) goto failure;
        }
        for (j = 0; j < f->instruction_count; ++j) {
            const OotStackStep *s = &f->steps[j];
            unsigned expected = j == 0 ? OOT_STACK_OPEN : j == 1 ? OOT_STACK_FP :
                j == f->instruction_count - 2 ? OOT_STACK_CLOSE : j == f->instruction_count - 1 ? OOT_STACK_RETURN : s->kind;
            if (layout != NULL) {
                if (s->kind == OOT_STACK_CALL) sites[nsites++] = f->entry + (j + 1) * 4;
                continue;
            }
            if (s->reserved || s->kind != expected) goto failure;
            if (j == 0) { if (s->offset || s->size != 16 || s->callee) goto failure; }
            else if (s->kind == OOT_STACK_LOAD || s->kind == OOT_STACK_STORE ||
                (cfg != NULL && (s->kind == OOT_STACK_SAVE || s->kind == OOT_STACK_RESTORE))) {
                unsigned minimum = s->kind == OOT_STACK_SAVE || s->kind == OOT_STACK_RESTORE ? 16 : d->functions[i].locals_begin;
                if (!transfer_size(s->size) || s->offset < minimum || s->offset > f->frame_size ||
                    s->size > f->frame_size - s->offset || s->callee) goto failure;
            } else {
                if (s->offset || s->size || (s->kind != OOT_STACK_CALL && s->callee)) goto failure;
                if (j > 1 && j < f->instruction_count - 2 && s->kind != OOT_STACK_NORMAL && s->kind != OOT_STACK_CALL &&
                    !(cfg != NULL && s->kind == OOT_STACK_BRANCH)) goto failure;
            }
            if (s->kind == OOT_STACK_CALL) sites[nsites++] = f->entry + (j + 1) * 4;
        }
    }
    d->root = find_function(d, root);
    if (d->root == count) goto failure;
    d->plt_count = plt_count;
    for (i = 0; i < plt_count; ++i) {
        OwnedPlt *o = &d->plts[i];
        const OotPltFunction *p = &plts[i];
        const OotGuestMemory *m = oot_runtime_memory(image);
        int readable = 0;
        o->info = *p;
        if (!oot_plt_decode(p,&o->page) || (i && p->entry < plts[i-1].entry+16) ||
            p->slot >= oot_runtime_stack_base(image) || oot_runtime_stack_base(image)-p->slot < 8) goto failure;
        for (j = 0; j < count; ++j)
            if (p->entry < functions[j].entry+functions[j].instruction_count*4 && functions[j].entry < p->entry+16) goto failure;
        for (j = 0; j < leaf_count; ++j) {
            if (p->entry < leaves[j].entry+leaves[j].instruction_count*4 && leaves[j].entry < p->entry+16) goto failure;
            if (p->target == leaves[j].entry) { o->target_words = leaves[j].instruction_count; o->target_hash = hashes[j]; }
        }
        if (!o->target_words) goto failure;
        for (j = 0; j < m->count; ++j) {
            const OotGuestRegion *r = &m->regions[j];
            if ((r->permissions & OOT_MEMORY_READ) && p->slot >= r->base && p->slot-r->base < r->size &&
                8 <= r->size-(p->slot-r->base)) readable = 1;
        }
        if (!readable) goto failure;
    }
    for (i = 0; i < return_count; ++i) {
        if (returns[i] % 4 || (pac && !canonical_pointer(returns[i])) || (i && returns[i] <= returns[i - 1])) goto failure;
        for (j = 0; j < count; ++j)
            if (returns[i] >= functions[j].entry && returns[i] < functions[j].entry + (uint64_t)functions[j].instruction_count * 4) goto failure;
        for (j = 0; j < plt_count; ++j) if (returns[i] >= plts[j].entry && returns[i] < plts[j].entry+16) goto failure;
        d->returns[i] = sites[i] = returns[i];
    }
    d->return_count = return_count;
    qsort(sites, nsites, sizeof(*sites), compare_pc);
    for (i = 0; i < nsites; ++i) if (!i || sites[i] != sites[i - 1]) sites[unique++] = sites[i];
    if (unique > OOT_LEAF_MAX_RETURNS) goto failure;
    if (leaf_count) {
        d->leaf = bounded_callees ? oot_leaf_dispatcher_create_bounded_bound(image,bounded_leaves,leaf_count,hashes,body_hash,
            sites,unique,ranges,range_count,write_ranges,write_count,error) : memory_callees ? oot_leaf_dispatcher_create_memory_bound(image,memory_leaves,leaf_count,hashes,body_hash,
            sites,unique,ranges,range_count,write_ranges,write_count,error) :
            oot_leaf_dispatcher_create_bound(image, leaves, leaf_count, hashes, body_hash, sites, unique, error);
        if (d->leaf == NULL) goto failure;
    }
    if (error != NULL) *error = OOT_STACK_BAD_REGISTRY;
    for (i = 0; i < count; ++i) for (j = 0; j < leaf_count; ++j)
        if (functions[i].entry < leaves[j].entry + (uint64_t)leaves[j].instruction_count * 4 &&
            leaves[j].entry < functions[i].entry + (uint64_t)functions[i].instruction_count * 4) goto failure;
    /* Resolve finite call ranks without recursing on either native or guest stacks. */
    for (pass = 0; pass < count; ++pass) for (i = 0; i < count; ++i) if (!bounds[i]) {
        uint64_t bound = functions[i].instruction_count;
        uint32_t depth = 1;
        int ready = 1;
        for (j = 0; j < functions[i].instruction_count; ++j) if (functions[i].steps[j].kind == OOT_STACK_CALL) {
            uint64_t target = functions[i].steps[j].callee;
            k = find_function(d, target);
            if (k != count) {
                if (!bounds[k]) { ready = 0; break; }
                bound += bounds[k];
                if (depth < depths[k] + 1) depth = depths[k] + 1;
            } else {
                for (k = 0; k < leaf_count && leaves[k].entry != target; ++k) { }
                if (k != leaf_count) bound += leaves[k].max_steps;
                else {
                    size_t li;
                    k = find_plt(d,target); if (k == plt_count) goto failure;
                    for (li = 0; li < leaf_count && leaves[li].entry != plts[k].target; ++li) { }
                    bound += 4 + leaves[li].max_steps;
                }
            }
        }
        if (ready) {
            if (cfg != NULL) {
                for (j = 0; j < functions[i].instruction_count; ++j) {
                    const OotStackCfgStep *flow = &d->functions[i].flow[j];
                    const OotStackStep *step = &functions[i].steps[j];
                    uint64_t weight = 1, longest = 0;
                    if (step->kind == OOT_STACK_CALL) {
                        k = find_function(d, step->callee);
                        if (k != count) weight += bounds[k];
                        else {
                            for (k = 0; k < leaf_count && leaves[k].entry != step->callee; ++k) { }
                            if (k != leaf_count) weight += leaves[k].max_steps;
                            else {
                                size_t pi = find_plt(d,step->callee), li;
                                if (pi == plt_count) goto failure;
                                for (li = 0; li < leaf_count && leaves[li].entry != plts[pi].target; ++li) { }
                                weight += 4 + leaves[li].max_steps;
                            }
                        }
                    }
                    if (flow->next_a != UINT16_MAX) longest = d->functions[i].flow[flow->next_a].max_steps;
                    if (flow->next_b != UINT16_MAX && longest < d->functions[i].flow[flow->next_b].max_steps)
                        longest = d->functions[i].flow[flow->next_b].max_steps;
                    if (weight + longest != flow->max_steps) goto failure;
                }
                bound = d->functions[i].flow[0].max_steps;
            }
            if (bound > OOT_STACK_MAX_STEPS || depth > OOT_STACK_MAX_DEPTH ||
                bound != functions[i].max_steps || depth != functions[i].max_depth) goto failure;
            bounds[i] = (uint32_t)bound; depths[i] = depth;
        }
    }
    for (i = 0; i < count; ++i) if (!bounds[i]) goto failure;
    pending[0] = d->root; visited[d->root] = 1;
    while (head < tail) {
        const OotStackFunction *f = &d->functions[pending[head++]].info;
        for (j = 0; j < f->instruction_count; ++j) if (f->steps[j].kind == OOT_STACK_CALL) {
            k = find_function(d, f->steps[j].callee);
            if (k != count && !visited[k]) { visited[k] = 1; pending[tail++] = k; }
        }
    }
    if (tail != count) goto failure;
    if (!oot_runtime_retain(image)) { if (error != NULL) *error = OOT_LEAF_BAD_IMAGE; goto failure; }
    d->image = image;
    if (pac) {
        if (!oot_pauth_retain(pauth)) goto failure;
        d->pauth = pauth;
    }
    memcpy(d->body_hash, body_hash, 32);
    for (i = 0; i < plt_count; ++i) {
        unsigned reason = plt_check(d,i,NULL);
        uint64_t word;
        if (reason) { if (error) *error = reason; goto failure; }
        for (j = 0; j < 4; ++j)
            if (!oot_memory_load(oot_runtime_memory(image),plts[i].entry+j*4,4,&word) || word != plts[i].words[j]) goto failure;
    }
    for (i = 0; i < count; ++i) {
        unsigned reason = code_match(d, i);
        if (reason) { if (error != NULL) *error = reason; goto failure; }
        if (reads) for (j = 0; j < functions[i].instruction_count; ++j) if (d->functions[i].read_words[j]) {
            uint64_t word;
            if (!oot_memory_load(oot_runtime_memory(image),functions[i].entry+j*4,4,&word) || word != d->functions[i].read_words[j]) goto failure;
        }
        if (lr_calls && d->functions[i].open_word) {
            uint64_t word;
            size_t close = functions[i].instruction_count - 2 -
                (d->functions[i].auth_word == UINT32_C(0xd50323bf) || d->functions[i].auth_word == UINT32_C(0xd50323ff));
            if (!oot_memory_load(oot_runtime_memory(image),functions[i].entry+4,4,&word) || word != d->functions[i].open_word ||
                !oot_memory_load(oot_runtime_memory(image),functions[i].entry+close*4,4,&word) || word != d->functions[i].close_word) goto failure;
        }
    }
    if (reads) {
        const OotGuestMemory *m = oot_runtime_memory(image);
        for (i = 0; i < range_count; ++i) {
            const OotReadRange *r = &ranges[i];
            int found = 0;
            if (!r->size || r->base >= oot_runtime_stack_base(image) || r->size > oot_runtime_stack_base(image)-r->base ||
                (i && (r->base < ranges[i-1].base || r->base-ranges[i-1].base < ranges[i-1].size))) goto failure;
            for (j = 0; j < m->count; ++j) {
                const OotGuestRegion *region = &m->regions[j];
                if ((region->permissions & OOT_MEMORY_READ) && r->base >= region->base &&
                    r->base-region->base < region->size && r->size <= region->size-(r->base-region->base)) found = 1;
            }
            if (!found) goto failure;
            d->read_ranges[i] = *r;
        }
        d->read_count = range_count;
    }
    if (writes) {
        const OotGuestMemory *m = oot_runtime_memory(image);
        for (i = 0; i < write_count; ++i) {
            const OotReadRange *r = &write_ranges[i];
            int found = 0;
            if (!r->size || r->base >= oot_runtime_stack_base(image) || r->size > oot_runtime_stack_base(image)-r->base ||
                (i && (r->base < write_ranges[i-1].base || r->base-write_ranges[i-1].base < write_ranges[i-1].size))) goto failure;
            for (j = 0; j < m->count; ++j) {
                const OotGuestRegion *region = &m->regions[j];
                if ((region->permissions & OOT_MEMORY_WRITE) && r->base >= region->base &&
                    r->base-region->base < region->size && r->size <= region->size-(r->base-region->base)) found = 1;
            }
            if (!found) goto failure;
            if (memory_callees) for (j = 0; j < plt_count; ++j)
                if (r->base < plts[j].slot+8 && plts[j].slot < r->base+r->size) goto failure;
            d->write_ranges[i] = *r;
        }
        d->write_count = write_count;
    }
    if (error != NULL) *error = 0;
    return d;
failure:
    (void)oot_stack_destroy(d);
    return NULL;
}

OotStackDispatcher *oot_stack_create(OotRuntimeImage *image,
    const OotStackFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error)
{
    return create_registry(image, functions, count, root, leaves, leaf_count, hashes, body_hash, returns, return_count, error, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, 0);
}

OotStackDispatcher *oot_stack_create_cfg(OotRuntimeImage *image,
    const OotStackCfgFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error)
{
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error != NULL) *error = OOT_LEAF_BAD_ARGUMENT;
    if (functions == NULL || count == 0 || count > OOT_STACK_MAX_FUNCTIONS) return NULL;
    for (i = 0; i < count; ++i) common[i] = functions[i].info;
    return create_registry(image, common, count, root, leaves, leaf_count, hashes, body_hash, returns, return_count, error, functions, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, 0);
}

OotStackDispatcher *oot_stack_create_layout(OotRuntimeImage *image,
    const OotStackLayoutFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error)
{
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error != NULL) *error = OOT_LEAF_BAD_ARGUMENT;
    if (functions == NULL || count == 0 || count > OOT_STACK_MAX_FUNCTIONS) return NULL;
    for (i = 0; i < count; ++i) { cfg[i] = functions[i].cfg; common[i] = cfg[i].info; }
    return create_registry(image, common, count, root, leaves, leaf_count, hashes, body_hash, returns, return_count, error, cfg, functions, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, 0);
}

OotStackDispatcher *oot_stack_create_pauth(OotRuntimeImage *image,
    const OotStackPauthFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, OotPauth *pauth, uint32_t *error)
{
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    OotStackLayoutFunction layout[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_STACK_MAX_FUNCTIONS) return NULL;
    for (i = 0; i < count; ++i) { layout[i] = functions[i].layout; cfg[i] = layout[i].cfg; common[i] = cfg[i].info; }
    return create_registry(image, common, count, root, leaves, leaf_count, hashes, body_hash, returns, return_count,
                           error, cfg, layout, functions, pauth, NULL, NULL, 0, NULL, NULL, 0, 0, NULL, 0, NULL, 0, NULL, 0);
}

OotStackDispatcher *oot_stack_create_reads(OotRuntimeImage *image,
    const OotStackReadFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count, uint32_t *error)
{
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    OotStackLayoutFunction layout[OOT_STACK_MAX_FUNCTIONS];
    OotStackPauthFunction pac[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_STACK_MAX_FUNCTIONS) return NULL;
    for (i=0;i<count;++i) { pac[i]=functions[i].pauth; layout[i]=pac[i].layout; cfg[i]=layout[i].cfg; common[i]=cfg[i].info; }
    return create_registry(image,common,count,root,leaves,leaf_count,hashes,body_hash,returns,return_count,error,
                           cfg,layout,pac,pauth,functions,ranges,range_count,NULL,NULL,0,0,NULL,0,NULL,0,NULL,0);
}

OotStackDispatcher *oot_stack_create_calls(OotRuntimeImage *image,
    const OotStackCallFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count, uint32_t *error)
{
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    OotStackLayoutFunction layout[OOT_STACK_MAX_FUNCTIONS];
    OotStackPauthFunction pac[OOT_STACK_MAX_FUNCTIONS];
    OotStackReadFunction reads[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_STACK_MAX_FUNCTIONS) return NULL;
    for (i = 0; i < count; ++i) {
        reads[i] = functions[i].reads; pac[i] = reads[i].pauth;
        layout[i] = pac[i].layout; cfg[i] = layout[i].cfg; common[i] = cfg[i].info;
    }
    return create_registry(image,common,count,root,leaves,leaf_count,hashes,body_hash,returns,return_count,error,
                           cfg,layout,pac,pauth,reads,ranges,range_count,functions,NULL,0,0,NULL,0,NULL,0,NULL,0);
}

OotStackDispatcher *oot_stack_create_plt(OotRuntimeImage *image,
    const OotStackCallFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count,
    const OotPltFunction *plts, size_t plt_count, uint32_t *error)
{
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    OotStackLayoutFunction layout[OOT_STACK_MAX_FUNCTIONS];
    OotStackPauthFunction pac[OOT_STACK_MAX_FUNCTIONS];
    OotStackReadFunction reads[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_STACK_MAX_FUNCTIONS || !plts || !plt_count) return NULL;
    for (i = 0; i < count; ++i) {
        reads[i] = functions[i].reads; pac[i] = reads[i].pauth;
        layout[i] = pac[i].layout; cfg[i] = layout[i].cfg; common[i] = cfg[i].info;
    }
    return create_registry(image,common,count,root,leaves,leaf_count,hashes,body_hash,returns,return_count,error,
                           cfg,layout,pac,pauth,reads,ranges,range_count,functions,plts,plt_count,0,NULL,0,NULL,0,NULL,0);
}

OotStackDispatcher *oot_stack_create_memory(OotRuntimeImage *image,
    const OotStackCallFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count,
    const OotPltFunction *plts, size_t plt_count,
    const OotReadRange *write_ranges, size_t write_count, uint32_t *error)
{
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    OotStackLayoutFunction layout[OOT_STACK_MAX_FUNCTIONS];
    OotStackPauthFunction pac[OOT_STACK_MAX_FUNCTIONS];
    OotStackReadFunction reads[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_STACK_MAX_FUNCTIONS) return NULL;
    for (i = 0; i < count; ++i) {
        reads[i] = functions[i].reads; pac[i] = reads[i].pauth;
        layout[i] = pac[i].layout; cfg[i] = layout[i].cfg; common[i] = cfg[i].info;
    }
    return create_registry(image,common,count,root,leaves,leaf_count,hashes,body_hash,returns,return_count,error,
                           cfg,layout,pac,pauth,reads,ranges,range_count,functions,plts,plt_count,1,write_ranges,write_count,NULL,0,NULL,0);
}

OotStackDispatcher *oot_stack_create_memory_callees(OotRuntimeImage *image,
    const OotStackCallFunction *functions, size_t count, uint64_t root,
    const OotMemoryLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count,
    const OotPltFunction *plts, size_t plt_count,
    const OotReadRange *write_ranges, size_t write_count, uint32_t *error)
{
    OotLeafFunction terminal[OOT_LEAF_MAX_FUNCTIONS];
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    OotStackLayoutFunction layout[OOT_STACK_MAX_FUNCTIONS];
    OotStackPauthFunction pac[OOT_STACK_MAX_FUNCTIONS];
    OotStackReadFunction reads[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_STACK_MAX_FUNCTIONS || leaf_count > OOT_LEAF_MAX_FUNCTIONS || (leaf_count && !leaves)) return NULL;
    for (i = 0; i < leaf_count; ++i) terminal[i] = leaves[i].info;
    for (i = 0; i < count; ++i) {
        reads[i] = functions[i].reads; pac[i] = reads[i].pauth;
        layout[i] = pac[i].layout; cfg[i] = layout[i].cfg; common[i] = cfg[i].info;
    }
    return create_registry(image,common,count,root,terminal,leaf_count,hashes,body_hash,returns,return_count,error,
                           cfg,layout,pac,pauth,reads,ranges,range_count,functions,plts,plt_count,1,write_ranges,write_count,leaves,1,NULL,0);
}

OotStackDispatcher *oot_stack_create_bounded_callees(OotRuntimeImage *image,
    const OotStackCallFunction *functions, size_t count, uint64_t root,
    const OotBoundedLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count,
    const OotPltFunction *plts, size_t plt_count,
    const OotReadRange *write_ranges, size_t write_count, uint32_t *error)
{
    OotMemoryLeafFunction legacy[OOT_LEAF_MAX_FUNCTIONS];
    OotLeafFunction terminal[OOT_LEAF_MAX_FUNCTIONS];
    OotStackFunction common[OOT_STACK_MAX_FUNCTIONS];
    OotStackCfgFunction cfg[OOT_STACK_MAX_FUNCTIONS];
    OotStackLayoutFunction layout[OOT_STACK_MAX_FUNCTIONS];
    OotStackPauthFunction pac[OOT_STACK_MAX_FUNCTIONS];
    OotStackReadFunction reads[OOT_STACK_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_STACK_MAX_FUNCTIONS || leaf_count > OOT_LEAF_MAX_FUNCTIONS || (leaf_count && !leaves)) return NULL;
    for (i = 0; i < leaf_count; ++i) { legacy[i] = leaves[i].memory; terminal[i] = legacy[i].info; }
    for (i = 0; i < count; ++i) {
        reads[i] = functions[i].reads; pac[i] = reads[i].pauth;
        layout[i] = pac[i].layout; cfg[i] = layout[i].cfg; common[i] = cfg[i].info;
    }
    return create_registry(image,common,count,root,terminal,leaf_count,hashes,body_hash,returns,return_count,error,
                           cfg,layout,pac,pauth,reads,ranges,range_count,functions,plts,plt_count,1,write_ranges,write_count,legacy,1,leaves,1);
}

static int same_state(const OotArm64State *a, const OotArm64State *b)
{
    return memcmp(a->x, b->x, sizeof(a->x)) == 0 && a->sp == b->sp && a->pc == b->pc && a->nzcv == b->nzcv;
}

static int fits(const OotStackDispatcher *d, size_t function, uint64_t sp)
{
    uint64_t low = oot_runtime_stack_base(d->image), high = oot_runtime_stack_pointer(d->image);
    return sp % 16 == 0 && sp >= low && sp <= high && sp - low >= d->functions[function].info.frame_size;
}

static void activate(OotStackDispatcher *d, size_t function, const OotArm64State *s, uint64_t expected_return)
{
    Activation *a = &d->frames[d->depth++];
    a->function = function; a->initial = *s; a->base = s->sp - d->functions[function].info.frame_size;
    a->expected_return = expected_return; a->owns = 0;
    a->signed_lr = 0;
}

int oot_stack_begin(OotStackDispatcher *d, const OotArm64State *s, uint64_t expected_return, OotLeafReport *out)
{
    size_t i;
    unsigned error;
    if (d == NULL || s == NULL) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing || d->phase == 1 || d->phase == 3)
        return result(d, s, out, OOT_LEAF_REJECTED, d->executing ? OOT_LEAF_REENTRY : OOT_LEAF_BUSY, 0);
    error = code_match(d, d->root);
    for (i = 0; i < d->return_count && d->returns[i] != expected_return; ++i) { }
    if (!error && s->pc != d->functions[d->root].info.entry) error = OOT_LEAF_BAD_ENTRY;
    if (!error && (i == d->return_count || s->x[30] != expected_return)) error = OOT_LEAF_BAD_RETURN;
    if (!error && !fits(d, d->root, s->sp)) error = OOT_LEAF_BAD_STACK;
    if (!error && (s->nzcv & UINT32_C(0x0fffffff))) error = OOT_LEAF_BAD_NZCV;
    if (error) return result(d, s, out, OOT_LEAF_REJECTED, error, 0);
    if (d->leaf != NULL) (void)oot_leaf_abort(d->leaf, NULL);
    d->depth = 0; activate(d, d->root, s, expected_return);
    d->checkpoint = *s; d->expected_return = expected_return; d->total = 0;
    d->phase = 1; d->fault = 0; d->leaf_active = 0; d->active_plt = 0;
    return result(d, s, out, OOT_LEAF_READY, 0, 0);
}

int oot_stack_abort(OotStackDispatcher *d, OotLeafReport *out)
{
    if (d == NULL) return result(NULL, NULL, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return result(d, &d->checkpoint, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    if (d->leaf != NULL) (void)oot_leaf_abort(d->leaf, NULL);
    d->phase = 0; d->depth = 0; d->total = 0; d->leaf_active = 0; d->active_plt = 0;
    return result(d, NULL, out, OOT_LEAF_READY, 0, 0);
}

static uint64_t read_le(const uint8_t *bytes, unsigned size)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < size; ++i) value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

static int read_frame(OotStackDispatcher *d, const Activation *a, uint8_t *bytes)
{
    unsigned i, j, size = d->functions[a->function].info.frame_size;
    for (i = 0; i < size; i += 16) {
        uint64_t first, second;
        if (!oot_memory_load_pair(oot_runtime_memory(d->image), a->base + i, 8, &first, &second)) return 0;
        for (j = 0; j < 8; ++j) { bytes[i + j] = (uint8_t)(first >> (8 * j)); bytes[i + j + 8] = (uint8_t)(second >> (8 * j)); }
    }
    return 1;
}

static unsigned check_owners(OotStackDispatcher *d, int check_code)
{
    size_t i;
    uint8_t bytes[OOT_STACK_MAX_FRAME];
    for (i = 0; i < d->depth; ++i) {
        Activation *a = &d->frames[i];
        unsigned reason = check_code ? code_match(d, a->function) : 0;
        if (reason) return reason;
        if (a->owns && (!read_frame(d, a, bytes) || memcmp(bytes, a->bytes, d->functions[a->function].info.frame_size)))
            return OOT_STACK_CHANGED;
    }
    if (d->active_plt) return plt_check(d,d->active_plt-1,NULL);
    return 0;
}

/* One original bridge instruction, with no image/frame access exposed to code. */
static unsigned plt_step(OotStackDispatcher *d, OotArm64State *working, int *contract)
{
    const OwnedPlt *o = &d->plts[d->active_plt-1];
    const OotPltFunction *p = &o->info;
    OotArm64State expected;
    OotGuestMemory window;
    OotGuestRegion region;
    uint8_t bytes[8] = {0}, original[8] = {0};
    uint64_t got, executed = UINT64_MAX;
    unsigned index, i, reason = plt_check(d,d->active_plt-1,&got);
    int status;
    *contract = 0;
    if (reason) return reason;
    if (working->pc < p->entry || working->pc-p->entry >= 16 || (working->pc-p->entry)%4)
        return OOT_LEAF_BAD_STATE;
    index = (unsigned)((working->pc-p->entry)/4);
    if (!oot_plt_expected(p,o->page,index,working,&expected)) return OOT_LEAF_BAD_STATE;
    if (index == 1) {
        for (i = 0; i < 8; ++i) bytes[i] = original[i] = (uint8_t)(got >> (i*8));
        region = (OotGuestRegion){p->slot,8,bytes,OOT_MEMORY_READ};
        (void)oot_memory_init(&window,&region,1);
    } else (void)oot_memory_init(&window,NULL,0);
    d->executing = 1;
    status = p->run(working,&window,1,&executed);
    d->executing = 0;
    if (status != (index == 3 ? OOT_LIFT_DISPATCH : OOT_LIFT_BUDGET)) reason = OOT_LEAF_BAD_LIFT_STATUS;
    else if (executed != 1) reason = OOT_LEAF_BAD_COUNT;
    else if (working->pc != expected.pc) reason = OOT_LEAF_BAD_EDGE;
    else if (window.fault.reason) reason = OOT_STACK_BAD_MEMORY;
    else if (!same_state(working,&expected) || window.valid != 1 ||
        (index == 1 ? (window.regions != &region || window.count != 1 || region.base != p->slot || region.size != 8 ||
            region.data != bytes || region.permissions != OOT_MEMORY_READ || memcmp(bytes,original,8)) :
            (window.regions != NULL || window.count != 0))) reason = OOT_STACK_BAD_PLT_EFFECT;
    if (reason) { *contract = 1; return reason; }
    reason = check_owners(d,0);
    if (reason) return reason;
    if (index == 3) {
        OotLeafReport report;
        if (oot_leaf_begin(d->leaf,working,p->target,d->plt_return,&report) != OOT_LEAF_READY) return report.error;
        d->leaf_active = 1;
    }
    return 0;
}

static int effect_allowed(const OotStackDispatcher *d, const Activation *a, const OotReadEffect *e, int write)
{
    const OwnedFunction *f = &d->functions[a->function];
    uint64_t low = oot_runtime_stack_base(d->image), high = oot_runtime_stack_pointer(d->image);
    size_t i;
    if (!e->size || e->size - 1 > UINT64_MAX-e->address) return 0;
    if (e->address >= a->base && e->address-a->base < f->info.frame_size &&
        e->size <= f->info.frame_size-(e->address-a->base)) {
        if (!a->owns) return 0;
        for (i=0;i<e->size;++i) if (f->reserved_bytes[(size_t)(e->address-a->base)+i]) return 0;
        return 1;
    }
    if (e->frame_base || (e->address < high && e->address+e->size-1 >= low)) return 0;
    for (i=0;i<(write ? d->write_count : d->read_count);++i) {
        const OotReadRange *r = write ? &d->write_ranges[i] : &d->read_ranges[i];
        if (e->address >= r->base && e->address-r->base < r->size && e->size <= r->size-(e->address-r->base)) return 1;
    }
    return 0;
}

int oot_stack_run(OotStackDispatcher *d, OotArm64State *s, uint64_t budget, OotLeafReport *out)
{
    uint64_t retired = 0;
    unsigned reason;
    if (d == NULL || s == NULL) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    if (d->phase == 0) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_NO_ACTIVE_CALL, 0);
    if (d->phase == 3) return result(d, s, out, OOT_LEAF_CONTRACT_FAULT, d->fault, 0);
    if (!same_state(s, &d->checkpoint)) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_STATE, 0);
    reason = check_owners(d, 1);
    if (reason) return result(d, s, out, OOT_LEAF_REJECTED, reason, 0);
    if (d->phase == 2) return result(d, s, out, OOT_LEAF_RETURNED, 0, 0);
    while (retired < budget) {
        Activation *a = &d->frames[d->depth - 1];
        const OotStackFunction *f = &d->functions[a->function].info;
        OotArm64State working = d->checkpoint;
        uint8_t shadow[OOT_STACK_MAX_FRAME], before[OOT_STACK_MAX_FRAME];
        unsigned kind = OOT_STACK_NORMAL, offset = 0, size = 0, i;
        uint32_t writable = 0;
        const OotStackCfgStep *flow = NULL;
        OotStackLayoutStep post = {0, 1, 0, 0};
        int child_status = 0;
        size_t target = d->count;
        size_t bridge = d->plt_count;
        uint64_t next = d->checkpoint.pc + 4;
        uint64_t signed_lr = a->signed_lr;
        OotReadEffect store_effect = {0};
        reason = check_owners(d, 0);
        if (reason) return result(d, s, out, OOT_LEAF_REJECTED, reason, retired);
        if (d->active_plt && !d->leaf_active) {
            int contract;
            reason = plt_step(d,&working,&contract);
            if (reason) {
                if (contract) { d->phase = 3; d->fault = reason; }
                return result(d,s,out,contract ? OOT_LEAF_CONTRACT_FAULT : OOT_LEAF_REJECTED,reason,retired);
            }
            d->checkpoint = working; *s = working; ++retired; ++d->total;
            continue;
        }
        if (!read_frame(d, a, shadow)) return result(d, s, out, OOT_LEAF_REJECTED, OOT_STACK_BAD_MEMORY, retired);
        memcpy(before, shadow, f->frame_size);
        if (d->leaf_active) {
            OotLeafReport child_report;
            d->executing = 1;
            child_status = oot_leaf_run(d->leaf, &working, 1, &child_report);
            d->executing = 0;
            if (child_status == OOT_LEAF_REJECTED) return result(d, s, out, OOT_LEAF_REJECTED, child_report.error, retired);
            if ((child_status != OOT_LEAF_YIELDED && child_status != OOT_LEAF_RETURNED) || child_report.retired_this_call != 1)
                reason = child_report.error ? child_report.error : OOT_LEAF_BAD_COUNT;
            writable = d->functions[a->function].saved_mask;
        } else {
            size_t index = (size_t)((working.pc - f->entry) / 4);
            const OotStackStep *step = &f->steps[index];
            OotGuestRegion region = {a->base, f->frame_size, shadow, 3};
            OotGuestMemory window;
            OotReadEffect read_effect = {0};
            OotArm64State expected_read = working;
            uint8_t read_bytes[16] = {0}, captured[16] = {0};
            uint64_t executed = UINT64_MAX;
            int status;
            kind = step->kind;
            if (f->policy_version >= OOT_STACK_CFG_POLICY_VERSION) {
                flow = &d->functions[a->function].flow[index];
                writable = flow->writable_mask;
            }
            if (f->policy_version >= OOT_STACK_LAYOUT_POLICY_VERSION) post = d->functions[a->function].states[index];
            if (kind == OOT_STACK_OPEN || kind == OOT_STACK_OPEN_LR || kind == OOT_STACK_STORE || kind == OOT_STACK_SAVE || kind == OOT_STACK_RECORD_SAVE) { offset = step->offset; size = step->size; }
            if (kind == OOT_STACK_RETURN) next = a->expected_return;
            if (kind == OOT_STACK_CALL) {
                next = step->callee; target = find_function(d, next);
                if (target != d->count) {
                    reason = code_match(d, target);
                    if (!reason && (d->depth == OOT_STACK_MAX_DEPTH || !fits(d, target, working.sp))) reason = OOT_STACK_DEPTH;
                    if (reason) return result(d, s, out, OOT_LEAF_REJECTED, reason, retired);
                } else {
                    bridge = find_plt(d,next);
                    if (bridge != d->plt_count) {
                        reason = plt_check(d,bridge,NULL);
                        if (reason) return result(d,s,out,OOT_LEAF_REJECTED,reason,retired);
                    }
                }
            }
            if (kind == OOT_STACK_READ || kind == OOT_STACK_WRITE) {
                if (!(kind == OOT_STACK_WRITE ? oot_write_decode : oot_read_decode)(d->functions[a->function].read_words[index],working.pc,&working,&read_effect))
                    return result(d,s,out,OOT_LEAF_REJECTED,OOT_STACK_BAD_REGISTRY,retired);
                if (!effect_allowed(d,a,&read_effect,kind == OOT_STACK_WRITE))
                    return result(d,s,out,OOT_LEAF_REJECTED,kind == OOT_STACK_WRITE ? OOT_STACK_BAD_WRITE_RANGE : OOT_STACK_BAD_READ_RANGE,retired);
                if (kind == OOT_STACK_WRITE) {
                    if (!oot_memory_probe(oot_runtime_memory(d->image),read_effect.address,read_effect.size,OOT_MEMORY_WRITE))
                        return result(d,s,out,OOT_LEAF_REJECTED,OOT_STACK_BAD_MEMORY,retired);
                    oot_write_expected(&read_effect,&working,captured,&expected_read);
                    for (i = 0; i < read_effect.size; ++i) read_bytes[i] = (uint8_t)~captured[i];
                    store_effect = read_effect;
                } else {
                    if (!oot_read_capture(oot_runtime_memory(d->image),&read_effect,read_bytes,&expected_read))
                        return result(d,s,out,OOT_LEAF_REJECTED,OOT_STACK_BAD_MEMORY,retired);
                    memcpy(captured,read_bytes,read_effect.size);
                }
                region = (OotGuestRegion){read_effect.address,read_effect.size,read_bytes,
                    kind == OOT_STACK_WRITE ? OOT_MEMORY_WRITE : OOT_MEMORY_READ};
            }
            (void)oot_memory_init(&window, &region, 1);
            if (kind == OOT_STACK_SIGN || kind == OOT_STACK_AUTH ||
                (d->pauth && kind == OOT_STACK_RETURN && d->functions[a->function].auth_word >= UINT32_C(0xd65f0000))) {
                OotArm64State expected = d->checkpoint;
                uint32_t word = kind == OOT_STACK_SIGN ? d->functions[a->function].sign_word : d->functions[a->function].auth_word;
                int pac_result = oot_pauth_step(d->pauth, &expected, word);
                if (kind == OOT_STACK_SIGN) {
                    if (pac_result != OOT_PAUTH_SIGNED || d->checkpoint.x[30] != a->initial.x[30] ||
                        d->checkpoint.sp != a->initial.sp) reason = OOT_LEAF_BAD_RETURN;
                    signed_lr = expected.x[30];
                } else if (pac_result != OOT_PAUTH_AUTHENTICATED ||
                    (kind == OOT_STACK_AUTH ? expected.x[30] != a->initial.x[30] : expected.pc != a->expected_return))
                    reason = OOT_LEAF_BAD_RETURN;
                if (reason) { d->phase = 3; d->fault = reason; return result(d, s, out, OOT_LEAF_CONTRACT_FAULT, reason, retired); }
            }
            d->executing = 1;
            status = d->functions[a->function].pauth_run ?
                d->functions[a->function].pauth_run(&working, &window, d->pauth, 1, &executed) :
                f->run(&working, &window, 1, &executed);
            d->executing = 0;
            if (status != (kind == OOT_STACK_CALL || kind == OOT_STACK_RETURN ? OOT_LIFT_DISPATCH : OOT_LIFT_BUDGET)) reason = OOT_LEAF_BAD_LIFT_STATUS;
            else if (executed != 1) reason = OOT_LEAF_BAD_COUNT;
            else if (kind == OOT_STACK_BRANCH ? (working.pc != f->entry + (uint64_t)flow->next_a * 4 &&
                working.pc != f->entry + (uint64_t)flow->next_b * 4) : working.pc != next) reason = OOT_LEAF_BAD_EDGE;
            else if (window.fault.reason != OOT_MEMORY_OK) reason = OOT_STACK_BAD_MEMORY;
            else if ((kind == OOT_STACK_READ || kind == OOT_STACK_WRITE) && (!same_state(&working,&expected_read) ||
                memcmp(read_bytes,captured,read_effect.size) || window.regions != &region || window.count != 1 || window.valid != 1 ||
                region.base != read_effect.address || region.size != read_effect.size ||
                region.data != read_bytes || region.permissions != (unsigned)(kind == OOT_STACK_WRITE ? OOT_MEMORY_WRITE : OOT_MEMORY_READ)))
                reason = kind == OOT_STACK_WRITE ? OOT_STACK_BAD_WRITE_EFFECT : OOT_STACK_BAD_READ_EFFECT;
        }
        for (i = 18; !reason && i <= 28; ++i)
            if (!(writable & (UINT32_C(1) << i)) && working.x[i] != a->initial.x[i]) reason = OOT_LEAF_PROTECTED_REGISTER;
        if (!reason && (working.nzcv & UINT32_C(0x0fffffff))) reason = OOT_LEAF_BAD_NZCV;
        if (!reason) {
            uint64_t sp = kind == OOT_STACK_CLOSE || kind == OOT_STACK_RETURN ? a->initial.sp : a->base;
            uint64_t fp = kind == OOT_STACK_OPEN || kind == OOT_STACK_CLOSE || kind == OOT_STACK_RETURN ? a->initial.x[29] : a->base;
            uint64_t lr = kind == OOT_STACK_CALL ? d->checkpoint.pc + 4 : kind == OOT_STACK_CLOSE || kind == OOT_STACK_RETURN ? a->initial.x[30] : d->checkpoint.x[30];
            if (f->policy_version >= OOT_STACK_LAYOUT_POLICY_VERSION) {
                sp = post.sp ? a->initial.sp : a->base;
                fp = post.fp ? a->base + d->functions[a->function].record_offset : a->initial.x[29];
                lr = post.lr == 3 ? signed_lr : post.lr == 2 ? d->checkpoint.pc + 4 : post.lr == 1 ? a->initial.x[30] : d->checkpoint.x[30];
            }
            if (d->leaf_active) {
                sp = d->checkpoint.sp; fp = d->checkpoint.x[29]; lr = d->checkpoint.x[30];
            }
            if (working.sp != sp || working.x[29] != fp || working.x[30] != lr) reason = OOT_LEAF_PROTECTED_REGISTER;
        }
        for (i = 0; !reason && i < f->frame_size; ++i)
            if ((i < offset || i >= offset + size) && shadow[i] != before[i]) reason = OOT_STACK_CHANGED;
        if (!reason && kind == OOT_STACK_OPEN &&
            (read_le(shadow, 8) != a->initial.x[29] || read_le(shadow + 8, 8) != (d->pauth ? signed_lr : a->initial.x[30]))) reason = OOT_STACK_CHANGED;
        if (!reason && kind == OOT_STACK_OPEN_LR) {
            uint32_t word = d->functions[a->function].open_word;
            unsigned first = word & 31, second = (word >> 10) & 31;
            if (read_le(shadow,8) != (first == 30 ? signed_lr : a->initial.x[first]) ||
                read_le(shadow+8,8) != (second == 30 ? signed_lr : a->initial.x[second])) reason = OOT_STACK_CHANGED;
        }
        if (!reason && kind == OOT_STACK_RECORD_SAVE &&
            (read_le(shadow + offset, 8) != a->initial.x[29] || read_le(shadow + offset + 8, 8) != (d->pauth ? signed_lr : a->initial.x[30]))) reason = OOT_STACK_CHANGED;
        if (!reason && kind == OOT_STACK_SAVE && (read_le(shadow + offset, 8) != a->initial.x[flow->saved_a] ||
            (size == 16 && read_le(shadow + offset + 8, 8) != a->initial.x[flow->saved_b]))) reason = OOT_STACK_CHANGED;
        if (!reason && !d->leaf_active && kind == OOT_STACK_CALL && target == d->count && bridge == d->plt_count) {
            OotLeafReport child_report;
            if (oot_leaf_begin(d->leaf, &working, working.pc, d->checkpoint.pc + 4, &child_report) != OOT_LEAF_READY)
                return result(d, s, out, OOT_LEAF_REJECTED, child_report.error, retired);
        }
        if (reason) { d->phase = 3; d->fault = reason; return result(d, s, out, OOT_LEAF_CONTRACT_FAULT, reason, retired); }
        if (kind == OOT_STACK_WRITE) {
            if (!oot_write_commit(oot_runtime_memory(d->image),&store_effect,&d->checkpoint))
                return result(d,s,out,OOT_LEAF_REJECTED,OOT_STACK_BAD_MEMORY,retired);
            if (store_effect.address >= a->base && store_effect.address-a->base < f->frame_size) {
                unsigned start = (unsigned)(store_effect.address-a->base);
                OotArm64State ignored;
                uint8_t bytes[16];
                oot_write_expected(&store_effect,&d->checkpoint,bytes,&ignored);
                memcpy(a->bytes+start,bytes,store_effect.size);
            }
        }
        if (size) {
            OotGuestMemory *memory = oot_runtime_memory(d->image);
            int stored = size == 16 ? oot_memory_store_pair(memory, a->base + offset, 8, read_le(shadow + offset, 8), read_le(shadow + offset + 8, 8)) :
                oot_memory_store(memory, a->base + offset, size, read_le(shadow + offset, size));
            if (!stored) return result(d, s, out, OOT_LEAF_REJECTED, OOT_STACK_BAD_MEMORY, retired);
            memcpy(a->bytes, shadow, f->frame_size); a->owns = 1;
        }
        if (f->policy_version >= OOT_STACK_LAYOUT_POLICY_VERSION) {
            if (post.owner == 1) { memcpy(a->bytes, shadow, f->frame_size); a->owns = 1; }
            if (post.owner == 2) a->owns = 0;
        } else if (kind == OOT_STACK_CLOSE) a->owns = 0;
        if (kind == OOT_STACK_SIGN) a->signed_lr = signed_lr;
        if (d->leaf_active && child_status == OOT_LEAF_RETURNED) { d->leaf_active = 0; d->active_plt = 0; }
        else if (kind == OOT_STACK_CALL) {
            if (target != d->count) activate(d, target, &working, d->checkpoint.pc + 4);
            else if (bridge != d->plt_count) { d->active_plt = bridge+1; d->plt_return = d->checkpoint.pc+4; }
            else d->leaf_active = 1;
        }
        d->checkpoint = working; *s = working; ++retired; ++d->total;
        if (kind == OOT_STACK_RETURN) {
            if (d->depth == 1) { d->phase = 2; return result(d, s, out, OOT_LEAF_RETURNED, 0, retired); }
            --d->depth;
        }
    }
    return result(d, s, out, OOT_LEAF_YIELDED, 0, retired);
}
