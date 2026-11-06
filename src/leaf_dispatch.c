#include "leaf_dispatch.h"
#include "checked_read.h"
#include <stdlib.h>
#include <string.h>

typedef struct OwnedLeaf {
    OotLeafFunction info;
    OotLeafStep steps[OOT_LEAF_MAX_WORDS];
    OotCodeHash hash;
    uint32_t effect_words[OOT_LEAF_MAX_WORDS];
    uint8_t effects[OOT_LEAF_MAX_WORDS];
    uint32_t words[OOT_LEAF_MAX_WORDS];
    OotLeafLoop loop;
} OwnedLeaf;

struct OotLeafDispatcher {
    OwnedLeaf *functions;
    uint64_t *return_sites;
    size_t count, return_count, current;
    uint64_t stack_low, stack_high, expected_return, total_retired;
    OotArm64State initial, checkpoint;
    unsigned phase, executing, loop_entered; /* 0 idle, 1 active, 2 returned, 3 failed. */
    uint32_t fault;
    OotRuntimeImage *image;
    uint8_t body_sha256[32];
    OotReadRange reads[OOT_LEAF_MAX_RANGES], writes[OOT_LEAF_MAX_RANGES];
    size_t read_count, write_count;
};

static int report_result(const OotLeafDispatcher *d, const OotArm64State *s, OotLeafReport *out,
                         unsigned status, unsigned error, uint64_t retired)
{
    if (out != NULL) {
        *out = (OotLeafReport){status, error, 0, s != NULL ? s->pc : 0, 0, retired, 0};
        if (d != NULL && d->phase != 0) {
            out->entry = d->functions[d->current].info.entry;
            out->expected_return = d->expected_return;
            out->total_retired = d->total_retired;
        }
    }
    return (int)status;
}

static int same_state(const OotArm64State *a, const OotArm64State *b)
{
    return memcmp(a->x, b->x, sizeof(a->x)) == 0 && a->sp == b->sp && a->pc == b->pc && a->nzcv == b->nzcv;
}

static int validate_cfg(const OotLeafFunction *f, const OotLeafLoop *loop)
{
    unsigned index, count = f->instruction_count, head = 0, tail = 1;
    uint16_t pending[OOT_LEAF_MAX_WORDS] = {0};
    uint8_t visited[OOT_LEAF_MAX_WORDS] = {1};
    for (index = 0; index < count; ++index) {
        const OotLeafStep *step = &f->steps[index];
        unsigned a = step->next_a, b = step->next_b;
        if (step->reserved != 0 || step->max_steps == 0 || step->max_steps > count)
            return 0;
        if (a == OOT_LEAF_RETURN || b == OOT_LEAF_RETURN) {
            if (a != OOT_LEAF_RETURN || b != OOT_LEAF_RETURN || step->max_steps != 1)
                return 0;
        } else {
            unsigned longest;
            if (a >= count || b >= count)
                return 0;
            if (loop->max_iterations && index == loop->latch) {
                if (!((a == loop->header && b == index+1) || (b == loop->header && a == index+1))) return 0;
                longest = f->steps[index+1].max_steps;
            } else longest = f->steps[a].max_steps > f->steps[b].max_steps ? f->steps[a].max_steps : f->steps[b].max_steps;
            if (step->max_steps != longest + 1)
                return 0;
        }
    }
    while (head < tail) {
        const OotLeafStep *step = &f->steps[pending[head++]];
        unsigned targets[2] = {step->next_a, step->next_b}, which;
        for (which = 0; which < 2; ++which) {
            unsigned target = targets[which];
            if (target != OOT_LEAF_RETURN && !visited[target]) {
                visited[target] = 1;
                pending[tail++] = (uint16_t)target;
            }
        }
    }
    return tail == count && f->max_steps == (loop->max_iterations ?
        count+(OOT_LEAF_MAX_ITERATIONS-1)*(loop->latch-loop->header+1) : f->steps[0].max_steps);
}

static uint64_t decrement_amount(uint32_t word)
{
    return (uint64_t)((word >> 10) & 4095) << (word & (1u << 22) ? 12 : 0);
}

static int validate_loop(const OwnedLeaf *o)
{
    const OotLeafFunction *f = &o->info;
    const OotLeafLoop *l = &o->loop;
    unsigned i;
    uint32_t dec, latch;
    int64_t delta;
    if (!l->max_iterations) return !l->header && !l->latch && !l->decrement && !l->guard && !l->counter && !l->width && !l->reserved;
    if (l->max_iterations != OOT_LEAF_MAX_ITERATIONS || l->reserved || l->counter >= 18 ||
        (l->width != 32 && l->width != 64) || l->header >= l->latch || l->latch >= f->instruction_count-1 ||
        l->decrement < l->header || l->decrement >= l->latch) return 0;
    dec = o->words[l->decrement]; latch = o->words[l->latch];
    if ((dec & UINT32_C(0x5f800000)) != UINT32_C(0x51000000) || (dec & 31) != l->counter ||
        ((dec >> 5) & 31) != l->counter || (dec >> 31 ? 64u : 32u) != l->width || !decrement_amount(dec)) return 0;
    if ((latch & UINT32_C(0x7f000000)) == UINT32_C(0x35000000)) {
        if ((latch & 31) != l->counter || (latch >> 31 ? 64u : 32u) != l->width) return 0;
    } else if ((latch & UINT32_C(0xff00001f)) != UINT32_C(0x54000001) || !(dec & (1u << 29))) return 0;
    delta = (int64_t)oot_arm64_sign_extend((latch >> 5) & 0x7ffff,19);
    if ((int64_t)l->latch+delta != l->header) return 0;
    for (i = 0; i < f->instruction_count; ++i) {
        const OotLeafStep *s = &f->steps[i];
        unsigned a = s->next_a, b = s->next_b;
        if (i >= l->header && i < l->latch) { if (a != i+1 || b != i+1) return 0; }
        if (i == l->latch) { if (!((a == l->header && b == i+1) || (b == l->header && a == i+1))) return 0; }
        else if ((a != OOT_LEAF_RETURN && a <= i) || (b != OOT_LEAF_RETURN && b <= i)) return 0;
        if (i < l->header || i > l->latch) {
            if ((a > l->header && a <= l->latch) || (b > l->header && b <= l->latch)) return 0;
        }
    }
    if (l->guard != UINT32_MAX) {
        uint32_t g;
        int64_t target;
        if (!l->header || l->guard != l->header-1) return 0;
        g = o->words[l->guard]; target = (int64_t)l->guard+(int64_t)oot_arm64_sign_extend((g >> 5) & 0x7ffff,19);
        if ((g & UINT32_C(0x7f000000)) != UINT32_C(0x34000000) || (g & 31) != l->counter ||
            (g >> 31 ? 64u : 32u) != l->width || target <= l->latch || target >= f->instruction_count ||
            !((f->steps[l->guard].next_a == (unsigned)target && f->steps[l->guard].next_b == l->header) ||
              (f->steps[l->guard].next_b == (unsigned)target && f->steps[l->guard].next_a == l->header))) return 0;
    }
    return 1;
}

int oot_leaf_dispatcher_destroy(OotLeafDispatcher *d)
{
    if (d == NULL)
        return 1;
    if (d->executing)
        return 0;
    free(d->functions);
    free(d->return_sites);
    oot_runtime_close(d->image);
    free(d);
    return 1;
}

static unsigned check_code(const OotLeafDispatcher *d, size_t index)
{
    int match;
    const OwnedLeaf *leaf = &d->functions[index];
    if (d->image == NULL) return OOT_LEAF_OK; /* Explicit unbound development API. */
    match = oot_runtime_check_code(d->image, d->body_sha256, leaf->info.entry,
                                  leaf->info.instruction_count * 4, leaf->hash.bytes);
    return match == OOT_CODE_MATCH ? OOT_LEAF_OK : match == OOT_CODE_BAD_IMAGE ? OOT_LEAF_BAD_IMAGE : OOT_LEAF_BAD_CODE;
}

OotLeafDispatcher *oot_leaf_dispatcher_create_bound(OotRuntimeImage *image,
    const OotLeafFunction *functions, size_t count, const OotCodeHash *code_hashes, const uint8_t body_sha256[32],
    const uint64_t *return_sites, size_t return_count, uint32_t *error)
{
    OotLeafDispatcher *d;
    size_t index;
    if (error != NULL) *error = OOT_LEAF_BAD_ARGUMENT;
    if (image == NULL || code_hashes == NULL || body_sha256 == NULL) return NULL;
    d = oot_leaf_dispatcher_create(functions, count, return_sites, return_count,
        oot_runtime_stack_base(image), oot_runtime_stack_pointer(image), error);
    if (d == NULL) return NULL;
    if (!oot_runtime_retain(image)) {
        if (error != NULL) *error = OOT_LEAF_BAD_IMAGE;
        (void)oot_leaf_dispatcher_destroy(d); return NULL;
    }
    d->image = image;
    memcpy(d->body_sha256, body_sha256, 32);
    for (index = 0; index < count; ++index) {
        unsigned reason;
        d->functions[index].hash = code_hashes[index];
        reason = check_code(d, index);
        if (reason != OOT_LEAF_OK) {
            if (error != NULL) *error = reason;
            (void)oot_leaf_dispatcher_destroy(d);
            return NULL;
        }
    }
    return d;
}

static OotLeafDispatcher *create_registry(const OotLeafFunction *functions, size_t count,
    const uint64_t *return_sites, size_t return_count, uint64_t stack_low, uint64_t stack_high, uint32_t *error,
    const OotMemoryLeafFunction *memory, const OotBoundedLeafFunction *bounded)
{
    OotLeafDispatcher *d;
    size_t index, function_index = 0;
    uint64_t previous_end = 0;
    if (error != NULL) *error = OOT_LEAF_BAD_ARGUMENT;
    if (functions == NULL || return_sites == NULL || count == 0 || count > OOT_LEAF_MAX_FUNCTIONS ||
        return_count == 0 || return_count > OOT_LEAF_MAX_RETURNS || stack_low >= stack_high ||
        stack_low % 16 != 0 || stack_high % 16 != 0)
        return NULL;
    if (error != NULL) *error = OOT_LEAF_ALLOCATION_FAILED;
    d = calloc(1, sizeof(*d));
    if (d == NULL) return NULL;
    d->functions = calloc(count, sizeof(*d->functions));
    d->return_sites = malloc(return_count * sizeof(*d->return_sites));
    if (d->functions == NULL || d->return_sites == NULL) goto failure;
    d->count = count; d->return_count = return_count;
    d->stack_low = stack_low; d->stack_high = stack_high;
    if (error != NULL) *error = OOT_LEAF_BAD_REGISTRY;
    for (index = 0; index < count; ++index) {
        OotLeafFunction *f = &d->functions[index].info;
        *f = functions[index];
        if (f->entry % 4 != 0 || f->instruction_count == 0 || f->instruction_count > OOT_LEAF_MAX_WORDS ||
            f->entry > UINT64_MAX - (uint64_t)f->instruction_count * 4 || f->entry < previous_end ||
            f->abi_version != OOT_LIFT_ABI_VERSION || (f->policy_version != OOT_LEAF_POLICY_VERSION && (!memory || f->policy_version != OOT_LEAF_MEMORY_POLICY_VERSION) && (!bounded || f->policy_version != OOT_LEAF_BOUNDED_POLICY_VERSION)) ||
            f->run == NULL || f->steps == NULL)
            goto failure;
        memcpy(d->functions[index].steps, f->steps, (size_t)f->instruction_count * sizeof(*f->steps));
        f->steps = d->functions[index].steps;
        if (bounded) {
            if (f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION) {
                if (!bounded[index].words) goto failure;
                memcpy(d->functions[index].words,bounded[index].words,f->instruction_count*sizeof(uint32_t));
                d->functions[index].loop = bounded[index].loop;
            } else {
                OotLeafLoop empty = {0};
                if (bounded[index].words || memcmp(&bounded[index].loop,&empty,sizeof(empty))) goto failure;
            }
        }
        if (!validate_loop(&d->functions[index]) || !validate_cfg(f,&d->functions[index].loop)) goto failure;
        if (memory) {
            unsigned j, found = 0;
            if (f->policy_version == OOT_LEAF_POLICY_VERSION) { if (memory[index].effect_words) goto failure; }
            else {
                if (!memory[index].effect_words) goto failure;
                for (j = 0; j < f->instruction_count; ++j) {
                    uint32_t word = memory[index].effect_words[j];
                    OotReadEffect effect;
                    OotArm64State empty = {0};
                    if (!word) continue;
                    if (f->steps[j].next_a != j+1 || f->steps[j].next_b != j+1 || j+1 == f->instruction_count) goto failure;
                    if ((f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION ? oot_leaf_read_decode : oot_read_decode)(word,f->entry+j*4,&empty,&effect)) {
                        if ((effect.rd >= 18 && effect.rd != 31) || (effect.pair && effect.rt2 >= 18 && effect.rt2 != 31)) goto failure;
                        d->functions[index].effects[j] = 1;
                    } else if ((f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION ? oot_leaf_write_decode : oot_write_decode)(word,f->entry+j*4,&empty,&effect)) d->functions[index].effects[j] = 2;
                    else goto failure;
                    if (effect.frame_base || (effect.writeback && effect.rn >= 18)) goto failure;
                    d->functions[index].effect_words[j] = word; ++found;
                }
                if (!found) goto failure;
            }
        }
        previous_end = f->entry + (uint64_t)f->instruction_count * 4;
    }
    for (index = 0; index < return_count; ++index) {
        uint64_t pc = return_sites[index];
        if (pc % 4 != 0 || (index != 0 && pc <= return_sites[index - 1])) goto failure;
        while (function_index < count && pc >= d->functions[function_index].info.entry +
               (uint64_t)d->functions[function_index].info.instruction_count * 4)
            ++function_index;
        if (function_index < count && pc >= d->functions[function_index].info.entry) goto failure;
        d->return_sites[index] = pc;
    }
    if (error != NULL) *error = OOT_LEAF_OK;
    return d;
failure:
    (void)oot_leaf_dispatcher_destroy(d);
    return NULL;
}

OotLeafDispatcher *oot_leaf_dispatcher_create(const OotLeafFunction *functions, size_t count,
    const uint64_t *returns, size_t return_count, uint64_t low, uint64_t high, uint32_t *error)
{
    return create_registry(functions,count,returns,return_count,low,high,error,NULL,NULL);
}

static int copy_ranges(OotLeafDispatcher *d, const OotReadRange *ranges, size_t count, unsigned access)
{
    const OotGuestMemory *m = oot_runtime_memory(d->image);
    size_t i, j;
    if (count > OOT_LEAF_MAX_RANGES || (count && !ranges)) return 0;
    for (i = 0; i < count; ++i) {
        const OotReadRange *r = &ranges[i];
        int found = 0;
        if (!r->size || r->base >= d->stack_low || r->size > d->stack_low-r->base ||
            (i && (r->base < ranges[i-1].base || r->base-ranges[i-1].base < ranges[i-1].size))) return 0;
        for (j = 0; j < m->count; ++j) {
            const OotGuestRegion *region = &m->regions[j];
            if ((region->permissions & access) && r->base >= region->base && r->base-region->base < region->size &&
                r->size <= region->size-(r->base-region->base)) found = 1;
        }
        if (!found) return 0;
        (access == OOT_MEMORY_READ ? d->reads : d->writes)[i] = *r;
    }
    if (access == OOT_MEMORY_READ) d->read_count = count; else d->write_count = count;
    return 1;
}

static OotLeafDispatcher *create_memory_bound(OotRuntimeImage *image,
    const OotMemoryLeafFunction *functions, size_t count, const OotCodeHash *hashes, const uint8_t body_hash[32],
    const uint64_t *returns, size_t return_count, const OotReadRange *reads, size_t read_count,
    const OotReadRange *writes, size_t write_count, uint32_t *error, const OotBoundedLeafFunction *bounded)
{
    OotLeafFunction common[OOT_LEAF_MAX_FUNCTIONS];
    OotLeafDispatcher *d;
    size_t i, j;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!image || !functions || !count || count > OOT_LEAF_MAX_FUNCTIONS || !hashes || !body_hash) return NULL;
    for (i = 0; i < count; ++i) common[i] = functions[i].info;
    d = create_registry(common,count,returns,return_count,oot_runtime_stack_base(image),oot_runtime_stack_pointer(image),error,functions,bounded);
    if (!d) return NULL;
    if (error) *error = OOT_LEAF_BAD_IMAGE;
    if (!oot_runtime_retain(image)) goto failure;
    d->image = image; memcpy(d->body_sha256,body_hash,32);
    if (error) *error = OOT_LEAF_BAD_REGISTRY;
    if (!copy_ranges(d,reads,read_count,OOT_MEMORY_READ) || !copy_ranges(d,writes,write_count,OOT_MEMORY_WRITE)) goto failure;
    for (i = 0; i < count; ++i) {
        unsigned reason;
        d->functions[i].hash = hashes[i]; reason = check_code(d,i);
        if (reason) { if (error) *error = reason; goto failure; }
        for (j = 0; j < common[i].instruction_count; ++j) if (d->functions[i].effect_words[j] || common[i].policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION) {
            uint64_t word;
            if (!oot_memory_load(oot_runtime_memory(image),common[i].entry+j*4,4,&word) || (common[i].policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION ?
                (word != d->functions[i].words[j] || (d->functions[i].effect_words[j] && word != d->functions[i].effect_words[j])) :
                word != d->functions[i].effect_words[j])) goto failure;
        }
    }
    if (error) *error = OOT_LEAF_OK;
    return d;
failure:
    (void)oot_leaf_dispatcher_destroy(d); return NULL;
}

OotLeafDispatcher *oot_leaf_dispatcher_create_memory_bound(OotRuntimeImage *image,
    const OotMemoryLeafFunction *functions, size_t count, const OotCodeHash *hashes, const uint8_t body_hash[32],
    const uint64_t *returns, size_t return_count, const OotReadRange *reads, size_t read_count,
    const OotReadRange *writes, size_t write_count, uint32_t *error)
{
    return create_memory_bound(image,functions,count,hashes,body_hash,returns,return_count,reads,read_count,writes,write_count,error,NULL);
}

OotLeafDispatcher *oot_leaf_dispatcher_create_bounded_bound(OotRuntimeImage *image,
    const OotBoundedLeafFunction *functions, size_t count, const OotCodeHash *hashes, const uint8_t body_hash[32],
    const uint64_t *returns, size_t return_count, const OotReadRange *reads, size_t read_count,
    const OotReadRange *writes, size_t write_count, uint32_t *error)
{
    OotMemoryLeafFunction memory[OOT_LEAF_MAX_FUNCTIONS];
    size_t i;
    if (error) *error = OOT_LEAF_BAD_ARGUMENT;
    if (!functions || !count || count > OOT_LEAF_MAX_FUNCTIONS) return NULL;
    for (i = 0; i < count; ++i) memory[i] = functions[i].memory;
    return create_memory_bound(image,memory,count,hashes,body_hash,returns,return_count,reads,read_count,writes,write_count,error,functions);
}

static int effect_allowed(const OotLeafDispatcher *d, const OotReadEffect *e, int write)
{
    size_t i, count = write ? d->write_count : d->read_count;
    const OotReadRange *ranges = write ? d->writes : d->reads;
    if (!e->size || e->size-1 > UINT64_MAX-e->address || e->frame_base ||
        (e->address < d->stack_high && e->address+e->size-1 >= d->stack_low)) return 0;
    for (i = 0; i < count; ++i) if (e->address >= ranges[i].base && e->address-ranges[i].base < ranges[i].size &&
        e->size <= ranges[i].size-(e->address-ranges[i].base)) return 1;
    return 0;
}

static size_t find_entry(const OotLeafDispatcher *d, uint64_t entry)
{
    size_t low = 0, high = d->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (d->functions[mid].info.entry < entry) low = mid + 1;
        else high = mid;
    }
    return low;
}

static int allowed_return(const OotLeafDispatcher *d, uint64_t pc)
{
    size_t low = 0, high = d->return_count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (d->return_sites[mid] < pc) low = mid + 1;
        else high = mid;
    }
    return low < d->return_count && d->return_sites[low] == pc;
}

int oot_leaf_begin(OotLeafDispatcher *d, const OotArm64State *s, uint64_t entry,
                   uint64_t expected_return, OotLeafReport *out)
{
    size_t index;
    unsigned error = OOT_LEAF_OK;
    if (d == NULL || s == NULL) return report_result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) error = OOT_LEAF_REENTRY;
    else if (d->phase == 1 || d->phase == 3) error = OOT_LEAF_BUSY;
    if (error) return report_result(d, s, out, OOT_LEAF_REJECTED, error, 0);
    index = find_entry(d, entry);
    if (index == d->count || d->functions[index].info.entry != entry || s->pc != entry)
        error = OOT_LEAF_BAD_ENTRY;
    else error = check_code(d, index);
    if (!error && (s->x[30] != expected_return || !allowed_return(d, expected_return))) error = OOT_LEAF_BAD_RETURN;
    if (!error && (s->sp % 16 != 0 || s->sp < d->stack_low || s->sp > d->stack_high)) error = OOT_LEAF_BAD_STACK;
    if (!error && (s->nzcv & UINT32_C(0x0fffffff))) error = OOT_LEAF_BAD_NZCV;
    if (error) return report_result(d, s, out, OOT_LEAF_REJECTED, error, 0);
    d->current = index; d->expected_return = expected_return; d->total_retired = 0;
    d->initial = *s; d->checkpoint = *s; d->phase = 1; d->loop_entered = 0; d->fault = OOT_LEAF_OK;
    return report_result(d, s, out, OOT_LEAF_READY, OOT_LEAF_OK, 0);
}

int oot_leaf_abort(OotLeafDispatcher *d, OotLeafReport *out)
{
    if (d == NULL) return report_result(NULL, NULL, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return report_result(d, &d->checkpoint, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    d->phase = 0; d->total_retired = 0; d->loop_entered = 0; d->fault = OOT_LEAF_OK;
    return report_result(d, NULL, out, OOT_LEAF_READY, OOT_LEAF_OK, 0);
}

int oot_leaf_run(OotLeafDispatcher *d, OotArm64State *s, uint64_t budget, OotLeafReport *out)
{
    uint64_t retired = 0;
    const OotLeafFunction *f;
    if (d == NULL || s == NULL) return report_result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return report_result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    if (d->phase == 0) return report_result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_NO_ACTIVE_CALL, 0);
    if (d->phase == 3) return report_result(d, s, out, OOT_LEAF_CONTRACT_FAULT, d->fault, 0);
    if (!same_state(s, &d->checkpoint)) return report_result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_STATE, 0);
    {
        unsigned reason = check_code(d, d->current);
        if (reason != OOT_LEAF_OK) return report_result(d, s, out, OOT_LEAF_REJECTED, reason, 0);
    }
    if (d->phase == 2) return report_result(d, s, out, OOT_LEAF_RETURNED, OOT_LEAF_OK, 0);
    f = &d->functions[d->current].info;
    while (retired < budget) {
        size_t index = (size_t)((d->checkpoint.pc - f->entry) / 4);
        const OotLeafStep *step = &f->steps[index];
        int returning = step->next_a == OOT_LEAF_RETURN, status;
        uint64_t executed = UINT64_MAX;
        OotArm64State working = d->checkpoint;
        unsigned error = OOT_LEAF_OK, kind = d->functions[d->current].effects[index], i;
        OotReadEffect effect = {0};
        OotArm64State expected = working, expected_loop = working;
        const OotLeafLoop *loop = &d->functions[d->current].loop;
        int control = 0;
        if (f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION && d->total_retired >= f->max_steps) {
            d->phase = 3; d->fault = OOT_LEAF_BAD_LOOP_LIMIT;
            return report_result(d,s,out,OOT_LEAF_CONTRACT_FAULT,d->fault,retired);
        }
        if (loop->max_iterations) {
            uint32_t dec = d->functions[d->current].words[loop->decrement];
            if (index == loop->header && !d->loop_entered) {
                uint64_t value = oot_arm64_read(&working,loop->counter,loop->width,0), amount = decrement_amount(dec);
                if (!value || value % amount || value / amount > loop->max_iterations)
                    return report_result(d,s,out,OOT_LEAF_REJECTED,OOT_LEAF_BAD_LOOP_INPUT,retired);
                d->loop_entered = 1;
            }
            if (index == loop->decrement) {
                uint64_t value = oot_arm64_addsub(&expected_loop,oot_arm64_read(&working,loop->counter,loop->width,0),
                    decrement_amount(dec),loop->width,1,!!(dec & (1u << 29)));
                oot_arm64_write(&expected_loop,loop->counter,loop->width,0,value);expected_loop.pc += 4;control = 1;
            } else if (index == loop->latch || index == loop->guard) {
                uint32_t word = d->functions[d->current].words[index];
                int take = index == loop->guard ? !oot_arm64_read(&working,loop->counter,loop->width,0) :
                    (word & UINT32_C(0x7f000000)) == UINT32_C(0x35000000) ? !!oot_arm64_read(&working,loop->counter,loop->width,0) :
                    (int)oot_arm64_condition(working.nzcv,1);
                expected_loop.pc += take ? oot_arm64_sign_extend((word >> 5) & 0x7ffff,19)*4 : 4;control = 1;
            }
        }
        OotGuestMemory window;
        OotGuestRegion region;
        uint8_t bytes[16] = {0}, wanted[16] = {0};
        (void)oot_memory_init(&window,NULL,0);
        if (kind) {
            uint32_t word = d->functions[d->current].effect_words[index];
            if (!(kind == 2 ? (f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION ? oot_leaf_write_decode : oot_write_decode) :
                (f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION ? oot_leaf_read_decode : oot_read_decode))(word,working.pc,&working,&effect))
                return report_result(d,s,out,OOT_LEAF_REJECTED,OOT_LEAF_BAD_REGISTRY,retired);
            if (!effect_allowed(d,&effect,kind == 2))
                return report_result(d,s,out,OOT_LEAF_REJECTED,OOT_LEAF_BAD_MEMORY_RANGE,retired);
            if (kind == 1) {
                if (!(f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION ? oot_leaf_read_capture : oot_read_capture)(oot_runtime_memory(d->image),&effect,bytes,&expected))
                    return report_result(d,s,out,OOT_LEAF_REJECTED,OOT_LEAF_BAD_MEMORY,retired);
                memcpy(wanted,bytes,effect.size);
            } else {
                if (!oot_memory_probe(oot_runtime_memory(d->image),effect.address,effect.size,OOT_MEMORY_WRITE))
                    return report_result(d,s,out,OOT_LEAF_REJECTED,OOT_LEAF_BAD_MEMORY,retired);
                (f->policy_version == OOT_LEAF_BOUNDED_POLICY_VERSION ? oot_leaf_write_expected : oot_write_expected)(&effect,&working,wanted,&expected);
                for (i = 0; i < effect.size; ++i) bytes[i] = (uint8_t)~wanted[i];
            }
            region = (OotGuestRegion){effect.address,effect.size,bytes,kind == 2 ? OOT_MEMORY_WRITE : OOT_MEMORY_READ};
            (void)oot_memory_init(&window,&region,1);
        }
        d->executing = 1;
        status = f->run(&working, f->policy_version >= OOT_LEAF_MEMORY_POLICY_VERSION ? &window : NULL, 1, &executed);
        d->executing = 0;
        if (status != (returning ? OOT_LIFT_DISPATCH : OOT_LIFT_BUDGET)) error = OOT_LEAF_BAD_LIFT_STATUS;
        else if (executed != 1) error = OOT_LEAF_BAD_COUNT;
        else if (working.sp != d->initial.sp || memcmp(working.x + 18, d->initial.x + 18, 13 * sizeof(uint64_t)) != 0)
            error = OOT_LEAF_PROTECTED_REGISTER;
        else if (working.nzcv & UINT32_C(0x0fffffff)) error = OOT_LEAF_BAD_NZCV;
        else if (returning ? working.pc != d->expected_return :
                 (working.pc != f->entry + (uint64_t)step->next_a * 4 && working.pc != f->entry + (uint64_t)step->next_b * 4))
            error = OOT_LEAF_BAD_EDGE;
        if (!error && f->policy_version >= OOT_LEAF_MEMORY_POLICY_VERSION) {
            if (window.fault.reason) error = OOT_LEAF_BAD_MEMORY;
            else if (window.valid != 1 || (kind ? (window.regions != &region || window.count != 1 ||
                region.base != effect.address || region.size != effect.size || region.data != bytes ||
                region.permissions != (unsigned)(kind == 2 ? OOT_MEMORY_WRITE : OOT_MEMORY_READ) ||
                memcmp(bytes,wanted,effect.size) || !same_state(&working,&expected)) : (window.regions != NULL || window.count != 0)))
                error = OOT_LEAF_BAD_MEMORY_EFFECT;
        }
        if (!error && loop->max_iterations) {
            if (control ? !same_state(&working,&expected_loop) :
                (index >= loop->header && index <= loop->latch && working.x[loop->counter] != d->checkpoint.x[loop->counter]))
                error = OOT_LEAF_BAD_LOOP_EFFECT;
            if (!error && index > loop->decrement && index <= loop->latch &&
                (d->functions[d->current].words[loop->latch] & UINT32_C(0xff00001f)) == UINT32_C(0x54000001) && working.nzcv != d->checkpoint.nzcv)
                error = OOT_LEAF_BAD_LOOP_EFFECT;
        }
        if (error) {
            d->phase = 3; d->fault = error;
            return report_result(d, s, out, OOT_LEAF_CONTRACT_FAULT, error, retired);
        }
        if (kind == 2 && !oot_write_commit(oot_runtime_memory(d->image),&effect,&d->checkpoint))
            return report_result(d,s,out,OOT_LEAF_REJECTED,OOT_LEAF_BAD_MEMORY,retired);
        d->checkpoint = working;
        *s = working;
        ++retired; ++d->total_retired;
        if (returning) {
            d->phase = 2;
            return report_result(d, s, out, OOT_LEAF_RETURNED, OOT_LEAF_OK, retired);
        }
    }
    return report_result(d, s, out, OOT_LEAF_YIELDED, OOT_LEAF_OK, retired);
}
