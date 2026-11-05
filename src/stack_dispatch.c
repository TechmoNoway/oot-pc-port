#include "stack_dispatch.h"
#include <stdlib.h>
#include <string.h>

typedef struct OwnedFunction {
    OotStackFunction info;
    OotStackStep steps[OOT_STACK_MAX_WORDS];
    OotStackCfgStep flow[OOT_STACK_MAX_WORDS];
    uint32_t saved_mask, locals_begin;
} OwnedFunction;
typedef struct Activation {
    size_t function;
    OotArm64State initial;
    uint64_t base, expected_return;
    uint8_t bytes[OOT_STACK_MAX_FRAME];
    unsigned owns;
} Activation;
struct OotStackDispatcher {
    OotRuntimeImage *image;
    OotLeafDispatcher *leaf;
    OwnedFunction functions[OOT_STACK_MAX_FUNCTIONS];
    Activation frames[OOT_STACK_MAX_DEPTH];
    OotArm64State checkpoint;
    uint64_t returns[256], total, expected_return;
    uint8_t body_hash[32];
    size_t count, root, depth, return_count;
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
    free(d);
    return 1;
}

static int compare_pc(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
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

static OotStackDispatcher *create_registry(OotRuntimeImage *image,
    const OotStackFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error,
    const OotStackCfgFunction *cfg)
{
    OotStackDispatcher *d;
    uint64_t sites[256 + OOT_STACK_MAX_FUNCTIONS * OOT_STACK_MAX_WORDS];
    uint32_t bounds[OOT_STACK_MAX_FUNCTIONS] = {0}, depths[OOT_STACK_MAX_FUNCTIONS] = {0};
    uint8_t visited[OOT_STACK_MAX_FUNCTIONS] = {0};
    size_t pending[OOT_STACK_MAX_FUNCTIONS], i, j, k, nsites = return_count, unique = 0, pass, head = 0, tail = 1;
    if (error != NULL) *error = OOT_LEAF_BAD_ARGUMENT;
    if (image == NULL || functions == NULL || count == 0 || count > OOT_STACK_MAX_FUNCTIONS ||
        leaf_count > OOT_LEAF_MAX_FUNCTIONS || (leaf_count && (leaves == NULL || hashes == NULL)) ||
        body_hash == NULL || returns == NULL || return_count == 0 || return_count > 256) return NULL;
    d = calloc(1, sizeof(*d));
    if (d == NULL) { if (error != NULL) *error = OOT_LEAF_ALLOCATION_FAILED; return NULL; }
    if (error != NULL) *error = OOT_STACK_BAD_REGISTRY;
    d->count = count;
    for (i = 0; i < count; ++i) {
        const OotStackFunction *f = &functions[i];
        if (f->entry % 4 || f->instruction_count < 4 || f->instruction_count > OOT_STACK_MAX_WORDS ||
            f->entry > UINT64_MAX - (uint64_t)f->instruction_count * 4 || f->run == NULL || f->steps == NULL ||
            f->abi_version != OOT_LIFT_ABI_VERSION || f->policy_version != (cfg != NULL ? OOT_STACK_CFG_POLICY_VERSION : OOT_STACK_POLICY_VERSION) ||
            f->frame_size < 16 || f->frame_size > OOT_STACK_MAX_FRAME || f->frame_size % 16 ||
            (i && f->entry < functions[i - 1].entry + (uint64_t)functions[i - 1].instruction_count * 4)) goto failure;
        d->functions[i].info = *f;
        memcpy(d->functions[i].steps, f->steps, f->instruction_count * sizeof(*f->steps));
        d->functions[i].info.steps = d->functions[i].steps;
        d->functions[i].locals_begin = 16;
        if (cfg != NULL) {
            if (cfg[i].flow == NULL) goto failure;
            memcpy(d->functions[i].flow, cfg[i].flow, f->instruction_count * sizeof(*cfg[i].flow));
            d->functions[i].saved_mask = cfg[i].saved_mask;
            d->functions[i].locals_begin = cfg[i].locals_begin;
            if (!validate_cfg_layout(&d->functions[i])) goto failure;
        }
        for (j = 0; j < f->instruction_count; ++j) {
            const OotStackStep *s = &f->steps[j];
            unsigned expected = j == 0 ? OOT_STACK_OPEN : j == 1 ? OOT_STACK_FP :
                j == f->instruction_count - 2 ? OOT_STACK_CLOSE : j == f->instruction_count - 1 ? OOT_STACK_RETURN : s->kind;
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
    for (i = 0; i < return_count; ++i) {
        if (returns[i] % 4 || (i && returns[i] <= returns[i - 1])) goto failure;
        for (j = 0; j < count; ++j)
            if (returns[i] >= functions[j].entry && returns[i] < functions[j].entry + (uint64_t)functions[j].instruction_count * 4) goto failure;
        d->returns[i] = sites[i] = returns[i];
    }
    d->return_count = return_count;
    qsort(sites, nsites, sizeof(*sites), compare_pc);
    for (i = 0; i < nsites; ++i) if (!i || sites[i] != sites[i - 1]) sites[unique++] = sites[i];
    if (unique > OOT_LEAF_MAX_RETURNS) goto failure;
    if (leaf_count) {
        d->leaf = oot_leaf_dispatcher_create_bound(image, leaves, leaf_count, hashes, body_hash, sites, unique, error);
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
                if (k == leaf_count) goto failure;
                bound += leaves[k].max_steps;
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
                            weight += leaves[k].max_steps;
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
    memcpy(d->body_hash, body_hash, 32);
    for (i = 0; i < count; ++i) {
        unsigned reason = code_match(d, i);
        if (reason) { if (error != NULL) *error = reason; goto failure; }
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
    return create_registry(image, functions, count, root, leaves, leaf_count, hashes, body_hash, returns, return_count, error, NULL);
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
    return create_registry(image, common, count, root, leaves, leaf_count, hashes, body_hash, returns, return_count, error, functions);
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
    d->phase = 1; d->fault = 0; d->leaf_active = 0;
    return result(d, s, out, OOT_LEAF_READY, 0, 0);
}

int oot_stack_abort(OotStackDispatcher *d, OotLeafReport *out)
{
    if (d == NULL) return result(NULL, NULL, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return result(d, &d->checkpoint, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    if (d->leaf != NULL) (void)oot_leaf_abort(d->leaf, NULL);
    d->phase = 0; d->depth = 0; d->total = 0; d->leaf_active = 0;
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
        int child_status = 0;
        size_t target = d->count;
        uint64_t next = d->checkpoint.pc + 4;
        reason = check_owners(d, 0);
        if (reason) return result(d, s, out, OOT_LEAF_REJECTED, reason, retired);
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
            uint64_t executed = UINT64_MAX;
            int status;
            kind = step->kind;
            if (f->policy_version == OOT_STACK_CFG_POLICY_VERSION) {
                flow = &d->functions[a->function].flow[index];
                writable = flow->writable_mask;
            }
            if (kind == OOT_STACK_OPEN || kind == OOT_STACK_STORE || kind == OOT_STACK_SAVE) { offset = step->offset; size = step->size; }
            if (kind == OOT_STACK_RETURN) next = a->expected_return;
            if (kind == OOT_STACK_CALL) {
                next = step->callee; target = find_function(d, next);
                if (target != d->count) {
                    reason = code_match(d, target);
                    if (!reason && (d->depth == OOT_STACK_MAX_DEPTH || !fits(d, target, working.sp))) reason = OOT_STACK_DEPTH;
                    if (reason) return result(d, s, out, OOT_LEAF_REJECTED, reason, retired);
                }
            }
            (void)oot_memory_init(&window, &region, 1);
            d->executing = 1;
            status = f->run(&working, &window, 1, &executed);
            d->executing = 0;
            if (status != (kind == OOT_STACK_CALL || kind == OOT_STACK_RETURN ? OOT_LIFT_DISPATCH : OOT_LIFT_BUDGET)) reason = OOT_LEAF_BAD_LIFT_STATUS;
            else if (executed != 1) reason = OOT_LEAF_BAD_COUNT;
            else if (kind == OOT_STACK_BRANCH ? (working.pc != f->entry + (uint64_t)flow->next_a * 4 &&
                working.pc != f->entry + (uint64_t)flow->next_b * 4) : working.pc != next) reason = OOT_LEAF_BAD_EDGE;
            else if (window.fault.reason != OOT_MEMORY_OK) reason = OOT_STACK_BAD_MEMORY;
        }
        for (i = 18; !reason && i <= 28; ++i)
            if (!(writable & (UINT32_C(1) << i)) && working.x[i] != a->initial.x[i]) reason = OOT_LEAF_PROTECTED_REGISTER;
        if (!reason && (working.nzcv & UINT32_C(0x0fffffff))) reason = OOT_LEAF_BAD_NZCV;
        if (!reason) {
            uint64_t sp = kind == OOT_STACK_CLOSE || kind == OOT_STACK_RETURN ? a->initial.sp : a->base;
            uint64_t fp = kind == OOT_STACK_OPEN || kind == OOT_STACK_CLOSE || kind == OOT_STACK_RETURN ? a->initial.x[29] : a->base;
            uint64_t lr = kind == OOT_STACK_CALL ? d->checkpoint.pc + 4 : kind == OOT_STACK_CLOSE || kind == OOT_STACK_RETURN ? a->initial.x[30] : d->checkpoint.x[30];
            if (working.sp != sp || working.x[29] != fp || working.x[30] != lr) reason = OOT_LEAF_PROTECTED_REGISTER;
        }
        for (i = 0; !reason && i < f->frame_size; ++i)
            if ((i < offset || i >= offset + size) && shadow[i] != before[i]) reason = OOT_STACK_CHANGED;
        if (!reason && kind == OOT_STACK_OPEN &&
            (read_le(shadow, 8) != a->initial.x[29] || read_le(shadow + 8, 8) != a->initial.x[30])) reason = OOT_STACK_CHANGED;
        if (!reason && kind == OOT_STACK_SAVE && (read_le(shadow + offset, 8) != a->initial.x[flow->saved_a] ||
            (size == 16 && read_le(shadow + offset + 8, 8) != a->initial.x[flow->saved_b]))) reason = OOT_STACK_CHANGED;
        if (!reason && !d->leaf_active && kind == OOT_STACK_CALL && target == d->count) {
            OotLeafReport child_report;
            if (oot_leaf_begin(d->leaf, &working, working.pc, d->checkpoint.pc + 4, &child_report) != OOT_LEAF_READY)
                return result(d, s, out, OOT_LEAF_REJECTED, child_report.error, retired);
        }
        if (reason) { d->phase = 3; d->fault = reason; return result(d, s, out, OOT_LEAF_CONTRACT_FAULT, reason, retired); }
        if (size) {
            OotGuestMemory *memory = oot_runtime_memory(d->image);
            int stored = size == 16 ? oot_memory_store_pair(memory, a->base + offset, 8, read_le(shadow + offset, 8), read_le(shadow + offset + 8, 8)) :
                oot_memory_store(memory, a->base + offset, size, read_le(shadow + offset, size));
            if (!stored) return result(d, s, out, OOT_LEAF_REJECTED, OOT_STACK_BAD_MEMORY, retired);
            memcpy(a->bytes, shadow, f->frame_size); a->owns = 1;
        }
        if (kind == OOT_STACK_CLOSE) a->owns = 0;
        if (d->leaf_active && child_status == OOT_LEAF_RETURNED) d->leaf_active = 0;
        else if (kind == OOT_STACK_CALL) {
            if (target != d->count) activate(d, target, &working, d->checkpoint.pc + 4);
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
