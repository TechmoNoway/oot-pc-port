#include "frame_dispatch.h"
#include <stdlib.h>
#include <string.h>

struct OotFrameDispatcher {
    OotRuntimeImage *image;
    OotLeafDispatcher *child;
    OotFrameFunction root;
    OotFrameStep steps[OOT_FRAME_MAX_WORDS];
    uint64_t returns[OOT_FRAME_MAX_RETURNS];
    size_t return_count;
    uint8_t body_hash[32], frame_bytes[16];
    OotArm64State initial, checkpoint;
    uint64_t expected_return, total, frame_base;
    unsigned phase, executing, child_active, owns_frame, fault;
};

static int result(const OotFrameDispatcher *d, const OotArm64State *s, OotLeafReport *out,
                  unsigned status, unsigned error, uint64_t retired)
{
    if (out != NULL) *out = (OotLeafReport){status, error, d != NULL ? d->root.entry : 0,
        s != NULL ? s->pc : 0, d != NULL ? d->expected_return : 0, retired, d != NULL ? d->total : 0};
    return (int)status;
}

static int same(const OotArm64State *a, const OotArm64State *b)
{
    return memcmp(a->x, b->x, sizeof(a->x)) == 0 && a->sp == b->sp && a->pc == b->pc && a->nzcv == b->nzcv;
}

static unsigned match_code(const OotFrameDispatcher *d)
{
    int code = oot_runtime_check_code(d->image, d->body_hash, d->root.entry,
                                     d->root.instruction_count * 4, d->root.hash.bytes);
    return code == OOT_CODE_MATCH ? OOT_LEAF_OK : code == OOT_CODE_BAD_IMAGE ? OOT_LEAF_BAD_IMAGE : OOT_LEAF_BAD_CODE;
}

int oot_frame_destroy(OotFrameDispatcher *d)
{
    if (d == NULL) return 1;
    if (d->executing) return 0;
    (void)oot_leaf_dispatcher_destroy(d->child);
    oot_runtime_close(d->image);
    free(d);
    return 1;
}

static int compare_pc(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

OotFrameDispatcher *oot_frame_create(OotRuntimeImage *image, const OotFrameFunction *root,
    const OotLeafFunction *leaves, size_t count, const OotCodeHash *hashes, const uint8_t body_sha256[32],
    const uint64_t *return_sites, size_t return_count, uint32_t *error)
{
    OotFrameDispatcher *d;
    uint64_t combined[OOT_FRAME_MAX_RETURNS + OOT_FRAME_MAX_WORDS], bound;
    size_t i, j, sites = return_count, unique = 0, calls = 0;
    if (error != NULL) *error = OOT_LEAF_BAD_ARGUMENT;
    if (image == NULL || root == NULL || leaves == NULL || hashes == NULL || body_sha256 == NULL || return_sites == NULL ||
        count == 0 || count > OOT_LEAF_MAX_FUNCTIONS || return_count == 0 || return_count > OOT_FRAME_MAX_RETURNS)
        return NULL;
    if (error != NULL) *error = OOT_FRAME_BAD_REGISTRY;
    if (root->entry % 4 || root->instruction_count < 5 || root->instruction_count > OOT_FRAME_MAX_WORDS ||
        root->entry > UINT64_MAX - (uint64_t)root->instruction_count * 4 || root->run == NULL || root->steps == NULL ||
        root->abi_version != OOT_LIFT_ABI_VERSION || root->policy_version != OOT_FRAME_POLICY_VERSION)
        return NULL;
    d = calloc(1, sizeof(*d));
    if (d == NULL) { if (error != NULL) *error = OOT_LEAF_ALLOCATION_FAILED; return NULL; }
    d->root = *root;
    memcpy(d->steps, root->steps, root->instruction_count * sizeof(*root->steps));
    d->root.steps = d->steps;
    memcpy(d->body_hash, body_sha256, 32);
    for (i = 0; i < return_count; ++i) {
        uint64_t pc = return_sites[i];
        if (pc % 4 || (i && pc <= return_sites[i - 1]) ||
            (pc >= root->entry && pc < root->entry + (uint64_t)root->instruction_count * 4)) goto failure;
        d->returns[i] = combined[i] = pc;
    }
    d->return_count = return_count;
    for (i = 0; i < root->instruction_count; ++i) {
        const OotFrameStep *step = &d->steps[i];
        unsigned expected = i == 0 ? OOT_FRAME_OPEN : i == 1 ? OOT_FRAME_FP :
            i == root->instruction_count - 2 ? OOT_FRAME_CLOSE : i == root->instruction_count - 1 ? OOT_FRAME_RETURN : step->kind;
        if (step->reserved || step->kind != expected || (i > 1 && i < root->instruction_count - 2 &&
            step->kind != OOT_FRAME_NORMAL && step->kind != OOT_FRAME_CALL) ||
            (step->kind != OOT_FRAME_CALL && step->callee != 0)) goto failure;
        if (step->kind == OOT_FRAME_CALL) {
            combined[sites++] = root->entry + (i + 1) * 4;
            ++calls;
        }
    }
    if (!calls) goto failure;
    qsort(combined, sites, sizeof(*combined), compare_pc);
    for (i = 0; i < sites; ++i) if (!i || combined[i] != combined[i - 1]) combined[unique++] = combined[i];
    d->child = oot_leaf_dispatcher_create_bound(image, leaves, count, hashes, body_sha256, combined, unique, error);
    if (d->child == NULL) goto failure;
    if (error != NULL) *error = OOT_FRAME_BAD_REGISTRY;
    bound = root->instruction_count;
    for (i = 0; i < count; ++i)
        if (leaves[i].entry < root->entry + (uint64_t)root->instruction_count * 4 &&
            root->entry < leaves[i].entry + (uint64_t)leaves[i].instruction_count * 4) goto failure;
    for (i = 0; i < root->instruction_count; ++i) if (d->steps[i].kind == OOT_FRAME_CALL) {
        for (j = 0; j < count && leaves[j].entry != d->steps[i].callee; ++j) { }
        if (j == count) goto failure;
        bound += leaves[j].max_steps;
    }
    if (bound != root->max_steps) goto failure;
    if (!oot_runtime_retain(image)) { if (error != NULL) *error = OOT_LEAF_BAD_IMAGE; goto failure; }
    d->image = image;
    {
        unsigned reason = match_code(d);
        if (reason) { if (error != NULL) *error = reason; goto failure; }
    }
    if (error != NULL) *error = OOT_LEAF_OK;
    return d;
failure:
    (void)oot_frame_destroy(d);
    return NULL;
}

int oot_frame_begin(OotFrameDispatcher *d, const OotArm64State *s, uint64_t expected_return, OotLeafReport *out)
{
    size_t i;
    unsigned error;
    if (d == NULL || s == NULL) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing || d->phase == 1 || d->phase == 3)
        return result(d, s, out, OOT_LEAF_REJECTED, d->executing ? OOT_LEAF_REENTRY : OOT_LEAF_BUSY, 0);
    error = match_code(d);
    for (i = 0; i < d->return_count && d->returns[i] != expected_return; ++i) { }
    if (!error && s->pc != d->root.entry) error = OOT_LEAF_BAD_ENTRY;
    if (!error && (i == d->return_count || s->x[30] != expected_return)) error = OOT_LEAF_BAD_RETURN;
    if (!error && (s->sp % 16 || s->sp < oot_runtime_stack_base(d->image) + 16 ||
                    s->sp > oot_runtime_stack_pointer(d->image))) error = OOT_LEAF_BAD_STACK;
    if (!error && (s->nzcv & UINT32_C(0x0fffffff))) error = OOT_LEAF_BAD_NZCV;
    if (error) return result(d, s, out, OOT_LEAF_REJECTED, error, 0);
    (void)oot_leaf_abort(d->child, NULL);
    d->initial = d->checkpoint = *s;
    d->expected_return = expected_return; d->frame_base = s->sp - 16;
    d->total = 0; d->phase = 1; d->fault = 0; d->child_active = 0; d->owns_frame = 0;
    return result(d, s, out, OOT_LEAF_READY, 0, 0);
}

int oot_frame_abort(OotFrameDispatcher *d, OotLeafReport *out)
{
    if (d == NULL) return result(NULL, NULL, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return result(d, &d->checkpoint, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    (void)oot_leaf_abort(d->child, NULL);
    d->phase = 0; d->total = 0; d->child_active = 0; d->owns_frame = 0;
    return result(d, NULL, out, OOT_LEAF_READY, 0, 0);
}

int oot_frame_run(OotFrameDispatcher *d, OotArm64State *s, uint64_t budget, OotLeafReport *out)
{
    uint64_t retired = 0;
    unsigned reason;
    if (d == NULL || s == NULL) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    if (d->phase == 0) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_NO_ACTIVE_CALL, 0);
    if (d->phase == 3) return result(d, s, out, OOT_LEAF_CONTRACT_FAULT, d->fault, 0);
    if (!same(s, &d->checkpoint)) return result(d, s, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_STATE, 0);
    reason = match_code(d);
    if (reason) return result(d, s, out, OOT_LEAF_REJECTED, reason, 0);
    if (d->phase == 2) return result(d, s, out, OOT_LEAF_RETURNED, 0, 0);
    while (retired < budget) {
        uint64_t old_a, old_b, a, b, executed = UINT64_MAX;
        uint8_t shadow[16], before[16];
        OotGuestRegion region = {d->frame_base, 16, shadow, 3};
        OotGuestMemory window;
        OotArm64State working = d->checkpoint;
        OotGuestMemory *memory = oot_runtime_memory(d->image);
        unsigned kind = OOT_FRAME_NORMAL;
        int status, child_result = 0;
        size_t index = 0;
        if (!oot_memory_load_pair(memory, d->frame_base, 8, &old_a, &old_b))
            return result(d, s, out, OOT_LEAF_REJECTED, OOT_FRAME_BAD_MEMORY, retired);
        for (index = 0; index < 8; ++index) { shadow[index] = (uint8_t)(old_a >> (index * 8)); shadow[index + 8] = (uint8_t)(old_b >> (index * 8)); }
        memcpy(before, shadow, 16);
        if (d->owns_frame && memcmp(shadow, d->frame_bytes, 16))
            return result(d, s, out, OOT_LEAF_REJECTED, OOT_FRAME_STACK_CHANGED, retired);
        reason = 0;
        if (d->child_active) {
            OotLeafReport child_report;
            d->executing = 1;
            child_result = oot_leaf_run(d->child, &working, 1, &child_report);
            d->executing = 0;
            if (child_result == OOT_LEAF_REJECTED)
                return result(d, s, out, OOT_LEAF_REJECTED, child_report.error, retired);
            if ((child_result != OOT_LEAF_YIELDED && child_result != OOT_LEAF_RETURNED) || child_report.retired_this_call != 1)
                reason = child_report.error ? child_report.error : OOT_LEAF_BAD_COUNT;
        } else {
            index = (size_t)((working.pc - d->root.entry) / 4);
            kind = d->steps[index].kind;
            (void)oot_memory_init(&window, &region, 1);
            d->executing = 1;
            status = d->root.run(&working, &window, 1, &executed);
            d->executing = 0;
            if (status != (kind == OOT_FRAME_CALL || kind == OOT_FRAME_RETURN ? OOT_LIFT_DISPATCH : OOT_LIFT_BUDGET)) reason = OOT_LEAF_BAD_LIFT_STATUS;
            else if (executed != 1) reason = OOT_LEAF_BAD_COUNT;
            else if (working.pc != (kind == OOT_FRAME_CALL ? d->steps[index].callee : kind == OOT_FRAME_RETURN ? d->expected_return : d->checkpoint.pc + 4))
                reason = OOT_LEAF_BAD_EDGE;
        }
        if (!reason && memcmp(working.x + 18, d->initial.x + 18, 11 * sizeof(uint64_t))) reason = OOT_LEAF_PROTECTED_REGISTER;
        if (!reason && (working.nzcv & UINT32_C(0x0fffffff))) reason = OOT_LEAF_BAD_NZCV;
        if (!reason) {
            uint64_t expected_sp = kind == OOT_FRAME_CLOSE || kind == OOT_FRAME_RETURN ? d->initial.sp : d->frame_base;
            uint64_t expected_fp = kind == OOT_FRAME_OPEN || kind == OOT_FRAME_CLOSE || kind == OOT_FRAME_RETURN ? d->initial.x[29] : d->frame_base;
            uint64_t expected_lr = kind == OOT_FRAME_CALL ? d->checkpoint.pc + 4 : kind == OOT_FRAME_CLOSE || kind == OOT_FRAME_RETURN ? d->initial.x[30] : d->checkpoint.x[30];
            if (working.sp != expected_sp || working.x[29] != expected_fp || working.x[30] != expected_lr) reason = OOT_LEAF_PROTECTED_REGISTER;
        }
        if (!reason && kind == OOT_FRAME_OPEN) {
            for (index = 0; index < 8; ++index)
                if (shadow[index] != (uint8_t)(d->initial.x[29] >> (index * 8)) || shadow[index + 8] != (uint8_t)(d->initial.x[30] >> (index * 8))) reason = OOT_FRAME_STACK_CHANGED;
        } else if (!reason && memcmp(shadow, before, 16)) reason = OOT_FRAME_STACK_CHANGED;
        if (!reason && !d->child_active && kind == OOT_FRAME_CALL) {
            OotLeafReport child_report;
            if (oot_leaf_begin(d->child, &working, working.pc, d->checkpoint.pc + 4, &child_report) != OOT_LEAF_READY)
                return result(d, s, out, OOT_LEAF_REJECTED, child_report.error, retired);
        }
        if (reason) { d->phase = 3; d->fault = reason; return result(d, s, out, OOT_LEAF_CONTRACT_FAULT, reason, retired); }
        if (kind == OOT_FRAME_OPEN) {
            a = b = 0;
            for (index = 0; index < 8; ++index) { a |= (uint64_t)shadow[index] << (index * 8); b |= (uint64_t)shadow[index + 8] << (index * 8); }
            if (!oot_memory_store_pair(memory, d->frame_base, 8, a, b)) return result(d, s, out, OOT_LEAF_REJECTED, OOT_FRAME_BAD_MEMORY, retired);
            memcpy(d->frame_bytes, shadow, 16); d->owns_frame = 1;
        }
        if (d->child_active && child_result == OOT_LEAF_RETURNED) d->child_active = 0;
        else if (kind == OOT_FRAME_CALL) d->child_active = 1;
        if (kind == OOT_FRAME_CLOSE) d->owns_frame = 0;
        d->checkpoint = working; *s = working; ++retired; ++d->total;
        if (kind == OOT_FRAME_RETURN) { d->phase = 2; return result(d, s, out, OOT_LEAF_RETURNED, 0, retired); }
    }
    return result(d, s, out, OOT_LEAF_YIELDED, 0, retired);
}
