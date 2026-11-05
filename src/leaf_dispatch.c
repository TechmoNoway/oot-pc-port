#include "leaf_dispatch.h"
#include <stdlib.h>
#include <string.h>

typedef struct OwnedLeaf {
    OotLeafFunction info;
    OotLeafStep steps[OOT_LEAF_MAX_WORDS];
} OwnedLeaf;

struct OotLeafDispatcher {
    OwnedLeaf *functions;
    uint64_t *return_sites;
    size_t count, return_count, current;
    uint64_t stack_low, stack_high, expected_return, total_retired;
    OotArm64State initial, checkpoint;
    unsigned phase, executing; /* 0 idle, 1 active, 2 returned, 3 failed. */
    uint32_t fault;
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

static int validate_cfg(const OotLeafFunction *f)
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
            longest = f->steps[a].max_steps > f->steps[b].max_steps ? f->steps[a].max_steps : f->steps[b].max_steps;
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
    return tail == count && f->max_steps == f->steps[0].max_steps;
}

int oot_leaf_dispatcher_destroy(OotLeafDispatcher *d)
{
    if (d == NULL)
        return 1;
    if (d->executing)
        return 0;
    free(d->functions);
    free(d->return_sites);
    free(d);
    return 1;
}

OotLeafDispatcher *oot_leaf_dispatcher_create(const OotLeafFunction *functions, size_t count,
    const uint64_t *return_sites, size_t return_count, uint64_t stack_low, uint64_t stack_high, uint32_t *error)
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
            f->abi_version != OOT_LIFT_ABI_VERSION || f->policy_version != OOT_LEAF_POLICY_VERSION ||
            f->run == NULL || f->steps == NULL)
            goto failure;
        memcpy(d->functions[index].steps, f->steps, (size_t)f->instruction_count * sizeof(*f->steps));
        f->steps = d->functions[index].steps;
        if (!validate_cfg(f)) goto failure;
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
    else if (s->x[30] != expected_return || !allowed_return(d, expected_return)) error = OOT_LEAF_BAD_RETURN;
    else if (s->sp % 16 != 0 || s->sp < d->stack_low || s->sp > d->stack_high) error = OOT_LEAF_BAD_STACK;
    else if (s->nzcv & UINT32_C(0x0fffffff)) error = OOT_LEAF_BAD_NZCV;
    if (error) return report_result(d, s, out, OOT_LEAF_REJECTED, error, 0);
    d->current = index; d->expected_return = expected_return; d->total_retired = 0;
    d->initial = *s; d->checkpoint = *s; d->phase = 1; d->fault = OOT_LEAF_OK;
    return report_result(d, s, out, OOT_LEAF_READY, OOT_LEAF_OK, 0);
}

int oot_leaf_abort(OotLeafDispatcher *d, OotLeafReport *out)
{
    if (d == NULL) return report_result(NULL, NULL, out, OOT_LEAF_REJECTED, OOT_LEAF_BAD_ARGUMENT, 0);
    if (d->executing) return report_result(d, &d->checkpoint, out, OOT_LEAF_REJECTED, OOT_LEAF_REENTRY, 0);
    d->phase = 0; d->total_retired = 0; d->fault = OOT_LEAF_OK;
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
    if (d->phase == 2) return report_result(d, s, out, OOT_LEAF_RETURNED, OOT_LEAF_OK, 0);
    f = &d->functions[d->current].info;
    while (retired < budget) {
        size_t index = (size_t)((d->checkpoint.pc - f->entry) / 4);
        const OotLeafStep *step = &f->steps[index];
        int returning = step->next_a == OOT_LEAF_RETURN, status;
        uint64_t executed = UINT64_MAX;
        OotArm64State working = d->checkpoint;
        unsigned error = OOT_LEAF_OK;
        d->executing = 1;
        status = f->run(&working, NULL, 1, &executed);
        d->executing = 0;
        if (status != (returning ? OOT_LIFT_DISPATCH : OOT_LIFT_BUDGET)) error = OOT_LEAF_BAD_LIFT_STATUS;
        else if (executed != 1) error = OOT_LEAF_BAD_COUNT;
        else if (working.sp != d->initial.sp || memcmp(working.x + 18, d->initial.x + 18, 13 * sizeof(uint64_t)) != 0)
            error = OOT_LEAF_PROTECTED_REGISTER;
        else if (working.nzcv & UINT32_C(0x0fffffff)) error = OOT_LEAF_BAD_NZCV;
        else if (returning ? working.pc != d->expected_return :
                 (working.pc != f->entry + (uint64_t)step->next_a * 4 && working.pc != f->entry + (uint64_t)step->next_b * 4))
            error = OOT_LEAF_BAD_EDGE;
        if (error) {
            d->phase = 3; d->fault = error;
            return report_result(d, s, out, OOT_LEAF_CONTRACT_FAULT, error, retired);
        }
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
