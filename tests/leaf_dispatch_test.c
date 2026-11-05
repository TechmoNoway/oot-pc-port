#include "leaf_dispatch.h"
#include <stdio.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "dispatch check failed at %d: %s\n", __LINE__, #test); return 1; } } while (0)
#define ENTRY UINT64_C(0x1000)
#define RETURN_PC UINT64_C(0x8000)
#define STACK_LOW UINT64_C(0x1000000)
#define STACK_HIGH UINT64_C(0x1001000)

static unsigned mode, calls, reentry_ok;
static OotLeafDispatcher *callback_dispatcher;

/* Trusted native test stubs deliberately violate one contract at a time. */
static int callback(OotArm64State *s, OotGuestMemory *memory, uint64_t budget, uint64_t *executed)
{
    int returning = s->pc == ENTRY + 4;
    OotLeafReport report;
    ++calls;
    if (memory != NULL || budget != 1) return OOT_LIFT_MEMORY_FAULT;
    if (mode == 6) {
        reentry_ok = oot_leaf_run(callback_dispatcher, s, 1, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_REENTRY;
        reentry_ok &= oot_leaf_abort(callback_dispatcher, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_REENTRY;
        reentry_ok &= oot_leaf_begin(callback_dispatcher, s, ENTRY, RETURN_PC, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_REENTRY;
        reentry_ok &= oot_leaf_dispatcher_destroy(callback_dispatcher) == 0;
    }
    if (returning) s->pc = s->x[30];
    else { ++s->x[0]; s->pc += 4; }
    *executed = mode == 2 ? 0 : mode == 8 ? 2 : 1;
    if (mode == 1 || (mode == 7 && returning)) ++s->x[19];
    if (mode == 3) s->pc += 4;
    if (mode == 5) s->nzcv |= 1;
    if (mode == 9) ++s->sp;
    if (mode == 10 && returning) s->pc = 0x9000; /* Allowed globally, wrong for this call. */
    if (mode == 4) return OOT_LIFT_MEMORY_FAULT;
    return returning ? OOT_LIFT_DISPATCH : OOT_LIFT_BUDGET;
}

static const OotLeafStep valid_steps[] = {{1, 1, 2, 0}, {OOT_LEAF_RETURN, OOT_LEAF_RETURN, 1, 0}};
static const uint64_t valid_returns[] = {RETURN_PC, UINT64_C(0x9000)};

static OotLeafFunction descriptor(void)
{
    return (OotLeafFunction){ENTRY, 2, 2, OOT_LIFT_ABI_VERSION, OOT_LEAF_POLICY_VERSION, callback, valid_steps};
}

static OotArm64State initial_state(void)
{
    OotArm64State state = {0};
    state.pc = ENTRY; state.sp = STACK_HIGH; state.x[0] = 5; state.x[30] = RETURN_PC; state.nzcv = UINT32_C(0xa0000000);
    return state;
}

static int same(const OotArm64State *a, const OotArm64State *b)
{
    return memcmp(a->x, b->x, sizeof(a->x)) == 0 && a->sp == b->sp && a->pc == b->pc && a->nzcv == b->nzcv;
}

int main(void)
{
    OotLeafFunction function = descriptor(), bad, pair[2];
    OotLeafDispatcher *d;
    OotLeafReport report;
    OotArm64State state, before;
    uint32_t error;
    unsigned which;
    d = oot_leaf_dispatcher_create(&function, 1, valid_returns, 2, STACK_LOW, STACK_HIGH, &error);
    CHECK(d != NULL && error == OOT_LEAF_OK);
    callback_dispatcher = d;
    state = initial_state();
    CHECK(oot_leaf_run(d, &state, 1, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_NO_ACTIVE_CALL);
    for (which = 0; which < 6; ++which) {
        state = initial_state();
        if (which == 0) state.pc += 4;
        if (which == 1) state.x[30] = 0x9000;
        if (which == 2) state.sp -= 1;
        if (which == 3) state.sp = STACK_HIGH + 16;
        if (which == 4) state.nzcv |= 1;
        before = state;
        CHECK(oot_leaf_begin(d, &state, which == 5 ? ENTRY + 4 : ENTRY, RETURN_PC, &report) == OOT_LEAF_REJECTED);
        CHECK(same(&state, &before) && calls == 0);
    }
    state = initial_state();
    state.x[30] = 0x7000;
    CHECK(oot_leaf_begin(d, &state, ENTRY, 0x7000, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_BAD_RETURN);
    state = initial_state();
    CHECK(oot_leaf_begin(d, &state, ENTRY, RETURN_PC, &report) == OOT_LEAF_READY);
    CHECK(oot_leaf_begin(d, &state, ENTRY, RETURN_PC, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_BUSY);
    CHECK(oot_leaf_run(d, &state, 0, &report) == OOT_LEAF_YIELDED && calls == 0 && report.total_retired == 0);
    CHECK(oot_leaf_run(d, &state, 1, &report) == OOT_LEAF_YIELDED && state.x[0] == 6 && report.total_retired == 1);
    before = state; state.x[0] ^= 1;
    CHECK(oot_leaf_run(d, &state, 1, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_BAD_STATE && calls == 1);
    state = before;
    CHECK(oot_leaf_run(d, &state, 1, &report) == OOT_LEAF_RETURNED && report.retired_this_call == 1 && report.total_retired == 2);
    CHECK(state.pc == RETURN_PC && state.x[30] == RETURN_PC && state.sp == STACK_HIGH);
    CHECK(oot_leaf_run(d, &state, UINT64_MAX, &report) == OOT_LEAF_RETURNED && report.retired_this_call == 0 && calls == 2);
    CHECK(oot_leaf_abort(d, NULL) == OOT_LEAF_READY && state.x[0] == 6);

    for (which = 1; which <= 10; ++which) {
        unsigned old_calls;
        mode = which; state = initial_state(); before = state;
        CHECK(oot_leaf_begin(d, &state, ENTRY, RETURN_PC, &report) == OOT_LEAF_READY);
        CHECK(oot_leaf_run(d, &state, 10, &report) == OOT_LEAF_CONTRACT_FAULT || which == 6);
        if (which == 6) {
            CHECK(report.status == OOT_LEAF_RETURNED && reentry_ok);
        } else {
            CHECK(report.error != OOT_LEAF_OK);
            if (which == 7 || which == 10) {
                CHECK(state.pc == ENTRY + 4 && state.x[0] == 6 && report.total_retired == 1);
                CHECK(state.x[19] == before.x[19]);
            } else CHECK(same(&state, &before) && report.total_retired == 0);
            old_calls = calls;
            CHECK(oot_leaf_run(d, &state, 1, &report) == OOT_LEAF_CONTRACT_FAULT && calls == old_calls);
            CHECK(oot_leaf_begin(d, &state, ENTRY, RETURN_PC, &report) == OOT_LEAF_REJECTED && report.error == OOT_LEAF_BUSY);
        }
        CHECK(oot_leaf_abort(d, &report) == OOT_LEAF_READY);
    }
    CHECK(oot_leaf_begin(NULL, &state, ENTRY, RETURN_PC, &report) == OOT_LEAF_REJECTED);
    CHECK(oot_leaf_run(d, NULL, 1, NULL) == OOT_LEAF_REJECTED);
    CHECK(oot_leaf_abort(NULL, NULL) == OOT_LEAF_REJECTED);
    CHECK(oot_leaf_dispatcher_destroy(d));
    CHECK(oot_leaf_dispatcher_destroy(NULL));

    for (which = 0; which < 10; ++which) {
        OotLeafStep steps[2];
        bad = descriptor();
        memcpy(steps, valid_steps, sizeof(steps)); bad.steps = steps;
        if (which == 0) bad.abi_version = 0;
        if (which == 1) bad.policy_version = 0;
        if (which == 2) bad.run = NULL;
        if (which == 3) bad.instruction_count = 257;
        if (which == 4) bad.entry = UINT64_MAX - 3;
        if (which == 5) bad.max_steps = 3;
        if (which == 6) steps[0].next_a = 2;
        if (which == 7) steps[0].next_a = 0;
        if (which == 8) steps[0] = valid_steps[1]; /* Unreachable second return. */
        if (which == 9) steps[0].reserved = 1;
        CHECK(oot_leaf_dispatcher_create(&bad, 1, valid_returns, 2, STACK_LOW, STACK_HIGH, &error) == NULL);
        CHECK(error == OOT_LEAF_BAD_REGISTRY);
    }
    pair[0] = descriptor(); pair[1] = descriptor();
    pair[1].entry += 4;
    CHECK(oot_leaf_dispatcher_create(pair, 2, valid_returns, 2, STACK_LOW, STACK_HIGH, &error) == NULL);
    CHECK(oot_leaf_dispatcher_create(NULL, 1, valid_returns, 2, STACK_LOW, STACK_HIGH, &error) == NULL);
    CHECK(oot_leaf_dispatcher_create(&function, 257, valid_returns, 2, STACK_LOW, STACK_HIGH, &error) == NULL);
    CHECK(oot_leaf_dispatcher_create(&function, 1, valid_returns, 4097, STACK_LOW, STACK_HIGH, &error) == NULL);
    {
        uint64_t invalid_returns[] = {ENTRY, RETURN_PC};
        CHECK(oot_leaf_dispatcher_create(&function, 1, invalid_returns, 2, STACK_LOW, STACK_HIGH, &error) == NULL);
        invalid_returns[0] = invalid_returns[1];
        CHECK(oot_leaf_dispatcher_create(&function, 1, invalid_returns, 2, STACK_LOW, STACK_HIGH, &error) == NULL);
    }
    {
        OotLeafStep mutable_steps[2];
        mode = 0; memcpy(mutable_steps, valid_steps, sizeof(mutable_steps));
        function = descriptor(); function.steps = mutable_steps;
        d = oot_leaf_dispatcher_create(&function, 1, valid_returns, 2, STACK_LOW, STACK_HIGH, &error);
        CHECK(d != NULL);
        function.run = NULL; mutable_steps[0].next_a = 0; /* Owned copies must stay valid. */
        state = initial_state();
        CHECK(oot_leaf_begin(d, &state, ENTRY, RETURN_PC, NULL) == OOT_LEAF_READY);
        CHECK(oot_leaf_run(d, &state, 100, &report) == OOT_LEAF_RETURNED && state.x[0] == 6);
        CHECK(oot_leaf_dispatcher_destroy(d));
    }
    puts("Leaf dispatcher self-test passed.");
    return 0;
}
