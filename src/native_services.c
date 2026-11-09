#include "native_services.h"

#include <string.h>

#define SERVICE_ADDRESS_LIMIT (UINT64_C(1)<<39)

static int finish(OotNativeReport *report, uint32_t id, uint32_t status,
    uint32_t error)
{
    if (report) *report=(OotNativeReport){status,id,error,0};
    return (int)status;
}

static int config_valid(const OotNativeServicesConfig *config)
{
    return config && config->version==OOT_NATIVE_SERVICES_VERSION &&
        config->aoc_catalog_mode==OOT_NATIVE_CATALOGUE_EMPTY &&
        config->parental_policy<=OOT_NATIVE_PARENTAL_ALLOWED && !config->reserved &&
        ((!config->clock_frequency && !config->clock_ticks && !config->clock_unix_seconds) ||
         (config->clock_frequency && config->clock_frequency<=UINT64_C(1000000000)));
}

static int all_zero(const void *bytes, size_t size)
{
    const uint8_t *p=(const uint8_t *)bytes;
    for (size_t n=0;n<size;++n) if (p[n]) return 0;
    return 1;
}

static int state_valid(const OotNativeServices *state)
{
    if (!state || state->version!=OOT_NATIVE_SERVICES_VERSION || !config_valid(&state->config) ||
        state->aoc_initialized>1 || state->err_initialized>1 || state->diag_initialized>1 ||
        state->pctl_initialized>1 || state->fs_mode>OOT_NATIVE_FS_APPLICATION ||
        state->local_access_log>1 || state->result_handled>1 || state->aoc_count ||
        state->context_size || state->mount_count ||
        (state->aoc_initialized && !state->aoc_references) ||
        (!state->aoc_initialized && state->aoc_references) ||
        state->clock_initialized>1 ||
        (state->clock_initialized && (!state->config.clock_frequency || !state->clock_references)) ||
        (!state->clock_initialized && state->clock_references) ||
        state->parental_policy!=state->config.parental_policy ||
        state->context_capacity!=(state->err_initialized ? OOT_NATIVE_CONTEXT_LIMIT:0) ||
        (!state->err_initialized && state->context_size) ||
        (!state->fs_mode && (state->local_access_log || state->result_handled)) ||
        state->observer_count!=(state->diag_initialized ? 1u:0u)) return 0;
    /* No public context writer, abort dispatch or mount consumer is admitted
     * yet. Their backing is owned and remains empty; unknown consumers stop. */
    if (!all_zero(state->context,sizeof(state->context)) ||
        !all_zero(state->mounts,sizeof(state->mounts))) return 0;
    for (unsigned n=0;n<OOT_NATIVE_ABORT_OBSERVERS;++n) {
        const OotNativeAbortObserver *observer=&state->observers[n];
        if (n<state->observer_count) {
            if (observer->kind!=OOT_NATIVE_ABORT_CAPTURE || observer->active!=1 || observer->captures) return 0;
        } else if (!all_zero(observer,sizeof(*observer))) return 0;
    }
    return 1;
}

static int separate(const void *a, size_t a_size, const void *b, size_t b_size)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x>=a_size:x-y>=b_size;
}

static int increment(uint64_t *value)
{
    if (*value==UINT64_MAX) return 0;
    ++*value;
    return 1;
}

int oot_native_services_init(OotNativeServices *state, const OotNativeServicesConfig *config)
{
    OotNativeServicesConfig copied;
    if (!state || !config_valid(config)) return 0;
    copied=*config;
    *state=(OotNativeServices){0};
    state->version=OOT_NATIVE_SERVICES_VERSION;
    state->config=copied;
    state->parental_policy=copied.parental_policy;
    return 1;
}

int oot_native_services_handler_valid(uint32_t id)
{
    return id==OOT_NATIVE_AOC_INITIALIZE || id==OOT_NATIVE_AOC_FINALIZE ||
        id==OOT_NATIVE_ERR_INITIALIZE_CONTEXT_WRITER ||
        id==OOT_NATIVE_DIAG_INITIALIZE_ABORT_OBSERVER || id==OOT_NATIVE_PCTL_INITIALIZE ||
        id==OOT_NATIVE_FS_INITIALIZE_FOR_APPLICATION ||
        id==OOT_NATIVE_FS_SET_LOCAL_APPLICATION_ACCESS_LOG || id==OOT_NATIVE_FS_SET_RESULT_HANDLED ||
        id==OOT_NATIVE_TIME_INITIALIZE;
}

int oot_native_services_returns_value(uint32_t id)
{
    /* Time initialization returns an nn::Result in W0. Other admitted APIs
     * are void and must preserve the incoming X0. */
    return id==OOT_NATIVE_TIME_INITIALIZE;
}

int oot_native_services_prepare(const OotNativeServices *state, uint32_t id,
    const OotArm64State *registers, OotGuestMemory *memory, OotNativeServices *next,
    OotArm64State *result, OotNativeServicesWrite *write, OotNativeReport *report)
{
    OotNativeServices candidate;
    OotArm64State output;
    OotNativeServicesWrite staged={0};
    if (!state_valid(state) || !registers || !memory || memory->valid!=1 || !next || !result || !write ||
        !separate(state,sizeof(*state),next,sizeof(*next)) ||
        !separate(state,sizeof(*state),result,sizeof(*result)) ||
        !separate(state,sizeof(*state),write,sizeof(*write)) ||
        !separate(registers,sizeof(*registers),next,sizeof(*next)) ||
        !separate(registers,sizeof(*registers),result,sizeof(*result)) ||
        !separate(registers,sizeof(*registers),write,sizeof(*write)) ||
        !separate(next,sizeof(*next),result,sizeof(*result)) ||
        !separate(next,sizeof(*next),write,sizeof(*write)) ||
        !separate(result,sizeof(*result),write,sizeof(*write)))
        return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_BAD_STATE);
    if (!registers->pc || registers->pc>=SERVICE_ADDRESS_LIMIT || registers->pc%4 ||
        registers->x[30]<4 || registers->x[30]>=SERVICE_ADDRESS_LIMIT || registers->x[30]%4 ||
        registers->sp%16 || (registers->nzcv & UINT32_C(0x0fffffff)))
        return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_BAD_ARGUMENT);
    if (!oot_native_services_handler_valid(id))
        return finish(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_OK);
    candidate=*state;
    output=*registers;
    output.pc=registers->x[30];
    if (!increment(&candidate.calls)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
    switch (id) {
    case OOT_NATIVE_AOC_INITIALIZE:
        /* The explicit launch catalogue is empty. No synthetic entitlement,
         * service session, purchase event or guest SDK client is constructed. */
        candidate.aoc_initialized=1;
        if (candidate.aoc_references==UINT32_MAX || !increment(&candidate.aoc_initializations))
            return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        ++candidate.aoc_references;
        break;
    case OOT_NATIVE_AOC_FINALIZE:
        if (!candidate.aoc_initialized || !candidate.aoc_references)
            return finish(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_STATE);
        if (!increment(&candidate.aoc_finalizations)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        --candidate.aoc_references;
        if (!candidate.aoc_references) candidate.aoc_initialized=0;
        break;
    case OOT_NATIVE_ERR_INITIALIZE_CONTEXT_WRITER:
        if (!candidate.err_initialized) {
            candidate.err_initialized=1;
            candidate.context_capacity=OOT_NATIVE_CONTEXT_LIMIT;
            if (!increment(&candidate.err_initializations)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        }
        break;
    case OOT_NATIVE_DIAG_INITIALIZE_ABORT_OBSERVER:
        if (candidate.diag_initialized)
            return finish(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_STATE);
        candidate.diag_initialized=1;
        candidate.observer_count=1;
        candidate.observers[0]=(OotNativeAbortObserver){OOT_NATIVE_ABORT_CAPTURE,1,0};
        if (!increment(&candidate.diag_initializations)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        break;
    case OOT_NATIVE_PCTL_INITIALIZE:
        candidate.pctl_initialized=1;
        if (!increment(&candidate.pctl_initializations)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        break;
    case OOT_NATIVE_FS_INITIALIZE_FOR_APPLICATION:
        if (!candidate.fs_mode) {
            candidate.fs_mode=OOT_NATIVE_FS_APPLICATION;
            if (!increment(&candidate.fs_initializations)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        }
        break;
    case OOT_NATIVE_FS_SET_LOCAL_APPLICATION_ACCESS_LOG:
    case OOT_NATIVE_FS_SET_RESULT_HANDLED:
        if (candidate.fs_mode!=OOT_NATIVE_FS_APPLICATION)
            return finish(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_STATE);
        /* bool is passed in W0; reject values outside the declared domain. */
        if ((uint32_t)registers->x[0]>1)
            return finish(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_INPUT);
        if (id==OOT_NATIVE_FS_SET_LOCAL_APPLICATION_ACCESS_LOG) {
            candidate.local_access_log=(uint32_t)registers->x[0];
            if (!increment(&candidate.access_log_updates)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        } else {
            candidate.result_handled=(uint32_t)registers->x[0];
            if (!increment(&candidate.result_handled_updates)) return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        }
        break;
    case OOT_NATIVE_TIME_INITIALIZE:
        if (!candidate.config.clock_frequency)
            return finish(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_STATE);
        if (candidate.clock_references==UINT32_MAX || !increment(&candidate.clock_initializations))
            return finish(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT);
        ++candidate.clock_references;
        candidate.clock_initialized=1;
        /* The owned user-clock provider has a launch calibration snapshot.
         * No original service object/shared memory is accessed or fabricated;
         * its unimplemented query/adjustment consumers remain explicit stops. */
        output.x[0]=0;
        break;
    default:
        return finish(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_OK);
    }
    *next=candidate;
    *result=output;
    *write=staged;
    return finish(report,id,OOT_NATIVE_IMPLEMENTED,OOT_NATIVE_OK);
}
