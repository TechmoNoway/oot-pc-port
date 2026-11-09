#include "native_platform.h"

#define PLATFORM_ADDRESS_LIMIT (UINT64_C(1)<<39)

typedef struct PlatformSpan {
    const void *address;
    size_t size;
} PlatformSpan;

static int separate(const void *a, size_t a_size, const void *b, size_t b_size)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x>=a_size : x-y>=b_size;
}

static int config_valid(const OotNativePlatformConfig *config)
{
    return config && config->version==OOT_NATIVE_PLATFORM_VERSION &&
        config->operation_mode<=1 && config->performance_mode<=1 &&
        config->focus_state>=1 && config->focus_state<=3 &&
        config->graphics_scale<=2 && !config->reserved &&
        config->process_id && config->main_thread_id;
}

int oot_native_platform_valid(const OotNativePlatform *state)
{
    return state && state->version==OOT_NATIVE_PLATFORM_VERSION &&
        config_valid(&state->config) && state->initialized<=1 &&
        state->cpu_boost_mode<=1 && state->focus_handling_mode<=3 &&
        state->resume_notification_enabled<=1 && state->operation_notification_enabled<=1 &&
        state->performance_notification_enabled<=1 && !state->reserved &&
        (!state->initialized || state->generations) &&
        (state->initialized || (!state->cpu_boost_mode && !state->focus_handling_mode &&
            !state->resume_notification_enabled && !state->operation_notification_enabled &&
            !state->performance_notification_enabled));
}

int oot_native_platform_init(OotNativePlatform *state, const OotNativePlatformConfig *config)
{
    OotNativePlatformConfig copied;
    if (!state || !config_valid(config)) return 0;
    copied=*config;
    *state=(OotNativePlatform){0};
    state->version=OOT_NATIVE_PLATFORM_VERSION;
    state->config=copied;
    return 1;
}

int oot_native_platform_handler_valid(uint32_t id)
{
    return id>=OOT_PLATFORM_INITIALIZE && id<=OOT_PLATFORM_GET_CURRENT_GRAPHICS_SCALE;
}

int oot_native_platform_returns_value(uint32_t id)
{
    return id==OOT_PLATFORM_GET_OPERATION_MODE || id==OOT_PLATFORM_GET_PERFORMANCE_MODE ||
        id==OOT_PLATFORM_GET_CURRENT_FOCUS_STATE || id==OOT_PLATFORM_GET_CURRENT_GRAPHICS_SCALE;
}

static int report_result(OotNativePlatformReport *report, uint32_t id,
    uint32_t status, uint32_t error)
{
    if (report) *report=(OotNativePlatformReport){status,id,error,0};
    return (int)status;
}

static int counter(uint64_t *value)
{
    if (*value==UINT64_MAX) return 0;
    ++*value;
    return 1;
}

/* Inspect pointer ranges before touching a report: even a failure report must
 * not corrupt an input, another output or the guest byte/metadata ownership. */
static int spans_valid(const PlatformSpan *spans, size_t count, OotGuestMemory *memory)
{
    for (size_t n=0;n<count;++n) {
        if (!spans[n].address) continue;
        if (!separate(spans[n].address,spans[n].size,memory,sizeof(*memory))) return 0;
        for (size_t k=n+1;k<count;++k)
            if (spans[k].address && !separate(spans[n].address,spans[n].size,
                    spans[k].address,spans[k].size)) return 0;
    }
    if (memory->valid!=1 || (memory->count && !memory->regions) ||
        memory->count>SIZE_MAX/sizeof(OotGuestRegion)) return 0;
    for (size_t n=0;n<count;++n) {
        if (!spans[n].address) continue;
        if (memory->count && !separate(spans[n].address,spans[n].size,
                memory->regions,memory->count*sizeof(OotGuestRegion))) return 0;
        for (size_t k=0;k<memory->count;++k) {
            const OotGuestRegion *region=memory->regions+k;
            if (region->size>SIZE_MAX || !separate(spans[n].address,spans[n].size,
                    region->data,(size_t)region->size)) return 0;
        }
    }
    return 1;
}

int oot_native_platform_prepare(const OotNativePlatform *state, uint32_t id,
    const OotArm64State *registers, OotGuestMemory *memory,
    OotNativePlatform *next, OotArm64State *result,
    OotNativePlatformWrite *write, OotNativePlatformReport *report)
{
    OotNativePlatform candidate;
    OotArm64State output;
    uint32_t value;
    PlatformSpan spans[]={
        {state,sizeof(*state)},{registers,sizeof(*registers)},
        {next,sizeof(*next)},{result,sizeof(*result)},
        {write,sizeof(*write)},{report,sizeof(*report)}
    };
    if (!memory || !spans_valid(spans,sizeof(spans)/sizeof(spans[0]),memory))
        return OOT_PLATFORM_FAULT;
    if (!oot_native_platform_valid(state) || !registers || !next || !result || !write)
        return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_BAD_STATE);
    if (!registers->pc || registers->pc>=PLATFORM_ADDRESS_LIMIT || registers->pc%4 ||
        registers->x[30]<4 || registers->x[30]>=PLATFORM_ADDRESS_LIMIT || registers->x[30]%4 ||
        registers->sp%16 || (registers->nzcv & UINT32_C(0x0fffffff)))
        return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_BAD_ARGUMENT);
    if (!oot_native_platform_handler_valid(id))
        return report_result(report,id,OOT_PLATFORM_UNSUPPORTED,OOT_PLATFORM_OK);
    if (id!=OOT_PLATFORM_INITIALIZE && !state->initialized)
        return report_result(report,id,OOT_PLATFORM_UNSUPPORTED,OOT_PLATFORM_BAD_STATE);
    candidate=*state;
    output=*registers;
    output.pc=registers->x[30];
    value=(uint32_t)registers->x[0];
    if (!counter(&candidate.calls))
        return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_LIMIT);
    switch (id) {
    case OOT_PLATFORM_INITIALIZE:
        if (!counter(&candidate.initialization_calls) ||
            (!candidate.initialized && !counter(&candidate.generations)))
            return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_LIMIT);
        candidate.initialized=1;
        break;
    case OOT_PLATFORM_FINALIZE:
        if (!counter(&candidate.finalization_calls))
            return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_LIMIT);
        candidate.initialized=0;
        candidate.cpu_boost_mode=0;
        candidate.focus_handling_mode=0;
        candidate.resume_notification_enabled=0;
        candidate.operation_notification_enabled=0;
        candidate.performance_notification_enabled=0;
        break;
    case OOT_PLATFORM_GET_OPERATION_MODE:
    case OOT_PLATFORM_GET_PERFORMANCE_MODE:
    case OOT_PLATFORM_GET_CURRENT_FOCUS_STATE:
    case OOT_PLATFORM_GET_CURRENT_GRAPHICS_SCALE:
        if (!counter(&candidate.queries))
            return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_LIMIT);
        if (id==OOT_PLATFORM_GET_OPERATION_MODE) output.x[0]=candidate.config.operation_mode;
        else if (id==OOT_PLATFORM_GET_PERFORMANCE_MODE) output.x[0]=candidate.config.performance_mode;
        else if (id==OOT_PLATFORM_GET_CURRENT_FOCUS_STATE) output.x[0]=candidate.config.focus_state;
        else output.x[0]=candidate.config.graphics_scale;
        break;
    case OOT_PLATFORM_SET_CPU_BOOST_MODE:
        /* This original public enum accepts only 0 and 1. The host records
         * the requested policy; it does not change physical clock settings. */
        if (value>1) return report_result(report,id,OOT_PLATFORM_UNSUPPORTED,OOT_PLATFORM_BAD_INPUT);
        if (!counter(&candidate.boost_updates))
            return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_LIMIT);
        candidate.cpu_boost_mode=value;
        break;
    case OOT_PLATFORM_SET_FOCUS_HANDLING_MODE:
        if (value>3) return report_result(report,id,OOT_PLATFORM_UNSUPPORTED,OOT_PLATFORM_BAD_INPUT);
        if (!counter(&candidate.focus_updates))
            return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_LIMIT);
        candidate.focus_handling_mode=value;
        break;
    default:
        if (value>1) return report_result(report,id,OOT_PLATFORM_UNSUPPORTED,OOT_PLATFORM_BAD_INPUT);
        if (!counter(&candidate.notification_updates))
            return report_result(report,id,OOT_PLATFORM_FAULT,OOT_PLATFORM_LIMIT);
        if (id==OOT_PLATFORM_SET_RESUME_NOTIFICATION_ENABLED) candidate.resume_notification_enabled=value;
        else if (id==OOT_PLATFORM_SET_OPERATION_MODE_NOTIFICATION_ENABLED) candidate.operation_notification_enabled=value;
        else candidate.performance_notification_enabled=value;
        break;
    }
    *next=candidate;
    *result=output;
    *write=(OotNativePlatformWrite){0};
    return report_result(report,id,OOT_PLATFORM_IMPLEMENTED,OOT_PLATFORM_OK);
}
