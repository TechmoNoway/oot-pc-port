#include "sdk_native.h"

#include <string.h>

#define NATIVE_ADDRESS_LIMIT (UINT64_C(1)<<39)
#define NATIVE_META_SIZE 40u
#define NATIVE_BODY_SIZE 24u

static int report_result(OotNativeReport *out, uint32_t id, uint32_t status,
    uint32_t error, uint32_t size)
{
    if (out) *out=(OotNativeReport){status,id,error,size};
    return (int)status;
}

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

static uint64_t read64(const uint8_t *p)
{
    uint64_t result=0;
    for (unsigned n=0;n<8;++n) result|=(uint64_t)p[n]<<(8*n);
    return result;
}

static int counter(uint64_t *value)
{
    if (*value==UINT64_MAX) return 0;
    ++*value;
    return 1;
}

static int config_valid(const OotNativeConfig *config)
{
    return config && config->version==OOT_SDK_NATIVE_VERSION &&
        config->operation_mode<=1 && config->performance_mode<=1 &&
        config->process_id && config->main_thread_id;
}

static int state_valid(const OotSdkNative *state)
{
    return state && state->version==OOT_SDK_NATIVE_VERSION &&
        config_valid(&state->config) && state->logging_initialized<=1 &&
        state->platform_initialized==0 && state->cpu_boost_mode==0 &&
        state->default_observer_enabled<=1 && state->last_log_size<=OOT_NATIVE_LOG_LIMIT &&
        (state->last_metadata_size==0 || state->last_metadata_size==NATIVE_META_SIZE) &&
        state->last_log_head<=1 && state->last_log_tail<=1 &&
        (state->destination==UINT32_C(0xffff) || !(state->destination & ~UINT32_C(7)));
}

static int separate(const void *a, size_t a_size, const void *b, size_t b_size)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x>=a_size:x-y>=b_size;
}

int oot_sdk_native_init(OotSdkNative *state, const OotNativeConfig *config)
{
    OotNativeConfig copied;
    if (!state || !config_valid(config)) return 0;
    copied=*config;
    *state=(OotSdkNative){0};
    state->version=OOT_SDK_NATIVE_VERSION;
    state->config=copied;
    state->destination=UINT32_C(0xffff);
    state->default_observer_enabled=1;
    return 1;
}

int oot_sdk_native_handler_valid(uint32_t id)
{
    return id==OOT_NATIVE_LM_INITIALIZE || id==OOT_NATIVE_LM_SET_DESTINATION ||
        id==OOT_NATIVE_DIAG_CALL_LOG_OBSERVERS ||
        id==OOT_NATIVE_DIAG_ENABLE_DEFAULT_LOG_OBSERVER || id==OOT_NATIVE_GUARD_UNSUPPORTED;
}

int oot_sdk_native_returns_value(uint32_t id)
{
    /* The initial registered family has only void APIs. Reserved getter IDs
     * are not valid handlers and cannot create an implicit return value. */
    (void)id;
    return 0;
}

static int capture_string(OotGuestMemory *memory, uint64_t address, char *out)
{
    uint64_t value;
    memset(out,0,OOT_NATIVE_STRING_LIMIT);
    if (!address) return 1;
    for (unsigned n=0;n<OOT_NATIVE_STRING_LIMIT;++n) {
        if (address>=NATIVE_ADDRESS_LIMIT || n>=NATIVE_ADDRESS_LIMIT-address ||
            !oot_memory_load(memory,address+n,1,&value)) return 0;
        out[n]=(char)(uint8_t)value;
        if (!value) return 1;
    }
    return 0;
}

int oot_sdk_native_prepare(const OotSdkNative *state, uint32_t id,
    const OotArm64State *registers, OotGuestMemory *memory, OotSdkNative *next,
    OotArm64State *result, OotNativeReport *report)
{
    OotSdkNative candidate;
    OotArm64State output;
    uint8_t metadata[NATIVE_META_SIZE],body[NATIVE_BODY_SIZE];
    uint64_t size,address;
    uint32_t captured_size=0;
    if (!state_valid(state) || !registers || !memory || memory->valid!=1 || !next || !result ||
        !separate(state,sizeof(*state),next,sizeof(*next)) ||
        !separate(state,sizeof(*state),result,sizeof(*result)) ||
        !separate(next,sizeof(*next),result,sizeof(*result)) ||
        !separate(registers,sizeof(*registers),next,sizeof(*next)) ||
        !separate(registers,sizeof(*registers),result,sizeof(*result)))
        return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_BAD_STATE,0);
    if (!registers->pc || registers->pc>=NATIVE_ADDRESS_LIMIT || registers->pc%4 ||
        registers->x[30]<4 || registers->x[30]>=NATIVE_ADDRESS_LIMIT || registers->x[30]%4 ||
        registers->sp%16 || (registers->nzcv & UINT32_C(0x0fffffff)))
        return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_BAD_ARGUMENT,0);
    if (!oot_sdk_native_handler_valid(id))
        return report_result(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_OK,0);
    if (id==OOT_NATIVE_GUARD_UNSUPPORTED)
        return report_result(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_UNSUPPORTED_CALLBACK,0);
    candidate=*state; output=*registers; output.pc=registers->x[30];
    if (!counter(&candidate.calls)) return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT,0);
    if (id==OOT_NATIVE_LM_INITIALIZE) {
        candidate.logging_initialized=1;
        if (!counter(&candidate.logging_initializations))
            return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT,0);
    }
    else if (id==OOT_NATIVE_DIAG_ENABLE_DEFAULT_LOG_OBSERVER) {
        if ((uint32_t)registers->x[0]>1)
            return report_result(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_INPUT,0);
        candidate.default_observer_enabled=(uint32_t)registers->x[0];
        if (!counter(&candidate.observer_updates))
            return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT,0);
    }
    else if (id==OOT_NATIVE_LM_SET_DESTINATION) {
        uint32_t destination=(uint32_t)registers->x[0];
        if (!candidate.logging_initialized ||
            (destination!=UINT32_C(0xffff) && destination & ~UINT32_C(7)))
            return report_result(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_INPUT,0);
        candidate.destination=destination;
        if (!counter(&candidate.destination_updates))
            return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT,0);
    }
    else {
        if (!candidate.logging_initialized)
            return report_result(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_STATE,0);
        if (!counter(&candidate.log_attempts)) return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT,0);
        if (candidate.default_observer_enabled && candidate.destination) {
            if (registers->x[0]>=NATIVE_ADDRESS_LIMIT || sizeof(metadata)>NATIVE_ADDRESS_LIMIT-registers->x[0] ||
                registers->x[1]>=NATIVE_ADDRESS_LIMIT || sizeof(body)>NATIVE_ADDRESS_LIMIT-registers->x[1] ||
                !oot_memory_load_native_input(memory,registers->x[0],metadata,sizeof(metadata)) ||
                !oot_memory_load_native_input(memory,registers->x[1],body,sizeof(body)))
                return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_BAD_MEMORY,0);
            size=read64(body+8); address=read64(body);
            if (size>OOT_NATIVE_LOG_LIMIT || body[16]>1 || body[17]>1 || read32(metadata+32)>4)
                return report_result(report,id,OOT_NATIVE_UNSUPPORTED,OOT_NATIVE_BAD_INPUT,0);
            if (size && (address>=NATIVE_ADDRESS_LIMIT || size>NATIVE_ADDRESS_LIMIT-address ||
                !oot_memory_load_native_input(memory,address,candidate.last_log,(unsigned)size)))
                return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_BAD_MEMORY,0);
            if (!capture_string(memory,read64(metadata+8),candidate.last_filename) ||
                !capture_string(memory,read64(metadata+16),candidate.last_function) ||
                !capture_string(memory,read64(metadata+24),candidate.last_module))
                return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_BAD_MEMORY,0);
            if (size>UINT64_MAX-candidate.log_bytes || !counter(&candidate.log_records))
                return report_result(report,id,OOT_NATIVE_FAULT,OOT_NATIVE_LIMIT,0);
            candidate.log_bytes+=size;
            candidate.last_log_size=(uint32_t)size;
            captured_size=(uint32_t)size;
            candidate.last_log_head=body[16]; candidate.last_log_tail=body[17];
            memset(candidate.last_log+size,0,sizeof(candidate.last_log)-(size_t)size);
            /* Keep only proved scalar metadata. Guest pointer fields and
             * uninspected extensions are not retained as borrowed references. */
            memset(candidate.last_metadata,0,sizeof(candidate.last_metadata));
            memcpy(candidate.last_metadata,metadata,4);
            memcpy(candidate.last_metadata+32,metadata+32,8);
            candidate.last_metadata_size=NATIVE_META_SIZE;
        }
    }
    *next=candidate; *result=output;
    return report_result(report,id,OOT_NATIVE_IMPLEMENTED,OOT_NATIVE_OK,captured_size);
}
