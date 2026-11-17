#ifndef OOT_NATIVE_NVN_RESOURCES_H
#define OOT_NATIVE_NVN_RESOURCES_H
#include "native_gpu.h"
#include "guest_memory.h"
#define OOT_NVN_POOL_INITIALIZE 466u
#define OOT_NVN_POOL_FINALIZE 467u
#define OOT_NVN_POOL_MAP 468u
#define OOT_NVN_POOL_GET_SIZE 469u
#define OOT_NVN_POOL_GET_FLAGS 470u
#define OOT_NVN_POOL_FLUSH 471u
#define OOT_NVN_POOL_INVALIDATE 472u
#define OOT_NVN_POOL_GET_ADDRESS 473u
#define OOT_NVN_BUFFER_INITIALIZE 474u
#define OOT_NVN_BUFFER_FINALIZE 475u
#define OOT_NVN_BUFFER_MAP 476u
#define OOT_NVN_BUFFER_GET_ADDRESS 477u
#define OOT_NVN_BUFFER_GET_POOL 478u
#define OOT_NVN_BUFFER_GET_OFFSET 479u
#define OOT_NVN_BUFFER_GET_SIZE 480u
#define OOT_NVN_BUFFER_FLUSH 481u
#define OOT_NVN_BUFFER_INVALIDATE 482u
#define OOT_NVN_SAMPLER_POOL_INITIALIZE 483u
#define OOT_NVN_SAMPLER_POOL_FINALIZE 484u
#define OOT_NVN_SAMPLER_POOL_GET_POOL 485u
#define OOT_NVN_SAMPLER_POOL_GET_OFFSET 486u
#define OOT_NVN_SAMPLER_POOL_GET_SIZE 487u
#define OOT_NVN_TEXTURE_POOL_INITIALIZE 488u
#define OOT_NVN_TEXTURE_POOL_FINALIZE 489u
#define OOT_NVN_TEXTURE_POOL_GET_POOL 490u
#define OOT_NVN_TEXTURE_POOL_GET_OFFSET 491u
#define OOT_NVN_TEXTURE_POOL_GET_SIZE 492u
#define OOT_NVN_SAMPLER_POOL_REGISTER 493u
#define OOT_NVN_SAMPLER_POOL_REGISTER_BUILDER 494u
#define OOT_NVN_RESOURCE_LAST OOT_NVN_SAMPLER_POOL_REGISTER_BUILDER
typedef struct OotNvnResources OotNvnResources;
typedef struct OotNvnRange {uint64_t address,size;} OotNvnRange;
typedef struct OotNvnResourcesReport {
    uint64_t pools,buffers,bytes,initializations,finalizations,maps,queries,flushes,invalidations;
    uint64_t descriptor_pools,descriptor_slots,descriptor_initializations,descriptor_finalizations,descriptor_queries;
    uint64_t samplers,sampler_registrations;
} OotNvnResourcesReport;
/* Serial creator-thread owner. Pool GPU VAs equal their checked guest storage
 * addresses in this explicit private model, with no range/identity reuse during
 * owner lifetime. They resolve only to the owned Vulkan shadow and offset.
 * They are neither Vulkan device addresses nor host pointers. All unsupported
 * NVN consumers stay guarded. Guest memory is recaptured at each future submit;
 * never retain native pointers into a remappable guest heap. */
OotNvnResources *oot_nvn_resources_create(OotGraphics*,OotGuestMemory*,uint64_t device,const OotNvnRange *forbidden,unsigned count);
void oot_nvn_resources_destroy(OotNvnResources*);
int oot_nvn_resources_call4(OotNvnResources*,uint32_t id,uint64_t object,uint64_t arg1,uint64_t arg2,uint64_t arg3,uint64_t *result);
int oot_nvn_resources_call(OotNvnResources*,uint32_t id,uint64_t object,uint64_t arg1,uint64_t arg2,uint64_t *result);
int oot_nvn_resources_output(const OotNvnResources*,uint64_t address,uint64_t size);
int oot_nvn_resources_resolve(OotNvnResources*,uint64_t address,uint64_t size,OotGpuBuffer **buffer,uint64_t *offset);
int oot_nvn_resources_snapshot(const OotNvnResources*,OotNvnResourcesReport*);
#endif
