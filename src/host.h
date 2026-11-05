#ifndef OOT_PC_PORT_HOST_H
#define OOT_PC_PORT_HOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t processor_count;
    uint32_t page_size;
    uint64_t counter_frequency;
} HostInfo;

bool host_query_info(HostInfo *info);
bool host_counter_read(uint64_t *ticks);
void *host_memory_allocate(size_t bytes);
bool host_memory_release(void *memory);

#endif
