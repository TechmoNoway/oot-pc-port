#include "host.h"

#include <windows.h>

bool host_query_info(HostInfo *info) {
    SYSTEM_INFO system;
    LARGE_INTEGER frequency;
    if (info == NULL || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
        return false;
    }
    GetSystemInfo(&system);
    info->processor_count = system.dwNumberOfProcessors;
    info->page_size = system.dwPageSize;
    info->counter_frequency = (uint64_t)frequency.QuadPart;
    return true;
}

bool host_counter_read(uint64_t *ticks) {
    LARGE_INTEGER counter;
    if (ticks == NULL || !QueryPerformanceCounter(&counter)) {
        return false;
    }
    *ticks = (uint64_t)counter.QuadPart;
    return true;
}

void *host_memory_allocate(size_t bytes) {
    if (bytes == 0) {
        return NULL;
    }
    return VirtualAlloc(NULL, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

bool host_memory_release(void *memory) {
    return memory == NULL || VirtualFree(memory, 0, MEM_RELEASE) != 0;
}
