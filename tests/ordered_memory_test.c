#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdio.h>
#include "arm64_lift.h"

/* Backend concurrency tests, not a guest scheduler. Every worker owns its view
 * and state; only immutable tables and backing accessed via the backend overlap.
 * Distinct guest aliases share the same native bytes to test the lock domain. */
typedef int (*TestReader)(OotArm64State *, OotGuestMemory *, uint64_t, uint64_t *);
typedef struct Worker {
    OotGuestMemory memory;
    HANDLE start;
    volatile LONG *failed;
    TestReader reader;
    uint64_t base, entry;
    unsigned size, rounds, consumer, mode;
} Worker;

static int read_flag(Worker *w, uint64_t *value)
{
    if (w->consumer && w->reader) {
        OotArm64State s = {0};
        uint64_t count = UINT64_MAX;
        s.pc = w->entry; s.x[0] = UINT64_MAX; s.x[1] = w->base;
        if (w->reader(&s, &w->memory, 1, &count) != OOT_LIFT_DISPATCH || count != 1 ||
            s.pc != w->entry + 4 || w->memory.fault.reason) return 0;
        *value = s.x[0];
        return 1;
    }
    return oot_memory_load_rcpc(&w->memory, w->base, w->size, 0, value);
}

static int wait_value(Worker *w, uint64_t address, uint64_t expected)
{
    ULONGLONG limit = GetTickCount64() + 15000;
    unsigned spins = 0;
    for (;;) {
        uint64_t value;
        int ok = address == w->base ? read_flag(w, &value) : oot_memory_load(&w->memory, address, w->size, &value);
        if (!ok || InterlockedCompareExchange(w->failed, 0, 0) || GetTickCount64() > limit) return 0;
        if (value == expected) return 1;
        if (++spins % 64 == 0) SwitchToThread();
    }
}

static DWORD WINAPI worker(void *argument)
{
    Worker *w = (Worker *)argument;
    uint64_t mask = UINT64_MAX >> ((8 - w->size) * 8);
    unsigned i;
    if (WaitForSingleObject(w->start, 15000) != WAIT_OBJECT_0) goto failure;
    for (i = 1; i <= w->rounds; ++i) {
        uint64_t a, b;
        if (InterlockedCompareExchange(w->failed, 0, 0)) return 1;
        if (w->mode == 0) {
            if (w->consumer) {
                if (!wait_value(w,w->base,i & mask) ||
                    !oot_memory_load(&w->memory,w->base+8,8,&a) ||
                    !oot_memory_load(&w->memory,w->base+16,8,&b) ||
                    a != (i ^ UINT64_C(0x7b38c4d2a69105ef)) || b != ~(uint64_t)i ||
                    !oot_memory_store(&w->memory,w->base+24,w->size,i & mask)) goto failure;
            } else if (!wait_value(w,w->base+24,(i-1) & mask) ||
                !oot_memory_store(&w->memory,w->base+8,8,i ^ UINT64_C(0x7b38c4d2a69105ef)) ||
                !oot_memory_store(&w->memory,w->base+16,8,~(uint64_t)i) ||
                !oot_memory_store(&w->memory,w->base,w->size,i & mask)) goto failure;
        } else if (w->mode == 1) {
            if (w->consumer) {
                if (!read_flag(w,&a) || (a != (UINT64_C(0xaaaaaaaaaaaaaaaa)&mask) &&
                                        a != (UINT64_C(0x5555555555555555)&mask))) goto failure;
            } else if (!oot_memory_store(&w->memory,w->base,w->size,
                           i & 1 ? UINT64_C(0xaaaaaaaaaaaaaaaa) : UINT64_C(0x5555555555555555))) goto failure;
        } else {
            if (w->consumer) {
                if (!oot_memory_load_pair(&w->memory,w->base+8,8,&a,&b) || a != ~b) goto failure;
            } else if (!oot_memory_store_pair(&w->memory,w->base+8,8,i,~(uint64_t)i)) goto failure;
        }
    }
    return 0;
failure:
    InterlockedExchange(w->failed, 1);
    return 1;
}

OOT_MEMORY_API int oot_ordered_memory_stress(TestReader reader, uint64_t entry, unsigned size, unsigned rounds)
{
    unsigned mode;
    if ((size != 1 && size != 2 && size != 4 && size != 8) || !rounds || rounds > 1000000) return 0;
    for (mode = 0; mode < 3; ++mode) {
        uint8_t backing[32] = {0};
        OotGuestRegion regions[2] = {{UINT64_C(0x200000000),32,backing,3},{UINT64_C(0x300000000),32,backing,3}};
        Worker args[2] = {0};
        HANDLE threads[2], start = CreateEventW(NULL,TRUE,FALSE,NULL);
        volatile LONG failed = 0;
        unsigned i;
        DWORD exit_code;
        if (!start) return 0;
        for (i = 0; i < 2; ++i) {
            if (!oot_memory_init(&args[i].memory,&regions[i],1)) { CloseHandle(start); return 0; }
            args[i].start=start; args[i].failed=&failed; args[i].reader=reader; args[i].entry=entry;
            args[i].base=regions[i].base; args[i].size=size; args[i].rounds=rounds; args[i].consumer=i; args[i].mode=mode;
        }
        if (mode == 1) (void)oot_memory_store(&args[0].memory,regions[0].base,size,UINT64_C(0xaaaaaaaaaaaaaaaa));
        if (mode == 2) (void)oot_memory_store_pair(&args[0].memory,regions[0].base+8,8,0,UINT64_MAX);
        threads[0]=CreateThread(NULL,0,worker,&args[0],0,NULL);
        threads[1]=CreateThread(NULL,0,worker,&args[1],0,NULL);
        if (!threads[0] || !threads[1]) {
            InterlockedExchange(&failed,1); SetEvent(start);
            for (i=0;i<2;++i) if (threads[i]) { (void)WaitForSingleObject(threads[i],INFINITE); CloseHandle(threads[i]); }
            CloseHandle(start); return 0;
        }
        SetEvent(start);
        /* A timeout must not unwind storage while a worker still uses it. */
        if (WaitForMultipleObjects(2,threads,TRUE,30000) != WAIT_OBJECT_0) ExitProcess(1);
        for (i=0;i<2;++i) {
            if (!GetExitCodeThread(threads[i],&exit_code) || exit_code) InterlockedExchange(&failed,1);
            CloseHandle(threads[i]);
        }
        CloseHandle(start);
        if (failed) return 0;
    }
    return 1;
}

#ifndef OOT_ORDERED_STRESS_SHARED
int main(void)
{
    unsigned size;
    for (size=1;size<=8;size*=2) if (!oot_ordered_memory_stress(NULL,0,size,10000)) {
        fprintf(stderr,"Ordered memory concurrency failed for width %u.\n",size); return 1;
    }
    puts("Ordered memory publication, scalar and pair atomicity checks passed.");
    return 0;
}
#endif
