#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "guest_memory.h"
#include <string.h>

/* One total order per linked backend instance. Never call external code while
 * holding this nonrecursive lock. Caller-owned state/fault views stay separate.
 * All concurrent participants must use this backend, including ordinary stores. */
static SRWLOCK transfer_lock = SRWLOCK_INIT;

void oot_memory_clear_fault(OotGuestMemory *memory)
{
    AcquireSRWLockExclusive(&transfer_lock);
    if (memory != NULL)
        memory->fault = (OotMemoryFault){0};
    ReleaseSRWLockExclusive(&transfer_lock);
}

static int fail(OotGuestMemory *memory, uint64_t address, unsigned size,
                unsigned access, unsigned reason, uint64_t failing_address)
{
    if (memory != NULL)
        memory->fault = (OotMemoryFault){address, failing_address, size, access, reason};
    return 0;
}

int oot_memory_init(OotGuestMemory *memory, const OotGuestRegion *regions, size_t count)
{
    size_t index;
    if (memory == NULL)
        return 0;
    *memory = (OotGuestMemory){0};
    if (count > 4096 || (count != 0 && regions == NULL))
        return fail(memory, 0, 0, 0, OOT_MEMORY_CONFIGURATION, 0);
    for (index = 0; index < count; ++index) {
        const OotGuestRegion *region = &regions[index];
        if (region->size == 0 || region->size > SIZE_MAX || region->data == NULL ||
            region->size - 1 > UINT64_MAX - region->base || (region->permissions & ~3u) != 0)
            return fail(memory, region->base, 0, 0, OOT_MEMORY_CONFIGURATION, region->base);
        if (index != 0) {
            const OotGuestRegion *previous = &regions[index - 1];
            if (region->base <= previous->base || region->base - previous->base < previous->size)
                return fail(memory, region->base, 0, 0, OOT_MEMORY_CONFIGURATION, region->base);
        }
    }
    memory->regions = regions;
    memory->count = count;
    memory->valid = 1;
    return 1;
}

static const OotGuestRegion *find_region(const OotGuestMemory *memory, uint64_t address)
{
    size_t low = 0, high = memory->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (memory->regions[middle].base <= address)
            low = middle + 1;
        else
            high = middle;
    }
    if (low != 0) {
        const OotGuestRegion *region = &memory->regions[low - 1];
        if (address - region->base < region->size)
            return region;
    }
    return NULL;
}

static int check_limit(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access, unsigned limit)
{
    unsigned index;
    if (memory != NULL) memory->fault = (OotMemoryFault){0};
    if (memory == NULL || !memory->valid || size == 0 || size > limit)
        return fail(memory, address, size, access, OOT_MEMORY_CONFIGURATION, address);
    if ((uint64_t)(size - 1) > UINT64_MAX - address)
        return fail(memory, address, size, access, OOT_MEMORY_ADDRESS_WRAP, address);
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        if (region == NULL)
            return fail(memory, address, size, access, OOT_MEMORY_UNMAPPED, address + index);
        if ((region->permissions & access) != access)
            return fail(memory, address, size, access, OOT_MEMORY_PERMISSION, address + index);
    }
    return 1;
}

static int check(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access)
{
    return check_limit(memory,address,size,access,16);
}

int oot_memory_probe(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = access == OOT_MEMORY_READ || access == OOT_MEMORY_WRITE ? check(memory,address,size,access) :
        fail(memory,address,size,access,OOT_MEMORY_CONFIGURATION,address);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

static uint64_t read_bytes(OotGuestMemory *memory, uint64_t address, unsigned size)
{
    unsigned index;
    uint64_t result = 0;
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        result |= (uint64_t)region->data[(size_t)(address + index - region->base)] << (index * 8);
    }
    return result;
}

static void write_bytes(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value)
{
    unsigned index;
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        region->data[(size_t)(address + index - region->base)] = (uint8_t)(value >> (index * 8));
    }
}

static int load(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t *value)
{
    if (value == NULL || (size != 1 && size != 2 && size != 4 && size != 8))
        return fail(memory, address, size, OOT_MEMORY_READ, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, size, OOT_MEMORY_READ))
        return 0;
    *value = read_bytes(memory, address, size);
    return 1;
}

static int store(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value)
{
    if (size != 1 && size != 2 && size != 4 && size != 8)
        return fail(memory, address, size, OOT_MEMORY_WRITE, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, size, OOT_MEMORY_WRITE))
        return 0;
    write_bytes(memory, address, size, value);
    return 1;
}

static int load_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                         uint64_t *first, uint64_t *second)
{
    uint64_t first_value, second_value;
    if ((element_size != 4 && element_size != 8) || first == NULL || second == NULL || first == second)
        return fail(memory, address, 0, OOT_MEMORY_READ, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, element_size * 2, OOT_MEMORY_READ))
        return 0;
    first_value = read_bytes(memory, address, element_size);
    second_value = read_bytes(memory, address + element_size, element_size);
    *first = first_value;
    *second = second_value;
    return 1;
}

static int store_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                          uint64_t first, uint64_t second)
{
    if (element_size != 4 && element_size != 8)
        return fail(memory, address, 0, OOT_MEMORY_WRITE, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, element_size * 2, OOT_MEMORY_WRITE))
        return 0;
    write_bytes(memory, address, element_size, first);
    write_bytes(memory, address + element_size, element_size, second);
    return 1;
}

int oot_memory_load(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t *value)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = load(memory, address, size, value);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_store(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = store(memory, address, size, value);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_load_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size, uint64_t *first, uint64_t *second)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = load_pair(memory, address, element_size, first, second);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_store_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size, uint64_t first, uint64_t second)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = store_pair(memory, address, element_size, first, second);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_load_rcpc(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned sp_base, uint64_t *value)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    if (!memory || !memory->valid || !value || sp_base > 1 || (size != 1 && size != 2 && size != 4 && size != 8))
        ok = fail(memory, address, size, OOT_MEMORY_READ, OOT_MEMORY_CONFIGURATION, address);
    else if (address % size || (sp_base && address % 16))
        ok = fail(memory, address, size, OOT_MEMORY_READ, OOT_MEMORY_ALIGNMENT, address);
    else ok = load(memory, address, size, value);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

static int compare_exchange(OotGuestMemory *memory, uint64_t address,
    unsigned size, unsigned sp_base, uint64_t expected, uint64_t desired, uint64_t *observed,unsigned narrow)
{
    int ok;
    uint64_t value;
    const unsigned access = OOT_MEMORY_READ | OOT_MEMORY_WRITE;
    AcquireSRWLockExclusive(&transfer_lock);
    if (!memory || !memory->valid || !observed || sp_base > 1 ||
        (narrow ? (size!=1 && size!=2):(size!=4 && size!=8)))
        ok = fail(memory,address,size,access,OOT_MEMORY_CONFIGURATION,address);
    else if (address % size || (sp_base && address % 16))
        ok = fail(memory,address,size,access,OOT_MEMORY_ALIGNMENT,address);
    else {
        ok = check(memory,address,size,access);
        if (ok) {
            /* Size is validated before this shift, including the 64-bit case. */
            uint64_t mask=UINT64_MAX>>((8-size)*8);
            value = read_bytes(memory,address,size);
            if (value == (expected & mask)) write_bytes(memory,address,size,desired);
            *observed = value;
        }
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_compare_exchange(OotGuestMemory *memory,uint64_t address,
    unsigned size,unsigned sp_base,uint64_t expected,uint64_t desired,uint64_t *observed)
{ return compare_exchange(memory,address,size,sp_base,expected,desired,observed,0); }

int oot_memory_compare_exchange_narrow(OotGuestMemory *memory,uint64_t address,
    unsigned size,unsigned sp_base,uint64_t expected,uint64_t desired,uint64_t *observed)
{ return compare_exchange(memory,address,size,sp_base,expected,desired,observed,1); }

static int fetch_update(OotGuestMemory *memory, uint64_t address,
    unsigned size, unsigned sp_base, uint64_t operand, uint64_t *observed,unsigned operation)
{
    int ok;
    const unsigned access=OOT_MEMORY_READ | OOT_MEMORY_WRITE;
    AcquireSRWLockExclusive(&transfer_lock);
    if (!memory || memory->valid!=1 || !observed || sp_base>1 || (size!=4 && size!=8))
        ok=fail(memory,address,size,access,OOT_MEMORY_CONFIGURATION,address);
    else if (address%size || (sp_base && address%16))
        ok=fail(memory,address,size,access,OOT_MEMORY_ALIGNMENT,address);
    else {
        ok=check(memory,address,size,access);
        if (ok) {
            uint64_t old=read_bytes(memory,address,size);
            /* Unsigned host addition and byte truncation provide exact W/X
             * modulo arithmetic, including an arbitrary high addend. */
            write_bytes(memory,address,size,operation==1 ? old|operand:operation==2 ? old&~operand:old+operand);
            *observed=old;
        }
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_fetch_add(OotGuestMemory *memory,uint64_t address,unsigned size,unsigned sp_base,uint64_t operand,uint64_t *observed)
{ return fetch_update(memory,address,size,sp_base,operand,observed,0); }
int oot_memory_fetch_or(OotGuestMemory *memory,uint64_t address,unsigned size,unsigned sp_base,uint64_t operand,uint64_t *observed)
{ return fetch_update(memory,address,size,sp_base,operand,observed,1); }
int oot_memory_fetch_clear(OotGuestMemory *memory,uint64_t address,unsigned size,unsigned sp_base,uint64_t operand,uint64_t *observed)
{ return fetch_update(memory,address,size,sp_base,operand,observed,2); }

int oot_memory_store_release(OotGuestMemory *memory, uint64_t address,
    unsigned size, unsigned sp_base, uint64_t value)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    if (!memory || memory->valid!=1 || sp_base>1 || (size!=1 && size!=2 && size!=4 && size!=8))
        ok=fail(memory,address,size,OOT_MEMORY_WRITE,OOT_MEMORY_CONFIGURATION,address);
    else if (address%size || (sp_base && address%16))
        ok=fail(memory,address,size,OOT_MEMORY_WRITE,OOT_MEMORY_ALIGNMENT,address);
    else ok=store(memory,address,size,value);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_load_record(OotGuestMemory *memory, uint64_t address, uint8_t *bytes, unsigned size)
{
    uint8_t captured[OOT_MEMORY_RECORD_LIMIT];
    unsigned i;
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = bytes ? check_limit(memory,address,size,OOT_MEMORY_READ,OOT_MEMORY_RECORD_LIMIT) :
        fail(memory,address,size,OOT_MEMORY_READ,OOT_MEMORY_CONFIGURATION,address);
    if (ok) {
        for (i = 0; i < size; ++i) {
            const OotGuestRegion *r = find_region(memory,address+i);
            captured[i] = r->data[(size_t)(address+i-r->base)];
        }
        memcpy(bytes,captured,size);
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_store_record(OotGuestMemory *memory, uint64_t address, const uint8_t *bytes, unsigned size)
{
    uint8_t captured[OOT_MEMORY_RECORD_LIMIT];
    unsigned i;
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = bytes ? check_limit(memory,address,size,OOT_MEMORY_WRITE,OOT_MEMORY_RECORD_LIMIT) :
        fail(memory,address,size,OOT_MEMORY_WRITE,OOT_MEMORY_CONFIGURATION,address);
    if (ok) {
        memcpy(captured,bytes,size);
        for (i = 0; i < size; ++i) {
            const OotGuestRegion *r = find_region(memory,address+i);
            r->data[(size_t)(address+i-r->base)] = captured[i];
        }
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_load_native_input(OotGuestMemory *memory, uint64_t address, uint8_t *bytes, unsigned size)
{
    uint8_t captured[OOT_MEMORY_NATIVE_INPUT_LIMIT];
    unsigned i;
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = bytes ? check_limit(memory,address,size,OOT_MEMORY_READ,OOT_MEMORY_NATIVE_INPUT_LIMIT) :
        fail(memory,address,size,OOT_MEMORY_READ,OOT_MEMORY_CONFIGURATION,address);
    if (ok) {
        for (i=0;i<size;++i) {
            const OotGuestRegion *r=find_region(memory,address+i);
            captured[i]=r->data[(size_t)(address+i-r->base)];
        }
        memcpy(bytes,captured,size);
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_barrier(OotGuestMemory *memory, uint32_t option)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    if (!memory || memory->valid!=1 || option>15 || !(option & 3u))
        ok=fail(memory,0,0,0,OOT_MEMORY_CONFIGURATION,0);
    else {
        memory->fault=(OotMemoryFault){0};
        ok=1;
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

static int service_range(OotGuestMemory *memory,uint64_t address,unsigned size,unsigned access)
{
    uint64_t done=0;
    if(!memory || memory->valid!=1 || memory->count>4096 || (memory->count && !memory->regions) || !size)
        return fail(memory,address,size,access,OOT_MEMORY_CONFIGURATION,address);
    if((uint64_t)(size-1)>UINT64_MAX-address)return fail(memory,address,size,access,OOT_MEMORY_ADDRESS_WRAP,address);
    while(done<size){
        const OotGuestRegion *r=find_region(memory,address+done);
        if(!r)return fail(memory,address,size,access,OOT_MEMORY_UNMAPPED,address+done);
        if((r->permissions&access)!=access)return fail(memory,address,size,access,OOT_MEMORY_PERMISSION,address+done);
        uint64_t step=r->size-(address+done-r->base);
        if(step>size-done)step=size-done;
        done+=step;
    }return 1;
}

int oot_memory_store_service(OotGuestMemory *memory,const OotServiceWrite *writes,unsigned count)
{
    OotServiceWrite captured[2];unsigned total=0;int ok=0;
    AcquireSRWLockExclusive(&transfer_lock);
    if(memory)memory->fault=(OotMemoryFault){0};
    if(!writes || !count || count>2){fail(memory,0,0,OOT_MEMORY_WRITE,OOT_MEMORY_CONFIGURATION,0);goto done;}
    memcpy(captured,writes,count*sizeof(*writes));
    for(unsigned n=0;n<count;++n){
        OotServiceWrite *w=captured+n;
        if(!w->bytes || !w->size || w->size>OOT_MEMORY_SERVICE_WRITE_LIMIT ||
           w->size>OOT_MEMORY_SERVICE_WRITE_LIMIT+64-total){fail(memory,w->address,w->size,OOT_MEMORY_WRITE,OOT_MEMORY_CONFIGURATION,w->address);goto done;}
        if(!service_range(memory,w->address,w->size,OOT_MEMORY_WRITE))goto done;
        total+=w->size;
        for(unsigned k=0;k<n;++k){
            uint64_t a=w->address,b=captured[k].address;
            if(a<=b ? b-a<w->size:a-b<captured[k].size){fail(memory,a,w->size,OOT_MEMORY_WRITE,OOT_MEMORY_CONFIGURATION,a);goto done;}
        }
    }
    for(unsigned n=0;n<count;++n){
        unsigned done_bytes=0;OotServiceWrite *w=captured+n;
        while(done_bytes<w->size){
            const OotGuestRegion *r=find_region(memory,w->address+done_bytes);
            size_t at=(size_t)(w->address+done_bytes-r->base),step=(size_t)r->size-at;
            if(step>w->size-done_bytes)step=w->size-done_bytes;
            memcpy(r->data+at,w->bytes+done_bytes,step);done_bytes+=(unsigned)step;
        }
    }ok=1;
done:ReleaseSRWLockExclusive(&transfer_lock);return ok;
}

int oot_memory_load_service_path(OotGuestMemory *memory,uint64_t address,char *bytes,unsigned capacity,unsigned *length)
{
    char captured[OOT_MEMORY_SERVICE_PATH_LIMIT+1];unsigned n;int ok=0;
    AcquireSRWLockExclusive(&transfer_lock);
    if(memory)memory->fault=(OotMemoryFault){0};
    if(!bytes || !length || !capacity || capacity>sizeof(captured)){
        fail(memory,address,capacity,OOT_MEMORY_READ,OOT_MEMORY_CONFIGURATION,address);goto done;
    }
    for(n=0;n<capacity;++n){
        if(n>UINT64_MAX-address){fail(memory,address,capacity,OOT_MEMORY_READ,OOT_MEMORY_ADDRESS_WRAP,address);goto done;}
        if(!service_range(memory,address+n,1,OOT_MEMORY_READ))goto done;
        const OotGuestRegion *r=find_region(memory,address+n);
        captured[n]=(char)r->data[(size_t)(address+n-r->base)];
        if(!captured[n]){memcpy(bytes,captured,n+1);*length=n;ok=1;goto done;}
    }
    fail(memory,address,capacity,OOT_MEMORY_READ,OOT_MEMORY_CONFIGURATION,address);
done:ReleaseSRWLockExclusive(&transfer_lock);return ok;
}
