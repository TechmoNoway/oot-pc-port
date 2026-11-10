#ifndef OOT_NATIVE_ROMFS_H
#define OOT_NATIVE_ROMFS_H
#include "sdk_native.h"
#define OOT_ROMFS_QUERY_CACHE 384u
#define OOT_ROMFS_MOUNT_CACHE 385u
#define OOT_ROMFS_MOUNT 386u
#define OOT_ROMFS_UNMOUNT 387u
#define OOT_ROMFS_OPEN_FILE 388u
#define OOT_ROMFS_CLOSE_FILE 389u
#define OOT_ROMFS_FILE_SIZE 390u
#define OOT_ROMFS_READ_COUNT 391u
#define OOT_ROMFS_READ_EXACT 392u
#define OOT_ROMFS_ENTRY_TYPE 393u
#define OOT_ROMFS_READ_COUNT_OPTION 394u
#define OOT_ROMFS_READ_EXACT_OPTION 395u
#define OOT_ROMFS_MOUNT_METADATA 64u
typedef struct OotRomFs OotRomFs;
typedef struct OotRomFsStats {
    uint64_t files,directories,cache_bytes,mount_calls,open_calls,read_calls,bytes_read,verified_files,missing_paths;
    uint32_t mounted,open_handles;
} OotRomFsStats;
/* Private prepared index; backing handles deny concurrent writes/deletion.
 * File tokens name owned bounded host views, never SDK object pointers or IPC
 * handles. One owner thread; all public arguments/results must be private and
 * nonaliasing with provider/memory storage. Original guest file objects are
 * not fabricated. Unsupported API consumers must remain body-bound guards. */
OOT_MEMORY_API OotRomFs *oot_romfs_open_index(const char *path,uint64_t program_id,const uint8_t expected_sha256[32]);
OOT_MEMORY_API void oot_romfs_close(OotRomFs *fs);
OOT_MEMORY_API int oot_romfs_stats(const OotRomFs *fs,OotRomFsStats *out);
OOT_MEMORY_API int oot_romfs_handler_valid(uint32_t id);
OOT_MEMORY_API int oot_romfs_returns_value(uint32_t id);
/* Complete memory/output preflight before publishing handles, counters or
 * register results. A successful Open verifies the actual decoded file hash;
 * reads use explicit offsets and a bounded joint guest output transaction. */
OOT_MEMORY_API int oot_romfs_call(OotRomFs *fs,uint32_t id,OotArm64State *state,
    OotGuestMemory *memory,OotNativeReport *report);
#endif
