#ifndef OOT_RUNTIME_IMAGE_H
#define OOT_RUNTIME_IMAGE_H

#include "guest_memory.h"

typedef struct OotRuntimeImage OotRuntimeImage;
enum OotCodeMatch { OOT_CODE_MATCH = 0, OOT_CODE_BAD_IMAGE = 1, OOT_CODE_BAD_RANGE = 2, OOT_CODE_BAD_HASH = 3 };

/* Opens a validated, data-only snapshot with one owning reference. No guest PC
 * is run. Borrowed views live until the final close; do not edit metadata. */
OOT_MEMORY_API OotRuntimeImage *oot_runtime_open(const char *path, char *error, size_t error_size);
OOT_MEMORY_API OotGuestMemory *oot_runtime_memory(OotRuntimeImage *image);
OOT_MEMORY_API uint64_t oot_runtime_stack_pointer(const OotRuntimeImage *image);
OOT_MEMORY_API uint64_t oot_runtime_backing_bytes(const OotRuntimeImage *image);
OOT_MEMORY_API uint64_t oot_runtime_stack_base(const OotRuntimeImage *image);
/* Single-threaded ownership: retain adds a reference, close releases one. */
OOT_MEMORY_API int oot_runtime_retain(OotRuntimeImage *image);
/* Snapshot identity is immutable; writable data may change after loading.
 * Code matching hashes the current bytes of one read-only text region. */
OOT_MEMORY_API int oot_runtime_check_code(const OotRuntimeImage *image, const uint8_t body_sha256[32],
    uint64_t entry, uint32_t byte_count, const uint8_t code_sha256[32]);
OOT_MEMORY_API void oot_runtime_close(OotRuntimeImage *image);

#endif
