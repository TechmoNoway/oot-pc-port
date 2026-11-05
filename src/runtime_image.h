#ifndef OOT_RUNTIME_IMAGE_H
#define OOT_RUNTIME_IMAGE_H

#include "guest_memory.h"

typedef struct OotRuntimeImage OotRuntimeImage;

/* Opens a validated, data-only snapshot. No constructors or guest PC are run.
 * The returned memory/table/backing remain live until close; do not edit metadata. */
OOT_MEMORY_API OotRuntimeImage *oot_runtime_open(const char *path, char *error, size_t error_size);
OOT_MEMORY_API OotGuestMemory *oot_runtime_memory(OotRuntimeImage *image);
OOT_MEMORY_API uint64_t oot_runtime_stack_pointer(const OotRuntimeImage *image);
OOT_MEMORY_API uint64_t oot_runtime_backing_bytes(const OotRuntimeImage *image);
OOT_MEMORY_API void oot_runtime_close(OotRuntimeImage *image);

#endif
