#include "runtime_image.h"
#include "host.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER_SIZE 96u
#define DESCRIPTOR_SIZE 64u
#define REGION_LIMIT 64u
#define MEMORY_LIMIT (UINT64_C(512) * 1024 * 1024)
#define ADDRESS_LIMIT (UINT64_C(1) << 39)

struct OotRuntimeImage {
    OotGuestMemory memory;
    OotGuestRegion regions[REGION_LIMIT];
    uint64_t stack_pointer;
    uint64_t backing_bytes;
    uint32_t kinds[REGION_LIMIT], region_count, references;
    uint8_t body_sha256[32];
    OotGuestRegion initial_regions[REGION_LIMIT];
    uint8_t initial_region_sha256[REGION_LIMIT][32];
    uint32_t startup_claimed;
};

static uint32_t read32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint64_t read64(const uint8_t *data)
{
    return read32(data) | ((uint64_t)read32(data + 4) << 32);
}

static int valid_name(const uint8_t *data)
{
    unsigned index = 0;
    while (index < 16 && data[index] != 0) {
        if (!((data[index] >= 'a' && data[index] <= 'z') ||
              (data[index] >= '0' && data[index] <= '9') || data[index] == '_'))
            return 0;
        ++index;
    }
    if (index == 0 || index == 16)
        return 0;
    for (; index < 16; ++index)
        if (data[index] != 0)
            return 0;
    return 1;
}

void oot_runtime_close(OotRuntimeImage *image)
{
    unsigned index;
    if (image == NULL)
        return;
    if (--image->references != 0)
        return;
    for (index = 0; index < REGION_LIMIT; ++index)
        if (image->regions[index].data != NULL)
            (void)host_memory_release(image->regions[index].data);
    free(image);
}

int oot_runtime_retain(OotRuntimeImage *image)
{
    if (image == NULL || image->references == UINT32_MAX) return 0;
    ++image->references;
    return 1;
}

int oot_runtime_claim_startup(OotRuntimeImage *image)
{
    uint32_t index;
    uint8_t digest[32];
    if (image == NULL || image->startup_claimed || image->memory.valid != 1 ||
        image->memory.regions != image->regions || image->memory.count != image->region_count)
        return 0;
    /* Check every descriptor before dereferencing any backing supplied through
     * the borrowed view. Stack changes also make an image non-pristine. */
    for (index = 0; index < image->region_count; ++index) {
        const OotGuestRegion *current = &image->regions[index], *initial = &image->initial_regions[index];
        if (current->base != initial->base || current->size != initial->size ||
            current->data != initial->data || current->permissions != initial->permissions)
            return 0;
    }
    for (index = 0; index < image->region_count; ++index) {
        const OotGuestRegion *r = &image->initial_regions[index];
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, r->data, (ULONG)r->size,
                       digest, sizeof(digest)) < 0 || memcmp(digest, image->initial_region_sha256[index], sizeof(digest)))
            return 0;
    }
    image->startup_claimed = 1;
    return 1;
}

uint64_t oot_runtime_stack_base(const OotRuntimeImage *image)
{
    return image != NULL && image->region_count != 0 ? image->regions[image->region_count - 1].base : 0;
}

uint32_t oot_runtime_region_kind(const OotRuntimeImage *image, size_t index)
{
    return image != NULL && index < image->region_count ? image->kinds[index] : 0;
}

int oot_runtime_check_code(const OotRuntimeImage *image, const uint8_t body_sha256[32],
    uint64_t entry, uint32_t byte_count, const uint8_t code_sha256[32])
{
    uint32_t index;
    uint8_t digest[32];
    if (image == NULL || body_sha256 == NULL || memcmp(image->body_sha256, body_sha256, 32) != 0)
        return OOT_CODE_BAD_IMAGE;
    if (code_sha256 == NULL || byte_count == 0 || byte_count > 65536 || !image->memory.valid ||
        image->memory.regions != image->regions || image->memory.count != image->region_count)
        return OOT_CODE_BAD_RANGE;
    for (index = 0; index < image->region_count; ++index) {
        const OotGuestRegion *r = &image->regions[index];
        if (image->kinds[index] == 1 && r->permissions == OOT_MEMORY_READ && entry >= r->base &&
            entry - r->base <= r->size && byte_count <= r->size - (entry - r->base)) {
            if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, r->data + (size_t)(entry - r->base), byte_count,
                           digest, sizeof(digest)) < 0 || memcmp(digest, code_sha256, 32) != 0)
                return OOT_CODE_BAD_HASH;
            return OOT_CODE_MATCH;
        }
    }
    return OOT_CODE_BAD_RANGE;
}

OotGuestMemory *oot_runtime_memory(OotRuntimeImage *image)
{
    return image != NULL ? &image->memory : NULL;
}

uint64_t oot_runtime_stack_pointer(const OotRuntimeImage *image)
{
    return image != NULL ? image->stack_pointer : 0;
}

uint64_t oot_runtime_backing_bytes(const OotRuntimeImage *image)
{
    return image != NULL ? image->backing_bytes : 0;
}

OotRuntimeImage *oot_runtime_open(const char *path, char *error, size_t error_size)
{
    FILE *file = NULL;
    uint8_t *blob = NULL, digest[32];
    OotRuntimeImage *image = NULL;
    const char *message = "invalid runtime package";
    long file_length;
    size_t length;
    uint32_t count, index;
    uint64_t cursor, previous_end = 0, total = 0, stack_pointer;
    unsigned stacks = 0;
    if (error != NULL && error_size != 0)
        error[0] = '\0';
    if (path == NULL || (file = fopen(path, "rb")) == NULL) {
        message = "could not open runtime package";
        goto failure;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (file_length = ftell(file)) < (long)HEADER_SIZE ||
        (uint64_t)file_length > MEMORY_LIMIT || fseek(file, 0, SEEK_SET) != 0)
        goto failure;
    length = (size_t)file_length;
    blob = malloc(length);
    if (blob == NULL) {
        message = "could not allocate package input buffer";
        goto failure;
    }
    if (fread(blob, 1, length, file) != length || fgetc(file) != EOF || ferror(file))
        goto failure;
    fclose(file);
    file = NULL;
    count = read32(blob + 12);
    if (memcmp(blob, "OOTMEM1\0", 8) != 0 || read32(blob + 8) != 1 || count == 0 || count > REGION_LIMIT ||
        read64(blob + 32) != HEADER_SIZE || read64(blob + 40) != HEADER_SIZE + (uint64_t)count * DESCRIPTOR_SIZE ||
        read64(blob + 48) != length || read64(blob + 56) != 0 || length < HEADER_SIZE + (size_t)count * DESCRIPTOR_SIZE)
        goto failure;
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, blob + HEADER_SIZE,
                   (ULONG)(length - HEADER_SIZE), digest, sizeof(digest)) < 0 || memcmp(digest, blob + 64, 32) != 0) {
        message = "runtime package body SHA-256 mismatch";
        goto failure;
    }
    image = calloc(1, sizeof(*image));
    if (image == NULL) {
        message = "could not allocate runtime image";
        goto failure;
    }
    image->references = 1;
    memcpy(image->body_sha256, blob + 64, 32);
    cursor = read64(blob + 40);
    stack_pointer = read64(blob + 16);
    for (index = 0; index < count; ++index) {
        const uint8_t *row = blob + HEADER_SIZE + (size_t)index * DESCRIPTOR_SIZE;
        uint64_t base = read64(row), size = read64(row + 8);
        uint64_t offset = read64(row + 16), payload = read64(row + 24);
        uint32_t permissions = read32(row + 32), kind = read32(row + 36);
        if (kind < 1 || kind > 5 || size == 0 || base >= ADDRESS_LIMIT || size > ADDRESS_LIMIT - base ||
            size > MEMORY_LIMIT - total || base < previous_end || offset != cursor ||
            cursor > length || payload > length - cursor || (payload != 0 && payload != size) ||
            (kind < 4 && payload != size) || permissions != (kind < 3 ? 1u : 3u) ||
            !valid_name(row + 40) || read64(row + 56) != 0)
            goto failure;
        if (kind == 5) {
            if (index != count - 1 || memcmp(row + 40, "stack\0", 6) != 0 || payload != 0 ||
                base % 4096 != 0 || size % 4096 != 0 || size < 4096 || size > UINT64_C(64) * 1024 * 1024 ||
                base < 4096 || previous_end > base - 4096 || base + size > ADDRESS_LIMIT - 4096 ||
                stack_pointer != base + size)
                goto failure;
            ++stacks;
        }
        image->regions[index] = (OotGuestRegion){base, size, NULL, permissions};
        image->kinds[index] = kind;
        image->regions[index].data = host_memory_allocate((size_t)size);
        if (image->regions[index].data == NULL) {
            message = "could not allocate native region backing";
            goto failure;
        }
        if (payload != 0)
            memcpy(image->regions[index].data, blob + (size_t)cursor, (size_t)payload);
        image->initial_regions[index] = image->regions[index];
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, image->regions[index].data,
                       (ULONG)size, image->initial_region_sha256[index], 32) < 0) {
            message = "could not fingerprint initial runtime region";
            goto failure;
        }
        cursor += payload;
        total += size;
        previous_end = base + size;
    }
    if (stacks != 1 || cursor != length || total != read64(blob + 24) ||
        !oot_memory_init(&image->memory, image->regions, count))
        goto failure;
    image->stack_pointer = stack_pointer;
    image->region_count = count;
    image->backing_bytes = total;
    free(blob);
    return image;

failure:
    if (file != NULL)
        fclose(file);
    free(blob);
    oot_runtime_close(image);
    if (error != NULL && error_size != 0)
        (void)snprintf(error, error_size, "%s", message);
    return NULL;
}
