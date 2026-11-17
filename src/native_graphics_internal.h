#ifndef OOT_NATIVE_GRAPHICS_INTERNAL_H
#define OOT_NATIVE_GRAPHICS_INTERNAL_H
/* Host-only renderer borrow. No member is serialized or exposed as a guest handle. */
#ifndef VK_NO_PROTOTYPES
#define VK_NO_PROTOTYPES
#endif
#include <vulkan/vulkan_core.h>
#include "native_graphics.h"
typedef struct OotGraphicsVulkan {
    VkInstance instance;
    VkPhysicalDevice physical;
    VkDevice device;
    VkQueue queue;
    uint32_t family;
    PFN_vkGetDeviceProcAddr get_device;
    PFN_vkGetPhysicalDeviceImageFormatProperties image_format;
    VkPhysicalDeviceProperties properties;
    VkPhysicalDeviceMemoryProperties memory;
} OotGraphicsVulkan;
/* A successful acquisition retains graphics. Release through oot_graphics_destroy.
 * Calls/queue use are serialized on the caller's thread. No GPU feature beyond
 * the parent's enabled Vulkan 1.0 baseline is implied by physical properties. */
int oot_graphics_acquire_vulkan(OotGraphics *graphics,OotGraphicsVulkan *out);
#endif
