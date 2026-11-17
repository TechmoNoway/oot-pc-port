#ifndef OOT_NVN_LAYOUT_H
#define OOT_NVN_LAYOUT_H
/* Source-proved serialized ABI geometry, not hardware feature/limit claims.
 * Guest resource/command consumers stay guarded until separately implemented. */
#define OOT_NVN_TEXTURE_DESCRIPTOR_SIZE 32u
#define OOT_NVN_SAMPLER_DESCRIPTOR_SIZE 32u
#define OOT_NVN_RESERVED_TEXTURE_DESCRIPTORS 256u
#define OOT_NVN_RESERVED_SAMPLER_DESCRIPTORS 256u
#define OOT_NVN_COMMAND_ALIGNMENT 4u
#define OOT_NVN_CONTROL_ALIGNMENT 8u
#endif
